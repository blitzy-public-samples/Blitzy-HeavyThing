# HeavyThing Data Structures

Core in-process containers (heap, list, maps, buffer, json) used by every other HeavyThing subsystem.

## Overview

The data structures subsystem provides five foundational in-process containers: a bin-based memory allocator (`heap.inc`), a doubly-linked list (`list.inc`), an AVL-tree-based ordered map family covering four key types (`maps.inc`), a growable byte buffer (`buffer.inc`), and a JSON parser and serialiser (`json.inc`). The heap is the base layer — it uses bin-based allocation that is never returned to the kernel (Source: `/heap.inc:35-42`), and every other container in this subsystem calls `heap$alloc`/`heap$free` to obtain and release storage. The maps family supplies AVL trees keyed by signed integer, unsigned integer, IEEE 754 double, or string, with no user-supplied comparator (Source: `/maps.inc:22-23`). All five containers follow the library-wide `subsystem$function` label-naming convention (for example, `heap$alloc`, `list$push_front`, `stringmap$find_value`) described in `../docs/calling-convention.md`.

## Architecture Fit

The five files form a small dependency chain within the library:

- `heap.inc` is foundational. Every other container in this subsystem allocates its control blocks and payload storage through `heap$alloc` and releases them through `heap$free`. Verified call sites include `list$new` at `/list.inc:50` invoking `heap$alloc` at `/list.inc:53`, `mapcommon$new` at `/maps.inc:53` invoking `heap$alloc` at `/maps.inc:69`, `buffer$new` at `/buffer.inc:40` invoking `heap$alloc` twice (at `/buffer.inc:43` for the object header and `/buffer.inc:46` for the initial 256-byte backing store), and `json$newvalue` at `/json.inc:45` invoking `heap$alloc` at `/json.inc:56`.
- `buffer.inc` is the foundation for string operations throughout the library. The string engines `string16.inc` and `string32.inc` build on the same byte-buffer idioms, and `json$tostring` at `/json.inc:367` explicitly calls `buffer$new` at `/json.inc:371` to compose its UTF-32 output before handing the bytes to the active string engine via `string$from_utf32` (Source: `/json.inc:381`).
- `json.inc` consumes `buffer.inc` and integrates with `maps.inc`: it uses `buffer.inc` for serialisation (`json$tostring`, Source: `/json.inc:367-387`) and for parsing (`json$parse_object` at `/json.inc:921` allocates its working buffer via `buffer$new` at `/json.inc:926`); it integrates with `maps.inc` as a structured-container layer built above the same heap foundation, although JSON tree nodes are stored as linked children rather than in an AVL tree.
- `maps.inc` exposes four parallel entry-point families (`intmap$*`, `unsignedmap$*`, `doublemap$*`, `stringmap$*`) that share a single AVL tree implementation via the `mapcommon$*` multi-entry-point labels (Source: `/maps.inc:53-82`).

The subsystem is loaded by `ht.inc` in the following order: `heap.inc` at `/ht.inc:90`, `list.inc` at `/ht.inc:106`, `json.inc` at `/ht.inc:118`, `maps.inc` at `/ht.inc:122`, and `buffer.inc` at `/ht.inc:128`. Note that `json.inc` is included before `maps.inc` and `buffer.inc`; FASM resolves forward references at end-of-pass, so the apparent out-of-order include has no runtime consequence. For the complete include-dependency graph across the entire library, see `../docs/architecture.md`.

## Key Components

| File | Purpose |
|---|---|
| `../heap.inc` | Bin-based memory allocator; foundation for all other containers. Provides `heap$init`, `heap$alloc`, `heap$alloc_clear`, `heap$alloc_permanent`, and `heap$free` (Source: `/heap.inc:83, 499, 836, 243, 891`). Allocations above 1 MiB go directly to `mmap`; smaller allocations use bins with varying granularity (Source: `/heap.inc:56-60`). |
| `../list.inc` | Doubly-linked list with push, pop, insert, iterate, and clear primitives (Source: `/list.inc:22-28`). List nodes are 24 bytes: value, next, prev (Source: `/list.inc:41-44`). |
| `../buffer.inc` | Dynamic growable byte buffer; foundation for string operations throughout the library (Source: `/buffer.inc:22`). Default initial capacity is 256 bytes (Source: `/buffer.inc:34`). |
| `../maps.inc` | AVL trees keyed by signed int, unsigned int, IEEE 754 double, or string (Source: `/maps.inc:22-24`). Insert-order and sort-order modes are selected at map creation time (Source: `/maps.inc:50-51`). |
| `../json.inc` | JSON parser and serialiser built on `buffer.inc` and the active string engine (Source: `/json.inc:22-26`). Supports the three standard JSON node types: value, array, object (Source: `/json.inc:29-31`). |

### Related files

| Related file | Purpose |
|---|---|
| `../mapped.inc` | Helper object that wraps `mmap`-backed regions for file-backed memory. |
| `../privmapped.inc` | Private `mmap` helper used by utilities such as `examples/minigzip`. |
| `../mappedheap.inc` | File-backed heap with a coalescing free-list for persistent storage. |
| `../string16.inc` / `../string32.inc` | Immutable UTF-16 or UTF-32 string engine selected at compile time via `string_bits` in `ht_defaults.inc`. |
| `../string_math.inc` | Numeric-string conversion helpers that build on the active string engine. |

### Memory layout

Internal control-block sizes for each container, verified from the header `virtual at` blocks and size constants in each file:

| Container | Control-block size | Layout | Source |
|---|---|---|---|
| List object | 24 bytes | `size`, `first`, `last` (three qwords) | `/list.inc:30-38` |
| List item | 24 bytes | `value`, `next`, `prev` (three qwords) | `/list.inc:41-44` |
| AVL node | 68 bytes | `parent`, `key`, `left`, `right`, `trunk`, `next`, `prev`, `value`, plus flags dword | `/maps.inc:33-44` |
| Buffer object | 56 bytes header, 256 bytes initial backing store | `endptr`, `length`, `itself`, `size`, and a 24-byte user region | `/buffer.inc:25-34` |
| JSON node | 24 bytes | `name`, `type` (dword), `value`/`contents` (shared qword at offset 16) | `/json.inc:28-38` |

Every control block above is allocated through `heap$alloc`. Buffer and JSON nodes also trigger additional heap allocations for their payload (the buffer backing store and the contents-list storage respectively).

### Heap bin tiers

The heap allocator groups non-`mmap` allocations into four tiered bins plus a direct-`mmap` path for large requests (Source: `/heap.inc:56-60`):

| Request size | Bin granularity | Bin count |
|---|---|---|
| up to 2048 bytes | 64 bytes | 32 |
| 2048 to 16384 bytes | 1024 bytes | 14 |
| 16384 to 131072 bytes | 4096 bytes | 28 |
| 131072 to 1048576 bytes | 65536 bytes | 14 |
| above 1048576 bytes | direct `mmap` | not binned |

On process start, `heap$init` at `/heap.inc:83` reserves up to 16 GiB of virtual address space by issuing `mmap` for 2 GiB shifted left by the `initial_heap_shiftcount = 3` constant at `/heap.inc:80`, and falls back to smaller reservations on `ENOMEM` (Source: `/heap.inc:85-104`). The actual committed bookkeeping region is `139272 + (heap_bincheck * 8)` bytes; the remainder of the reservation is lazily faulted in as allocations progress.

## Calling Convention

All data-structure labels follow the library-wide `subsystem$function` naming pattern and the HeavyThing register calling convention. Integer arguments are passed in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`; the return value comes back in `rax`. Callee-saved registers (`rbx`, `rbp`, `r12`-`r15`) are preserved through the `prolog`/`epilog` macros defined in `../profiler.inc`. For the full register contract, the `prolog`/`epilog` macro semantics, and the 16-byte stack-alignment expectation at call sites, see `../docs/calling-convention.md`.

### Heap (heap.inc)

| Label | Arguments | Returns | Source |
|---|---|---|---|
| `heap$init` | none | initialises the global heap; terminates with exit code 99 on `mmap` failure | `/heap.inc:83` |
| `heap$alloc` | `rdi` = byte count | `rax` = pointer, or `exit(99)` on `mremap` failure | `/heap.inc:499` |
| `heap$alloc_clear` | `rdi` = byte count | `rax` = pointer to a zero-initialised region (memset rounded up to the nearest 8 bytes) | `/heap.inc:836` |
| `heap$alloc_permanent` | `rdi` = byte count | `rax` = pointer from a direct `mmap`; memory is never returned to the bins | `/heap.inc:243` |
| `heap$free` | `rdi` = pointer | none | `/heap.inc:891` |

`heap$init` is normally invoked from `ht$init` rather than directly by user code (Source: `/ht.inc:609` and `/heap.inc:83`).

### List (list.inc)

| Label | Arguments | Returns | Source |
|---|---|---|---|
| `list$new` | none | `rax` = new empty list object | `/list.inc:50` |
| `list$push_front` | `rdi` = list, `rsi` = value | `rax` = new list item | `/list.inc:127` |
| `list$push_back` | `rdi` = list, `rsi` = value | `rax` = new list item | `/list.inc:155` |
| `list$pop_front` | `rdi` = list | `rax` = popped value | `/list.inc:240` |
| `list$foreach` | `rdi` = list, `rsi` = function pointer (receives value in `rdi`) | none | `/list.inc:517` |
| `list$clear` | `rdi` = list, `rsi` = optional cleanup function (or 0) | none | `/list.inc:743` |
| `list$destroy` | `rdi` = list | none; frees only the list object and its nodes — call `list$clear` first if values need freeing | `/list.inc:64-67` |

The `list$destroy` narrative comment states that the routine does not walk the list and that callers must invoke `list$clear` first to free stored values (Source: `/list.inc:64-67`).

### Maps (maps.inc)

| Label | Arguments | Returns | Source |
|---|---|---|---|
| `stringmap$new` | `edi` = insert-order bool (`0` = sorted, `1` = insert-order) | `rax` = new empty map | `/maps.inc:64` |
| `stringmap$insert` | `rdi` = map, `rsi` = key, `rdx` = value | none; accepts duplicate keys (multimap behaviour) | `/maps.inc:3089` |
| `stringmap$insert_unique` | `rdi` = map, `rsi` = key, `rdx` = value | `rax` = bool success, `r8` = existing node if the unique constraint was violated | `/maps.inc:2262` |
| `stringmap$find` | `rdi` = map, `rsi` = key | `rax` = node pointer or 0 | `/maps.inc:419` |
| `stringmap$find_value` | `rdi` = map, `rsi` = key | `eax` = found bool, `rdx` = value if found | `/maps.inc:401` |
| `stringmap$destroy` | `rdi` = map | none; frees only the map object — call `stringmap$clear` first if keys and values need freeing | `/maps.inc:101` |

The `intmap$*`, `unsignedmap$*`, and `doublemap$*` families mirror the string variants with equivalent contracts; they share the AVL machinery through the `mapcommon$*` multi-entry-point labels at `/maps.inc:53-82`. The doublemap variant differs in one respect: its optional foreach and clear callback functions receive the key in `xmm0` and the value in `rdi` rather than the standard `rdi`/`rsi` pairing (Source: `/maps.inc:114`).

### Buffer (buffer.inc)

| Label | Arguments | Returns | Source |
|---|---|---|---|
| `buffer$new` | none | `rax` = new buffer with initial capacity of `buffer_default_size` (256) | `/buffer.inc:40`, `/buffer.inc:34` |
| `buffer$append` | `rdi` = buffer, `rsi` = source bytes, `rdx` = length | none; the buffer grows via `buffer$reserve` as required | `/buffer.inc:263` |
| `buffer$reserve` | `rdi` = buffer, `rsi` = length to reserve | none; ensures the backing store has at least the requested free space | `/buffer.inc:129` |
| `buffer$reset` | `rdi` = buffer | none; sets length to 0 without releasing the backing store | `/buffer.inc:189` |
| `buffer$copy` | `rdi` = buffer | `rax` = clone of the buffer | `/buffer.inc:77` |
| `buffer$destroy` | `rdi` = buffer | none; frees the backing store and the buffer object | `/buffer.inc:63` |

### JSON (json.inc)

| Label | Arguments | Returns | Source |
|---|---|---|---|
| `json$newvalue` | `rdi` = name string, `rsi` = value string | `rax` = new JSON value node; both inputs are copied via `string$copy`, no ownership is assumed | `/json.inc:45` |
| `json$newarray` | `rdi` = name string | `rax` = new empty array node | `/json.inc:91` |
| `json$newobject` | `rdi` = name string | `rax` = new empty object node | `/json.inc:134` |
| `json$appendchild` | `rdi` = parent, `rsi` = child | none | `/json.inc:336` |
| `json$parse_object` | `rdi` = source string, `esi` = bool expect-leading-function-name | `rax` = new JSON tree or 0 on parse error | `/json.inc:921` |
| `json$tostring` | `rdi` = JSON object | `rax` = new string in JSON encoding | `/json.inc:367` |
| `json$destroy` | `rdi` = JSON object | none; recursive over all descendants | `/json.inc:278` |

## Usage

The following snippet shows the three-file include contract and a representative list-allocate-append call sequence. Every HeavyThing program begins with `include 'ht_defaults.inc'`, then `include 'ht.inc'`, then the program body, and ends with `include 'ht_data.inc'` as the final statement (Source: `/examples/hello_world/hello_world.asm:24-41`).

```nasm
include 'ht_defaults.inc'
include 'ht.inc'
public _start
_start:
    call    ht$init              ; required before any heap-dependent call
    call    list$new             ; rax = new empty list
    mov     rdi, rax             ; rdi = list pointer
    mov     rsi, 42              ; rsi = value to append
    call    list$push_back       ; appends 42 to the back of the list
    mov     eax, syscall_exit
    xor     edi, edi
    syscall
include 'ht_data.inc'
```

`ht$init` must run before any routine that allocates from the heap, because it performs the initial `mmap` of the heap base (Source: `/ht.inc:609` and `/heap.inc:83-84`). Every public data-structure entry point follows the `subsystem$function` convention shown above — `list$new`, `list$push_back`, `heap$alloc`, and so on — which is the same pattern used throughout the rest of the library (Source: `/examples/hello_world/hello_world.asm:30-33`).

A more complete lifecycle example demonstrates the ownership contract called out in the Limitations section: containers must be cleared with a cleanup function before destruction if their stored values are heap-owned. The snippet below allocates a buffer, appends content, then releases it; and allocates a list of buffers, iterates them for free, and destroys the list:

```nasm
include 'ht_defaults.inc'
include 'ht.inc'
public _start
_start:
    call    ht$init                 ; required before any heap-dependent call

    ; --- buffer lifecycle ---
    call    buffer$new              ; rax = new empty buffer (Source: /buffer.inc:40)
    mov     rdi, rax                ; rdi = buffer pointer
    lea     rsi, [msg]              ; rsi = source bytes
    mov     rdx, msg_len            ; rdx = byte count
    call    buffer$append           ; appends bytes (Source: /buffer.inc:263)
    call    buffer$destroy          ; frees buffer and its backing store (Source: /buffer.inc:63)

    ; --- list-of-buffers lifecycle with proper cleanup ---
    call    list$new                ; rax = new empty list (Source: /list.inc:50)
    ; (insert buffer pointers via list$push_back here)
    mov     rdi, rax                ; rdi = list pointer
    lea     rsi, [buffer$destroy]   ; rsi = cleanup function; each value is freed
    call    list$clear              ; walks list, calls cleanup per value (Source: /list.inc:743)
    call    list$destroy            ; releases list object and nodes (Source: /list.inc:64-67)

    mov     eax, syscall_exit
    xor     edi, edi
    syscall
include 'ht_data.inc'
```

The key invariant shown above is that `list$clear` — not `list$destroy` — is responsible for releasing the heap memory owned by stored values; the same ownership rule applies to `stringmap$clear` versus `stringmap$destroy` (Source: `/maps.inc:85-86`). Callers that omit the `*$clear` step leak the contents.

## Configuration

The following `ht_defaults.inc` knobs directly affect the behaviour of this subsystem:

| Knob | Default | Effect | Source |
|---|---|---|---|
| `heap_bincheck` | `0` | When set to `1`, the bin-index qword that precedes every non-`mmap` allocation is validated on `heap$free`. Adds runtime overhead but catches heap corruption. | `/ht_defaults.inc:82` |
| `heap_barriers` | `0` | When set to `1`, an 8-byte canary (`0x46464646`) is prepended to every non-`mmap` allocation and checked on `heap$free`; a mismatch triggers a breakpoint. Increases per-allocation overhead by 8 bytes. | `/ht_defaults.inc:86`; canary check at `/heap.inc:893-895` |
| `string_bits` | `32` | Selects the string engine that is linked into the binary: `16` includes `string16.inc` (UTF-16), `32` includes `string32.inc` (UTF-32). The chosen engine ripples through every `string$*` label as well as the `buffer$append_string` and `json$tostring` helpers. | `/ht_defaults.inc:103`; selector at `/ht.inc:111-115` |

Some TUI components require `string_bits = 32` to work correctly (Source: `/ht_defaults.inc:102`); reducing to 16 is therefore an advanced choice that constrains the rest of the library.

## Limitations

- In-process only. The five primary containers live in the calling process's heap; none of them are shared across processes and none of them persist across program runs. For file-backed or cross-process memory, see `../mapped.inc`, `../privmapped.inc`, and `../mappedheap.inc`.
- No thread-safety guarantees. HeavyThing programs are single-threaded per process by default; concurrent mutation of a list, map, buffer, or JSON tree from multiple threads without external synchronisation is undefined behaviour. Multi-process applications such as `rwasa` and `webslap` achieve concurrency through `fork` and IPC rather than threads.
- `list$destroy` does not iterate the list. Freeing stored values requires calling `list$clear` with a cleanup function first; calling `list$destroy` alone releases the list object and its nodes but leaks any pointers stored as values (Source: `/list.inc:64-65`).
- Map destroy is similarly shallow. `stringmap$destroy` and its int, unsigned, and double siblings free only the map object itself; to free keys and values, call `*map$clear` with a cleanup function first (Source: `/maps.inc:85-86` and `/maps.inc:111-113`).
- The heap is never returned to the kernel. Once the HeavyThing heap is grown via `mremap`, freed blocks remain reserved inside the process for later reuse (Source: `/heap.inc:35-42`). This is a deliberate design choice for server workloads rather than a defect.
- Heap allocation failures terminate the process with exit code 99. `heap$init`, `heap$alloc_permanent`, and the `mremap` path inside `heap$alloc` all invoke `syscall_exit` with code 99 rather than returning an error (Source: `/heap.inc:227-228, 263-265, 827-828` and the exit-code table at `/ht.inc:38-42`). Callers cannot recover from allocation failure.
- JSON is acknowledged as intentionally messy in its source header, which notes the trade-off between versatility and internal cleanliness (Source: `/json.inc:26`).
- Maps use fixed key types. The four supported key types (signed int, unsigned int, double, string) are the only variants; contributing a new key type requires extending `maps.inc` directly because no user-supplied comparator is provided on purpose (Source: `/maps.inc:23`).

## See Also

- `../README.md` — project landing page, subsystem map, build flow
- `../docs/architecture.md` — full include-dependency graph, `ht$init` lifecycle, IO chaining model, exit codes 96-99
- `../docs/calling-convention.md` — library-wide register contract, `prolog`/`epilog` macros, stack alignment, label-naming convention
- `../docs/building.md` — FASM invocation, compile-time configuration, adding a new `.inc` module
- `../crypto/README.md` — cryptographic primitives that allocate working state via `heap$alloc`
- `../net/README.md` — networking subsystem, which uses lists for queued I/O
- `../tui/README.md` — TUI widget framework, which composes with `stringmap` and `buffer`

---

Licensed under GPLv3. See [`../LICENSE`](../LICENSE).

