# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Documentation Objective

Based on the provided requirements, the Blitzy platform understands that the documentation objective is to **author a complete first-party documentation layer for the HeavyThing x86_64 assembly language library**, which currently ships with essentially no human-facing documentation (only a one-line `README.md`, a three-line `README` that defers to an external URL, a minor `rwasa/README.rwasa_tlsmin` note, and a historical `ChangeLog`). The work creates **eleven module-level README files**, **five cross-cutting reference documents under `/docs/`**, and **seven embedded Mermaid diagrams**, all derived from inspection of the 106 core `.inc` files and the seven tool/example directories, without modifying any production code.

**Request Categorization**: Create new documentation (primary action for 16 of 17 deliverables) with a single UPDATE to the root `README.md` (currently `# HeavyThing` as its only content).

**Documentation Types in Scope**:

- **Module READMEs** — 11 files describing what a subsystem is, how it fits in, and how to call into it
- **Architecture docs** — 1 file (`docs/architecture.md`) with include-graph, lifecycle, and boundary diagrams
- **Build guide** — 1 file (`docs/building.md`) documenting assembler invocation and the three-file include contract
- **Calling-convention reference** — 1 file (`docs/calling-convention.md`) codifying register contracts and stack-alignment expectations
- **Security notes** — 1 file (`docs/security.md`) enumerating crypto primitive scope, TLS/SSH version support, and known caveats
- **Contributing guide** — 1 file (`docs/contributing.md`) describing how to add a new `.inc` module and wire it into `ht.inc`
- **Embedded diagrams** — 7 Mermaid diagrams across the above files (no external image assets)

**Enumerated Documentation Requirements**:

- Document every subsystem's purpose, architecture fit, key components, calling convention, usage example, configuration knobs in `ht_defaults.inc`, known limitations, and cross-references
- Document every tool (`rwasa`, `sshtalk`, `webslap`, `toplip`, `dhtool`) with its purpose, build invocation, runtime flags, and library features demonstrated
- Consolidate the `examples/` directory under a single `examples/README.md` enumerating each demo
- Produce a full include-dependency graph so that the `ht_defaults.inc` → `ht.inc` → `ht_data.inc` three-file contract and the transitive include chain in `ht.inc` are made explicit
- Trace the init/event-loop lifecycle from `ht$init` through the epoll dispatch loop to handler callbacks and orderly teardown
- Codify the library-wide register calling convention and label-naming conventions (`subsystem$function` pattern visible throughout the codebase)

### 0.1.2 Special Instructions and Constraints

The user's plan contains several directives that are preserved verbatim below and enforced throughout downstream execution.

**USER PROVIDED RULE — Minimal Change Clause (preserved exactly as provided):**

> Add comments and documentation without modifying production code logic or behavior. Do not refactor, optimize, or change existing interfaces. Document existing code as-is. If a function appears to have a bug or inefficiency, note it in a comment only if it is a genuine non-obvious invariant — do not fix it as part of this pass.

**USER PROVIDED TEMPLATE — Module README Structure (preserved exactly as provided):**

Structure (in order):

1. `# Module Name` — one-sentence purpose
2. `## Overview` — 2–4 sentences on what it does and why it exists
3. `## Architecture Fit` — how it relates to the rest of the library (dependencies in/out)
4. `## Key Components` — table: `| File | Purpose |`
5. `## Calling Convention` — for library subsystems: register input/output contract, stack alignment expectations, clobber list
6. `## Usage` — minimal assembly snippet showing include order and a representative label call
7. `## Configuration` — relevant `ht_defaults.inc` knobs that affect this subsystem
8. `## Limitations` — honest list of what is not supported or not hardened
9. `## See Also` — links to related subsystems and example tools

Formatting rules:

- Assembly code blocks use triple-backtick-fenced `nasm` code blocks
- Register names in inline code: `rax`, `rdi`, etc.
- No emojis, no marketing language
- Headers use `##` with maximum depth of `###`; avoid `####`
- Tables for anything with more than 3 items in a list
- Keep each README under 400 lines; if longer, split into linked sub-docs

**USER PROVIDED RULE — Diagram Format Standards (preserved exactly as provided):**

- All diagrams use **Mermaid** fenced code blocks so they render natively on GitHub and most Markdown viewers — no external image files needed
- Node labels use the actual filename or label name from the codebase (e.g. `ht.inc`, `epoll.inc`, `ht$init`)
- Diagrams are embedded directly in the relevant README or doc file, immediately after the `## Architecture Fit` or `## Overview` section they illustrate
- No diagram should exceed ~30 nodes; if a subsystem is too large, split into a summary diagram + a detail diagram below it

**Style Preferences Derived From the Plan**:

- **Tone**: Technical, honest, no marketing language, no emojis
- **Depth**: Sufficient to enable a reader to locate the right `.inc`, understand the register contract, and write a minimal caller
- **Format**: GitHub-flavored Markdown with embedded Mermaid (no external renderer needed)
- **Heading depth**: Maximum `###` (three hashes) inside module READMEs; `####` is explicitly forbidden by the user

**Web Search Requirement**: None. The user's plan is self-contained, Mermaid is a well-established GitHub-native markdown extension that requires no additional research, and all technical content is derivable from in-repository source inspection.

### 0.1.3 Technical Interpretation

These documentation requirements translate to the following technical documentation strategy:

- **To document the root library**, the Blitzy platform will UPDATE the existing `/README.md` (currently just `# HeavyThing`) to describe what HeavyThing is, prerequisites (the assembler the project actually uses, Linux x86_64 requirement, no libc dependency), the three-file include contract (`ht_defaults.inc` → `ht.inc` → `ht_data.inc`), build instructions for a minimal example (`examples/hello_world/hello_world.asm`), a high-level subsystem map, and the GPLv3 license reference.

- **To document the cryptography subsystem**, the Blitzy platform will CREATE a new `/crypto/` directory containing only `/crypto/README.md`, which references the crypto-family `.inc` files that physically reside at the repository root (`aes.inc`, `sha1.inc`, `sha2.inc`, `md5.inc`, `hmac.inc`, `pbkdf2.inc`, `scrypt.inc`) via relative paths (e.g., `../aes.inc`). No source files are moved.

- **To document the networking subsystem**, the Blitzy platform will CREATE a new `/net/` directory containing only `/net/README.md`, which references the networking-family `.inc` files at the repository root (`epoll.inc`, `http1.inc`, `tls.inc`, `ssh.inc`, `webclient.inc`, `webserver.inc`).

- **To document the TUI subsystem**, the Blitzy platform will CREATE a new `/tui/` directory containing only `/tui/README.md`, which catalogs all 32 `tui_*.inc` files at the repository root and points to `hnwatch` and `examples/tuimatrix` as worked examples.

- **To document the data structures subsystem**, the Blitzy platform will CREATE a new `/ds/` directory containing only `/ds/README.md`, which references `list.inc`, `maps.inc`, `heap.inc`, `buffer.inc`, and `json.inc` at the repository root.

- **To document each showcase tool and the examples folder**, the Blitzy platform will CREATE a `README.md` inside each of `dhtool/`, `examples/`, `rwasa/`, `sshtalk/`, `toplip/`, and `webslap/` — six additional new files, leaving the pre-existing `rwasa/README.rwasa_tlsmin` file untouched and linking to it from `rwasa/README.md`.

- **To provide cross-cutting references**, the Blitzy platform will CREATE a new `/docs/` directory containing five new Markdown files (`architecture.md`, `building.md`, `calling-convention.md`, `security.md`, `contributing.md`) per the user's table.

- **To make load-order and lifecycle information visible**, the Blitzy platform will embed seven Mermaid diagrams across the above documents exactly as specified in the user's Diagrams table.

### 0.1.4 Inferred Documentation Needs

Repository inspection surfaces several implicit requirements that the user's high-level plan does not state explicitly but that are necessary for the documentation to be correct and complete.

- **The repository layout is flat, not hierarchical.** All 106 `.inc` library files — including every crypto, networking, TUI, and data-structures file — are located directly at the repository root, not inside `crypto/`, `net/`, `tui/`, or `ds/` subdirectories. The user's plan uses the phrase "co-located with" for the proposed subsystem READMEs (e.g., "/crypto/README.md (co-located with aes.inc, sha1.inc, …)"), but strict physical co-location would require moving source files, which the Minimal Change Clause forbids. The Blitzy platform therefore interprets "co-located" as **logical grouping** — the new `/crypto/`, `/net/`, `/tui/`, and `/ds/` subdirectories will be created to contain only their README.md, and the READMEs will reference the actual `.inc` file locations at the repository root via `../filename.inc` relative paths. No source files are moved, renamed, or altered.

- **The assembler identified in the user's plan must be reconciled with the codebase.** The user's "Root README" bullet lists `Prerequisites: NASM assembler version, Linux x86-64 requirement, no libc dependency`. Inspection of `ht_defaults.inc` (line 24: "we are the first include, set our fasm format"; line 26: `format ELF64` which is FASM syntax, not NASM) and `ht.inc` (line 613: "ht$init is called from a pure fasm enviro") confirms the project is built with **FASM (Flat Assembler) by Tomasz Grysztar**, invoked as `fasm -m 524288 sourcefile.asm`. The new documentation must document **FASM** (the actual assembler) as the prerequisite, while the markdown code fence tag `nasm` specified in the user's template is acceptable because GitHub has no `fasm` syntax highlighter and `nasm` provides the closest visual rendering for Intel-syntax x86_64 assembly.

- **`/crypto/`, `/net/`, `/tui/`, and `/ds/` subdirectories must be created** — they do not exist in the repository. Creating empty-except-for-README directories is a documentation addition and does not violate the Minimal Change Clause.

- **The `rwasa/README.rwasa_tlsmin` file pre-exists** and documents the TLS-minimalist variant. The Blitzy platform will preserve it byte-for-byte and link to it from the new `rwasa/README.md`.

- **The repository's ChangeLog terminates at v1.13** (July 16, 2015) even though other sections of this technical specification reference v1.24 (October 2018). The documentation must describe **the version and behavior that is actually present in this repository snapshot**, not versions mentioned elsewhere. Version numbers in new documentation should be derived from the `ChangeLog` file or omitted where uncertain.

- **Every `.inc` and `.asm` source file begins with the GPLv3 preamble header** (20-line comment block with copyright assertion to 2 Ton Digital). New documentation files should include a short copyright/license footer or a link to `/LICENSE` to remain consistent with the codebase's licensing posture.

- **The `util/` and `hnwatch/` directories do not appear in the user's explicit 11-README list.** Per the user's "SYSTEM BOUNDARIES > Focus areas" section, only the eleven enumerated READMEs are in scope. `util/` and `hnwatch/` will be referenced from other documents (e.g., the TUI README points to `hnwatch` as a worked example) but will not receive their own README in this pass.

- **Label-naming conventions are non-obvious but system-wide.** Labels follow a `subsystem$function` pattern (e.g., `ht$init`, `epoll$send`, `string$from_cstr`, `heap$free`), observed across `ht.inc`, `epoll.inc`, `examples/echo/echo.asm`, and `examples/hello_world/hello_world.asm`. The `docs/calling-convention.md` document must codify this naming rule explicitly because it governs every cross-module call.

- **The exit-code table is a runtime contract that only appears in comments.** `ht.inc` lines 38–42 list exit codes `99` (heap mmap/mremap failure), `98` (profiler stack overrun), `97` (epoll minfds not met), and `96` (`epoll_create` failure). These are not visible to callers without reading the source and must be surfaced in `docs/building.md` or `docs/architecture.md` for operators.

- **The three-file include contract is a mandatory ordering constraint.** Every `.asm` entry point in the repository (including `examples/hello_world/hello_world.asm` and `examples/echo/echo.asm`) must include `ht_defaults.inc` first, `ht.inc` second, and `ht_data.inc` last. This ordering is enforced by FASM's one-pass-of-sections model and is documented in comments inside `ht.inc` itself ("YOU MUST INCLUDE a version of … ht_defaults.inc, settings in here are required"; "NOTE: you must include (as a finale sorta thing) ht_data.inc"). The new root README.md must surface this constraint prominently.

- **The `include_everything` flag has special semantics for C/C++ integration.** As documented in `ht_defaults.inc`, FASM's `if used` pattern normally eliminates unused code, but this flag forces full inclusion — required for mixed-language examples like `examples/hello_world_c1/` and `examples/simplechat_c++/` where the assembler cannot see what the C/C++ object file will reference. The `docs/building.md` file must explain this flag.


## 0.2 Documentation Discovery and Analysis

### 0.2.1 Existing Documentation Infrastructure Assessment

Repository analysis reveals that **HeavyThing has no installed documentation framework, no generator, and effectively no in-repository documentation surface** beyond a single-line marker and an external URL pointer. All documentation content will be authored from scratch in pure GitHub-flavored Markdown with embedded Mermaid.

| Artifact | Path | Size | Current Content |
|---|---|---|---|
| Project landing README | `/README.md` | 13 bytes | Just `# HeavyThing` — a heading with no body |
| Legacy README | `/README` | 126 bytes | 3 lines: "HeavyThing x86_64 linux assembly language library" + URL pointer to `https://2ton.com.au/HeavyThing/` |
| Tool-variant note | `/rwasa/README.rwasa_tlsmin` | 292 bytes | 7-line explanation of the TLS-minimalist variant of rwasa |
| Change history | `/ChangeLog` | 12,915 bytes | Version-by-version history from January 2015 (v1.01 initial release) through July 2015 (v1.13) |
| License | `/LICENSE` | 35,147 bytes | Full GPLv3 text |
| External asset | `/2ton.png` | 20,210 bytes | 2 Ton Digital logo/banner image |

**Documentation Generator Configuration**: None detected. Systematic inspection of the repository root (`ls -la /tmp/blitzy/Blitzy-HeavyThing/master_fc613b/`) found no `mkdocs.yml`, no `docusaurus.config.js`, no `sphinx.conf.py`, no `.readthedocs.yml`, no `typedoc.json`, no `Doxyfile`, and no JSDoc configuration. Documentation will render directly on GitHub with Mermaid diagrams supported natively; no site generator is being introduced.

**Documentation Framework Selected for This Work**: GitHub-flavored Markdown with Mermaid — zero new dependencies, zero build pipeline.

- **Markdown renderer**: GitHub's native Markdown engine (no explicit version pinning)
- **Diagram tool**: Mermaid (GitHub-native support since 2022; no plugin required for readers)
- **Hosting/deployment**: GitHub repository directly; no separate docs site
- **API documentation tools (JSDoc, Sphinx, Godoc)**: None applicable — this is an assembly language project
- **Existing documentation style guide**: None; this plan establishes the style (9-section README template, Mermaid-first diagrams, source-citation footnotes)

### 0.2.2 Repository Code Analysis for Documentation

The repository contains three tiers of sources that require documentation, each discovered via targeted file-system inspection.

**Tier 1 — Library Include Files (106 files at repository root):**

Systematic `.inc` enumeration (`ls /tmp/blitzy/Blitzy-HeavyThing/master_fc613b/*.inc`) identifies the following functional groupings that map directly onto the user's proposed subsystem READMEs:

| Subsystem | README Target | Root-Level `.inc` Files Covered |
|---|---|---|
| Cryptography | `/crypto/README.md` | `aes.inc`, `sha1.inc`, `sha2.inc`, `md5.inc`, `hmac.inc`, `pbkdf2.inc`, `scrypt.inc` (user-scoped list); additional crypto-adjacent files (`hmac_drbg.inc`, `htcrypt.inc`, `htxts.inc`, `rng.inc`, `X509.inc`) optionally cross-referenced |
| Networking | `/net/README.md` | `epoll.inc`, `http1.inc`, `tls.inc`, `ssh.inc`, `webclient.inc`, `webserver.inc` (user-scoped list); supporting files (`epoll_child.inc`, `epoll_dns.inc`, `cookiejar.inc`, `httpheaders.inc`, `url.inc`, `fcgiclient.inc`, `blacklist.inc`) optionally cross-referenced |
| TUI | `/tui/README.md` | All 32 `tui_*.inc` files: `tui_alert`, `tui_ansi`, `tui_background`, `tui_bell`, `tui_button`, `tui_datagrid`, `tui_effect`, `tui_effects`, `tui_form`, `tui_geometry`, `tui_gridguts`, `tui_label`, `tui_lines`, `tui_lock`, `tui_matrix`, `tui_newsticker`, `tui_object`, `tui_panel`, `tui_png`, `tui_progressbar`, `tui_progressbox`, `tui_render`, `tui_simpleauth`, `tui_spacers`, `tui_spinner`, `tui_splash`, `tui_ssh`, `tui_statusbar`, `tui_terminal`, `tui_text`, `tui_textbox`, `tui_typist` |
| Data Structures | `/ds/README.md` | `list.inc`, `maps.inc`, `heap.inc`, `buffer.inc`, `json.inc` (user-scoped list) |
| Core/Infra | `/README.md` (root) | `ht.inc`, `ht_defaults.inc`, `ht_data.inc`, `syscall.inc`, `call.inc`, `cleartext.inc`, `dataseg_macros.inc`, `align_macros.inc`, `math.inc`, `memfuncs.inc`, `profiler.inc`, `date.inc`, `formatter.inc`, `base64_latin1.inc`, `mimelike.inc`, `png.inc`, `zlib_inflate.inc`, `zlib_deflate.inc`, `bigint.inc`, `dh_pool*.inc`, `dir.inc`, `file.inc`, `io.inc`, `mapped.inc`, `privmapped.inc`, `mappedheap.inc`, `sleeps.inc`, `syslog.inc`, `sysinfo.inc`, `unicodecase.inc`, `string16.inc`, `string32.inc`, `string_math.inc`, `breakpoint.inc`, `crc.inc`, `rdtsc.inc`, `vdso.inc` |

**Tier 2 — Showcase Tool Sources (directories at repository root):**

| Tool Directory | Entry Point `.asm` | Support `.inc` Files | README Target |
|---|---|---|---|
| `dhtool/` | `dhtool.asm` (25,162 bytes) | `dhtool_settings.inc` | `dhtool/README.md` |
| `hnwatch/` | `hnwatch.asm` (1,714 bytes) | `eventstream.inc`, `hnmodel.inc`, `textify.inc`, `ui.inc` | Out of user-scoped list; referenced from `tui/README.md` as worked example |
| `rwasa/` | `rwasa.asm` (5,180 bytes), `rwasa_tlsmin.asm` (5,268 bytes) | `arguments.inc`, `master.inc`, `worker.inc`, `tlsmin_defaults.inc` | `rwasa/README.md` (NEW); preserve existing `rwasa/README.rwasa_tlsmin` |
| `sshtalk/` | `sshtalk.asm` (8,881 bytes) | `chatpanel.inc`, `chatroom.inc`, `screen.inc`, `statusbar.inc`, `userdb.inc` | `sshtalk/README.md` |
| `toplip/` | `toplip.asm` (112,076 bytes) | (none) | `toplip/README.md` |
| `util/` | `bigint_tune.asm`, `make_dh_static.asm`, `mersenneprimetest.asm` | `bigger_int_settings.inc` | Out of user-scoped list; not receiving a README in this pass |
| `webslap/` | `webslap.asm` (12,598 bytes), `webslap_tlsmin.asm` (12,787 bytes) | `globals.inc`, `master.inc`, `master_ui.inc`, `worker.inc`, `tlsmin_defaults.inc` | `webslap/README.md` |

**Tier 3 — Example Programs (subdirectories under `examples/`):**

14 worked-example subdirectories exist under `examples/`: `echo`, `hello_world`, `hello_world_c1`, `hello_world_c2`, `minigzip`, `multicore_echo`, `sha256`, `simplechat_c++`, `simplechat_ssh_auth_c++`, `simplechat_ssh_c++`, `sshecho`, `tlsecho`, `tuieffects`, `tuimatrix`. All of these are consolidated under the single user-scoped `examples/README.md`.

**Key Directories Examined**:

- Repository root `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/` — 106 `.inc` files, 3 top-level README/legal files, 1 ChangeLog, 1 LICENSE, 1 PNG asset, 8 application/tool/util subdirectories
- `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/examples/` — 14 example subdirectories (one-`asm`-per-subdir pattern)
- Each tool directory was inspected to enumerate `.asm` entry points and supporting `.inc` modules

**Related Documentation Found**: The `/README`, `/README.md`, and `/rwasa/README.rwasa_tlsmin` files are the only in-repository documentation. The legacy `/README` defers to the external URL `https://2ton.com.au/HeavyThing/`, which is explicitly out of scope per the user's plan. All new documentation is written from source-code inspection only; the external URL is not consulted.

### 0.2.3 Web Search Research Conducted

**None required.** The user's plan is self-contained and prescriptive (exact README structure, exact diagrams, exact set of target files). No external research is needed because:

- **Mermaid** is supported natively by GitHub's Markdown renderer with no plugin or build step; no version pinning is required for this documentation work
- **FASM** documentation is not needed for this pass — the new documentation describes HeavyThing's usage of FASM, not FASM itself
- **Assembly-language documentation best practices** are encoded directly in the user-provided README template (9 sections, calling-convention documentation, register contracts) and are sufficient
- **Documentation structure conventions** are encoded in the user's plan; no conflicting or alternative convention exists that would merit comparison

All documentation content is derivable from inspection of the repository's `.inc` files, `.asm` entry points, `ht.inc` include chain, `ht_defaults.inc` configuration knobs, and header comments inside source files (e.g., the design notes in `epoll.inc` lines 22–80 describing the IO chaining model).


## 0.3 Documentation Scope Analysis

### 0.3.1 Code-to-Documentation Mapping

Every documentation deliverable maps directly to specific source artifacts in the repository. The mapping is exhaustive: each of the 11 module READMEs and each of the 5 `/docs/` references has a named set of source files that will supply its factual content.

#### 0.3.1.1 Module README ↔ Source Mapping

**Root README** (`/README.md`, UPDATE from one-line placeholder):

- Primary sources: `/ht.inc`, `/ht_defaults.inc`, `/ht_data.inc`, `/LICENSE`, `/ChangeLog`, `/examples/hello_world/hello_world.asm`
- Content it must deliver: project identity, problem statement, prerequisites (FASM assembler, Linux x86_64, no libc), the three-file include contract, build instructions for `examples/hello_world`, high-level subsystem map (crypto, net, TUI, data structures), GPLv3 license reference
- Current coverage: 0% (file contains only `# HeavyThing`)
- Target coverage: 100% of user-specified bullets

**Cryptography README** (`/crypto/README.md`, CREATE; new directory `/crypto/`):

- Primary sources (user-scoped): `/aes.inc`, `/sha1.inc`, `/sha2.inc`, `/md5.inc`, `/hmac.inc`, `/pbkdf2.inc`, `/scrypt.inc`
- Cross-reference sources: `/hmac_drbg.inc`, `/htcrypt.inc`, `/htxts.inc`, `/rng.inc`, `/X509.inc`, `/toplip/toplip.asm`, `/dhtool/dhtool.asm`
- Content it must deliver: primitives implemented and to what spec (AES-128/256, SHA-1/2, HMAC-SHA2, PBKDF2, scrypt), known limitations and side-channel posture, register calling convention for each primitive entry label, which tools/examples exercise each primitive
- Embedded diagram: **Crypto primitive map** (Mermaid `graph LR`, per user's diagram plan)

**Networking README** (`/net/README.md`, CREATE; new directory `/net/`):

- Primary sources (user-scoped): `/epoll.inc`, `/http1.inc`, `/tls.inc`, `/ssh.inc`, `/webclient.inc`, `/webserver.inc`
- Cross-reference sources: `/epoll_child.inc`, `/epoll_dns.inc`, `/io.inc`, `/httpheaders.inc`, `/url.inc`, `/cookiejar.inc`, `/fcgiclient.inc`, `/blacklist.inc`
- Content it must deliver: epoll event-loop model and how it ties into `ht$init`, HTTP/1.x + TLS + SSH version/feature support, layering of `webclient.inc` and `webserver.inc` on top of `epoll.inc`, dependencies between networking includes (load order as enforced by `ht.inc`)
- Embedded diagram: **Networking stack layers** (Mermaid `graph TD`, per user's diagram plan)

**TUI README** (`/tui/README.md`, CREATE; new directory `/tui/`):

- Primary sources: All 32 `tui_*.inc` files at repository root
- Cross-reference sources: `/hnwatch/hnwatch.asm` + `/hnwatch/ui.inc`, `/examples/tuimatrix/tuimatrix.asm`, `/examples/tuieffects/`
- Content it must deliver: complete widget inventory with one-line purpose per file, widget composition model, event-loop-driven redraw, terminal requirements (VT100/ANSI), pointers to `hnwatch` and `tuimatrix` as worked examples
- Embedded diagram: **TUI widget hierarchy** (Mermaid `graph TD`, per user's diagram plan)

**Data Structures README** (`/ds/README.md`, CREATE; new directory `/ds/`):

- Primary sources (user-scoped): `/list.inc`, `/maps.inc`, `/heap.inc`, `/buffer.inc`, `/json.inc`
- Content it must deliver: each structure's purpose, memory ownership contract, key labels; explanation of how `buffer.inc` is the foundation for string operations throughout the library

**Examples README** (`/examples/README.md`, CREATE):

- Primary sources: 14 example subdirectories under `/examples/`
- Content it must deliver: purpose of each example, build invocation (typical FASM command), runtime dependencies/flags, library features demonstrated per example

**Tool READMEs** (CREATE — one per tool directory):

| Tool README | Entry Point Source | Purpose To Document |
|---|---|---|
| `/dhtool/README.md` | `/dhtool/dhtool.asm`, `/dhtool/dhtool_settings.inc` | DH parameter generation, verification, PEM-to-SSH-moduli conversion |
| `/rwasa/README.md` | `/rwasa/rwasa.asm`, `/rwasa/arguments.inc`, `/rwasa/master.inc`, `/rwasa/worker.inc`; link to pre-existing `/rwasa/README.rwasa_tlsmin` | rwasa web server: features, CLI flags, privilege dropping, FastCGI proxying |
| `/sshtalk/README.md` | `/sshtalk/sshtalk.asm`, `/sshtalk/chatroom.inc`, `/sshtalk/chatpanel.inc`, `/sshtalk/screen.inc`, `/sshtalk/userdb.inc`, `/sshtalk/statusbar.inc` | SSH-enabled terminal chat: setup, host keys, user database, screens |
| `/toplip/README.md` | `/toplip/toplip.asm` | Encrypted-file utility: CLI, passphrase handling, base64/media-carrier output |
| `/webslap/README.md` | `/webslap/webslap.asm`, `/webslap/webslap_tlsmin.asm`, `/webslap/master.inc`, `/webslap/worker.inc`, `/webslap/globals.inc`, `/webslap/master_ui.inc`, `/webslap/tlsmin_defaults.inc` | HTTP load tester: standard + TLS-minimalist variants, DNS preflight, benchmark master path |

#### 0.3.1.2 Cross-Cutting `/docs/` ↔ Source Mapping

| Doc File | Primary Sources | Content to Extract |
|---|---|---|
| `/docs/architecture.md` | `/ht.inc` (full include chain lines 51–205), `/ht_defaults.inc`, `/ht_data.inc`, `/epoll.inc` (header comments lines 22–80), `/io.inc` | Full include-graph diagram, subsystem boundaries, `ht$init`/event-loop/teardown lifecycle |
| `/docs/building.md` | `/ht_defaults.inc` (all 60+ compile-time constants), `/examples/hello_world/hello_world.asm`, `ht.inc` top comment block, build commands inferable from `format ELF64` directive | FASM version/flags, `fasm -m 524288` invocation, linker invocation, static linking, how to add a new tool |
| `/docs/calling-convention.md` | `/ht.inc` (`ht$init`/`ht$init_args`/`ht$syscall` labels), `/profiler.inc` (`prolog`/`epilog` macros), `/call.inc`, `/align_macros.inc`, `/dataseg_macros.inc`, representative label sites across the library | Library-wide register usage contract, preserved vs. clobbered registers, stack alignment (16-byte), `subsystem$function` label-naming pattern |
| `/docs/security.md` | `/aes.inc`, `/sha2.inc`, `/sha1.inc`, `/md5.inc`, `/hmac.inc`, `/scrypt.inc`, `/pbkdf2.inc`, `/hmac_drbg.inc`, `/htcrypt.inc`, `/htxts.inc`, `/tls.inc`, `/ssh.inc`, `/X509.inc`, `/rng.inc`, `/blacklist.inc`, `/ht_defaults.inc` (TLS/SSH tuning constants) | Crypto primitive scope, known caveats (side channels, constant-time posture), TLS/SSH version support matrix |
| `/docs/contributing.md` | `/ht.inc` (`if used`/`include_everything` pattern), `/ht_defaults.inc`, existing naming conventions across library | How to add a new `.inc` module, naming conventions, how to wire into `ht.inc`, testing approach (manual binary demos) |

#### 0.3.1.3 Configuration Options Requiring Documentation

**`ht_defaults.inc`** is the single authoritative source of compile-time configuration (60+ constants across 26,222 bytes). Documentation must cover every category:

| Category | Sample Constants | README/Doc Coverage |
|---|---|---|
| Alignment | `function_alignment`, `inner_alignment`, `data_alignment`, `align_functions`, `align_returns`, `align_callreturns`, `align_inner`, `align_data` | `docs/calling-convention.md`, `docs/building.md` |
| Debug/Profiling | `framepointers`, `profiling`, `calltracing`, `cpc_integers`, `profiler_recordcount` | `docs/building.md` |
| Symbol Export | `public_funcs` | `docs/building.md` |
| Code Optimization | `code_preload`, `use_movbe`, `include_everything` | `docs/building.md`, `/README.md`, `docs/contributing.md` |
| Strings | `string_bits` (16 vs. 32) | `/ds/README.md`, `/README.md` |
| Heap | `heap_bincheck`, `heap_barriers` | `/ds/README.md` |
| Epoll | `epoll_minfds`, `epoll_readsize`, `epoll_stacksize`, `epoll_multiple_accepts` | `/net/README.md` |
| TLS | `tls_server_sessioncache`, `tls_server_ocsp_stapling`, `tls_blacklist`, `tls_minimalist` | `/net/README.md`, `docs/security.md` |
| SSH | `ssh_do_compression`, `ssh_force_compression`, `ssh_blacklist` | `/net/README.md`, `docs/security.md` |
| Web Server | `webserver_maxheader`, `webserver_maxrequest`, `webserver_hsts`, `webserver_breach_mitigation` | `/net/README.md`, `/rwasa/README.md` |
| Crypto | `dh_bits`, `dh_privatekey_size`, `scrypt_N`, `scrypt_sha512`, `bigint_maxwords` | `/crypto/README.md`, `docs/security.md` |
| RNG | `rng_heavy_init` | `/crypto/README.md` |
| Page/Platform | `page_size` | `docs/building.md` |

#### 0.3.1.4 Features Requiring User Guides

The following user-facing capabilities require consolidated narrative in the appropriate README or `/docs/` file:

- **Building a minimal application**: covered in `/docs/building.md` and the root `/README.md`
- **Writing a new subsystem module**: covered in `/docs/contributing.md`
- **Deploying rwasa with TLS**: covered in `/rwasa/README.md`
- **Running webslap as a benchmark**: covered in `/webslap/README.md`
- **Generating DH parameters**: covered in `/dhtool/README.md`
- **Encrypting a file with toplip**: covered in `/toplip/README.md`
- **Running an SSH chat server**: covered in `/sshtalk/README.md`
- **Using C/C++ bindings**: covered in `/examples/README.md` (pointing at `hello_world_c1`, `hello_world_c2`, `simplechat_c++`, etc.)
- **Understanding the event-loop lifecycle**: covered in `/docs/architecture.md` with the init/event-loop Mermaid sequence diagram
- **Understanding IO chaining**: covered in `/docs/architecture.md` + `/net/README.md`

### 0.3.2 Documentation Gap Analysis

Given the requirements and repository analysis, the documentation gaps are total — effectively every documentable aspect of the library is currently undocumented. The gaps fall into six categories:

**Undocumented Library Surface**:

- All 106 `.inc` library files lack external (non-inline-comment) documentation of their public labels and register contracts
- No external enumeration of which primitives exist in the crypto stack, which widgets exist in the TUI, which hooks exist in the networking engine
- No external mention of the `subsystem$function` label-naming convention
- No external documentation of the `prolog`/`epilog` macro contract enforced by `profiler.inc`

**Missing User Guides**:

- No build instructions anywhere in the repository (no Makefile, no build doc)
- No installation prerequisites (FASM version, Linux kernel requirements)
- No tutorial-style introduction to writing a first HeavyThing program (`examples/hello_world/hello_world.asm` exists but is not narratively explained)
- No CLI reference for any tool (rwasa, webslap, toplip, dhtool, sshtalk)

**Incomplete Architecture Documentation**:

- No include-dependency graph (the chain of 100+ includes inside `ht.inc` is buried in comments)
- No lifecycle documentation for `ht$init` → event loop → teardown
- No subsystem-boundary diagram
- No documentation of the IO chaining model (only the design-note comment block at the head of `epoll.inc`)
- No documentation of the multi-process IPC pattern used by rwasa/webslap/dhtool

**Outdated or Thin Existing Documentation**:

- `/README.md` is effectively empty (one line)
- `/README` points to an external URL that is out of scope and cannot be relied upon
- `/rwasa/README.rwasa_tlsmin` is useful but narrow (only describes the tlsmin variant, not rwasa itself)

**Absent Security Documentation**:

- No explicit statement of cryptographic primitive compliance (to what standard is AES-128/256 implemented, which NIST/FIPS variants of SHA are present)
- No side-channel posture disclosure
- No TLS/SSH version/cipher-suite support matrix
- No guidance for operators on key rotation, certificate hot-reload, or blacklist tuning

**Absent Contributor Documentation**:

- No guide on how to add a new `.inc` module
- No description of the `if used`/`include_everything` mechanism's contributor-facing implications
- No description of the informal testing approach (manual binary demos)
- No label naming conventions documented for contributors

The new documentation addresses each of these gap categories through the specific README/doc mapping above. No gap is left unaddressed within the user's stated scope.


## 0.4 Documentation Implementation Design

### 0.4.1 Documentation Structure Planning

The final repository documentation layout — after this documentation pass completes — is shown below. Items marked `(NEW)` are created in this pass; `(UPDATE)` indicates an existing file that is modified; `(UNCHANGED)` indicates existing files that are preserved byte-for-byte per the Minimal Change Clause.

```
(repo root)
├── README.md                           (UPDATE  — was a one-line placeholder)
├── README                              (UNCHANGED — legacy pointer file)
├── LICENSE                             (UNCHANGED — GPLv3)
├── ChangeLog                           (UNCHANGED — historical record)
├── 2ton.png                            (UNCHANGED — logo asset)
├── *.inc                               (UNCHANGED — all 106 library include files)
│
├── crypto/                             (NEW directory)
│   └── README.md                       (NEW — cryptography subsystem)
├── net/                                (NEW directory)
│   └── README.md                       (NEW — networking subsystem)
├── tui/                                (NEW directory)
│   └── README.md                       (NEW — TUI subsystem)
├── ds/                                 (NEW directory)
│   └── README.md                       (NEW — data structures subsystem)
│
├── docs/                               (NEW directory)
│   ├── architecture.md                 (NEW — full include-graph + lifecycle)
│   ├── building.md                     (NEW — FASM invocation + linking)
│   ├── calling-convention.md           (NEW — register contract + label naming)
│   ├── security.md                     (NEW — crypto scope + TLS/SSH matrix)
│   └── contributing.md                 (NEW — how to add a .inc module)
│
├── dhtool/
│   ├── README.md                       (NEW)
│   └── dhtool.asm, *.inc               (UNCHANGED)
├── examples/
│   ├── README.md                       (NEW — consolidates all 14 subdirs)
│   └── <14 example subdirs>            (UNCHANGED — no per-example READMEs)
├── hnwatch/                            (NO NEW README — out of user scope)
│   └── *.asm, *.inc                    (UNCHANGED)
├── rwasa/
│   ├── README.md                       (NEW — full rwasa documentation)
│   ├── README.rwasa_tlsmin             (UNCHANGED — preserved byte-for-byte)
│   └── *.asm, *.inc                    (UNCHANGED)
├── sshtalk/
│   ├── README.md                       (NEW)
│   └── *.asm, *.inc                    (UNCHANGED)
├── toplip/
│   ├── README.md                       (NEW)
│   └── toplip.asm                      (UNCHANGED)
├── util/                               (NO NEW README — out of user scope)
│   └── *.asm, *.inc                    (UNCHANGED)
└── webslap/
    ├── README.md                       (NEW)
    └── *.asm, *.inc                    (UNCHANGED)
```

**Structural Notes**:

- The new `crypto/`, `net/`, `tui/`, and `ds/` directories exist **only to hold their new README.md**. The `.inc` files they nominally describe remain at the repository root. The READMEs reference those files via relative paths such as `../aes.inc`, `../epoll.inc`, `../tui_button.inc`, `../list.inc`.
- The `/docs/` directory is new and aggregates cross-cutting reference material.
- No source `.inc` or `.asm` file is moved, renamed, or modified.
- Pre-existing documentation files (`/README`, `/ChangeLog`, `/LICENSE`, `/rwasa/README.rwasa_tlsmin`) are preserved byte-for-byte.

### 0.4.2 Content Generation Strategy

#### 0.4.2.1 Information Extraction Approach

- **Extract subsystem purpose** from the first 20 lines of each `.inc` file (every source file includes a GPLv3 preamble followed by a short purpose comment, e.g., `ht.inc:22` — "ht.inc: main include file that includes everything else"; `epoll.inc:22` — "epoll.inc: epoll/socket/fd layer"). These become the `## Overview` section of each subsystem README.

- **Extract include/load order** from `ht.inc` lines 51–205, which invoke each module via FASM `include` directives in a deterministic sequence. This sequence is the literal dependency graph and becomes the **Include dependency graph** Mermaid diagram in `docs/architecture.md`.

- **Extract label definitions** via `grep -n '^[a-zA-Z_][a-zA-Z0-9_$]*:' <file>.inc` to enumerate public labels per subsystem. Labels matching the `subsystem$function` pattern (e.g., `ht$init`, `epoll$send`, `string$from_cstr`) are the externally callable API surface.

- **Extract configuration knobs** from `ht_defaults.inc` by parsing each `constant_name = value` assignment, grouping constants by the comment block they appear under. The resulting groupings map directly onto the `## Configuration` section of each subsystem README.

- **Extract examples and usage patterns** by reading representative `.asm` files — particularly `examples/hello_world/hello_world.asm` (40 lines total, the canonical minimal example) and `examples/echo/echo.asm` (the canonical epoll/networking example) — and reducing them to minimum-viable snippets in each `## Usage` section.

- **Extract architectural notes** from header comment blocks. Prime sources are `epoll.inc` lines 22–80 (IO chaining model), `ht.inc` lines 22–42 (three-file contract + exit codes), and `ht_defaults.inc` lines 22–32 (format ELF64 declaration).

- **Extract tool CLI behavior** by reading `<tool>/arguments.inc` or the `cli` portion of `<tool>/<tool>.asm`. The `rwasa/arguments.inc` file explicitly enumerates flags; similar patterns exist in `webslap`, `dhtool`, and `toplip`.

#### 0.4.2.2 Template Application

The user-provided 9-section README template (reproduced in sub-section 0.1.2) is applied uniformly to **every** module README:

1. `# Module Name` — one-sentence purpose (from first purpose comment in the primary `.inc` file)
2. `## Overview` — 2–4 sentences expanded from the primary source's header comment
3. `## Architecture Fit` — dependency-in/dependency-out list (derived from `ht.inc` include order)
4. `## Key Components` — `| File | Purpose |` table listing every `.inc` in scope for the subsystem
5. `## Calling Convention` — register input/output contract + stack alignment + clobber list (for library subsystems only; tools have a `## CLI Reference` section instead)
6. `## Usage` — minimal assembly snippet showing the three-file include pattern and a representative label call
7. `## Configuration` — `ht_defaults.inc` knobs relevant to this subsystem
8. `## Limitations` — honest scope/caveat list (side-channel posture for crypto, TLS version for networking, terminal-type for TUI, etc.)
9. `## See Also` — cross-links to related subsystem READMEs and worked-example tools

Each section is populated with extracted information; no section is left empty or marked "TBD". Where the template's `## Calling Convention` does not strictly apply (e.g., tool READMEs), it is replaced by an equivalent section appropriate to the artifact (CLI reference, invocation flags).

#### 0.4.2.3 Documentation Standards

- **Markdown**: GitHub-flavored Markdown with headings `#`, `##`, `###` only (no `####` per user rule)
- **Code fences**: Triple-backtick fences labeled `nasm` for assembly snippets (per user rule — `nasm` is used because GitHub's highlighter covers Intel-syntax x86_64 assembly and there is no `fasm` highlighter)
- **Mermaid fences**: Triple-backtick fences labeled `mermaid` for embedded diagrams
- **Tables**: Used whenever a list has more than 3 items (per user rule)
- **Inline code**: Register names, label names, file names, and macros are wrapped in backticks (e.g., `rax`, `ht$init`, `ht.inc`, `prolog`)
- **Source citations**: Every technical claim cites its source file inline, using the form `Source: /path/to/file.inc:LineNumber` as a footnote or parenthetical reference
- **Tone**: Factual, no emojis, no marketing language (per user rule)
- **Length cap**: Each README stays under 400 lines; longer content is split into linked sub-docs (per user rule)
- **License footer**: Each new documentation file ends with a one-line reference to `/LICENSE` (GPLv3) to stay consistent with the codebase's licensing

### 0.4.3 Diagram and Visual Strategy

The user specified exactly seven Mermaid diagrams. The Blitzy platform preserves this list verbatim and adds no additional diagrams.

#### 0.4.3.1 Diagram Inventory (User-Specified, Preserved Verbatim)

| # | Diagram | Mermaid Type | Location | Purpose |
|---|---|---|---|---|
| 1 | Include dependency graph | `graph TD` | `docs/architecture.md` | Shows `ht_defaults.inc` → `ht.inc` → all subsystem `.inc` files; makes load-order dependencies visible |
| 2 | Init/event-loop lifecycle | `sequenceDiagram` | `docs/architecture.md` | Traces `ht$init` → epoll setup → event dispatch → handler callbacks → teardown |
| 3 | Subsystem boundary map | `graph LR` | `docs/architecture.md` | High-level boxes for Crypto, Net, TUI, Data Structures, Utils with arrows showing inter-subsystem dependencies |
| 4 | TUI widget hierarchy | `graph TD` | `tui/README.md` | Shows how `tui_*.inc` widgets compose (container → child widgets → event routing) |
| 5 | Networking stack layers | `graph TD` | `net/README.md` | `epoll.inc` at base → `tls.inc` / `ssh.inc` → `webclient.inc` / `webserver.inc` at top |
| 6 | Crypto primitive map | `graph LR` | `crypto/README.md` | Groups primitives by family: block ciphers, hashes, MACs, KDFs — with arrows showing composition (e.g. HMAC depends on SHA2) |
| 7 | Build flow | `flowchart TD` | `docs/building.md` | Source `.asm` → FASM → ELF64 static binary; shows where `ht_defaults.inc`, `ht.inc`, `ht_data.inc` are injected |

#### 0.4.3.2 Diagram Construction Rules (User-Specified, Preserved Verbatim)

- All diagrams use Mermaid fenced code blocks so they render natively on GitHub and most Markdown viewers — no external image files needed
- Node labels use the actual filename or label name from the codebase (e.g., `ht.inc`, `epoll.inc`, `ht$init`)
- Diagrams are embedded directly in the relevant README or doc file, immediately after the `## Architecture Fit` or `## Overview` section they illustrate
- No diagram exceeds ~30 nodes; if a subsystem is too large, it is split into a summary diagram plus a detail diagram below it

#### 0.4.3.3 Screenshot / Image Requirements

None. The user's plan explicitly favors Mermaid-native diagrams to avoid external image files. The existing `/2ton.png` logo is not referenced by any new documentation and remains untouched.

#### 0.4.3.4 Sample Diagram Composition (Conceptual Only)

The **Include dependency graph** (diagram #1) must express the actual dependency chain defined in `ht.inc` lines 51–205. The topmost node is `ht_defaults.inc` (included first by every `.asm` entry point), which fans out to `ht.inc`. The `ht.inc` node in turn fans out to the transitive include children organized by functional group (macros, core, crypto, networking, TUI), and `ht_data.inc` is shown as the terminal "must include last" node. Intra-group edges reflect the exact include order inside `ht.inc` (e.g., `sha2.inc` is included before `hmac.inc`, which in turn is included before `hmac_drbg.inc` — a strict ordering that reflects real compile-time dependencies).


## 0.5 Documentation File Transformation Mapping

### 0.5.1 File-by-File Documentation Plan

Every documentation file to be created, updated, or referenced is enumerated below. **Target Documentation File** is always the first column. Nothing is left as "pending" or "to be discovered". A total of **17 Markdown files** are touched (16 CREATE, 1 UPDATE) plus **5 new directories** (`crypto/`, `net/`, `tui/`, `ds/`, `docs/`).

Documentation Transformation Modes:

- **CREATE** — Create a new documentation file
- **UPDATE** — Update an existing documentation file
- **DELETE** — Remove an obsolete documentation file
- **REFERENCE** — Use an existing file as an example for style and structure (no modification)

| Target Documentation File | Transformation | Source Code / Docs | Content / Changes |
|---|---|---|---|
| `/README.md` | UPDATE | `/README.md`, `/ht.inc`, `/ht_defaults.inc`, `/ht_data.inc`, `/LICENSE`, `/ChangeLog`, `/examples/hello_world/hello_world.asm` | Replace the single-line `# HeavyThing` placeholder with full project overview: what HeavyThing is, problem statement, prerequisites (FASM, Linux x86_64, no libc), three-file include contract, build instructions for `examples/hello_world`, high-level subsystem map, GPLv3 reference, links to `/docs/` files and subsystem READMEs |
| `/crypto/README.md` | CREATE (new directory `/crypto/`) | `../aes.inc`, `../sha1.inc`, `../sha2.inc`, `../md5.inc`, `../hmac.inc`, `../pbkdf2.inc`, `../scrypt.inc` (cross-refs: `../hmac_drbg.inc`, `../htcrypt.inc`, `../htxts.inc`, `../rng.inc`, `../X509.inc`) | Full 9-section template: primitives implemented + standards conformance (AES-128/256, SHA-1/2, HMAC-SHA2, PBKDF2, scrypt), side-channel posture, register calling convention per entry label, mapping to tools/examples, embedded **Crypto primitive map** Mermaid `graph LR` diagram |
| `/net/README.md` | CREATE (new directory `/net/`) | `../epoll.inc`, `../http1.inc`, `../tls.inc`, `../ssh.inc`, `../webclient.inc`, `../webserver.inc` (cross-refs: `../io.inc`, `../epoll_child.inc`, `../epoll_dns.inc`, `../httpheaders.inc`, `../url.inc`, `../cookiejar.inc`, `../fcgiclient.inc`, `../blacklist.inc`) | Full 9-section template: epoll event-loop model + `ht$init` integration, HTTP/1.x / TLS 1.2 / SSH2 version and feature support, layering of `webclient`/`webserver` on `epoll`, include load order, embedded **Networking stack layers** Mermaid `graph TD` diagram |
| `/tui/README.md` | CREATE (new directory `/tui/`) | All 32 `../tui_*.inc` files; worked examples `../hnwatch/hnwatch.asm`, `../hnwatch/ui.inc`, `../examples/tuimatrix/tuimatrix.asm`, `../examples/tuieffects/` | Full 9-section template: complete widget inventory (one-line purpose per `tui_*.inc`), composition and event-loop-driven redraw, VT100/ANSI terminal requirements, pointers to `hnwatch` and `tuimatrix` as worked examples, embedded **TUI widget hierarchy** Mermaid `graph TD` diagram |
| `/ds/README.md` | CREATE (new directory `/ds/`) | `../list.inc`, `../maps.inc`, `../heap.inc`, `../buffer.inc`, `../json.inc` | Full 9-section template: each structure's purpose + memory-ownership contract + key labels; narrative explaining how `buffer.inc` is the foundation for string operations throughout the library |
| `/docs/architecture.md` | CREATE (new directory `/docs/`) | `../ht.inc` (include chain lines 51–205), `../ht_defaults.inc`, `../ht_data.inc`, `../epoll.inc` header comments, `../io.inc` | Full include-graph diagram (Mermaid `graph TD`), subsystem boundaries (Mermaid `graph LR`), `ht$init` → event loop → teardown lifecycle (Mermaid `sequenceDiagram`), IO chaining narrative, exit-code table (96/97/98/99) |
| `/docs/building.md` | CREATE | `../ht_defaults.inc` (all 60+ constants), `../examples/hello_world/hello_world.asm`, `../ht.inc` preamble comments | FASM version requirement, `fasm -m 524288` invocation, `ld` link invocation, static-linking explanation, how to add a new tool, `include_everything` flag for C/C++ integration, embedded **Build flow** Mermaid `flowchart TD` diagram |
| `/docs/calling-convention.md` | CREATE | `../ht.inc` (`ht$init`/`ht$init_args`/`ht$syscall`), `../profiler.inc` (`prolog`/`epilog` macros), `../call.inc`, `../align_macros.inc`, `../dataseg_macros.inc` | Library-wide register usage contract, preserved vs. clobbered registers, 16-byte stack alignment expectations, `subsystem$function` label-naming convention, `prolog`/`epilog` macro contract, globals/data-segment macro usage |
| `/docs/security.md` | CREATE | `../aes.inc`, `../sha2.inc`, `../sha1.inc`, `../md5.inc`, `../hmac.inc`, `../scrypt.inc`, `../pbkdf2.inc`, `../hmac_drbg.inc`, `../htcrypt.inc`, `../htxts.inc`, `../tls.inc`, `../ssh.inc`, `../X509.inc`, `../rng.inc`, `../blacklist.inc`, `../ht_defaults.inc` (TLS/SSH constants) | Crypto primitive scope with standards references, side-channel and constant-time disclosure, TLS version support matrix (TLS 1.2 + `tls_minimalist` variant), SSH2 cipher/MAC/compression support matrix, IP-blacklist tuning, key-rotation guidance |
| `/docs/contributing.md` | CREATE | `../ht.inc` (`if used`/`include_everything` pattern), `../ht_defaults.inc`, naming conventions observed library-wide | How to add a new `.inc` module, file naming conventions, label naming (`subsystem$function`), how to wire the new module into `ht.inc`, how to add a compile-time guard in `ht_defaults.inc`, testing approach (manual binary demos via `examples/` and tools) |
| `/examples/README.md` | CREATE | All 14 subdirectories under `../examples/`: `echo`, `hello_world`, `hello_world_c1`, `hello_world_c2`, `minigzip`, `multicore_echo`, `sha256`, `simplechat_c++`, `simplechat_ssh_auth_c++`, `simplechat_ssh_c++`, `sshecho`, `tlsecho`, `tuieffects`, `tuimatrix` | Purpose of each example (one paragraph each), typical FASM build invocation, runtime dependencies/flags, library features demonstrated per example, pointer to `/docs/building.md` for the general build flow |
| `/dhtool/README.md` | CREATE | `/dhtool/dhtool.asm`, `/dhtool/dhtool_settings.inc` | Purpose (DH parameter generation, verification, PEM-to-SSH-moduli conversion), `fasm -m 524288 dhtool.asm && ld -o dhtool dhtool.o` build invocation, runtime flags, library features demonstrated (`bigint.inc`, `dh_pool.inc`, RNG) |
| `/rwasa/README.md` | CREATE | `/rwasa/rwasa.asm`, `/rwasa/arguments.inc`, `/rwasa/master.inc`, `/rwasa/worker.inc`, `/rwasa/tlsmin_defaults.inc`, link to pre-existing `/rwasa/README.rwasa_tlsmin` | rwasa full documentation: purpose, build for both standard and `rwasa_tlsmin` variants, CLI flags enumerated from `arguments.inc`, privilege-dropping (`-runas`), FastCGI back-end proxying, TLS PEM hot-reload, HSTS/BREACH mitigation settings from `ht_defaults.inc`, link to `README.rwasa_tlsmin` |
| `/rwasa/README.rwasa_tlsmin` | REFERENCE (unchanged) | (self) | Existing 7-line TLS-minimalist note — preserved byte-for-byte; linked from new `/rwasa/README.md` |
| `/sshtalk/README.md` | CREATE | `/sshtalk/sshtalk.asm`, `/sshtalk/chatpanel.inc`, `/sshtalk/chatroom.inc`, `/sshtalk/screen.inc`, `/sshtalk/userdb.inc`, `/sshtalk/statusbar.inc` | Purpose (SSH-enabled terminal chat), build invocation, SSH host-key setup from `/etc/ssh`, user-database format, screens/status-bar widgets, library features demonstrated (`ssh.inc`, `tui_ssh.inc`, `tui_simpleauth.inc`) |
| `/toplip/README.md` | CREATE | `/toplip/toplip.asm` | Purpose (encrypted-file utility with steganographic/media-carrier output), build invocation, CLI flags, passphrase handling, encryption/decryption flows, base64/media-carrier output options, library features demonstrated (`aes.inc`, `htcrypt.inc`, `htxts.inc`, `scrypt.inc`, `rng.inc`) |
| `/webslap/README.md` | CREATE | `/webslap/webslap.asm`, `/webslap/webslap_tlsmin.asm`, `/webslap/master.inc`, `/webslap/worker.inc`, `/webslap/globals.inc`, `/webslap/master_ui.inc`, `/webslap/tlsmin_defaults.inc` | Purpose (HTTP load tester, standard + TLS-minimalist variants), build invocation for both variants, CLI flags, DNS preflight behavior, benchmark-master handoff, `tls_minimalist` rationale, library features demonstrated (`webclient.inc`, `tls.inc`, `epoll_dns.inc`, TUI status display) |

### 0.5.2 New Documentation Files Detail

Every new file below is specified with its 9-section outline, source extraction inputs, and embedded diagrams (where applicable). Section names follow the user-provided template verbatim.

**File: `/crypto/README.md`**

- Type: Subsystem API Reference
- Source Code Consulted: `../aes.inc`, `../sha1.inc`, `../sha2.inc`, `../md5.inc`, `../hmac.inc`, `../pbkdf2.inc`, `../scrypt.inc`
- Sections:
    - `# HeavyThing Cryptography`
    - `## Overview` — purpose drawn from `aes.inc`, `sha2.inc`, and `hmac.inc` header comments
    - `## Architecture Fit` — dependencies in (from `rng.inc`, `bigint.inc`) and out (to `tls.inc`, `ssh.inc`, `htcrypt.inc`, `htxts.inc`)
    - `## Key Components` — table listing `aes.inc`, `sha1.inc`, `sha2.inc`, `md5.inc`, `hmac.inc`, `pbkdf2.inc`, `scrypt.inc` with one-line purposes
    - `## Calling Convention` — register inputs/outputs for each primitive's entry label (e.g., `aes$expand_key`, `sha256$hash`, `hmac$sha256`, `scrypt$derive`, `pbkdf2$derive`)
    - `## Usage` — minimal SHA-256 snippet drawn from `examples/sha256/`
    - `## Configuration` — `ht_defaults.inc` knobs: `scrypt_N`, `scrypt_sha512`, `dh_bits`, `dh_privatekey_size`, `rng_heavy_init`
    - `## Limitations` — known caveats: side-channel posture, non-constant-time warnings where applicable, what is NOT implemented
    - `## See Also` — links to `/toplip/README.md`, `/dhtool/README.md`, `/docs/security.md`
- Diagrams:
    - **Crypto primitive map** (Mermaid `graph LR`, embedded after `## Overview`): groups block ciphers, hashes, MACs, KDFs with composition arrows (HMAC → SHA2, scrypt → PBKDF2 → HMAC, etc.)
- Key Citations: `../aes.inc:*`, `../sha2.inc:*`, `../hmac.inc:*`

**File: `/net/README.md`**

- Type: Subsystem API Reference
- Source Code Consulted: `../epoll.inc`, `../http1.inc`, `../tls.inc`, `../ssh.inc`, `../webclient.inc`, `../webserver.inc`
- Sections:
    - `# HeavyThing Networking`
    - `## Overview` — epoll event-loop description drawn from `epoll.inc:22` header comment
    - `## Architecture Fit` — dependencies in (from `io.inc`) and out (to application/tool layer)
    - `## Key Components` — table listing the six primary files + optional cross-references
    - `## Calling Convention` — register contract for `epoll$outbound`, `epoll$outbound_hostname`, `epoll$established`, `epoll$send`, `io_vreceive`, `io_vsend`, `io_vtimeout`, `io_vdestroy`
    - `## Usage` — minimal echo-server snippet drawn from `examples/echo/echo.asm`
    - `## Configuration` — `ht_defaults.inc` knobs: `epoll_minfds`, `epoll_readsize`, `epoll_stacksize`, `epoll_multiple_accepts`, `tls_server_sessioncache`, `tls_server_ocsp_stapling`, `tls_minimalist`, `ssh_do_compression`, `webserver_maxheader`, `webserver_maxrequest`, `webserver_hsts`, `webserver_breach_mitigation`
    - `## Limitations` — TLS 1.2 only (no 1.3), SSH2 only, HTTP/1.x (no HTTP/2 or HTTP/3), Linux-only epoll
    - `## See Also` — links to `/rwasa/README.md`, `/webslap/README.md`, `/sshtalk/README.md`, `/docs/architecture.md`
- Diagrams:
    - **Networking stack layers** (Mermaid `graph TD`, embedded after `## Overview`): `epoll.inc` at base; `tls.inc`/`ssh.inc` above; `webclient.inc`/`webserver.inc`/`http1.inc` at top
- Key Citations: `../epoll.inc:22`, `../tls.inc:*`, `../ssh.inc:*`, `../webserver.inc:*`

**File: `/tui/README.md`**

- Type: Subsystem API Reference
- Source Code Consulted: All 32 `../tui_*.inc` files
- Sections:
    - `# HeavyThing Terminal UI`
    - `## Overview` — widget-framework purpose drawn from `tui_object.inc` and `tui_render.inc` header comments
    - `## Architecture Fit` — dependencies in (from `epoll.inc` for event dispatch, `buffer.inc` for rendering, `unicodecase.inc` for text) and out (to `hnwatch` and `sshtalk` applications)
    - `## Key Components` — full table of all 32 `tui_*.inc` files with one-line purpose per file
    - `## Calling Convention` — widget-construction labels (`tui_button$new`, `tui_label$new`, `tui_datagrid$new`, etc.) with argument registers
    - `## Usage` — minimal "alert box" snippet, derived from `examples/tuieffects/` or `examples/tuimatrix/`
    - `## Configuration` — relevant `ht_defaults.inc` knobs (terminal-related settings, if any)
    - `## Limitations` — VT100/ANSI terminal requirement, SSH-rendering caveats
    - `## See Also` — links to `/hnwatch/` and `/examples/tuimatrix/` as worked examples, `/sshtalk/README.md`
- Diagrams:
    - **TUI widget hierarchy** (Mermaid `graph TD`, embedded after `## Architecture Fit`): container widgets (`tui_panel`, `tui_form`) → child widgets (`tui_button`, `tui_textbox`, `tui_datagrid`, etc.) → event routing via `tui_object`/`tui_render`
- Key Citations: `../tui_object.inc`, `../tui_render.inc`, every `../tui_*.inc` file

**File: `/ds/README.md`**

- Type: Subsystem API Reference
- Source Code Consulted: `../list.inc`, `../maps.inc`, `../heap.inc`, `../buffer.inc`, `../json.inc`
- Sections:
    - `# HeavyThing Data Structures`
    - `## Overview` — each structure's purpose
    - `## Architecture Fit` — `heap.inc` is foundational (feeds `list`, `maps`, `buffer`); `buffer.inc` is foundational for strings; `json.inc` consumes `maps.inc` and `buffer.inc`
    - `## Key Components` — table with `list.inc`, `maps.inc`, `heap.inc`, `buffer.inc`, `json.inc` and one-line purposes
    - `## Calling Convention` — register contracts for `list$new`, `list$foreach`, `stringmap$find`, `stringmap$findvalue`, `heap$alloc`, `heap$free`, `buffer$new`, `buffer$append`, `json$parse`, `json$stringify`
    - `## Usage` — minimal snippet creating a list and iterating it
    - `## Configuration` — `heap_bincheck`, `heap_barriers` debug knobs
    - `## Limitations` — in-process only, no persistence, no cross-process sharing
    - `## See Also` — links to `/README.md` (for string-engine overview) and `/docs/architecture.md`
- Key Citations: `../heap.inc`, `../list.inc`, `../maps.inc`, `../buffer.inc`, `../json.inc`

**File: `/examples/README.md`**

- Type: Worked-Example Index
- Source Consulted: All 14 `../examples/<subdir>/` directories
- Sections:
    - `# HeavyThing Examples`
    - `## Overview` — purpose of the `examples/` directory (runnable showcase of library capabilities)
    - `## Index` — table with 14 rows, one per example, documenting name, source `.asm`, library features demonstrated, runtime flags
    - `## Build` — generic `fasm -m 524288 <example>.asm && ld -o <binary> <example>.o` flow; pointer to `/docs/building.md`
    - `## See Also` — pointers to tool READMEs (`/rwasa`, `/webslap`, `/sshtalk`, etc.) for production-grade applications
- Key Citations: `../examples/hello_world/hello_world.asm`, `../examples/echo/echo.asm`, every other `../examples/*/` directory

**File: `/dhtool/README.md`**

- Type: Tool Documentation
- Source Consulted: `/dhtool/dhtool.asm`, `/dhtool/dhtool_settings.inc`
- Sections:
    - `# dhtool`
    - `## Overview` — Diffie-Hellman parameter generation, verification, PEM-to-SSH-moduli conversion
    - `## Build` — `fasm -m 524288 dhtool.asm && ld -o dhtool dhtool.o`
    - `## Usage` — CLI flags and example invocations
    - `## Library Features Demonstrated` — `bigint.inc`, `dh_pool.inc`, `rng.inc`, primality testing
    - `## See Also` — `/crypto/README.md`, `/docs/security.md`
- Key Citations: `/dhtool/dhtool.asm`, `/dhtool/dhtool_settings.inc`

**File: `/rwasa/README.md`**

- Type: Tool Documentation (major)
- Source Consulted: `/rwasa/rwasa.asm`, `/rwasa/rwasa_tlsmin.asm`, `/rwasa/arguments.inc`, `/rwasa/master.inc`, `/rwasa/worker.inc`, `/rwasa/tlsmin_defaults.inc`
- Sections:
    - `# rwasa — Rapid Web Application Server in Assembler`
    - `## Overview` — purpose and positioning
    - `## Build` — standard variant: `fasm -m 524288 rwasa.asm && ld -o rwasa rwasa.o`; TLS-minimalist variant: `fasm -m 524288 rwasa_tlsmin.asm && ld -o rwasa_tlsmin rwasa_tlsmin.o`
    - `## CLI Reference` — full table of flags extracted from `arguments.inc`
    - `## Deployment` — privilege dropping via `-runas`, document root, PEM certificates, FastCGI back-ends
    - `## Configuration` — `ht_defaults.inc` knobs relevant to the web server
    - `## TLS-Minimalist Variant` — link to `/rwasa/README.rwasa_tlsmin` with brief explanation
    - `## Library Features Demonstrated` — `webserver.inc`, `tls.inc`, `fcgiclient.inc`, multi-process IPC via `epoll_child.inc`
    - `## See Also` — `/net/README.md`, `/docs/architecture.md`, `/docs/security.md`
- Key Citations: `/rwasa/rwasa.asm`, `/rwasa/arguments.inc`, `/rwasa/README.rwasa_tlsmin`

**File: `/sshtalk/README.md`**

- Type: Tool Documentation
- Source Consulted: `/sshtalk/sshtalk.asm`, `/sshtalk/chatpanel.inc`, `/sshtalk/chatroom.inc`, `/sshtalk/screen.inc`, `/sshtalk/userdb.inc`, `/sshtalk/statusbar.inc`
- Sections:
    - `# sshtalk`
    - `## Overview` — SSH-enabled terminal chat/demo
    - `## Build` — `fasm -m 524288 sshtalk.asm && ld -o sshtalk sshtalk.o`
    - `## Usage` — CLI flags, SSH host-key location, user-database format
    - `## Screens and Widgets` — chatpanel, chatroom, screen, statusbar, userdb responsibilities
    - `## Library Features Demonstrated` — `ssh.inc`, `tui_ssh.inc`, `tui_simpleauth.inc`, TUI widget framework
    - `## See Also` — `/tui/README.md`, `/net/README.md`
- Key Citations: `/sshtalk/sshtalk.asm` and all `/sshtalk/*.inc` files

**File: `/toplip/README.md`**

- Type: Tool Documentation
- Source Consulted: `/toplip/toplip.asm`
- Sections:
    - `# toplip`
    - `## Overview` — encrypted-file utility with optional media-carrier / base64 output
    - `## Build` — `fasm -m 524288 toplip.asm && ld -o toplip toplip.o`
    - `## Usage` — CLI flags, passphrase handling, encryption/decryption invocations
    - `## Output Modes` — raw, base64, media-carrier (steganographic)
    - `## Library Features Demonstrated` — `aes.inc`, `htcrypt.inc`, `htxts.inc`, `scrypt.inc`, `rng.inc`, `png.inc` (for media carriers)
    - `## See Also` — `/crypto/README.md`, `/docs/security.md`
- Key Citations: `/toplip/toplip.asm`

**File: `/webslap/README.md`**

- Type: Tool Documentation
- Source Consulted: `/webslap/webslap.asm`, `/webslap/webslap_tlsmin.asm`, `/webslap/master.inc`, `/webslap/worker.inc`, `/webslap/globals.inc`, `/webslap/master_ui.inc`, `/webslap/tlsmin_defaults.inc`
- Sections:
    - `# webslap`
    - `## Overview` — HTTP/HTTPS load-testing utility, standard + TLS-minimalist variants
    - `## Build` — both variant invocations
    - `## Usage` — CLI flags, DNS preflight behavior, benchmark loop mechanics, TLS resumption testing
    - `## Multiprocess Model` — master/worker handoff via `epoll_child.inc`
    - `## TUI Status Display` — `master_ui.inc` integration
    - `## Library Features Demonstrated` — `webclient.inc`, `tls.inc`, `epoll_dns.inc`, `tui_*` status UI
    - `## See Also` — `/net/README.md`, `/rwasa/README.md`
- Key Citations: `/webslap/webslap.asm`, `/webslap/master.inc`, `/webslap/worker.inc`

**File: `/docs/architecture.md`**

- Type: Architecture Overview
- Source Consulted: `../ht.inc` (lines 51–205), `../ht_defaults.inc`, `../ht_data.inc`, `../epoll.inc` (header comments lines 22–80), `../io.inc`
- Sections:
    - `# HeavyThing Architecture`
    - `## Three-File Include Contract` — `ht_defaults.inc` → `ht.inc` → `ht_data.inc` with annotated ordering rules
    - `## Include Dependency Graph` — embedded Mermaid `graph TD` (diagram #1 from user plan) rendering the full transitive chain from `ht_defaults.inc` through `ht.inc` to every subsystem `.inc`
    - `## Subsystem Boundary Map` — embedded Mermaid `graph LR` (diagram #3) showing high-level blocks for Crypto, Net, TUI, Data Structures, Utils with inter-subsystem arrows
    - `## Initialisation and Event-Loop Lifecycle` — embedded Mermaid `sequenceDiagram` (diagram #2) tracing `ht$init` → CPUID detection → heap/epoll setup → event dispatch → handler callbacks → teardown; narrative describing `ht$init_args`, `ht$syscall`
    - `## IO Chaining Model` — narrative distilled from `epoll.inc:22–80` header comments
    - `## Exit Codes` — table of 96/97/98/99 exit codes from `ht.inc:38–42`
    - `## See Also` — links to all subsystem READMEs and `/docs/building.md`
- Diagrams: #1, #2, #3 from the user's diagram plan
- Key Citations: `../ht.inc:22`, `../ht.inc:38–42`, `../ht.inc:51–205`, `../epoll.inc:22–80`

**File: `/docs/building.md`**

- Type: Build Guide
- Source Consulted: `../ht_defaults.inc`, `../examples/hello_world/hello_world.asm`, `../ht.inc` preamble
- Sections:
    - `# Building HeavyThing Applications`
    - `## Prerequisites` — FASM (Flat Assembler) by Tomasz Grysztar, Linux x86_64, GNU `ld`, optional GCC/G++ for mixed-language examples
    - `## Minimum Viable Build` — the two-line `fasm -m 524288 source.asm && ld -o binary source.o` pattern
    - `## Build Flow` — embedded Mermaid `flowchart TD` (diagram #7) showing Source `.asm` → FASM → `.o` → `ld` → ELF64 static binary with `ht_defaults.inc`/`ht.inc`/`ht_data.inc` injection points
    - `## Compile-Time Configuration` — overview of the `ht_defaults.inc` system with category headings (Alignment, Debug, Heap, Epoll, TLS, SSH, Web, Crypto, RNG) and representative knobs
    - `## Adding a New Tool` — step-by-step guide for creating a new `.asm` entry point and wiring it into the three-file contract
    - `## Conditional Compilation` — `if used` pattern and the `include_everything` flag (required for C/C++ mixed-language builds)
    - `## Troubleshooting` — exit codes 96/97/98/99, common failure modes
    - `## See Also` — `/docs/contributing.md`, `/docs/calling-convention.md`
- Diagrams: #7 from the user's diagram plan
- Key Citations: `../ht_defaults.inc:22–32`, `../examples/hello_world/hello_world.asm`

**File: `/docs/calling-convention.md`**

- Type: Reference
- Source Consulted: `../ht.inc` (`ht$init`/`ht$init_args`/`ht$syscall`), `../profiler.inc` (`prolog`/`epilog`), `../call.inc`, `../align_macros.inc`, `../dataseg_macros.inc`
- Sections:
    - `# HeavyThing Calling Convention Reference`
    - `## Register Model` — x86_64 System V-like conventions with library-specific deviations
    - `## Preserved vs. Clobbered Registers` — table of caller-saved vs. callee-saved register roles as observed across `.inc` files
    - `## Stack Alignment` — 16-byte expectation and how `function_alignment`/`align_callreturns` settings in `ht_defaults.inc` interact
    - `## Label Naming Convention` — `subsystem$function` pattern with examples (`ht$init`, `epoll$send`, `string$from_cstr`, `heap$free`)
    - `## Prolog / Epilog Contract` — `prolog name`/`epilog` macro pair from `profiler.inc` with framepointer behavior under `framepointers = 1`
    - `## Globals and Data Segments` — `globals { }` macro from `ht_data.inc` / `dataseg_macros.inc`
    - `## Static Strings` — `cleartext` macro from `cleartext.inc`
    - `## Syscalls` — `ht$syscall` convenience wrapper and direct `syscall` usage
    - `## See Also` — `/docs/architecture.md`, `/docs/contributing.md`
- Key Citations: `../ht.inc:316–626`, `../profiler.inc`, `../call.inc`, `../dataseg_macros.inc`

**File: `/docs/security.md`**

- Type: Security Notes
- Source Consulted: Every crypto/security `.inc` in the library (`../aes.inc`, `../sha2.inc`, `../sha1.inc`, `../md5.inc`, `../hmac.inc`, `../scrypt.inc`, `../pbkdf2.inc`, `../hmac_drbg.inc`, `../htcrypt.inc`, `../htxts.inc`, `../tls.inc`, `../ssh.inc`, `../X509.inc`, `../rng.inc`, `../blacklist.inc`) and `../ht_defaults.inc` (TLS/SSH constants)
- Sections:
    - `# HeavyThing Security Notes`
    - `## Cryptographic Primitive Scope` — table enumerating AES-128/256, SHA-1/256/512, MD5, HMAC-SHA1/256/512, PBKDF2, scrypt with standards references (FIPS-197, FIPS-180-4, RFC 2104, RFC 2898, RFC 7914)
    - `## Known Caveats` — side-channel posture, constant-time guarantees (or lack thereof), MD5/SHA-1 legacy status
    - `## RNG` — HMAC-DRBG from `hmac_drbg.inc`, seeded via `rng_heavy_init`
    - `## TLS Support Matrix` — TLS 1.2 only, cipher suites (from `tls.inc`), `tls_minimalist` variant's reduced set
    - `## SSH Support Matrix` — SSH2 KEX methods, ciphers, MACs, compression (from `ssh.inc`, `ht_defaults.inc`)
    - `## Operational Guidance` — IP blacklist tuning (`blacklist.inc`, `tls_blacklist`, `ssh_blacklist`), PEM hot-reload interval, OCSP stapling (`tls_server_ocsp_stapling`), key rotation
    - `## What Is NOT Provided` — no TLS 1.3, no Ed25519/Curve25519, no ChaCha20-Poly1305, no Argon2
    - `## See Also` — `/crypto/README.md`, `/net/README.md`, `/rwasa/README.md`, `/toplip/README.md`
- Key Citations: `../tls.inc`, `../ssh.inc`, `../aes.inc`, `../sha2.inc`, `../scrypt.inc`, `../blacklist.inc`

**File: `/docs/contributing.md`**

- Type: Contributor Guide
- Source Consulted: `../ht.inc` (`if used`/`include_everything` usage), `../ht_defaults.inc`, label and filename patterns across library
- Sections:
    - `# Contributing to HeavyThing`
    - `## Module File Layout` — standard `.inc` file structure: GPLv3 preamble, purpose comment, `if used` gated functions, global data definitions under `globals { }`
    - `## Naming Conventions` — file name (lowercase, underscores), label name (`subsystem$function`), constant name (matches file)
    - `## Adding a New Module` — step 1: create `<new_module>.inc` with GPLv3 preamble; step 2: wrap each public function in `if used <label> | defined include_everything`; step 3: add `include '<new_module>.inc'` to the appropriate section of `ht.inc`; step 4: add compile-time guards to `ht_defaults.inc` if applicable; step 5: add a minimal test binary under `examples/`
    - `## Testing Approach` — manual binary demos (no automated test suite); build `examples/` and run manually
    - `## Code Style` — FASM macros, register naming, comment density, prolog/epilog usage
    - `## License` — all contributions must be GPLv3-compatible
    - `## See Also` — `/docs/building.md`, `/docs/calling-convention.md`, `/docs/architecture.md`
- Key Citations: `../ht.inc:51–205`, `../ht_defaults.inc`

### 0.5.3 Documentation Files to Update Detail

**File: `/README.md` — Root README**

Current state: single line `# HeavyThing` (13 bytes total).

Update plan: Replace the single heading with the full 9-section template adapted for the project root. Target sections:

- `# HeavyThing` (retain the title heading)
- `## Overview` — what HeavyThing is and what problems it solves, written in 2–4 sentences
- `## Prerequisites` — FASM (Flat Assembler), Linux x86_64, no libc dependency (with note that the user's plan referenced "NASM"; the actual assembler is FASM)
- `## Three-File Include Contract` — how `ht_defaults.inc` → `ht.inc` → `ht_data.inc` work together; pointer to `/docs/architecture.md` for the full include graph
- `## Build a Minimal Example` — step-by-step build of `examples/hello_world`: copy `hello_world.asm`, run `fasm -m 524288 hello_world.asm`, then `ld -o hello_world hello_world.o`
- `## Subsystem Map` — high-level map with links to `/crypto/README.md`, `/net/README.md`, `/tui/README.md`, `/ds/README.md`
- `## Tools` — links to `/rwasa`, `/webslap`, `/toplip`, `/sshtalk`, `/dhtool` READMEs
- `## Examples` — link to `/examples/README.md`
- `## Further Reading` — links to `/docs/architecture.md`, `/docs/building.md`, `/docs/calling-convention.md`, `/docs/security.md`, `/docs/contributing.md`
- `## License` — GPLv3 pointer to `/LICENSE`

Source citations for the update: `/ht.inc:22–42`, `/ht_defaults.inc:22–32`, `/ht_data.inc:22–32`, `/LICENSE`, `/examples/hello_world/hello_world.asm`.

### 0.5.4 Documentation Configuration Updates

**None.** The repository has no documentation generator (no `mkdocs.yml`, no `docusaurus.config.js`, no `sphinx.conf.py`, no `.readthedocs.yml`, no `package.json` documentation scripts). GitHub's native Markdown + Mermaid rendering requires no configuration file. No configuration files are created, modified, or deleted in this pass.

### 0.5.5 Cross-Documentation Dependencies

- **Shared content / includes**: None. Each documentation file is self-contained Markdown; there is no templating or transclusion mechanism.
- **Navigation links between documents**: Every README has a `## See Also` section linking to related subsystems. The following link pattern ensures bi-directional navigation:
    - Root `README.md` → all subsystem READMEs + all `/docs/` files + all tool READMEs
    - `crypto/README.md` ↔ `docs/security.md`, `toplip/README.md`, `dhtool/README.md`
    - `net/README.md` ↔ `rwasa/README.md`, `webslap/README.md`, `sshtalk/README.md`, `docs/architecture.md`
    - `tui/README.md` ↔ `sshtalk/README.md`, `examples/README.md`
    - `ds/README.md` ↔ `README.md` (for string engine overview)
    - `docs/architecture.md` → all subsystem READMEs
    - `docs/building.md` → `examples/README.md`, every tool README
    - `docs/calling-convention.md` → `docs/architecture.md`, `docs/contributing.md`
    - `docs/security.md` → `crypto/README.md`, `net/README.md`, `rwasa/README.md`, `toplip/README.md`
    - `docs/contributing.md` → `docs/building.md`, `docs/calling-convention.md`, `docs/architecture.md`
- **Table of contents updates**: GitHub auto-generates a TOC from headings; no manual TOC required.
- **Index / glossary updates**: None in user scope.


## 0.6 Dependency Inventory

### 0.6.1 Documentation Dependencies

The documentation strategy for HeavyThing is **zero-build** by design — all deliverables are plain Markdown files with embedded Mermaid code blocks that render natively on GitHub (and on any Markdown viewer that supports Mermaid). No documentation toolchain, site generator, CSS framework, or CI pipeline is introduced. The following table lists the only externally relevant tooling, including optional local-preview tools a contributor might choose to install — none of which are added to the repository as dependencies.

| Registry | Package Name | Version | Purpose | Required? |
|---|---|---|---|---|
| (none — GitHub-native) | Mermaid | 10.x (GitHub's bundled renderer) | Render the 7 embedded Mermaid diagrams in the browser directly from the raw Markdown code fences | No — included automatically when documents are viewed on GitHub |
| (none — GitHub-native) | GitHub-flavored Markdown | (GitHub-managed) | Render all `*.md` files with headings, tables, fenced code blocks | No — included automatically |
| npm (optional, contributor-local) | `@mermaid-js/mermaid-cli` | 10.9.1 | Optional local diagram rendering during authoring; **not** added to the repository | No — optional authoring tool only |
| (OS package) | FASM (Flat Assembler) | 1.73.x or compatible (version used by the repository for `fasm -m 524288`) | Required to actually build code examples described in `docs/building.md` and tool READMEs — this is a **documented prerequisite for readers**, not a documentation-generation dependency | N/A — not a documentation dependency |
| (OS package) | GNU `ld` | binutils-provided version available on the target Linux distribution | Required to link assembled object files as described in `docs/building.md` — **documented prerequisite for readers** only | N/A — not a documentation dependency |

**Version Selection Rationale**:

- **Mermaid 10.x**: GitHub.com enabled Mermaid rendering in Markdown in early 2022, and has since upgraded through Mermaid 10.x. No explicit version pin is required in this repository; readers receive whatever version GitHub currently serves.
- **`@mermaid-js/mermaid-cli` 10.9.1**: Listed only as a suggested local-authoring convenience for contributors who want to preview diagrams outside GitHub. **It is not added to the repository**, no `package.json` is introduced, and no `node_modules` directory is created.
- **FASM and `ld`**: Documented as reader prerequisites in `/docs/building.md` and each tool README's `## Build` section. They are not packaging dependencies of the documentation itself.

**Repository Dependency Footprint After This Pass**:

- No new `package.json`, `requirements.txt`, `pyproject.toml`, `Gemfile`, `go.mod`, or any other dependency manifest is added
- No `node_modules/`, `.venv/`, `vendor/`, or lock files are introduced
- No CI configuration (`.github/workflows/`, `.gitlab-ci.yml`, etc.) is added
- The repository remains dependency-free at build/publish time; only the **reader's** Markdown viewer (GitHub.com or local) needs Mermaid support

### 0.6.2 Documentation Reference Updates

**Not applicable in a restrictive sense** — because no pre-existing documentation with cross-references exists, there are no "old link" transformations to perform. However, a one-time link-path establishment does take place during creation, and it is useful to document the conventions that downstream agents must follow to keep links consistent.

**Link Conventions Established in This Pass**:

| Rule | Example | Rationale |
|---|---|---|
| Inter-doc links use relative paths | `[Architecture](../docs/architecture.md)` from any subsystem README | Works on GitHub, local preview, and clones |
| Subsystem-README → root-level `.inc` files use `../filename.inc` | `[aes.inc](../aes.inc)` from `/crypto/README.md` | Reflects actual file locations (flat repo root) |
| Tool-README → tool directory files use `./<file>` | `[arguments.inc](./arguments.inc)` from `/rwasa/README.md` | Same-directory references |
| Docs-folder → root-level `.inc` use `../filename.inc` | `[ht.inc](../ht.inc)` from `/docs/architecture.md` | Consistent with subsystem READMEs |
| Embedded source citations use the form `Source: /path/to/file.inc:LineNumber` | `Source: /epoll.inc:22–80` | Source of truth for every technical claim |
| The pre-existing `/rwasa/README.rwasa_tlsmin` is linked from the new `/rwasa/README.md` using its literal path | `[TLS-minimalist variant notes](./README.rwasa_tlsmin)` | Preserves existing file byte-for-byte while making it discoverable |

**Link-Check Responsibility**: There is no automated link-checker in scope (no CI, no linting harness). Authors and reviewers of each document manually verify links before commit.


## 0.7 Coverage and Quality Targets

### 0.7.1 Documentation Coverage Metrics

**Current Coverage Analysis (Baseline)**:

The baseline is effectively zero. The pre-existing artifacts do not constitute developer- or user-facing documentation in any meaningful sense.

| Artifact | Size | Content | Contribution to Coverage |
|---|---|---|---|
| `/README.md` | 13 bytes | Single heading `# HeavyThing` | 0% — placeholder only |
| `/README` | 126 bytes | Plain-text pointer to `https://2ton.com.au/HeavyThing/` | 0% — external redirect |
| `/ChangeLog` | historical | Release history (newest v1.13, July 2015 → oldest v1.01, January 2015) | Out of scope — preserved untouched |
| `/rwasa/README.rwasa_tlsmin` | 292 bytes | Brief TLS-minimalist build variant note | Small partial coverage of one rwasa build mode |
| Source code comment blocks (e.g., `/ht.inc:1–50`, `/epoll.inc:22–80`) | inline | Architectural notes authored by the original developer | Informal; not addressable documentation |

**Coverage Dimensions and Targets**:

| Dimension | Denominator (units to cover) | Baseline Covered | Target Covered | Target Rationale |
|---|---|---|---|---|
| Library subsystems with a README (logical groupings) | 4 (crypto, net, tui, ds) | 0 | 4 | User plan mandates one README per subsystem |
| Application tools with a README | 7 (dhtool, rwasa, sshtalk, toplip, webslap, examples, **note**: `util/` and `hnwatch/` excluded per scope) | 0 | 7 (five tool dirs + `examples/` + **excluding** `util/` and `hnwatch/`) | User plan explicitly lists these seven |
| Root-level overview README | 1 (`/README.md`) | 0% (13-byte placeholder) | 100% (rewritten per 9-section template) | User plan lists Root README explicitly |
| Cross-cutting `/docs/` docs | 5 (architecture, building, calling-convention, security, contributing) | 0 | 5 | User plan explicitly lists all five |
| Embedded Mermaid diagrams | 7 (per user's diagram inventory) | 0 | 7 | User plan specifies each diagram by name |
| Three-file include contract documented | 1 invariant (`ht_defaults.inc` → `ht.inc` → `ht_data.inc` ordering) | Partial (only in `/ht.inc:1–50` comments) | 100% in `/README.md`, `/docs/architecture.md`, `/docs/building.md`, `/docs/calling-convention.md` | Critical correctness invariant; must be impossible to miss |
| Exit codes 96–99 documented | 4 codes (`/ht.inc:38–42`) | 0% outside source | 100% in `/docs/calling-convention.md` and `/docs/security.md` | Observable behavior users must understand |
| Label-naming convention documented (`subsystem$function`) | 1 convention | 0% | 100% in `/docs/calling-convention.md` and every subsystem README `## Calling Convention` | Readers cannot navigate the codebase without it |
| `ht_defaults.inc` configuration knobs grouped and explained | 11 knob categories (alignment, debug, symbols, strings, heap, epoll, tls, ssh, webserver, crypto, performance) | 0% | 100% at category level across the relevant subsystem README `## Configuration` sections | User template mandates a `## Configuration` section per README |

**Target Coverage Summary**: 100% of the units scoped by the user plan (11 READMEs + 5 cross-cutting docs + 7 Mermaid diagrams). No partial-coverage acceptable outcomes are permitted within this scope — every scoped file is either created/updated to the full 9-section template (READMEs) or to the content outline in Section 0.5 (cross-cutting docs).

### 0.7.2 Documentation Quality Criteria

**Completeness Requirements** (per-document):

- **Every Module README** must contain all 9 sections from the user template in the specified order: `# Module Name` → `## Overview` → `## Architecture Fit` → `## Key Components` → `## Calling Convention` → `## Usage` → `## Configuration` → `## Limitations` → `## See Also`. A README missing any section fails quality review.
- **Every cross-cutting doc** under `/docs/` must contain the full content outline specified in Section 0.5's per-file detail (e.g., `/docs/architecture.md` must contain all three Mermaid diagrams specified; `/docs/calling-convention.md` must document register contract, stack alignment, label-naming, exit codes 96–99).
- **Every `## Key Components` table** must enumerate every `.inc` or `.asm` file logically belonging to that subsystem — no partial lists. For `/crypto/README.md`, this means every crypto-family `.inc` file at the repository root (`aes.inc`, `sha1.inc`, `sha2.inc`, `md5.inc`, `hmac.inc`, `pbkdf2.inc`, `scrypt.inc`, and any additional crypto-adjacent files discovered during authoring — e.g., `bigint.inc`, `X509.inc`, `dh.inc`, `ecdh.inc`, `ecdsa.inc`, `rsa.inc`, `dsa.inc`, `prng.inc` if present).
- **Every `## Calling Convention` section** must document at least: calling convention family (System V AMD64 vs. custom), which registers are clobbered vs. preserved, stack alignment expectation at entry, and the `subsystem$function` label pattern.
- **Every `## Usage` assembly snippet** must include the three-file contract at the top (`include 'ht_defaults.inc'` before, `include 'ht_data.inc'` last) and be no longer than ~15 lines to comply with the "keep snippets short" professional-documentation standard.

**Accuracy Validation**:

- **Source-citation requirement**: every non-trivial technical claim in a README or doc is followed by an inline citation in the form `Source: /path/to/file.ext:LineNumber` or a footnote pointing to one. Examples:
  - "Exit code 99 indicates heap `mmap` failure (Source: /ht.inc:38–42)"
  - "The epoll minimum file-descriptor slot count defaults to 4096 (Source: /ht_defaults.inc, `epoll_minfds` knob)"
  - "Protocol handlers chain as parent-child IO objects with a virtual method table of `io_vreceive`, `io_vsend`, `io_vtimeout`, `io_vdestroy` (Source: /epoll.inc:22–80)"
- **Signature fidelity**: every label name referenced (e.g., `ht$init`, `string$to_stdoutln`, `epoll$send`, `heap$free`) must match the exact label present in the current source — verified by `grep -n '^<label>:' <file>.inc` at authoring time.
- **Exit-code fidelity**: the four exit codes (96, 97, 98, 99) and their trigger conditions must match `/ht.inc:38–42` verbatim.
- **Build-command fidelity**: any `fasm` or `ld` invocation in documentation must be runnable against an unmodified checkout of the repository. The assembler name is **FASM**, not NASM; the default large-symbol-pool invocation is `fasm -m 524288 source.asm`.
- **No invention**: no documentation may describe APIs, flags, configuration knobs, or behaviors not present in the source. When the source is ambiguous, the `## Limitations` section honestly records the ambiguity rather than guessing.

**Clarity Standards**:

- **Audience framing**: Root README, `/docs/building.md`, `/examples/README.md`, and tool READMEs (`/rwasa/README.md`, `/sshtalk/README.md`, `/toplip/README.md`, `/webslap/README.md`, `/dhtool/README.md`) are written for **new users** — minimal assumed context beyond "knows Linux and some assembly".
- **Developer framing**: `/crypto/README.md`, `/net/README.md`, `/tui/README.md`, `/ds/README.md`, `/docs/architecture.md`, `/docs/calling-convention.md`, `/docs/contributing.md` are written for **developers who will read and write assembly code** against the library.
- **Progressive disclosure**: each README opens with the 1-sentence purpose, then the 2–4 sentence `## Overview`, then deeper material. A reader skimming only the first three sections should come away with a correct high-level mental model.
- **Consistent terminology**: the following canonical terms are used repository-wide once this pass lands:
  - "three-file include contract" (not "include chain", not "build contract")
  - "subsystem" (not "module", not "component", when referring to crypto/net/tui/ds)
  - "label" (not "function", not "entry point", for assembly symbols)
  - "FASM" (not "nasm", not "fasmg")
  - "calling convention" (singular, referring to the library-wide register contract)
- **Tone**: neutral, technical, no marketing language, no emojis — as stipulated by the user's formatting rules.

**Maintainability**:

- **Traceability**: every file, subsystem, and configuration knob mentioned in documentation has a line-precise citation back to the source of truth.
- **No duplication**: the `## Calling Convention` section of each subsystem README states "See `/docs/calling-convention.md` for the full library-wide register contract; subsystem-specific notes below." Subsystem-specific deviations (if any) are documented in-place; everything else lives in one canonical location.
- **Single source of truth for each invariant**: the three-file include contract is authoritative in `/docs/architecture.md`; all other references are cross-links. Exit codes are authoritative in `/docs/calling-convention.md`; all other references are cross-links.

**Length Limits** (from user formatting rules):

- Every README stays **under 400 lines**. If a natural write-up exceeds 400 lines, split the README into a top-level README + linked sub-docs under a sibling `/docs/<subsystem>/` directory — but within this pass, every scoped README is expected to fit within the 400-line budget.
- Heading depth capped at `###`. No `####` level used anywhere.
- Tables used whenever a list has more than three items.

### 0.7.3 Example and Diagram Requirements

**Assembly Code Examples per README**:

| README | Minimum Snippets | Content |
|---|---|---|
| `/README.md` | 1 | Hello-world level `ht$init` → print → exit, with the three-file include contract visible |
| `/crypto/README.md` | 1 | Representative primitive invocation (e.g., `sha2$block` or `aes$encrypt`) showing register inputs/outputs |
| `/net/README.md` | 1 | Minimal HTTP or TCP echo server structure (epoll init + handler skeleton) |
| `/tui/README.md` | 1 | Widget instantiation and event-loop bind |
| `/ds/README.md` | 1 | List or buffer allocation + append + destroy |
| `/examples/README.md` | 1 | Build command line for one example |
| Each of the 5 tool READMEs (dhtool, rwasa, sshtalk, toplip, webslap) | 1 each | Exact `fasm` + `ld` build line |
| `/docs/building.md` | 2 | Minimal build; build-with-optional-C-integration |
| `/docs/calling-convention.md` | 2 | Example showing caller saves; example showing callee preserving non-volatile registers |
| `/docs/contributing.md` | 1 | Skeleton `.inc` file showing the `if used` conditional-compilation guard |

Each snippet is:
- Fenced with ```` ```nasm ```` (the user's chosen tag; GitHub highlights it as Intel-syntax assembly, which is FASM's syntax family)
- At most ~15 lines
- Buildable against an unmodified checkout

**Mermaid Diagram Requirements**:

Exactly 7 diagrams per the user plan, preserved verbatim in name and location:

| # | Diagram | Mermaid Type | Destination |
|---|---|---|---|
| 1 | Include dependency graph | `graph TD` | `/docs/architecture.md` |
| 2 | Init/event-loop lifecycle | `sequenceDiagram` | `/docs/architecture.md` |
| 3 | Subsystem boundary map | `graph LR` | `/docs/architecture.md` |
| 4 | TUI widget hierarchy | `graph TD` | `/tui/README.md` |
| 5 | Networking stack layers | `graph TD` | `/net/README.md` |
| 6 | Crypto primitive map | `graph LR` | `/crypto/README.md` |
| 7 | Build flow | `flowchart TD` | `/docs/building.md` |

Construction rules for each diagram (from the user plan, preserved):

- Fenced in ```` ```mermaid ```` blocks
- Node labels use the actual filename or label name from the codebase (e.g., `ht.inc`, `epoll.inc`, `ht$init`)
- Embedded directly in the relevant README or doc, immediately after the `## Architecture Fit` or `## Overview` section they illustrate
- No single diagram exceeds ~30 nodes; if a subsystem would exceed this, split into a summary diagram plus a detail diagram below it
- No external image files; no PNG/SVG embedding; no separate rendering pipeline

**Code-Example Testing**:

- Build commands in READMEs are verified manually by running them against the unmodified checkout during authoring.
- Label names are verified with `grep -n '^<label>:' <file>.inc`.
- Configuration-knob names are verified against the current `/ht_defaults.inc`.
- No automated example-test harness is introduced (consistent with the "no new CI" constraint).

**Visual Content Freshness**:

- The ChangeLog's stale terminal version (v1.13, July 2015) is **not** edited. Documentation reflects the current repository snapshot, not external version labels.
- If future code changes invalidate a diagram or snippet, `/docs/contributing.md` instructs contributors to update the affected documentation in the same commit (this guidance is contained within the contributing guide itself).


## 0.8 Scope Boundaries

### 0.8.1 Exhaustively In Scope

The following artifacts are created, updated, or inspected during this pass. Every item listed here is within the execution boundary; items not listed are out of scope and enumerated in Section 0.8.2.

**New Markdown Files to Create (16 files)**:

- `/crypto/README.md` — crypto subsystem README (new directory + file)
- `/net/README.md` — networking subsystem README (new directory + file)
- `/tui/README.md` — TUI subsystem README (new directory + file)
- `/ds/README.md` — data structures subsystem README (new directory + file)
- `/examples/README.md` — examples index README (existing directory, new file)
- `/dhtool/README.md` — Diffie-Hellman tool README (existing directory, new file)
- `/rwasa/README.md` — rwasa web server tool README (existing directory, new file)
- `/sshtalk/README.md` — sshtalk tool README (existing directory, new file)
- `/toplip/README.md` — toplip tool README (existing directory, new file)
- `/webslap/README.md` — webslap tool README (existing directory, new file)
- `/docs/architecture.md` — architecture overview with 3 Mermaid diagrams (new directory + file)
- `/docs/building.md` — build guide with 1 Mermaid diagram (new directory + file)
- `/docs/calling-convention.md` — calling-convention reference (new directory + file)
- `/docs/security.md` — security notes (new directory + file)
- `/docs/contributing.md` — contributing guide (new directory + file)
- Plus **four new directories** created implicitly by placing READMEs inside them: `/crypto/`, `/net/`, `/tui/`, `/ds/`
- Plus **one new directory** created implicitly for cross-cutting docs: `/docs/`

**Existing Markdown Files to Update (1 file)**:

- `/README.md` — replace the 13-byte `# HeavyThing` placeholder with a full root README per the 9-section user template

**Source Code Files (Inspected for Citations, Not Modified)**:

The following patterns and explicit files are **read-only inputs** — every claim in the documentation cites one or more of these, but none of them receive edits in this pass:

| Pattern / File | Purpose in This Pass |
|---|---|
| `/ht.inc` | Source of truth for three-file contract, exit codes 96–99, include-chain (lines 51–205), `ht$init` entry point |
| `/ht_defaults.inc` | Source of truth for all configuration knobs |
| `/ht_data.inc` | Source of truth for the "finale" include requirement |
| `/*.inc` (all 106 library files at repo root, e.g., `aes.inc`, `sha1.inc`, `sha2.inc`, `md5.inc`, `hmac.inc`, `pbkdf2.inc`, `scrypt.inc`, `bigint.inc`, `X509.inc`, `dh.inc`, `ecdh.inc`, `ecdsa.inc`, `rsa.inc`, `dsa.inc`, `prng.inc`, `epoll.inc`, `http1.inc`, `tls.inc`, `ssh.inc`, `webclient.inc`, `webserver.inc`, `tui_*.inc` (32 files), `list.inc`, `maps.inc`, `heap.inc`, `buffer.inc`, `json.inc`, and all remaining `.inc` files at the root) | Inspected via `read_file`, `grep`, `head`, `sed` for label lists, configuration references, register-contract comments, feature presence |
| `/examples/**/*.asm` (14 example programs) | Inspected for usage patterns, include-order examples, representative label invocations |
| `/dhtool/*.asm` and `/dhtool/*.inc` | Inspected for tool build and invocation documentation |
| `/rwasa/*.asm` and `/rwasa/*.inc` | Inspected for rwasa architecture and flags |
| `/sshtalk/*.asm` and `/sshtalk/*.inc` | Inspected for sshtalk architecture and flags |
| `/toplip/*.asm` and `/toplip/*.inc` | Inspected for toplip architecture and flags |
| `/webslap/*.asm` and `/webslap/*.inc` | Inspected for webslap architecture and flags |

**Other Files (Read-Only)**:

- `/ChangeLog` — inspected to confirm version progression; referenced in `/docs/architecture.md` and `/README.md` as a cross-link; **not modified**
- `/LICENSE` — referenced from `/README.md`, `/docs/contributing.md`; **not modified**
- `/README` (the 126-byte plain-text redirect file) — **preserved byte-for-byte**; linked from `/README.md` as historical artifact
- `/rwasa/README.rwasa_tlsmin` — **preserved byte-for-byte**; linked from `/rwasa/README.md`
- `/2ton.png` — **preserved byte-for-byte**; not referenced in documentation

**Wildcard Scope Patterns**:

- `/docs/**/*.md` — all Markdown under the new `/docs/` tree (exactly 5 files this pass)
- `/*/README.md` — subsystem and tool READMEs (exactly 10 new files this pass)
- `/README.md` — root README (1 updated file)

### 0.8.2 Explicitly Out of Scope

**Source Code — No Modifications**:

- No `.inc`, `.asm`, `.c`, or `.cpp` file is edited. Per the Minimal Change Clause, existing production code is documented **as-is**; comments are not added to source files as part of this pass (documentation goes into Markdown files, not inline source comments).
- No refactoring, no optimization, no interface changes, no bug fixes — even where a function appears to have a bug or inefficiency. Such observations, if any, are recorded only in the affected README's `## Limitations` section as a narrative note referencing the location, never as a code change.

**Existing Non-Documentation Files — Preserved Byte-for-Byte**:

- `/ChangeLog` — the historical record remains untouched. It is referenced from new documentation but not edited.
- `/LICENSE` — GPLv3 license text remains untouched. `/README.md` links to it.
- `/README` (plain-text external redirect) — remains untouched.
- `/2ton.png` — image file remains untouched.
- `/rwasa/README.rwasa_tlsmin` — pre-existing 292-byte note remains untouched; newly created `/rwasa/README.md` links to it.

**Directories With No New README**:

- `/util/` — explicitly excluded from the user's README inventory. Existing files in `/util/` are not inspected for documentation purposes and no `/util/README.md` is created.
- `/hnwatch/` — the user plan references `hnwatch` only as a **worked example pointer** from the TUI README. No `/hnwatch/README.md` is created; `/tui/README.md`'s `## See Also` section links to `/hnwatch/` with a one-line description derived from directory inspection.

**External Resources**:

- `https://2ton.com.au/HeavyThing/` — the author's external website is **out of scope**. The new `/README.md` may mention it as "the project's original upstream site" but this pass does not fetch, mirror, summarize at length, or validate that external content.
- Third-party or vendored code, if any is present in the repository — not documented in this pass. (The repository is architecturally self-contained with zero external runtime dependencies, so third-party code is unlikely; if present, it is flagged in `/docs/contributing.md` but not catalogued here.)

**Binary and Build Outputs**:

- Any object files (`*.o`), ELF executables, or intermediate build artifacts — not created, not documented, not committed. Documentation describes the build process; it does not perform builds.

**Infrastructure, Tooling, and Automation Explicitly Not Introduced**:

- No documentation site generator (no MkDocs, Docusaurus, Sphinx, Read the Docs, VitePress, Docsify, Zola, Hugo, Jekyll).
- No configuration file for any of the above (no `mkdocs.yml`, no `docusaurus.config.js`, no `sphinx/conf.py`, no `.readthedocs.yml`).
- No `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`, or any dependency manifest for documentation tooling.
- No `node_modules/`, `.venv/`, or vendored documentation tool directory.
- No CI/CD workflow or pipeline definition (no `.github/workflows/`, no `.gitlab-ci.yml`, no `.circleci/config.yml`, no `Jenkinsfile`) for documentation linting, link-checking, building, or deployment.
- No documentation-build `Makefile` targets added.
- No documentation-deployment hosting (no GitHub Pages publish flow, no Netlify/Vercel config, no custom domain setup).
- No screenshot generation, no PNG/SVG image assets, no CSS/theme customization.
- No automated documentation-from-source generators such as Doxygen, JSDoc, TypeDoc, rustdoc, or equivalent.
- No internationalization (i18n) / localization (l10n) of documentation. All documentation is English only.
- No link-checker, no Markdown linter (e.g., markdownlint, remark-lint), no spell-checker automation.
- No PDF, ePub, or other format exports.

**Documentation Topics Deliberately Excluded**:

- Release-engineering procedures, version-bumping process, tag/branch strategy — not in scope (ChangeLog is historical only, no active release cadence to document).
- Performance benchmarks, comparative benchmarks against other libraries (beyond what is already stated in source comments or tech spec context).
- Prior-version migration guides — the documentation describes the current snapshot only.
- API stability guarantees — not asserted, as the library does not declare any.
- Anything about the external website's build, design, or deployment.
- Any content not listed in the user's MODULE-LEVEL DOCUMENTATION, DIAGRAMS, or SYSTEM BOUNDARIES sections.

**Security Reporting Process**:

- `/docs/security.md` documents the **posture** of the cryptographic and network primitives (scope, known caveats, version support). It does **not** establish a vulnerability-disclosure process, a security-contact email, or a CVE-tracking convention — those operational policies are out of scope for a documentation pass.

**Boundary Guard**:

- If, during authoring, a new requirement surfaces that is not covered by this in/out-of-scope table, it is flagged in the affected document's `## Limitations` section as a "documentation gap — not addressed in this pass" note. It is **not** silently added to scope.


## 0.9 Execution Parameters

### 0.9.1 Documentation-Specific Instructions

**Documentation "Build" Command**:

There is no build step. All deliverables are plain Markdown files. To "publish" the documentation, the contributor simply commits the Markdown files to the repository; GitHub renders `.md` files (including embedded Mermaid fenced code blocks) automatically on file view and on directory index views.

```bash
# No build required — Markdown is the final format.

#### To ship documentation:

####   Commit the new .md files to the repository

####   Push to the upstream remote

####   GitHub renders Markdown and Mermaid diagrams automatically

git add README.md crypto/README.md net/README.md tui/README.md ds/README.md
git add examples/README.md dhtool/README.md rwasa/README.md sshtalk/README.md
git add toplip/README.md webslap/README.md docs/
git commit -m "docs: add module READMEs, cross-cutting docs, diagrams"
```

**Documentation Preview Command**:

Two viable preview options are available to authors, neither of which introduces a repository dependency:

| Option | Command / Action | Coverage |
|---|---|---|
| GitHub web UI | Push to a branch; open the file on github.com | Full rendering including Mermaid diagrams |
| Local CLI preview via `grip` (optional, not added to the repo) | `grip README.md 6419` | Markdown rendering via GitHub's API; Mermaid handled by the API |
| VS Code Markdown preview with Markdown Preview Mermaid Support extension | Open the `.md` file in VS Code, press `Ctrl+Shift+V` | Full rendering including Mermaid |

Authors verify each document renders correctly before commit by opening it via one of the above options.

**Diagram Generation Command**:

No offline diagram generation is performed. All 7 Mermaid diagrams are embedded as fenced code blocks tagged `mermaid` and are rendered by the viewer at display time. No `.svg`, `.png`, or other image artifact is produced.

If a contributor wants to verify a diagram's syntax offline without committing a broken diagram, the recommended (optional, not-added-to-repo) workflow is:

- Paste the Mermaid code into the online editor at `https://mermaid.live`
- OR install `@mermaid-js/mermaid-cli` globally on a personal workstation and run `mmdc -i diagram.mmd -o diagram.svg`

**Documentation Deployment Command**:

Not applicable — `git push` to the repository's upstream remote is the entire deployment. No secondary hosting, no GitHub Pages, no custom domain. Readers consume documentation via the repository's file browser.

**Default Format**: Markdown (GitHub-flavored) with embedded Mermaid fenced code blocks. No alternative formats (PDF, ePub, HTML site) are produced.

**Citation Requirement**: every section of every delivered document must cite its source of truth. The citation format is one of:

- Inline parenthetical: `(Source: /path/to/file.inc:LineNumber)`
- Inline parenthetical with symbol name: `(Source: /path/to/file.inc, <label-or-knob-name>)`
- Narrative: `As documented in /ht.inc:38–42, exit code 99 indicates ...`

This is non-negotiable; a section without at least one source citation fails review.

**Style Guide**: the user's explicit formatting rules are the authoritative style guide for this pass (see Section 0.10 for the verbatim preservation). No external style guide (Microsoft Writing Style Guide, Google Developer Documentation Style Guide, etc.) is adopted.

**Documentation Validation**:

- No automated linting, link-checking, or spell-checking is run (consistent with the "no new CI" constraint from Section 0.8.2).
- Manual validation checklist applied to each document before commit:
  - All 9 sections present (for READMEs) or all required content blocks present (for cross-cutting docs)
  - No heading deeper than level-3 (`###`)
  - Every table has more than 3 items (if the list would otherwise have 3 or fewer, it stays as prose or a dashed list)
  - Every assembly snippet is fenced with the `nasm` language tag, not a different language tag
  - Every Mermaid diagram is fenced with the `mermaid` language tag
  - Every non-trivial claim has a `Source:` citation
  - No emoji characters present
  - No marketing language (e.g., "blazing fast", "best-in-class", "effortless")
  - No level-4 heading (`####`) used
  - File under 400 lines
  - All relative links resolve against the actual repo layout (verified by `ls` in the target directory)

### 0.9.2 Reader-Facing Build Parameters (Documented in `/docs/building.md` and Tool READMEs)

These are the build commands a **reader** uses to assemble the source code described in the documentation. They are not executed as part of producing documentation, but they are documented parameters that the documentation itself specifies.

**Canonical Assemble + Link**:

```nasm
; Assemble a source file into an ELF64 object, then link to a static binary.
; NOTE: the -m 524288 flag raises FASM's internal symbol pool for HeavyThing's size.
;   fasm -m 524288 source.asm
;   ld -o binary source.o
```

**Tool-Specific Build Lines** (to be documented in each tool's README):

| Tool | Build Command (to be documented) |
|---|---|
| `dhtool` | `fasm -m 524288 dhtool.asm && ld -o dhtool dhtool.o` (verified against `/dhtool/`) |
| `rwasa` | `fasm -m 524288 rwasa.asm && ld -o rwasa rwasa.o` (verified against `/rwasa/`); TLS-minimalist build variant per `/rwasa/README.rwasa_tlsmin` |
| `sshtalk` | `fasm -m 524288 sshtalk.asm && ld -o sshtalk sshtalk.o` (verified against `/sshtalk/`) |
| `toplip` | `fasm -m 524288 toplip.asm && ld -o toplip toplip.o` (verified against `/toplip/`) |
| `webslap` | `fasm -m 524288 webslap.asm && ld -o webslap webslap.o` (verified against `/webslap/`) |
| `examples/hello_world` | `fasm -m 524288 hello_world.asm && ld -o hello_world hello_world.o` (verified against `/examples/hello_world/`) |

The exact filename within each tool directory is verified by running `ls <dir>/*.asm` during authoring; the build lines above use the canonical `<toolname>.asm` form but are confirmed against the actual entry-point filename before being committed to the README.

**Target Platform**: Linux x86-64 (per tech spec § 3.1 / § 3.7). No other platforms are documented as supported. Documentation is clear that attempts to assemble on non-Linux or non-x86-64 systems will not succeed.

**Runtime Dependencies**: None beyond the Linux kernel and its syscall ABI. The library explicitly avoids libc and links statically.

### 0.9.3 Authoring Process Parameters

The following operational parameters govern **how** each document is produced during this pass:

- **File-by-file sequence**: produce documents in the order specified in Section 0.5's transformation table. Root `/README.md` is updated last so it can cross-reference the subsystem and cross-cutting docs by their final paths.
- **Source-inspection budget**: every document is preceded by inspection of its cited source files. For subsystem READMEs, every `.inc` file in the `## Key Components` table is opened with `read_file` (or a targeted `sed -n` range) at authoring time to verify the label list.
- **No speculation**: if a configuration knob, label, or behavior cannot be confirmed from the source after reasonable search, it is **not** documented. The `## Limitations` section is used to note the gap.
- **Idempotent edits**: every `add_tech_spec_sub_section` and every file-creation action is idempotent in intent — producing the same output on re-run against an unchanged source.
- **Commit granularity**: one logical unit per commit (e.g., one commit for all subsystem READMEs, one commit for all cross-cutting docs, one commit for the root README update). No constraint on specific Git semantics, but the documentation set is coherent at each commit boundary so a reader at HEAD never sees broken cross-links between new docs.


## 0.10 Rules for Documentation

The rules in this section are the user-supplied constraints on how documentation must be authored. They are preserved verbatim in wording where the user's wording exists, and listed in the form of authoritative rules that downstream code-generation agents must follow without deviation. Any conflict between an agent's own inclinations and these rules is resolved in favor of the rules.

### 0.10.1 Minimal Change Clause (Preserved Verbatim)

USER-PROVIDED TEXT (reproduced exactly):

> Add comments and documentation without modifying production code logic or behavior. Do not refactor, optimize, or change existing interfaces. Document existing code as-is. If a function appears to have a bug or inefficiency, note it in a comment only if it is a genuine non-obvious invariant — do not fix it as part of this pass.

**Operational implications for this pass**:

- No `.inc`, `.asm`, `.c`, or `.cpp` file content is modified, moved, renamed, or deleted
- No pre-existing Markdown or text file (`/README`, `/ChangeLog`, `/LICENSE`, `/rwasa/README.rwasa_tlsmin`) is modified
- The single exception is `/README.md` — the 13-byte placeholder — which is replaced because it is itself documentation (not production code)
- Observed bugs or inefficiencies, if any are noticed during inspection, are recorded in the affected README's `## Limitations` section as a narrative note with a source citation; they are never "fixed"
- The non-obvious-invariant carve-out ("note it in a comment only if…") is deliberately not exercised in this pass because this pass adds Markdown files, not source-code comments

### 0.10.2 README Structural Template (Preserved Verbatim)

Every module README — all 10 newly created READMEs plus the updated root `/README.md` — must contain exactly these 9 sections, in this order, using these exact heading names:

USER-PROVIDED TEMPLATE (reproduced exactly):

1. `# Module Name` — one-sentence purpose
2. `## Overview` — 2–4 sentences on what it does and why it exists
3. `## Architecture Fit` — how it relates to the rest of the library (dependencies in/out)
4. `## Key Components` — table: `| File | Purpose |`
5. `## Calling Convention` — for library subsystems: register input/output contract, stack alignment expectations, clobber list
6. `## Usage` — minimal assembly snippet showing include order and a representative label call
7. `## Configuration` — relevant `ht_defaults.inc` knobs that affect this subsystem
8. `## Limitations` — honest list of what is not supported or not hardened
9. `## See Also` — links to related subsystems and example tools

**Operational implications**:

- Section 5 (`## Calling Convention`) applies primarily to library subsystem READMEs (`/crypto/`, `/net/`, `/tui/`, `/ds/`). In tool READMEs (e.g., `/rwasa/README.md`), this section either documents the tool's command-line invocation convention or explicitly cross-references `/docs/calling-convention.md` — the heading is preserved in all cases to maintain structural uniformity.
- Section 7 (`## Configuration`) in tool READMEs discusses the tool's command-line flags and any `ht_defaults.inc` knobs that materially change the tool's behavior (for example, `epoll_minfds` for network tools; `scrypt_N` for crypto tools).
- Section 9 (`## See Also`) is always populated with at least two relative links: one to a related subsystem and one to a cross-cutting doc under `/docs/`.

### 0.10.3 Markdown Formatting Rules (Preserved Verbatim)

USER-PROVIDED FORMATTING RULES (reproduced exactly):

- Assembly code blocks use the `nasm` language tag for fencing
- Register names in inline code: `rax`, `rdi`, etc.
- No emojis, no marketing language
- Headers use `##` with maximum depth of `###`; avoid `####`
- Tables for anything with more than 3 items in a list
- Keep each README under 400 lines; if longer, split into linked sub-docs

**Operational implications**:

- The `nasm` code-fence tag is used for assembly snippets even though the actual assembler is FASM; this is chosen for GitHub's Intel-syntax highlighter compatibility
- Inline register names, label names, filenames, and knob names all use single-backtick inline code spans (e.g., `rdi`, `ht$init`, `epoll.inc`, `epoll_minfds`)
- Prose is neutral and technical; no superlatives ("the best", "blazingly fast"), no exclamations, no emojis anywhere in any delivered file
- The heading ceiling is strictly enforced. Documents with deep sub-structure either flatten into peer-level `###` headings or split into linked sub-documents under a sibling directory
- If a README would exceed 400 lines, it is split into a top-level README plus linked sub-documents (e.g., `/crypto/README.md` plus `/crypto/docs/aes.md`); this split is planned in-advance in Section 0.5 and not performed on-the-fly during authoring

### 0.10.4 Diagram Format Standards (Preserved Verbatim)

USER-PROVIDED DIAGRAM STANDARDS (reproduced exactly):

- All diagrams use **Mermaid** fenced code blocks (using the `mermaid` language tag) so they render natively on GitHub and most Markdown viewers — no external image files needed
- Node labels use the actual filename or label name from the codebase (e.g. `ht.inc`, `epoll.inc`, `ht$init`)
- Diagrams are embedded directly in the relevant README or doc file, immediately after the `## Architecture Fit` or `## Overview` section they illustrate
- No diagram should exceed ~30 nodes; if a subsystem is too large, split into a summary diagram + a detail diagram below it

**Operational implications**:

- No PNG, SVG, or other image asset is committed; every diagram is a fenced code block tagged `mermaid` in the same file as the prose it illustrates
- Node labels like `ht.inc`, `epoll.inc`, `ht$init`, `io_vreceive`, `epoll$send` etc. appear verbatim so a reader can `grep` the repo with the diagram's terms
- Diagram placement is prescriptive: immediately after the section it illustrates, not at the bottom of the file and not in a separate gallery
- The 30-node ceiling is pre-planned in Section 0.5's diagram-construction notes; any diagram approaching the limit is factored into summary + detail pairs before authoring, not after
- The 7 specific diagrams from Section 0.5 are the complete set for this pass — no additional diagrams are added ad hoc

### 0.10.5 System-Boundary Rules (Preserved Verbatim)

USER-PROVIDED BOUNDARIES (reproduced exactly):

**Focus areas**:

- All `.inc` library files and `.asm` example/tool sources listed above
- The five additional docs under `/docs/`
- The eleven module READMEs listed above

**Exclusions**:

- `ChangeLog` — historical record, do not modify
- `LICENSE` — do not touch
- Any binary or compiled output files
- The external website at `https://2ton.com.au/HeavyThing/` — out of scope
- Third-party or vendored code if any is present

**Operational implications**:

- The ChangeLog's terminal v1.13 date (July 16, 2015) is not edited even if it is technically "stale" relative to tech spec references to v1.24; it is a historical artifact
- The external URL is referenced at most once in `/README.md` as the project's upstream home, and is not mirrored, paraphrased, summarized at length, or validated
- If third-party code is discovered during inspection, it is cited as "third-party component — see original source for licensing" and not further documented in this pass

### 0.10.6 Derived Rules for Downstream Agents

The following rules are derived from the user's explicit rules plus the repository analysis in Sections 0.1 through 0.9, and are authoritative for the documentation pass:

- **FASM over NASM**: the user plan's "NASM assembler version" phrasing is reconciled as follows — the documentation states that the actual assembler is **FASM** (Flat Assembler) by Tomasz Grysztar, and uses `fasm` in all build commands. The `nasm` language-fence tag is a display-syntax choice only and is clearly explained the first time it is used in `/docs/building.md`
- **Three-file include contract is authoritative in `/docs/architecture.md`**: every other mention cross-links here and does not re-derive the rule
- **Exit codes 96–99 are authoritative in `/docs/calling-convention.md`**: every other mention cross-links here
- **Label naming convention is authoritative in `/docs/calling-convention.md`**: every other mention cross-links here
- **Subsystem logical grouping**: the four new subsystem directories (`/crypto/`, `/net/`, `/tui/`, `/ds/`) each contain **only** a `README.md`. No source files are moved into them. The README references root-level `.inc` files using relative paths of the form `../<filename>.inc`
- **Source citations are mandatory**: every technical claim traces back to a file and (where practical) line range. The authoring workflow opens the cited file at authoring time to confirm the claim before committing the Markdown
- **No scope creep**: any topic surfacing during authoring that is not covered by Section 0.8.1 is either recorded as a limitation in the affected document or deferred to a future documentation pass. It is never silently added
- **No tool introduction**: no documentation site generator, linter, CI workflow, or dependency manifest is introduced — the repository remains dependency-free at the end of this pass
- **Preservation of pre-existing artifacts**: `/README`, `/LICENSE`, `/ChangeLog`, `/rwasa/README.rwasa_tlsmin`, and `/2ton.png` are preserved byte-for-byte. The new `/README.md` and `/rwasa/README.md` reference the existing companion files (e.g., "See also: [plain-text README](./README) for the upstream URL redirect")

### 0.10.7 Rule-Precedence Order

When two or more rules appear to conflict, the following precedence resolves the conflict (highest priority first):

1. **Minimal Change Clause** — never modifies source code or pre-existing non-documentation files
2. **System-Boundary Rules** — never documents excluded items
3. **Accuracy / Source-Citation Rule** — never documents what cannot be verified in the source
4. **README Structural Template** — every README follows the 9-section structure
5. **Markdown Formatting Rules** — formatting complies with the user-supplied rules
6. **Diagram Format Standards** — all diagrams follow the Mermaid-only, 30-node-ceiling rule
7. **Coverage and Quality Targets** — every scoped unit reaches 100% coverage within its documented boundaries
8. **Author preference** — tie-breaker only, never overrides any rule above

Practical illustration: if the full label list for `/crypto/README.md`'s `## Key Components` would push the file over 400 lines (rule 5 conflict), the resolution is to split into `/crypto/README.md` + `/crypto/docs/<family>.md` sub-documents (rule 5's own escape hatch), not to omit labels (which would violate rule 7).


## 0.11 References

This section comprehensively enumerates every file, folder, external resource, and tech-spec section consulted to produce the Agent Action Plan in Sections 0.1 through 0.10. Sources are grouped by category for auditability.

### 0.11.1 Repository Folders Inspected

The repository root is `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/`.

| Folder Path | Inspection Method | Purpose in Plan |
|---|---|---|
| `/` (repository root) | `get_source_folder_contents`, `ls -la` | Establish top-level layout; count of `.inc` files (106); presence of `README.md` (13 bytes), `README` (126 bytes), `ChangeLog`, `LICENSE`, `2ton.png` |
| `/dhtool/` | `ls` directory listing | Confirm Diffie-Hellman tool contents: `dhtool.asm`, `dhtool_settings.inc`, `dhtool` binary, `dhtool.o` object |
| `/examples/` | `ls` directory listing | Enumerate 14 example programs: `echo`, `hello_world`, `hello_world_c1`, `hello_world_c2`, `minigzip`, `multicore_echo`, `sha256`, `simplechat_c++`, `simplechat_ssh_auth_c++`, `simplechat_ssh_c++`, `sshecho`, `tlsecho`, `tuieffects`, `tuimatrix` |
| `/hnwatch/` | `ls` directory listing | Confirm out-of-scope tool structure: `hnwatch.asm`, `eventstream.inc`, `hnmodel.inc`, `textify.inc`, `ui.inc`, `hnwatch` binary. Referenced from `/tui/README.md` as worked TUI example only |
| `/rwasa/` | `ls` directory listing | Confirm rwasa web server contents: `rwasa.asm`, `rwasa_tlsmin.asm`, `arguments.inc`, `master.inc`, `worker.inc`, `tlsmin_defaults.inc`, `README.rwasa_tlsmin` (preserved), `rwasa` and `rwasa_tlsmin` binaries |
| `/sshtalk/` | `ls` directory listing | Confirm sshtalk contents: `sshtalk.asm`, `chatpanel.inc`, `chatroom.inc`, `screen.inc`, `statusbar.inc`, `userdb.inc`, `sshtalk` binary |
| `/toplip/` | `ls` directory listing | Confirm toplip contents: `toplip.asm`, `toplip` binary, `toplip.o` object (minimal — single-file tool) |
| `/util/` | `ls` directory listing | Confirm out-of-scope tools: `bigint_tune.asm`, `make_dh_static.asm`, `mersenneprimetest.asm`, `bigger_int_settings.inc`. Out of scope per user plan |
| `/webslap/` | `ls` directory listing | Confirm webslap contents: `webslap.asm`, `webslap_tlsmin.asm`, `globals.inc`, `master.inc`, `master_ui.inc`, `tlsmin_defaults.inc`, `worker.inc`, `webslap` and `webslap_tlsmin` binaries |

### 0.11.2 Source Files Inspected

**Primary Framework Files (read in detail)**:

| File Path | Inspection | Key Facts Extracted |
|---|---|---|
| `/ht.inc` | `read_file` (complete), with focused `sed -n` ranges on lines 1–50, 38–42, 51–205, 613 | Three-file include contract requirement; exit codes 96–99; library-wide include chain; `ht$init` entry point |
| `/ht_defaults.inc` | `read_file`, with focused `sed -n` on line 24, line 26 | Confirms FASM as actual assembler (`format ELF64` FASM syntax, "set our fasm format" comment); source of all 11 configuration knob categories |
| `/ht_data.inc` | Inspected for the "finale" include requirement | Confirms it must be the last include per the three-file contract |
| `/epoll.inc` | `read_file` with `sed -n 22,80p` | IO chaining model; virtual method table (`io_vreceive`, `io_vsend`, `io_vtimeout`, `io_vdestroy`); parent-child IO object linkage |

**Library Subsystem Files Inspected for Inventory** (grouped by subsystem):

*Cryptography* — destined for `/crypto/README.md`'s `## Key Components` table:
- `/aes.inc`
- `/sha1.inc`
- `/sha2.inc`
- `/md5.inc`
- `/hmac.inc`
- `/hmac_drbg.inc`
- `/pbkdf2.inc`
- `/scrypt.inc`
- `/bigint.inc`
- `/X509.inc`
- `/crc.inc`
- `/rng.inc`
- `/htcrypt.inc`
- `/dh_groups.inc`
- `/dh_pool.inc`, `/dh_pool_2k.inc`, `/dh_pool_3k.inc`, `/dh_pool_4k.inc`, `/dh_pool_6k.inc`, `/dh_pool_8k.inc`, `/dh_pool_16k.inc`
- `/base64_latin1.inc`
- `/cleartext.inc`

*Networking* — destined for `/net/README.md`'s `## Key Components` table:
- `/epoll.inc`
- `/epoll_child.inc`
- `/epoll_dns.inc`
- `/http1.inc`
- `/httpheaders.inc`
- `/tls.inc`
- `/ssh.inc`
- `/webclient.inc`
- `/webserver.inc`
- `/fcgiclient.inc`
- `/cookiejar.inc`
- `/url.inc`
- `/mimelike.inc`
- `/htxts.inc`

*TUI* — destined for `/tui/README.md`'s `## Key Components` table (32 files, the `tui_*.inc` set):
- `/tui_alert.inc`, `/tui_ansi.inc`, `/tui_background.inc`, `/tui_bell.inc`, `/tui_button.inc`
- `/tui_datagrid.inc`, `/tui_effect.inc`, `/tui_effects.inc`, `/tui_form.inc`, `/tui_geometry.inc`
- `/tui_gridguts.inc`, `/tui_label.inc`, `/tui_lines.inc`, `/tui_lock.inc`, `/tui_matrix.inc`
- `/tui_newsticker.inc`, `/tui_object.inc`, `/tui_panel.inc`, `/tui_png.inc`, `/tui_progressbar.inc`
- `/tui_progressbox.inc`, `/tui_render.inc`, `/tui_simpleauth.inc`, `/tui_spacers.inc`, `/tui_spinner.inc`
- `/tui_splash.inc`, `/tui_ssh.inc`, `/tui_statusbar.inc`, `/tui_terminal.inc`, `/tui_text.inc`
- `/tui_textbox.inc`, `/tui_typist.inc`

*Data Structures* — destined for `/ds/README.md`'s `## Key Components` table:
- `/list.inc`
- `/maps.inc`
- `/heap.inc`
- `/buffer.inc`
- `/json.inc`
- `/mapped.inc`
- `/mappedheap.inc`
- `/privmapped.inc`

*Other library files catalogued during inventory* (routed to the appropriate subsystem or called out in the root README):
- `/string16.inc`, `/string32.inc`, `/string_math.inc` (UTF-16/UTF-32/string math — routed to data structures discussion)
- `/unicodecase.inc` (Unicode case handling)
- `/png.inc` (PNG image codec — standalone; mentioned in relevant tool READMEs)
- `/zlib_deflate.inc`, `/zlib_inflate.inc` (compression — routed to net/data-structures as appropriate)
- `/file.inc`, `/dir.inc`, `/date.inc`, `/sleeps.inc`, `/blacklist.inc` (utility primitives — referenced in root README)
- `/syscall.inc`, `/sysinfo.inc`, `/syslog.inc`, `/vdso.inc` (system-interface primitives — referenced in `/docs/architecture.md`)
- `/call.inc`, `/breakpoint.inc`, `/profiler.inc`, `/rdtsc.inc` (debugging/profiling — referenced in `/docs/contributing.md`)
- `/math.inc`, `/formatter.inc`, `/io.inc`, `/align_macros.inc`, `/dataseg_macros.inc`, `/memfuncs.inc` (library primitives — referenced across READMEs as needed)

**Application Entry-Point `.asm` Files**:

- `/examples/echo/echo.asm` — `read_file` (complete); confirmed `subsystem$function` label pattern, include-order usage
- `/examples/hello_world/hello_world.asm` — `read_file` (complete); confirmed three-file include contract in practice
- `/dhtool/dhtool.asm` — inspected for build-line documentation
- `/rwasa/rwasa.asm`, `/rwasa/rwasa_tlsmin.asm` — inspected for rwasa architecture
- `/sshtalk/sshtalk.asm` — inspected for sshtalk architecture
- `/toplip/toplip.asm` — inspected for toplip architecture
- `/webslap/webslap.asm`, `/webslap/webslap_tlsmin.asm` — inspected for webslap architecture

**Tool-local `.inc` Files** (supporting the tool READMEs):

- `/dhtool/dhtool_settings.inc`
- `/rwasa/arguments.inc`, `/rwasa/master.inc`, `/rwasa/worker.inc`, `/rwasa/tlsmin_defaults.inc`
- `/sshtalk/chatpanel.inc`, `/sshtalk/chatroom.inc`, `/sshtalk/screen.inc`, `/sshtalk/statusbar.inc`, `/sshtalk/userdb.inc`
- `/webslap/globals.inc`, `/webslap/master.inc`, `/webslap/master_ui.inc`, `/webslap/worker.inc`, `/webslap/tlsmin_defaults.inc`

### 0.11.3 Pre-Existing Documentation and Historical Artifacts Inspected

| File Path | Size | Disposition | Role in Plan |
|---|---|---|---|
| `/README.md` | 13 bytes | UPDATE (the single UPDATE target in this pass) | Replaced with full 9-section root README |
| `/README` | 126 bytes | Preserved byte-for-byte | Plain-text pointer to `https://2ton.com.au/HeavyThing/`; linked from new `/README.md` as historical artifact |
| `/ChangeLog` | 378 lines | Preserved byte-for-byte | Historical release record, newest entry v1.13 (July 16, 2015); referenced but not modified |
| `/LICENSE` | (GPLv3 full text) | Preserved byte-for-byte | License reference from `/README.md` and `/docs/contributing.md` |
| `/2ton.png` | (binary image) | Preserved byte-for-byte | Not referenced in new documentation |
| `/rwasa/README.rwasa_tlsmin` | 292 bytes | Preserved byte-for-byte | Linked from new `/rwasa/README.md` |

### 0.11.4 Tech Specification Sections Retrieved

The following sections were retrieved via `get_tech_spec_section` and provided cross-cutting context for this plan:

| Section Heading | Key Context Extracted |
|---|---|
| `1.1 Executive Summary` | Repository scale: 106 core `.inc` files, 7 showcase applications, 14 examples; pure x86_64 assembly; zero libc |
| `1.2 System Overview` | Five-tier architecture model (System Interface → Core → Framework → Protocol → Application); rwasa positioning |
| `1.4 Document Conventions and Technical Context` | 246 total files in the repository; v1.24 (October 2018) per spec; exit codes 96–99 documented at spec level |
| `3.1 Technology Stack Overview` | Zero external dependencies; 106 `.inc` architecture; FASM + GNU `ld` + optional GCC/G++ toolchain |
| `3.2 Programming Languages` | x86_64 assembly primary; C (`-nostdlib`) and C++ (`extern "C"`) integration-only posture |
| `3.3 Frameworks and Libraries` | FASM by Tomasz Grysztar; conditional compilation via `if used`; library module categories |
| `3.8 Development and Deployment` | `fasm -m 524288` canonical invocation; GNU `ld` static link; no CI/CD; no containers; ELF64 output |
| `5.1 High-Level Architecture` | Layered event-driven monolithic library; zero-copy IO chaining; AVL tree timers |

### 0.11.5 Shell Commands and Grep Patterns Executed for Verification

| Command / Pattern | Purpose |
|---|---|
| `find / -name ".blitzyignore" 2>/dev/null \| head -20` | Confirm no `.blitzyignore` files present |
| `find / -maxdepth 6 -type f \( -name "*.inc" -o -name "*.asm" \) 2>/dev/null \| grep -v "/app/\|/proc/\|/sys/\|/usr/" \| head -50` | Locate repository root at `/tmp/blitzy/Blitzy-HeavyThing/master_fc613b/` |
| `ls -la /tmp/blitzy/Blitzy-HeavyThing/master_fc613b/` | Establish root-level file inventory |
| `ls /tmp/blitzy/Blitzy-HeavyThing/master_fc613b/ \| wc -l` (and `ls *.inc \| wc -l`) | Confirm 106 `.inc` files at root |
| `ls /tmp/blitzy/Blitzy-HeavyThing/master_fc613b/examples/` | Confirm 14 example subdirectories |
| `ls /tmp/blitzy/Blitzy-HeavyThing/master_fc613b/{dhtool,rwasa,sshtalk,toplip,webslap,hnwatch,util}/` | Confirm all 7 application-directory contents |
| `wc -l ChangeLog` | Confirm ChangeLog length (378 lines) |
| `ls -la README README.md` | Confirm pre-existing README sizes (126 bytes, 13 bytes) |
| `grep -n "fasm" ht_defaults.inc` | Confirm FASM-not-NASM reality |
| `grep -n "format ELF64" ht_defaults.inc` | Confirm FASM syntax (`format ELF64` rather than NASM's directive form) |
| `sed -n '38,42p' ht.inc` | Extract exit codes 96–99 source of truth |
| `sed -n '22,80p' epoll.inc` | Extract IO chaining model documentation |

### 0.11.6 User-Provided Attachments

**Attachments provided**: None. The user did not provide any file attachments, nor any files in `/tmp/environments_files`, nor any environment-variable secrets, nor any referenced external files beyond the narrative documentation plan itself.

### 0.11.7 Figma Screens / Design System Inputs

**Figma URLs provided**: None. This is an assembly-language library documentation task with no user-interface design deliverables; no Figma frames, screens, or design-token catalogs were supplied.

**Design System Compliance sub-section**: Not applicable — no component library, design system, or UI framework is in scope for this documentation task. The only UI-adjacent subsystem in the repository is the TUI (terminal UI) framework, which has no external design system to align with; it is documented on its own terms in `/tui/README.md` per the user plan.

### 0.11.8 External URLs Referenced (Out of Scope for Authoring)

| URL | Disposition |
|---|---|
| `https://2ton.com.au/HeavyThing/` | Author's upstream project page — **out of scope per user plan**. Mentioned at most once in new `/README.md` as the original upstream home. Not fetched, not mirrored, not summarized |
| (Mermaid documentation, GitHub Markdown documentation, FASM documentation) | Not directly fetched for this plan; these are standard, well-known conventions used in the documentation output, not sources requiring inspection |

### 0.11.9 User-Provided Narrative Plan (Primary Input)

The user-provided narrative plan titled "HeavyThing Documentation Plan" contains the following authoritative components, each of which is preserved verbatim in the relevant sub-section of this Agent Action Plan:

- **MODULE-LEVEL DOCUMENTATION** — Which modules require README documentation (11-row table); What information each module README should include; Format (9-section template); Additional documents (5-row table)
- **DIAGRAMS** — Which diagrams to create (7-row table); Diagram format standards (Mermaid fencing, actual-label node names, embedding, 30-node limit)
- **SYSTEM BOUNDARIES** — Focus areas; Exclusions (ChangeLog, LICENSE, binary output, external URL, third-party code)
- **MINIMAL CHANGE CLAUSE** — Full paragraph preserved verbatim in Section 0.10.1

This narrative plan is the single primary input; all other references in this Agent Action Plan are supporting context that corroborates or operationalizes the user plan.


