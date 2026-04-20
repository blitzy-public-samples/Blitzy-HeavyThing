# dhtool

Diffie-Hellman safe-prime parameter generator, verifier, and PEM-to-SSH-moduli converter implemented in pure x86_64 assembly on top of HeavyThing's `bigint` and RNG subsystems.

## Overview

`dhtool` operates in three modes driven by argument parsing in `_start`: **generation** (last argument is numeric bit-size), **verification** (last argument is a filename), and **conversion** (`-convert filename` reformats a PEM file into an `/etc/ssh/moduli`-compatible line) (Source: `/dhtool/dhtool.asm:22-53`). Generation uses a fork-based worker pool — one child per CPU core by default — communicating with a parent `epoll`-driven coordinator through `AF_UNIX` socketpairs; the first child to find a safe prime wins and the parent sends `SIGTERM` to the remaining workers (Source: `/dhtool/dhtool.asm:200-244`). Safe primes are verified with 192 Miller-Rabin rounds for both the prime `p` and its Sophie-Germain counterpart `q = (p - 1) / 2`, and the generator `g` is chosen as a quadratic residue mod `p` with order `q` (Wei Dai's preference) (Source: `/dhtool/dhtool.asm:58-60, :62-76`). PEM output is written to `stderr`; `stdout` receives progress markers (`' '` for each sieve candidate, `'.'` for trial-division passes, `'+'` for probable-prime `q`, `'$'` for probable-prime `p`), which lets callers redirect `stdout` to `/dev/null` without losing the generated parameters (Source: `/dhtool/dhtool.asm:37-43`).

## Architecture Fit

### Dependencies In

- [`./dhtool_settings.inc`](./dhtool_settings.inc) — first include; sets FASM `format ELF64` and all compile-time knobs. It is essentially a copy of `../ht_defaults.inc` with a small number of tool-specific overrides (notably `base64_maxline = 64` for standard PEM line width) (Source: `/dhtool/dhtool.asm:83`; `/dhtool/dhtool_settings.inc:22-27`).
- [`../ht.inc`](../ht.inc) — HeavyThing runtime core; transitively pulls `rng.inc`, `bigint.inc`, `epoll.inc`, `list.inc`, `heap.inc`, `file.inc`, `buffer.inc`, `formatter.inc`, and all other library modules required at link time (Source: `/dhtool/dhtool.asm:84`).
- [`../ht_data.inc`](../ht_data.inc) — final include; provides `bigint$one`, `bigint$two`, and other canonical read-only data required by `bigint$subtract`, `bigint$assign`, and similar calls (Source: `/dhtool/dhtool.asm:1097`).

### Dependencies Out

None. `dhtool` produces a standalone static ELF64 binary with no runtime library dependencies and no shared-object links.

The labels directly called by `dhtool` (not the transitive set) are: `ht$init` for library bootstrap (Source: `/dhtool/dhtool.asm:128`); `list$new`, `list$push_back`, `list$pop_back`, and `list$clear` for child-PID tracking and argv handling (Source: `/dhtool/dhtool.asm:99, :133, :137, :157, :226, :618`); `string$isnumber`, `string$to_unsigned`, `string$substr`, `string$indexof_charcode`, `string$substring`, `string$split`, `string$equals`, `string$hexdecode`, `string$from_bintobase64`, `string$from_bintohex`, `string$from_unsigned`, `string$to_stdout`, `string$to_stderr`, `string$to_stdoutln`, `string$to_stderrln`, `string$to_upper_inplace`, and `string$replace` for argument parsing and PEM/moduli I/O (Source: `/dhtool/dhtool.asm` — throughout); `sysinfo$cpucount` for core detection (Source: `/dhtool/dhtool.asm:182, :189`); `epoll$new`, `epoll$established`, `epoll$run`, `epoll$destroy`, `epoll$clone`, and `epoll$send` for the parent-side event loop (Source: `/dhtool/dhtool.asm:117, :236, :239, :244`); `io$connected`, `io$error`, and `io$timeout` in the parent's `io` virtual-table (Source: `/dhtool/dhtool.asm:117`); `rng$init` for per-child RNG re-seed after `fork()` (Source: `/dhtool/dhtool.asm:264`); `bigint$new`, `bigint$dh_params`, `bigint$new_encoded`, `bigint$ssh_encode`, `bigint$bytecount`, `bigint$bitcount`, `bigint$new_copy`, `bigint$subtract`, `bigint$shr`, `bigint$assign`, `bigint$verifyprime`, `bigint$jacobi`, `bigint$add`, `bigint$modword`, `bigint$debug`, `bigint$destroy`, and `bigint$encode` for the core arithmetic (Source: `/dhtool/dhtool.asm` — throughout `.inchild` and `.dh_verify`); `monty$new` and `monty$doit` for Montgomery exponentiation during subgroup-order checks (Source: `/dhtool/dhtool.asm:915, :922, :953, :960`); `heap$free`, `buffer$new`, `buffer$destroy`, `buffer$append_base64decode`, `buffer$has_more_lines`, `buffer$nextline`, `file$mtime`, `file$to_buffer`, and `file$to_string` for file I/O and buffer management (Source: `/dhtool/dhtool.asm` — `.maybeverify` and `.maybesshmoduli` paths); `formatter$new`, `formatter$add_datetime`, `formatter$add_unsigned`, `formatter$add_string`, `formatter$doit`, and `formatter$destroy` for composing SSH-moduli lines in `.convert` mode (Source: `/dhtool/dhtool.asm:758-815`); and the macros `timestamp`, `asn1_tag`, `memcpy`, and `sleep` (Source: `/dhtool/dhtool.asm:313, :340, :749, :802`).

`dhtool` does not directly include `epoll_child.inc`, `dh_pool*.inc`, or `dh_groups.inc`; those are pulled in transitively by `ht.inc` but their labels are not referenced by this tool (Source: `/dhtool/dhtool.asm` — verified: no direct calls to `dh_pool$*`, `dh$pool`, or `epoll_child$*`).

## Key Components

| File | Purpose |
|------|---------|
| [`./dhtool.asm`](./dhtool.asm) | Complete program (1097 lines): `_start`, argument dispatch, worker fork/socketpair orchestration, PEM and SSH moduli I/O, DH verification, and `-convert` mode (Source: `/dhtool/dhtool.asm:1-1097`). |
| [`./dhtool_settings.inc`](./dhtool_settings.inc) | Compile-time configuration: a copy of `../ht_defaults.inc` with `base64_maxline = 64` for standard PEM line width and a handful of other tool-specific knobs (Source: `/dhtool/dhtool_settings.inc:22-23, :115`). |

The compiled binary `./dhtool` and object file `./dhtool.o` (if present) are build artefacts and are not source material; they are preserved byte-for-byte by this documentation pass.

## CLI Reference

The in-binary usage string, emitted verbatim on invalid invocation (Source: `/dhtool/dhtool.asm:394-400`):

```text
Usage:
To create a new DH parameter file (similar to openssl dhparam):
./dhtool [-XX] SIZE
Where SIZE is size in bits of the safe prime you want, XX specifies how many cores to use

To verify an existing dhparam file, -or- an OpenSSH moduli file:
./dhtool filename

To convert an existing dhparam file to an OpenSSH moduli compatible line:
./dhtool -convert filename
```

### Generate mode

Invocation: `./dhtool [-CPUCOUNT] SIZE`

- `SIZE` is an unsigned integer giving the requested safe-prime bit size. Minimum: `1536` (below this the tool aborts with the "too small" diagnostic). Maximum: `insane_primesize = 131072` (above this the tool aborts with the "insane" diagnostic). Bounds are validated in `_start` (Source: `/dhtool/dhtool.asm:86, :150-153`).
- `-CPUCOUNT` is an optional leading argument where `CPUCOUNT` is an unsigned integer giving the worker-pool size. If absent, the pool size is `sysinfo$cpucount` clamped to `[1, 16384]` (Source: `/dhtool/dhtool.asm:155-198`).
- If `CPUCOUNT` exceeds the detected core count the tool exits with the diagnostic "You requested more CPUs than we have available." (Source: `/dhtool/dhtool.asm:403-413`).
- Output: PKCS#3 DH parameters in PEM format written to `stderr`; progress markers on `stdout` (Source: `/dhtool/dhtool.asm:30-35, :309-338`).
- PEM preface: `-----BEGIN DH PARAMETERS-----`; postface: `-----END DH PARAMETERS-----` (Source: `/dhtool/dhtool.asm:347-351`).

```bash
# Generate a 2048-bit safe prime using all detected cores;
# PEM goes to stderr, progress markers to stdout (redirect stdout
# to /dev/null for scripts).
./dhtool 2048 > /dev/null 2> dh2048.pem

# Generate a 4096-bit prime using exactly 8 cores.
./dhtool -8 4096 > /dev/null 2> dh4096.pem
```

### Verify mode

Invocation: `./dhtool filename`

- The file format is auto-detected: if the first matching line contains `-----BEGIN DH PARAMETERS-----`, the body is parsed as PEM (Source: `/dhtool/dhtool.asm:631-725`); otherwise each line is parsed as an `/etc/ssh/moduli`-format record (Source: `/dhtool/dhtool.asm:473-621`).
- PEM flow: the base64 body is decoded with `buffer$append_base64decode`, and the enclosing ASN.1/DER `SEQUENCE` of `INTEGER p` and `INTEGER g` is walked via the internal `.gettag` routine (which wraps the `asn1_tag` macro) (Source: `/dhtool/dhtool.asm:670-712, :748-750`).
- Each extracted `(p, g)` pair is passed to the internal `.dh_verify` routine, which reports:
  - `bigint$verifyprime(p)` — "Ridiculous p verification (MR=192)..." (Source: `/dhtool/dhtool.asm:877-886, :1079`).
  - `bigint$verifyprime((p - 1) / 2)` — "Ridiculous Sophie Germain counterpart verification (MR=192)..." (Source: `/dhtool/dhtool.asm:888-907, :1080`).
  - Subgroup order `q`: `g^q mod p ?= 1` via `monty$new` + `monty$doit` (Source: `/dhtool/dhtool.asm:909-930, :1081`).
  - Subgroup order `2q`: `g^(2q) mod p ?= 1` (Source: `/dhtool/dhtool.asm:932-968, :1082`).
  - Jacobi symbol of `g` mod `p` via `bigint$jacobi` — expected to be `1` for a QR (Source: `/dhtool/dhtool.asm:973-984, :1083`).
  - Modulus diagnostics: `p % 8`, `p % 7`, `p % 12`, `p % 24` via `bigint$modword` (Source: `/dhtool/dhtool.asm:1015-1071, :1091-1094`).
- SSH moduli flow: each line is split on spaces, expected to have exactly 7 fields (timestamp, type, tests, tries, size, generator, hex-encoded prime); the hex field is decoded to a `bigint` via `string$hexdecode` + `bigint$new_encoded`, and the declared size is compared to `bigint$bitcount` before delegating to `.dh_verify` (Source: `/dhtool/dhtool.asm:486-609`).

### Convert mode

Invocation: `./dhtool -convert filename`

- The file is parsed via the same PEM path as Verify mode; after extracting `(p, g)` the tool formats a single SSH-moduli line and writes it to `stdout` (Source: `/dhtool/dhtool.asm:725, :751-854`).
- Output fields, in order: timestamp (`YYYYMMDDHHMMSS`, stripped of `-`, `T`, `:`, and `Z` via repeated `string$replace`), type `2`, tests `6`, tries `192`, size (`bigint$bitcount(p) - 1`), generator (the low-word of `g`), and uppercased hex of the prime `p` (Source: `/dhtool/dhtool.asm:762-812, :816-845`).

## Usage

`dhtool.asm` is the canonical example of the three-file include contract **with a project-specific settings file**: instead of `ht_defaults.inc`, `dhtool` substitutes `dhtool_settings.inc`, which sets FASM's `format ELF64` and overrides `base64_maxline` to the standard PEM width of 64 characters (Source: `/dhtool/dhtool.asm:83-84, :1097`; `/dhtool/dhtool_settings.inc:22-27, :115`). The actual assembler is FASM; the `nasm` language tag below is used solely for GitHub's Intel-syntax highlighter — see [`../docs/building.md`](../docs/building.md) for the full reconciliation.

```nasm
; dhtool.asm -- the three-file include contract with a tool-specific settings file
include 'dhtool_settings.inc'   ; replaces ht_defaults.inc; first include, sets FASM format ELF64
include '../ht.inc'             ; HeavyThing runtime core

; ... your code here ...

include '../ht_data.inc'        ; final include, provides bigint$one, bigint$two, etc.
```

Build:

```bash
fasm -m 524288 dhtool.asm && ld -o dhtool dhtool.o
```

See [`../docs/building.md`](../docs/building.md) for the full build flow, FASM version notes, and troubleshooting.

End-to-end example — build, generate, verify, and convert:

```bash
# 1. Build the tool.
fasm -m 524288 dhtool.asm && ld -o dhtool dhtool.o

# 2. Generate 2048-bit DH parameters (PEM on stderr, progress on stdout).
./dhtool 2048 > /dev/null 2> dh2048.pem

# 3. Verify the parameters we just generated.
./dhtool dh2048.pem

# 4. Convert to OpenSSH /etc/ssh/moduli format.
./dhtool -convert dh2048.pem >> moduli
```

Invoking with no arguments, or with a zero-valued `SIZE`, triggers the usage string and `exit(1)` (Source: `/dhtool/dhtool.asm:130-131, :148-149, :383-401`).

## Configuration

`dhtool_settings.inc` is a copy of `../ht_defaults.inc` with one essential override — `base64_maxline = 64`, matching the standard PEM line width used by `openssl dhparam`. The full set of knobs that materially affect `dhtool`'s behaviour is listed below.

| Knob | Default | Effect | Source |
|------|---------|--------|--------|
| `base64_maxline` | `64` | PEM base64 line width for `string$from_bintobase64`. Standard PEM expects 64; the library-wide default differs. | `/dhtool/dhtool_settings.inc:115` |
| `base64_linebreaks` | `1` | Enable line-breaks in base64 output (required for standard PEM). | `/dhtool/dhtool_settings.inc:114` |
| `insane_primesize` | `131072` | Hard upper limit on the requested safe-prime bit size. Defined in `dhtool.asm`, not the settings file. | `/dhtool/dhtool.asm:86` |
| `bigint_maxwords` | `512` | Maximum 64-bit limbs per `bigint` (`512 words x 64 bits = 32768-bit ceiling`, well above `insane_primesize`). | `/dhtool/dhtool_settings.inc:263` |
| `bigint_unrollsize` | `16` | Unrolled squaring/multiplication width; raising inflates the binary. | `/dhtool/dhtool_settings.inc:269` |
| `millerrabinerrorrate` | `64` | Default Miller-Rabin error rate (target `2^-64`). Overridden at the safe-prime call sites, where the tool hard-codes 192 rounds and reports "MR=192" in verifier output. | `/dhtool/dhtool_settings.inc:273`; `/dhtool/dhtool.asm:807, :1079-1080` |
| `dh_bits` | `2048` | Library-wide default DH size. The commented alternative `dh_bits = 4096` is available. | `/dhtool/dhtool_settings.inc:281-282` |
| `dh_privatekey_size` | `256` | DH private-exponent size in bits (NIST 224 for a 2048-bit group plus margin). Not used directly by `dhtool` — parameter generation only — but declared for library consistency. | `/dhtool/dhtool_settings.inc:293-294` |
| `rng_heavy_init` | `1` | When `1`, `rng$init` seeds from `/dev/urandom` plus `rdtsc` plus `gettimeofday`; when `0`, `rdtsc`-only. Each forked child re-calls `rng$init` so identical seeds are avoided. | `/dhtool/dhtool_settings.inc:95`; `/dhtool/dhtool.asm:264` |
| `rng_paranoid` | `0` | When `1`, the heavy-init source switches from `/dev/urandom` to `/dev/random` (may block). | `/dhtool/dhtool_settings.inc:99` |
| `string_bits` | `32` | Native string encoding is UTF-32. Required by TUI components elsewhere; unused by `dhtool` itself. | `/dhtool/dhtool_settings.inc:104` |
| `framepointers` | `1` | Emit frame pointers for `gdb` compatibility. | `/dhtool/dhtool_settings.inc:57` |
| `public_funcs` | `1` | Emit ELF symbol entries for library labels (helpful when debugging with `gdb` or `objdump`). | `/dhtool/dhtool_settings.inc:60` |

The minimum safe-prime size (`1536` bits) is hard-coded in `dhtool.asm` at line 152 and is not a configurable knob. To change either the 1536 floor or the `insane_primesize` ceiling, edit `dhtool.asm` directly — the error messages say so explicitly (Source: `/dhtool/dhtool.asm:413, :427, :441`).

## Limitations

- **Linux x86_64 only.** The tool uses `syscall_socketpair`, `syscall_fork`, `syscall_kill`, and other Linux-specific syscalls via `ht.inc`'s `syscall.inc` wrappers. It will not build or run on macOS, Windows, BSD, or any non-x86_64 architecture (Source: `/dhtool/dhtool.asm:207-218`).
- **Generator choice differs from OpenSSL/OpenSSH.** `dhtool` follows Wei Dai's preference — generator `g` of order `q` and a quadratic residue mod `p` — rather than OpenSSL/OpenSSH's order-`2q` convention. Consequently, `openssl dhparam -check` will report the generators as "bad" even though they are cryptographically valid under the chosen convention (Source: `/dhtool/dhtool.asm:62-79`).
- **PEM output goes to `stderr`, not `stdout`.** `stdout` carries progress markers. Any script capturing `dhtool`'s output must redirect `2>` to save the PEM; this is intentional so automated jobs can send `stdout` to `/dev/null` (Source: `/dhtool/dhtool.asm:30-35, :309-338`).
- **Multi-process model: first child wins.** The parent does not merge or cross-validate results from multiple workers. As soon as any child sends a PEM blob over its socketpair, the parent writes it to `stderr` and `SIGTERM`s all tracked children (Source: `/dhtool/dhtool.asm:91-113, :224-244`).
- **Size is clamped.** Requested sizes below `1536` are rejected as insecure; sizes above `insane_primesize = 131072` are rejected as insane. The "MR=192" label in verifier output is independent of the `millerrabinerrorrate = 64` library setting and is used at every safe-prime call site (Source: `/dhtool/dhtool.asm:86, :150-153`).
- **No ECDH, no RSA keygen, no DSA keygen.** This tool generates and verifies DH parameters (safe prime `p` plus generator `g`) only. Elliptic-curve Diffie-Hellman and other asymmetric primitives are not provided; see [`../docs/security.md`](../docs/security.md) for the full list of what HeavyThing does and does not implement cryptographically.
- **RNG posture.** Parameter-generation quality depends on `rng_heavy_init = 1` plus a forked-child re-seed of `rng$init`. With `rng_paranoid = 0` (default) the initial 32-byte seed comes from `/dev/urandom`; with `rng_paranoid = 1`, from `/dev/random`. Cryptographic keying should still use `hmac_drbg` rather than the raw `rng` — see [`../crypto/README.md`](../crypto/README.md) and [`../docs/security.md`](../docs/security.md) (Source: `/dhtool/dhtool_settings.inc:94-99`; `/dhtool/dhtool.asm:264`).
- **Exit codes are coarse.** All tool-level error paths (`.forkdeath`, `.socketpairdeath`, `.cputoomany`, `.yourenuts`, `.toosmall`, `.noinput`, `.error`) exit with status `1` after writing a single-line diagnostic to `stderr`. There is no machine-readable error taxonomy. Library-level failures (exit codes 96, 97, 98, 99) are documented in [`../docs/calling-convention.md`](../docs/calling-convention.md) and [`../docs/architecture.md`](../docs/architecture.md).
- **No retry on `.dh_verify` failure.** `.dh_verify` reports verification outcomes ("Good."/"Bad."/"Yes."/"No.") to `stdout` but does not abort the program with a distinct exit code on "Bad" — the caller must parse the output text to detect failures (Source: `/dhtool/dhtool.asm:882-886, :1086-1089`).
- **`.convert` mode declared size is `bitcount - 1`.** The SSH moduli `size` field is one less than `bigint$bitcount(p)`, matching the OpenSSH convention that `size` reflects the bit length of `(p - 1) / 2` (Source: `/dhtool/dhtool.asm:800-809`).
- **Embedded banner is v1.12.** The `.banner` cleartext string predates the `ChangeLog`'s last entry (v1.13). Newer version numbers mentioned elsewhere in the repository do not apply to this tool's embedded banner (Source: `/dhtool/dhtool.asm:352`).

Full cryptographic primitive scope, side-channel posture, and operational guidance: [`../docs/security.md`](../docs/security.md).

## See Also

- Project overview: [`../README.md`](../README.md)
- Cryptography subsystem (`bigint`, RNG, HMAC-DRBG): [`../crypto/README.md`](../crypto/README.md)
- Networking subsystem — DH parameters are consumed by TLS and SSH KEX: [`../net/README.md`](../net/README.md)
- Library architecture and include graph: [`../docs/architecture.md`](../docs/architecture.md)
- Build instructions (FASM version, `fasm -m 524288`, linker): [`../docs/building.md`](../docs/building.md)
- Library-wide register, stack, and label conventions: [`../docs/calling-convention.md`](../docs/calling-convention.md)
- Security posture, RNG disclosure, cipher-suite matrix: [`../docs/security.md`](../docs/security.md)
- How to add a module and wire it into `ht.inc`: [`../docs/contributing.md`](../docs/contributing.md)

---

Licensed under GPLv3. See [`../LICENSE`](../LICENSE).
