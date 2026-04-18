# dhtool

A Diffie-Hellman parameter generation, verification, and conversion utility that showcases the HeavyThing library's big-integer, primality-testing, multi-process, and RNG subsystems.

## Overview

`dhtool` is a command-line utility that operates in one of three modes: **create** a new Diffie-Hellman safe-prime parameter file using many CPU cores, **verify** an existing dhparam PEM file or OpenSSH `/etc/ssh/moduli` file with roughly 192 Miller-Rabin iterations per prime, or **convert** a dhparam PEM to an OpenSSH moduli-compatible line (Source: `dhtool/dhtool.asm:22-50`). It is both an independently useful tool and a showcase of how to wire the HeavyThing library's `bigint.inc`, `rng.inc`, `dh_groups.inc` and multi-process primitives together on Linux x86_64.

Create-mode writes the PEM output to `stderr`; `stdout` is simultaneously streamed with progress indicator characters so the operator can see work is progressing during the long sieve (Source: `dhtool/dhtool.asm:30-43`). Redirecting `stdout` to `/dev/null` therefore does not suppress the PEM result.

## Architecture Fit

`dhtool` consumes HeavyThing as a library via the standard three-file include contract (`ht_defaults.inc` -> `ht.inc` -> `ht_data.inc`). The build unit is a single assembly file plus a tool-local settings file that overrides two knobs from the library defaults.

Dependencies in (HeavyThing subsystems `dhtool` relies on):

| Subsystem | Role in `dhtool` |
|---|---|
| [`../bigint.inc`](../bigint.inc) | Arbitrary-precision integer arithmetic for safe-prime search, Miller-Rabin rounds, generator selection, PKCS#3 DER encoding (`bigint$ssh_encode`) |
| [`../rng.inc`](../rng.inc) | HMAC-DRBG-backed random-number generator used for candidate seeding (must be reseeded post-`fork` in each child) |
| [`../dh_groups.inc`](../dh_groups.inc) | Reference group/modulus helpers shared with the library's TLS and SSH paths |
| [`../base64_latin1.inc`](../base64_latin1.inc) | Base64 encoding for the PEM body, with line width set via `base64_maxline` in `dhtool_settings.inc` |
| [`../epoll.inc`](../epoll.inc) | Parent-process event loop that multiplexes progress traffic from each child over an `AF_UNIX` socketpair |
| [`../heap.inc`](../heap.inc), [`../string16.inc`](../string16.inc), [`../buffer.inc`](../buffer.inc), [`../io.inc`](../io.inc) | Memory, string, buffer, and IO primitives that the parent and children both rely on |
| [`../syscall.inc`](../syscall.inc), [`../profiler.inc`](../profiler.inc), [`../call.inc`](../call.inc) | Library-wide infrastructure used by every HeavyThing binary |

Dependents (who uses `dhtool`): no in-repository consumers. `dhtool` is a standalone operator utility. Its output can be fed to `rwasa` (as a `dhparam` PEM), to OpenSSH (as a `moduli` line), or to any other TLS/SSH stack that accepts PKCS#3 DH parameters.

## Key Components

| File | Purpose |
|---|---|
| [`dhtool.asm`](./dhtool.asm) | Entry point, CLI parsing, create/verify/convert mode dispatch, PEM emission, parent epoll loop, and child worker body (1097 lines) |
| [`dhtool_settings.inc`](./dhtool_settings.inc) | Tool-local compile-time settings: defines two overrides vs. `../ht_defaults.inc` and otherwise mirrors the library defaults |

### Internal Labels

The following anchor labels in `dhtool.asm` define `dhtool`'s runtime contract (Source: `dhtool/dhtool.asm`, enumerated by line):

| Label | Line | Purpose |
|---|---|---|
| `parent_receive` | 91 | Epoll callback invoked on each progress message arriving from a child worker |
| `parent_vtable` | 116 | IO virtual method table binding `parent_receive` as the parent-side read handler |
| `_start` | 127 | Program entry; parses argv, decides create/verify/convert mode, forks workers in create mode |
| `.banner` | 352 | Static banner text emitted once at startup: version, author, commercial-support note, homepage |
| `.usage` | 384 | Usage-message write-and-exit path |
| `.usagestr` | 394 | Literal usage text (reproduced below under CLI Reference) |
| `.maybeverify` | 631 | Dispatch to verify-mode when argv is interpreted as a filename |
| `.convert` | 753 | Convert-mode body: reads a dhparam PEM, emits an OpenSSH moduli line |
| `.dh_verify` | 863 | Hardcore verification body: ~192 Miller-Rabin rounds per prime, applied to both `p` and `q` |

## Calling Convention

`dhtool` is a freestanding program, not a library; it is entered at `_start` by the Linux ELF loader with the standard x86_64 System V ABI for `_start` (argc in `[rsp]`, argv pointer array at `[rsp+8]`, envp array following a terminating null). See [`../docs/calling-convention.md`](../docs/calling-convention.md) for the HeavyThing library-wide register contract that every internal call inside `dhtool.asm` honours.

### CLI Reference

The canonical usage message is emitted verbatim from `.usagestr` (Source: `dhtool/dhtool.asm:394-403`):

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

Mode selection rules:

| Mode | Invocation Pattern | Notes |
|---|---|---|
| Create | `./dhtool [-XX] SIZE` | `SIZE` is the safe-prime bit-length; `-XX` is optional explicit core count. When omitted, `dhtool` uses every online CPU reported by `/proc/cpuinfo` (Source: `dhtool/dhtool.asm:188-198`). |
| Verify | `./dhtool filename` | Accepts either a PEM `dhparam` file or an OpenSSH `moduli` file; verifies every parameter present (Source: `dhtool/dhtool.asm:25-28`). |
| Convert | `./dhtool -convert filename` | Reads a dhparam PEM and prints a single OpenSSH-compatible moduli line to `stdout`. |

Size bounds (Source: `dhtool/dhtool.asm:86,150-152`):

| Constant | Value | Enforcement |
|---|---|---|
| Minimum bits | `1536` | `_start` compares `SIZE` against 1536 and rejects smaller values |
| Maximum bits | `insane_primesize = 131072` | `_start` compares `SIZE` against 131072 and rejects larger values |
| Maximum CPU count | `16384` | `_start` caps `-XX` at 16384; values higher than this are rejected |

Output streams in create mode (Source: `dhtool/dhtool.asm:30-43`):

| Stream | Content |
|---|---|
| `stderr` (fd 2) | PEM preface `-----BEGIN DH PARAMETERS-----`, base64 body, postface `-----END DH PARAMETERS-----`; plus usage and error text |
| `stdout` (fd 1) | Progress characters: space for each sieve candidate, `.` for each `q` that passed trial division, `+` for each `q` probably prime, `$` for each `p` probably prime (verification then begins) |

Progress-character legend for operators watching a long create run:

| Char | Meaning |
|---|---|
| ` ` (space) | A fresh sieve candidate was generated but did not pass early rejection |
| `.` | Candidate `q` survived trial division by small primes |
| `+` | `q` is probably prime (passed the Miller-Rabin rounds on `q`) |
| `$` | `p = 2q + 1` is probably prime; hardcore verification (~192 Miller-Rabin iterations each for `p` and `q`) is starting |

## Usage

The minimum-viable consumer is the tool itself. Build and run:

```bash
# Build.
fasm -m 524288 dhtool.asm && ld -o dhtool dhtool.o

# Generate a 2048-bit DH parameter file using all cores, save PEM to params.pem.
./dhtool 2048 2>params.pem

# Generate a 4096-bit parameter file using 8 cores, keep visual progress.
./dhtool -8 4096 2>params.pem

# Verify an existing PEM or OpenSSH moduli file (hardcore ~192-round Miller-Rabin).
./dhtool params.pem
./dhtool /etc/ssh/moduli

# Convert a dhparam PEM to a single OpenSSH moduli line.
./dhtool -convert params.pem >moduli.line
```

The program reuses the HeavyThing three-file include contract; the source opens with:

```nasm
include 'ht_defaults.inc'
include '../ht.inc'
include 'dhtool_settings.inc'
; ... body ...
include '../ht_data.inc'
```

See [`../docs/building.md`](../docs/building.md) for the library-wide build flow, including the `-m 524288` symbol-pool flag and the conditional-inclusion (`if used`) mechanism.

## Configuration

`dhtool/dhtool_settings.inc` is the tool-local compile-time configuration file. It overrides the library defaults in [`../ht_defaults.inc`](../ht_defaults.inc) in two places; every other constant simply mirrors the library default so that `dhtool` stays a single, self-contained translation unit.

| Knob | `dhtool_settings.inc` Value | Library Default | Rationale |
|---|---|---|---|
| `base64_maxline` | `64` (Source: `dhtool/dhtool_settings.inc:115`) | `76` (Source: `ht_defaults.inc:114`) | PEM body lines are 64 columns wide per PKCS and OpenSSL convention |
| `webclient_maxconns` | `6` (Source: `dhtool/dhtool_settings.inc:510`) | `4` (Source: `ht_defaults.inc:509`) | Header-slot count reserved per host; unused in `dhtool`'s current modes but kept for parity with other HeavyThing tools that embed the `webclient` stack |

Runtime behaviour is entirely CLI-driven; there are no environment variables, no config file, and no `/etc/dhtool` convention. The RNG is seeded at program start and is explicitly re-seeded inside each forked child so that worker processes do not produce identical candidate streams (Source: `dhtool/dhtool.asm`, post-`fork` path).

## Limitations

- **Linux x86_64 only.** Like every HeavyThing binary, `dhtool` uses Linux-specific syscalls (`epoll_create1`, `socketpair`, `fork`, `clone`) directly via the `syscall` instruction; it does not run on BSD, macOS, or Windows.
- **DH group 2 generator only.** `dhtool` selects a generator `g` that is a quadratic residue modulo `p` and is therefore of order exactly `q`, not `2q`. This differs from OpenSSL's and OpenSSH's typical output, where the generator can be `2` with order `2q`. The order-`q` choice is deliberate; see the design discussion at `dhtool/dhtool.asm:57-85` for citations to sci.crypt, `crypto.stackexchange` (poncho), and Wei Dai's Crypto++ wiki.
- **Primality confidence.** Verification uses ~192 Miller-Rabin rounds applied to both the safe prime `p` and its Sophie-Germain counterpart `q`. This gives a negligible probability of accepting a composite, but it is not a deterministic proof (e.g. AKS). Accept the parameters knowing that no probabilistic primality test offers certainty.
- **No resumable create mode.** A long-running `dhtool 8192` that is interrupted must start the sieve over. There is no checkpoint file.
- **Create mode writes PEM to `stderr`.** Consumers expecting PEM on `stdout` will need `2>outfile` (or shell redirection) to capture the parameter file. This is documented and intentional so that `stdout` remains available for progress characters.
- **No side-channel hardening is claimed for the primality-test code path.** `dhtool` operates on public DH parameters on a trusted host, so constant-time guarantees are not a stated goal. Do not repurpose this codebase as the sole test for secret primes.

## See Also

- [`../crypto/README.md`](../crypto/README.md) — HeavyThing cryptography subsystem: big-integer, HMAC-DRBG, AES, SHA, scrypt.
- [`../docs/security.md`](../docs/security.md) — TLS/SSH support matrix and operational guidance for DH parameters in production.
- [`../docs/architecture.md`](../docs/architecture.md) — Library-wide architecture: include dependency graph, event-loop lifecycle, subsystem boundaries.
- [`../docs/building.md`](../docs/building.md) — FASM invocation, linker flags, and compile-time configuration.
- [`../docs/calling-convention.md`](../docs/calling-convention.md) — Library-wide register contract and label-naming convention.
- [`../rwasa/README.md`](../rwasa/README.md) — Web server that consumes `dhtool`-produced PEM files via its TLS configuration.

---

Licensed under GPLv3. See [`../LICENSE`](../LICENSE).
