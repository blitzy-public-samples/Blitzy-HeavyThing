# HeavyThing Cryptographic Known-Answer-Test (KAT) Suite

This directory contains a self-contained **Known-Answer-Test (KAT)** suite for the
HeavyThing cryptographic stack. Primitives fall into two tiers, and the suite labels
every primitive explicitly:

- **Tier-1 — standards-body KATs.** The `expected_hex` values are published output
  from the IETF (RFC) or NIST (FIPS / CAVP / Special Publications), traceable
  byte-for-byte to the cited document. Tier-1 covers MD5, SHA-1, the SHA-2 family,
  HMAC-MD5 / HMAC-SHA-1 / HMAC-SHA-256, PBKDF2 over SHA-1 / SHA-256 / MD5, and AES.
- **Tier-2 — HeavyThing-specific regression vectors.** A subset of primitives cannot
  be matched byte-for-byte against a published vector *without modifying HeavyThing's
  read-only source* (forbidden by the scope rules), because the library bakes
  parameters in at compile time, fixes an HMAC block size, hardcodes a hash, or
  instantiates a standard *mode* over a non-standard cipher. These are validated as
  deterministic **regression / self-consistency / round-trip-identity** anchors whose
  `expected_hex` values are HeavyThing-actual outputs captured from the reference
  build — **not** published standards output. Tier-2 covers scrypt, HMAC-DRBG, htxts,
  HMAC-SHA-224 / SHA-384 / SHA-512 (and the PBKDF2 variants that inherit them),
  htcrypt, bigint, RSA, DSA, and the DH parameter pool.

The exact tier of every primitive is given in the [Tier-1 vs Tier-2
classification](#tier-1-vs-tier-2-classification) table, and the rationale for each
Tier-2 entry is in the [Tier-2 Regression Vectors](#tier-2-regression-vectors)
registry. The per-file JSON `source` field is the authoritative per-vector record.

Each primitive is exercised by a small, statically linked C11 harness binary that
calls HeavyThing's native assembly symbols directly; a Python 3
[pytest](https://docs.pytest.org/) runner invokes each harness once per vector and
asserts byte-exact hexadecimal equality on the binary's standard output.

The suite is **purely additive** and entirely greenfield: HeavyThing previously had
no formal tests, no test directory, no build automation for tests, and no continuous
integration. Nothing here changes that situation for the rest of the repository —
the suite lives wholly inside `tests/`.

## Scope and ground rules

These boundaries are **hard requirements**, not guidelines. They are enforced by the
design of the suite and must be preserved by anyone extending it.

- **Everything lives under `tests/`.** This suite **MUST NOT** create, modify, or
  delete any file outside the `tests/` directory. There is no top-level `Makefile`,
  no top-level `.gitignore` change, and no continuous-integration configuration.
- **The HeavyThing source tree is READ-ONLY REFERENCE material.** Every `.inc`
  source file, `ht.inc`, `ht_defaults.inc`, `ht_data.inc`, every showcase `.asm`
  program, and HeavyThing's manual two-step FASM build system are read for reference
  only. The FASM shim reads `../../ht.inc` and `../../ht_data.inc` via FASM's
  `include` directive but never alters their bytes. The local
  `harness/settings.inc` is a *copy* of `ht_defaults.inc`, not a replacement for it.
- **`falign`-prefixed public labels are public API.** Public crypto entry points
  such as `sha256$new` or `hmac$new_sha256` are the library's stable ABI. They are
  **never** renamed, wrapped, or moved. The harness calls them by their literal
  names — including the `$` character — exactly as `examples/hello_world_c1/hello.c`
  already does. The shim adds no new symbols and renames none.
- **This is KAT-only.** There is no fuzzing, no property-based testing, no
  integration or end-to-end testing, and **no mocking**. Cryptographic primitives
  are pure functions of their byte inputs, so mocking is neither necessary nor
  permitted. Network, TLS, SSH, HTTP, TUI, and event-loop code are all out of scope.

## How it works

The suite is a three-stage pipeline orchestrated by `tests/Makefile`. The FASM and
GCC stages build self-contained binaries; the pytest stage drives them.

### Stage 1 — Build the FASM shim

`harness/shim.asm` is a thin Flat Assembler source file that includes, in order, a
local `harness/settings.inc`, then `../../ht.inc`, then `../../ht_data.inc`. The
local `settings.inc` is a copy of the repository-root `ht_defaults.inc` whose single
meaningful change is that the line `include_everything = 1` is **uncommented**.
That one toggle bypasses HeavyThing's compile-time `if used` dead-code elimination,
so **every** crypto symbol — not just the ones a given program references — is
emitted into the resulting object file and made available to the C linkage stage.

The shim is assembled with:

```
fasm -m 524288 harness/shim.asm build/shim.o
```

The `-m 524288` flag raises FASM's assembly memory ceiling so the full library
(which transitively pulls in every cryptographic module via `ht.inc`) assembles
without exhausting the assembler's default working set.

### Stage 2 — Archive and compile the C harnesses

The shim object is packaged into a static archive, and each per-primitive C harness
is compiled and statically linked against it:

```
ar rcs build/libht.a build/shim.o
gcc -std=c11 -Wall -Wextra -O2 -nostdlib -static \
    -o build/bin/kat_<name> harness/kat_<name>.c harness/ht_kat_common.c build/libht.a
```

Every `harness/kat_*.c` driver is compiled together with the shared
`harness/ht_kat_common.c` helper and linked against `build/libht.a`. The result is
one self-contained, statically linked binary per primitive under `build/bin/`.

The `-nostdlib -static` combination is **mandatory**, not optional. HeavyThing
replaces the C standard library with its own syscall layer and memory subsystem;
mixing libc and HeavyThing's memory model causes crashes. The `-static` flag is also
required because modern GCC defaults to position-independent executables (`-pie`),
while HeavyThing's FASM-emitted objects use non-PIC (`R_X86_64_32S`) relocations —
a bare `gcc -nostdlib` link without `-static` (or `-no-pie`) fails to link.

### Stage 3 — Run the pytest runner

`pytest` discovers the test modules under `runner/test_*.py`. Each module loads its
primitive's JSON fixture(s) from `vectors/`, and uses `@pytest.mark.parametrize` to
fan out one pytest case per committed vector. For each case the runner invokes the
matching `build/bin/kat_*` binary as a subprocess
(`subprocess.run(..., capture_output=True, text=True)`) and asserts:

- the harness exited successfully (`returncode == 0`), and
- the harness output matches the expected value (`stdout.strip() == vector["expected_hex"]`).

For negative vectors marked `expect_mismatch: true` (tampered MACs, wrong keys), the
equality assertion is **inverted**: the genuine output must *not* equal the tampered
or wrong-key expected value.

### Directory map

```
tests/
├── Makefile            # build orchestration: FASM -> ar -> GCC; PHONY all/build/test/clean
├── conftest.py         # pytest fixtures: bin_dir, vectors_dir, autouse _require_build precheck
├── pytest.ini          # pytest config: testpaths = runner, addopts = -v --tb=short --maxfail=0
├── .gitignore          # excludes build/ artifacts from version control
├── README.md           # this document
├── harness/            # FASM shim + C11 KAT drivers
│   ├── settings.inc    # copy of ht_defaults.inc with include_everything = 1 uncommented
│   ├── shim.asm        # thin FASM shim: settings.inc + ../../ht.inc + ../../ht_data.inc
│   ├── ht_kat_common.h # shared C declarations + HeavyThing entry-point externs
│   ├── ht_kat_common.c # shared C helpers: init, hex decode/print, exit, _start stub
│   └── kat_*.c         # one KAT driver per primitive
├── runner/             # pytest package
│   ├── __init__.py
│   ├── _harness.py     # vector loader + subprocess wrapper + hex-equality helpers
│   └── test_*.py       # one parameterized pytest module per primitive
├── vectors/            # committed JSON KAT fixtures (one or more per primitive)
│   └── *.json
└── build/              # GENERATED, gitignored: shim.o, libht.a, bin/kat_*
    ├── shim.o
    ├── libht.a
    └── bin/
        └── kat_*
```

## Environment setup

The suite depends on a small, widely available toolchain: the Flat Assembler, a
C11-capable GCC, GNU binutils (`ld` + `ar`), GNU Make, Python 3, and pytest. The
one-time setup below is required only before the first build.

### Install (Debian / Ubuntu)

```
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
     fasm gcc make binutils python3 python3-pip
pip3 install --user 'pytest>=9.0.3'
```

The `pytest>=9.0.3` pin is a **security floor**, not merely a convenience: pytest
versions through 9.0.2 are affected by **CVE-2025-71176**, fixed in **9.0.3**, so
that release is the minimum this suite documents. Newer pytest works unchanged. On
PEP-668 "externally-managed" Python installs (recent Debian/Ubuntu, including this
environment), `pip3 install --user` is refused with an
`externally-managed-environment` error; in that case install pytest into a virtual
environment (`python3 -m venv .venv && . .venv/bin/activate && pip install 'pytest>=9.0.3'`)
or add `--break-system-packages` to the `pip3` command.

### Fallback: install FASM from the official tarball

Some Debian/Ubuntu releases do not package `fasm`. When that is the case, download
the official x86_64 Linux tarball from `flatassembler.net`, extract it, and place
the binary on `$PATH`:

```
curl -L https://flatassembler.net/fasm-1.73.32.tgz -o /tmp/fasm.tgz
tar -xzf /tmp/fasm.tgz -C /opt/
sudo ln -sf /opt/fasm/fasm /usr/local/bin/fasm
```

### Verify the toolchain

```
fasm | head -1        # expect "flat assembler  version 1.73.x" (>= 1.73.x; see CVE note)
gcc --version         # expect 13.x or newer (any C11-capable GCC, 4.7+)
make --version        # expect 4.3+
python3 --version     # expect 3.10+
pytest --version      # expect 9.0.3 or newer (see CVE note)
```

### Toolchain version pins

The suite uses only stable features that have been present in these tools across
multiple major releases. Preferred versions maximize stability; the minimums are the
floor below which the suite is no longer guaranteed to build or run. Newer releases
than the "preferred" column (for example, a newer GCC or pytest) are fine — they
satisfy the minimums and the documented behavior is unchanged.

| Tool | Preferred | Minimum |
|------|-----------|---------|
| FASM (Flat Assembler) | 1.73.x (latest 1.x) | 1.73.x — see security note |
| GCC | 13.2 / 14.x | 4.7 (C11) |
| GNU binutils (`ld`, `ar`) | 2.42+ | 2.30 |
| GNU Make | 4.3+ | 3.81 |
| Python 3 | 3.12.3 | 3.10 |
| pytest | 9.0.3 or newer | 9.0.3 — see security note |

The FASM 1.x series is the production-supported branch; community evidence confirms
1.71+ assembles HeavyThing showcase code successfully, and C11 is supported by every
GCC from 4.7 onward (selected with `-std=c11`).

> **Security note (minimum versions are CVE-driven).** Because this is a
> cryptographic test suite, the documented minimums deliberately exclude known-
> vulnerable toolchain releases:
>
> - **pytest** — versions **through 9.0.2** are affected by **CVE-2025-71176**,
>   fixed in **9.0.3**. The minimum is therefore **9.0.3** (this environment runs
>   9.0.3). Earlier 7.x / 8.x lines, although feature-compatible with the runner,
>   are **not** recommended.
> - **FASM** — releases **up to and including 1.71.21** are affected by
>   **CVE-2017-20228** (fixed in 1.71.22). The minimum is set to the current
>   **1.73.x** line (this environment runs 1.73.32), comfortably past the fix.
>
> The remaining tools (GCC, binutils, GNU Make) have no project-applicable advisory
> at the documented floors; use current distribution packages.

### Runtime characteristics

Each `build/bin/kat_*` binary is statically linked with `-nostdlib -static` and
therefore depends on **no** runtime shared library — not libc, not libm, not
libpthread. It runs identically on any glibc-based or musl-based Linux x86_64 system
with kernel 2.6.28 or later (HeavyThing's documented platform floor). The binaries
require no environment variables, no `LD_LIBRARY_PATH`, and no working directory
assumptions.

## Building, running, and cleaning

All commands below assume the working directory is `tests/`. To drive the suite from
the repository root instead, replace `make` with `make -C tests` and `pytest` with
`pytest tests`.

The `tests/Makefile` exposes four PHONY targets — `all`, `build`, `test`, and
`clean`:

| Command | Effect |
|---------|--------|
| `cd tests && make` (or `make all`) | Build **and test** (default target is `all: build test`): assemble the shim, archive `libht.a`, compile every harness binary, then run the full pytest suite. Equivalent to `make build` followed by `make test`. |
| `cd tests && make build` | Build only — produce `build/shim.o`, `build/libht.a`, and `build/bin/kat_*`. |
| `cd tests && make test` | Build (if needed) and then run the full pytest suite. |
| `cd tests && pytest` | Run the suite (uses `pytest.ini`: `testpaths = runner`, `addopts = -v --tb=short --maxfail=0`). |
| `cd tests && make clean` | Remove `build/` in full. Never deletes any source or vector file. |

`--maxfail=0` ensures the full suite always runs to completion and reports the
complete failure set rather than short-circuiting on the first failure.

### Selective and single-test execution

```
# All cases for a single primitive
cd tests && pytest -v runner/test_sha2.py

# A single parameterized case by node id (format: <variant>-<category>-<vector id>)
cd tests && pytest -v "runner/test_sha2.py::test_kat[sha256-happy_path-fips_abc]"

# Keyword filters (pytest -k)
cd tests && pytest -v -k "sha256 and edge_case"
cd tests && pytest -v -k "hmac_sha256 and negative"
cd tests && pytest -v -k "block_boundary"
```

### Debugging

```
# Verbose output with full tracebacks
cd tests && pytest -vv --tb=long runner/test_sha2.py

# Stop on first failure and drop into the debugger
cd tests && pytest -x --pdb runner/test_hmac.py
```

You can also run a harness binary directly, without pytest, by passing it the same
arguments pytest would. The SHA-2 family is driven by a single `kat_sha2` binary
whose first argument selects the variant (`sha224` / `sha256` / `sha384` / `sha512`)
and whose second argument is the **hex-encoded** message. For example:

```
tests/build/bin/kat_sha2 sha256 616263   # SHA-256 of "abc" (616263 = hex of "abc")
```

prints `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` to standard
output and exits `0` — the variant selector and hex-encoded input are exactly how
`runner/test_sha2.py` invokes it internally.

### Optional: long-running cases (`HT_KAT_SLOW`)

A single optional environment variable controls the most expensive vectors:

```
HT_KAT_SLOW=1 pytest        # from inside tests/
```

Setting **`HT_KAT_SLOW=1`** enables the long-running cases — RFC 6070's
16,777,216-iteration PBKDF2 vector and RFC 7914's `N=1,048,576` scrypt vector — that
are otherwise skipped to keep the default suite under roughly one minute. The
`N=1,048,576` scrypt case is additionally guarded by `@pytest.mark.skipif` on
available RAM below 1 GB. No other environment variables are required; the harness
binaries use none of the inherited environment.

## Vector-source attribution

Every committed vector under `vectors/*.json` carries a `source` field naming the
publication it derives from, so any reviewer can trace each value back to its origin.
For **Tier-1** primitives the happy-path and edge-case `expected_hex` values come
verbatim from the cited standards body. For **Tier-2** primitives the standards-body
*inputs* are used where applicable, but the `expected_hex` values are HeavyThing-
actual deterministic outputs captured from the reference build — regression /
self-consistency / round-trip-identity anchors, **not** published standards output —
and each such file states this explicitly in its `source` field. For negative cases
(tampered MAC, wrong key, round-trip identity) the *test logic* is what is negative;
the assertion is inverted or recomputed.

All `expected_hex` and `*_hex` fields are lowercase, with no `0x` prefix, no spaces,
and no separators. The harness emits lowercase hex on stdout, and equality is
byte-exact after `.strip()`. Vector files are pretty-printed with two-space
indentation and committed with a trailing newline for diff readability.

### Tier-1 vs Tier-2 classification

Each primitive is either a **Tier-1** standards-body KAT (the `expected_hex` values
are published RFC / NIST / FIPS output) or a **Tier-2** HeavyThing-specific
regression vector (the `expected_hex` values are HeavyThing-actual deterministic
outputs, for the reason given in the [Tier-2 Regression Vectors](#tier-2-regression-vectors)
registry below). The per-file JSON `source` field is the authoritative per-vector
record; this table is the roll-up.

| Primitive | Module | Tier | Source / basis |
|-----------|--------|------|----------------|
| MD5 | `md5.inc` | **Tier-1** | RFC 1321 §A.5 |
| SHA-1 | `sha1.inc` | **Tier-1** | NIST FIPS 180-4 |
| SHA-2 (224 / 256 / 384 / 512) | `sha2.inc` | **Tier-1** | NIST FIPS 180-4 + CAVP |
| HMAC-MD5 / SHA-1 / SHA-256 | `hmac.inc` | **Tier-1** | RFC 2202 (MD5, SHA-1) + RFC 4231 (SHA-256) + FIPS 198-1 |
| HMAC-SHA-224 / SHA-384 / SHA-512 | `hmac.inc` | **Tier-2** | RFC 4231 *inputs*; HeavyThing-actual MACs — see [1] |
| HMAC-DRBG | `hmac_drbg.inc` | **Tier-2** | NIST SP 800-90A *inputs*; HeavyThing-actual output — see [4] |
| PBKDF2 (SHA-1 / SHA-256 / MD5) | `pbkdf2.inc` | **Tier-1** | RFC 6070 + RFC 7914 §11 |
| PBKDF2 (SHA-224 / SHA-384 / SHA-512) | `pbkdf2.inc` | **Tier-2** | inherits the HMAC-SHA-224/384/512 deviation — see [1] |
| scrypt | `scrypt.inc` | **Tier-2** | RFC 7914 §12 *inputs*; HeavyThing-actual output — see [2] |
| AES | `aes.inc` | **Tier-1** | NIST FIPS 197 Appendix B/C + CAVP |
| htcrypt | `htcrypt.inc` | **Tier-2** | self-consistency (round-trip identity) — see [6] |
| htxts (XTS-AES) | `htxts.inc` | **Tier-2** | XTS mode over custom cipher; round-trip identity — see [5] |
| bigint arithmetic | `bigint.inc` | **Tier-2** | Knuth TAoCP §4.3 identities (self-consistency) — see [6] |
| RSA (`bigint$rsaprivate`) | `bigint.inc` | **Tier-2** | RFC 8017 §5.1.2 RSADP *algorithm*; textbook + generated keys — see [7] |
| DSA (`bigint$dsa_params` / `bigint$verify_dsa_params`) | `bigint.inc` | **Tier-2** | FIPS 186-4 App. A validity *rules*; textbook + generated params — see [8] |
| DH parameter pool | `dh_pool*.inc` | **Tier-2** | custom 2 Ton Digital safe primes (not RFC 3526) — see [3] |

### Tier-2 Regression Vectors

The primitives below are **Tier-2**: they are validated against HeavyThing-actual
deterministic outputs rather than published standards-body output, because matching
the cited standard byte-for-byte is impossible without modifying HeavyThing's
read-only source (which the scope forbids) or stepping outside the single-build
model. For each, the standards-body *inputs* (or the standard's *algorithm* /
*validity rules*) are used where applicable, the primitive's full public API is still
exercised, and every committed vector is subprocess-run and stdout-asserted (none
skipped). These are **regression / self-consistency / round-trip-identity** tests,
**not** standards-body KATs, and they make no claim of external standards conformance.
Each entry is cross-referenced from the matching driver/runner header and the
per-file JSON `source` field; this registry is the single authoritative list.

| # | Primitive(s) | Why it is Tier-2 (deviation from / relation to the cited standard) |
|---|--------------|--------------------------------------------------------------------|
| [1] | HMAC-SHA-224 / SHA-384 / SHA-512 (and PBKDF2 over them) | Fixed HMAC block size B=64 for every hash (RFC 4231 uses B=128 for SHA-384/512); SHA-224/384 finalize via the SHA-256/512 IV path, so MACs differ from the published RFC digests. RFC 4231 *inputs* are used; outputs are HeavyThing-actual. |
| [2] | scrypt | Cost parameters and PRF baked in at compile time (`scrypt_N=1024`, `r=1`, `p=1`, HMAC-SHA-512); runtime N/r/p ignored, so HeavyThing's output cannot match the RFC 7914 §12 (HMAC-SHA-256, variable N/r/p) vectors. RFC 7914 §12 *inputs* are used; outputs are HeavyThing-actual. |
| [3] | DH parameter pool | 20 custom 2 Ton Digital safe primes with a per-entry generator (g[0]=3, g[1]=2, …) instead of the RFC 3526 MODP moduli and fixed g=2; moduli are HeavyThing-actual, not RFC 3526. |
| [4] | HMAC-DRBG | `hmac_drbg$new` omits the final `V = HMAC(K, V)` update at instantiation (and hardcodes SHA-256), so generated bytes differ from the NIST SP 800-90A CAVP ReturnedBits. CAVP *inputs* are used; outputs are HeavyThing-actual. |
| [5] | htxts (XTS-AES) | XTS *mode* instantiated over HeavyThing's custom htcrypt AES-256 cascade (not raw AES), so no published NIST SP 800-38E / IEEE 1619 byte-for-byte vector applies; validated by `decrypt(encrypt(sector)) == sector` round-trip identity. |
| [6] | htcrypt; bigint arithmetic | Custom HeavyThing primitives with no external published vector: htcrypt is validated by encrypt/decrypt round-trip identity; bigint arithmetic is validated by algebraic self-consistency identities (Knuth TAoCP §4.3), e.g. `(a+b)-b == a`. |
| [7] | RSA (`bigint$rsaprivate`) | Exercises the RFC 8017 §5.1.2 RSADP *algorithm*, but the key material is **not** a published RFC 8017 example: a textbook key (n=3233) plus freshly generated 1024/2048-bit keys. `expected_hex` is the recovered plaintext, cross-checked against Python `pow(c, d, n)` — a round-trip / identity vector, not a standards KAT. |
| [8] | DSA (`bigint$dsa_params` / `bigint$verify_dsa_params`) | Checks the FIPS 186-4 Appendix A domain-parameter validity *rules*, but the parameter trios are **not** published FIPS examples: small textbook trios plus a HeavyThing-generated L=3072/N=256 trio that self-verifies. Output is the verify_status boolean — a parameter-validity regression vector, not a standards KAT. |

**Notes on the Tier-2 primitives.** The per-file JSON `source` field is the
authoritative record; the notes below mirror it so the classification table is not
misread as "pure published-RFC output". For these primitives the standards-body
*inputs* (or the standard's *algorithm* / *validity rules*) are used where
applicable, but the *expected outputs* are HeavyThing-actual and were captured from
the HeavyThing reference build:

- **[1] HMAC-SHA-224 / SHA-384 / SHA-512** use the RFC 2202 / RFC 4231 inputs, but the
  expected MACs are not the published RFC digests. HeavyThing fixes the HMAC block
  size at B=64 for every hash (RFC 4231 uses B=128 for SHA-384/512), and SHA-224/384
  finalize through the SHA-256/512 IV path. Details are documented in each
  `hmac_sha{224,384,512}.json` `source` field. HMAC-MD5, HMAC-SHA-1, and HMAC-SHA-256
  are unaffected and remain the published RFC 2202 / RFC 4231 values.
- **[2] scrypt — Tier-2 regression, not an RFC 7914 KAT.**
  HeavyThing bakes its cost parameters **and** its PRF at compile time
  (`scrypt_N=1024`, `scrypt_r=1`, `scrypt_p=1`, `scrypt_sha512=1` ⇒ HMAC-SHA-512),
  ignoring the supplied N/r/p arguments, whereas RFC 7914 §12 requires
  runtime-varying N/r/p (16, 1024, 16384, 1048576) and an HMAC-SHA-256 PRF — so the
  two produce different bytes. Reaching the published RFC values would require either
  modifying the read-only HeavyThing `.inc` source (Rule R2 forbids this) or a
  per-tuple multi-build matrix outside the single-shim / single-`libht.a` build
  model. This primitive is therefore scoped as a deterministic HeavyThing regression
  anchor rather than a Tier-1 standards KAT: the committed `scrypt.json` holds
  HeavyThing-actual self-consistency values over the RFC 7914 §12 *inputs*; the N/r/p
  fields are informational only (and are strictly validated so malformed values are
  rejected). Full record: the `kat_scrypt.c` header and the `scrypt.json` `source`
  field.
- **[3] DH parameter pool** ships 20 custom 2 Ton Digital 2048-bit safe primes
  (Sophie-Germain verified) instead of the RFC 3526 MODP moduli, and the generator
  varies per entry (g[0]=3, g[1]=2, …) rather than RFC 3526's fixed g=2. The expected
  moduli and generators are HeavyThing-actual, as documented in `dh_pool.json`.
- **[4] HMAC-DRBG — generated bytes deviate from NIST SP 800-90A CAVP.**
  HeavyThing's `hmac_drbg$new` omits the final `V = HMAC(K, V)` update after the
  second K update during instantiation, so the generated bytes do not match the
  published NIST CAVP ReturnedBits; SHA-256 is hardcoded as the DRBG hash. This is a
  Tier-2 regression test, not a standards KAT: the CAVP entropy / nonce /
  personalization *inputs* are used verbatim, but the committed `hmac_drbg.json`
  `expected_hex` values are HeavyThing-actual deterministic outputs (CAVP convention:
  first generate discarded, second emitted), not NIST ReturnedBits.
  The negative `generate-after-destroy` case fails **cleanly** with a positive nonzero
  exit and empty stdout — the harness destroys the context and then refuses to reuse
  it, so a use-after-free SIGSEGV is never relied upon (and `test_hmac_drbg.py` rejects
  any signal / `rc < 0` termination). Full record: the `kat_hmac_drbg.c` header and the
  `hmac_drbg.json` `source` field.
- **[5] htxts (XTS-AES) — round-trip identity instead of a published byte KAT.**
  NIST SP 800-38E / IEEE Std 1619-2018 standardize the XTS *mode* over a raw-AES block
  cipher, but HeavyThing instantiates XTS over its custom htcrypt 64-deep AES-256
  cascade, so no published byte-for-byte vector applies to this cipher. This is a
  Tier-2 regression test, not a standards KAT — exactly as for `htcrypt` itself, a
  custom primitive validated by round-trip identity. htxts is validated by the
  `decrypt(encrypt(sector)) == sector` round-trip identity plus cross-process
  determinism, with negative cases asserting the ciphertext genuinely differs from the
  plaintext. Full record: the `test_htxts.py` header and the `htxts.json` `source` field.
- **[6] htcrypt and bigint arithmetic — custom primitives, no external vector.**
  htcrypt is HeavyThing's own authenticated cipher (a 64-deep AES-256 cascade) with
  no published byte-for-byte KAT; it is validated by encrypt/decrypt round-trip
  identity with wrong-passphrase negatives. bigint arithmetic is validated by
  algebraic self-consistency identities drawn from Knuth TAoCP §4.3 (for example
  `(a + b) - b == a` and `(a * b) / b == a`), with `mod_inverse` non-coprime
  negatives. Both are deterministic regression tests, not standards KATs.
- **[7] RSA (`bigint$rsaprivate`) — round-trip / identity, not a published RFC 8017 vector.**
  The harness exercises the RFC 8017 (PKCS#1 v2.2) §5.1.2 RSADP *algorithm* through
  HeavyThing's CRT routine, but the key material is **not** a standards-body example:
  a textbook key (n=3233, p=61, q=53, e=17) plus freshly generated 1024-bit and
  2048-bit PKCS#1 keys (public exponent 65537). `expected_hex` is the recovered
  plaintext m = c^d mod n, captured from the HeavyThing reference build and
  independently cross-checked against Python `pow(c, d, n)`; the negative case tampers
  the expected plaintext so the recovered value no longer matches. Full record: the
  `rsa.json` `source` field.
- **[8] DSA (`bigint$dsa_params` / `bigint$verify_dsa_params`) — parameter-validity regression, not a published FIPS 186-4 vector.**
  The harness checks the FIPS 186-4 Appendix A domain-parameter validity *rules*
  (q prime, p prime, q | (p−1), g^q mod p == 1), but the parameter trios are **not**
  published FIPS examples: small textbook trios (p=23, q=11, g=4 and p=47, q=23, g=4)
  plus a HeavyThing-generated L=3072/N=256 trio that self-verifies. Output is the
  verify_status boolean (01=valid, 00=invalid); negative trios (composite q,
  non-order-q generator, composite p) must return 00. Full record: the `dsa.json`
  `source` field.

### Deferred primitives

The original request also named `poly1305`, `chacha20`, and `sodium_compat`. These
are explicitly **DEFERRED** and **not tested**, because no Poly1305, ChaCha20, or
libsodium-compatible implementation exists in this repository. This is a documented,
intentional gap — the suite does **not** fabricate stub files or fake test results
for primitives that do not exist. Coverage for these will be added if and when the
underlying primitives are implemented in the HeavyThing library.

## Troubleshooting

- **`fasm: command not found`** — FASM is not installed or not on `$PATH`. Install
  it via `apt-get install -y fasm`, or use the official-tarball fallback above, then
  confirm `fasm | head -1` reports a `1.73.x` version (1.73.x is the documented
  minimum; see the CVE-driven security note under "Toolchain version pins").
- **`gcc: command not found` or a too-old GCC** — install with
  `apt-get install -y gcc` and verify C11 support (`gcc --version`; any 4.7+ works).
- **`ld: cannot find entry symbol _start`** — this is the key gotcha for a
  `-nostdlib -static` link: there is no libc `crt0`, so the program must supply its
  own `_start`. The suite resolves this with a small `crt0` stub in
  `harness/ht_kat_common.c` that aligns the stack and calls `main`. If you hit this
  error, the `_start` stub is missing or was not linked — make sure
  `harness/ht_kat_common.c` is part of the link line, or build with the documented
  `-e main` entry-point fallback in the Makefile. Note that `main()` never returns;
  it terminates the process via `ht$syscall(60, status)` (the `exit` syscall).
- **`ld: cannot find -lc` or undefined libc symbols (`malloc`, `printf`, `exit`)** —
  the harness must use HeavyThing's `ht$*` helpers (`ht$malloc`, the custom write
  helpers, and `ht$syscall`), never libc. Do **not** remove `-nostdlib`; mixing libc
  with HeavyThing's memory model crashes.
- **`ar: command not found`** — install GNU binutils (`apt-get install -y binutils`).
- **pytest aborts collection with a "run `make` first" message** — the autouse
  `_require_build` fixture (and the `pytest_collection` hook) in `conftest.py` found
  `build/bin/` missing or empty and exited early. The exact message is:

  > HeavyThing KAT harness binaries not found in tests/build/bin/. Run `make` (or `make build`) inside tests/ before running pytest.

  This is expected behavior, not a bug — run `make build` first, then re-run pytest.
- **`pytest: command not found`** — install it with
  `pip3 install --user 'pytest>=9.0.3'` and ensure `~/.local/bin` is on your `$PATH`.
- **A KAT case fails** — the report (with `--tb=short`) shows the expected hex from
  the vector, the actual stdout from the harness, the harness exit code, and its
  stderr (which should be empty on success). Re-derive the expected value from the
  publication named in that vector's `source` field, and confirm the harness was
  rebuilt after any change (`make clean && make build`).
- **Long cases are too slow or run out of memory** — leave `HT_KAT_SLOW` unset (the
  default), which keeps the 16,777,216-iteration PBKDF2 case and the `N=1,048,576`
  scrypt case in skipped state. The `N=1,048,576` scrypt case is also
  `@pytest.mark.skipif`-guarded on available RAM below 1 GB.

## Coverage philosophy

There is **no gcov/lcov line-coverage report** for this suite, and you should not
look for one. Standard GNU coverage tooling instruments source code at GCC's
front-end at compile time; FASM emits machine code directly without a `.gcno` graph,
so FASM-built code is not gcov-instrumentable. Instead, coverage is reasoned about by
two complementary metrics:

- **API-symbol-exercise count** — every public entry point of each testable crypto
  `.inc` module is driven, at runtime, by at least one harness binary observed
  emitting an expected-equal output. The target is 100% of the public API surface
  for each testable primitive (some `bigint.inc` internals are reached transitively
  through the RSA, DSA, and DH paths rather than by a standalone KAT).
- **Authoritative-vector pass rate** — every committed vector under `vectors/*.json`
  must pass, with zero tolerance for partial success. `--maxfail=0` lets the full
  suite report its complete pass/fail set as the coverage evidence.

The suite ships **22** committed vector JSON files (one or more per primitive:
`md5`, `sha1`, the four SHA-2 files, the six `hmac_*` files, `hmac_drbg`, `pbkdf2`,
`scrypt`, `aes`, `htcrypt`, `htxts`, `bigint`, `rsa`, `dsa`, `dh_pool`). On the
exported-symbol count: `aes.inc` exposes **7** public symbols as built into
`build/libht.a` (`aes$data`, `aes$init_common`, `aes$init_encrypt`,
`aes$init_decrypt`, `aes$encrypt`, `aes$decrypt`, `aes$tls`) — verify with
`nm -g --defined-only build/libht.a | grep 'aes\$'`. The S-box and T-table labels
are internal data under `aes$data`, not separately exported public symbols; all 7
exported symbols are exercised by the AES harness.

## Determinism and reproducibility

Every vector produces a deterministic expected output; no randomness or wall-clock
dependence enters any case. HMAC-DRBG — the only primitive that would be
non-deterministic in production use — is tested with the fixed entropy, nonce, and
personalization inputs from the NIST SP 800-90A vector set, making its generated
bytes fully reproducible.

The build itself is deterministic: given the same FASM version, the same GCC
version, and the same source bytes, the assembled shim and compiled harness binaries
are byte-identical across reproducible builds, and the test outputs are byte-identical
because the primitives are deterministic on identical inputs.
