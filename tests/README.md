# HeavyThing Cryptographic Known-Answer-Test (KAT) Suite

This directory contains a self-contained **Known-Answer-Test (KAT)** suite for the
HeavyThing cryptographic stack. Every public cryptographic primitive is validated
against authoritative standards-body test vectors published by the IETF (RFC) and
NIST (FIPS / CAVP / Special Publications). Each primitive is exercised by a small,
statically linked C11 harness binary that calls HeavyThing's native assembly
symbols directly; a Python 3 [pytest](https://docs.pytest.org/) runner invokes each
harness once per vector and asserts byte-exact hexadecimal equality on the binary's
standard output.

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
pip3 install --user 'pytest==8.4.0'
```

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
fasm | head -1        # expect "flat assembler  version 1.73.x"
gcc --version         # expect 13.x or 14.x
make --version        # expect 4.3+
python3 --version     # expect 3.10+
pytest --version      # expect 8.4.0
```

### Toolchain version pins

The suite uses only stable features that have been present in these tools across
multiple major releases. Preferred versions maximize stability; the minimums are the
floor below which the suite is no longer guaranteed to build or run. Newer releases
than the "preferred" column (for example, a newer GCC or pytest) are fine — they
satisfy the minimums and the documented behavior is unchanged.

| Tool | Preferred | Minimum |
|------|-----------|---------|
| FASM (Flat Assembler) | 1.73.x (latest 1.x) | 1.71 |
| GCC | 13.2 / 14.x | 4.7 (C11) |
| GNU binutils (`ld`, `ar`) | 2.42+ | 2.30 |
| GNU Make | 4.3+ | 3.81 |
| Python 3 | 3.12.3 | 3.10 |
| pytest | 8.4.0 | 7.0 |

The FASM 1.x series is the production-supported branch; community evidence confirms
1.71+ assembles HeavyThing showcase code successfully. C11 is supported by every GCC
from 4.7 onward and is selected with `-std=c11`.

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
| `cd tests && make` (or `make all`) | Full build: assemble the shim, archive `libht.a`, compile every harness binary. |
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

# A single parameterized case by node id
cd tests && pytest -v "runner/test_sha2.py::test_kat[sha256-abc]"

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

You can also run a harness binary directly, without pytest, by passing it a vector
argument. For example:

```
tests/build/bin/kat_sha256 abc
```

prints the SHA-256 hex digest of the ASCII string `abc` to standard output and exits
`0` — exactly the way pytest invokes it internally.

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
authoritative publication it derives from, so any reviewer can trace each value back
to its origin. **No synthesized vectors are accepted** in the happy-path or
edge-case categories — those values come verbatim from the cited standards body. For
negative cases (tampered MAC, wrong key, round-trip identity) the *test logic* is
what is negative; the underlying inputs still derive from authoritative sources, and
the assertion is inverted or recomputed.

All `expected_hex` and `*_hex` fields are lowercase, with no `0x` prefix, no spaces,
and no separators. The harness emits lowercase hex on stdout, and equality is
byte-exact after `.strip()`. Vector files are pretty-printed with two-space
indentation and committed with a trailing newline for diff readability.

### Authoritative sources per primitive

| Primitive | Module | Authoritative source |
|-----------|--------|----------------------|
| MD5 | `md5.inc` | RFC 1321 §A.5 |
| SHA-1 | `sha1.inc` | NIST FIPS 180-4 |
| SHA-2 (224 / 256 / 384 / 512) | `sha2.inc` | NIST FIPS 180-4 + CAVP |
| HMAC | `hmac.inc` | RFC 2202 (MD5, SHA-1) + RFC 4231 (SHA-2 family) + FIPS 198-1 — see note [1] |
| HMAC-DRBG | `hmac_drbg.inc` | NIST SP 800-90A CAVP |
| PBKDF2 | `pbkdf2.inc` | RFC 6070 + RFC 7914 §11 |
| scrypt | `scrypt.inc` | RFC 7914 §12 — see note [2] |
| AES | `aes.inc` | NIST FIPS 197 Appendix B/C + CAVP |
| htcrypt | `htcrypt.inc` | self-consistency (round-trip identity) |
| htxts (XTS-AES) | `htxts.inc` | NIST SP 800-38E / IEEE Std 1619-2018 |
| bigint arithmetic | `bigint.inc` | Knuth TAoCP §4.3 identities |
| RSA (`bigint$rsaprivate`) | `bigint.inc` | RFC 8017 PKCS#1 v1.5 §C |
| DSA (`bigint$dsa_params` / `bigint$verify_dsa_params`) | `bigint.inc` | FIPS 186-4 Appendix A.1.1.2 |
| DH parameter pool | `dh_pool*.inc` | RFC 3526 §3 / RFC 7919 — see note [3] |

**Notes on HeavyThing-specific deviations.** The per-file JSON `source` field is the
authoritative record; the notes below mirror it so the table above is not misread as
"pure published-RFC output". For these primitives the standards-body *inputs* are
used verbatim, but the *expected outputs* are HeavyThing-actual and were captured
from the HeavyThing reference build:

- **[1] HMAC-SHA-224 / SHA-384 / SHA-512** use the RFC 2202 / RFC 4231 inputs, but the
  expected MACs are not the published RFC digests. HeavyThing fixes the HMAC block
  size at B=64 for every hash (RFC 4231 uses B=128 for SHA-384/512), and SHA-224/384
  finalize through the SHA-256/512 IV path. Details are documented in each
  `hmac_sha{224,384,512}.json` `source` field. HMAC-MD5, HMAC-SHA-1, and HMAC-SHA-256
  are unaffected and remain the published RFC 2202 / RFC 4231 values.
- **[2] scrypt** bakes its cost parameters at compile time (`scrypt_N=1024`,
  `scrypt_r=1`, `scrypt_p=1`) and uses an HMAC-SHA-512 PRF rather than RFC 7914's
  HMAC-SHA-256, ignoring the supplied N/r/p arguments. The expected keys are therefore
  HeavyThing-actual over the RFC 7914 §12 inputs, as documented in `scrypt.json`.
- **[3] DH parameter pool** ships 20 custom 2 Ton Digital 2048-bit safe primes
  (Sophie-Germain verified) instead of the RFC 3526 MODP moduli, and the generator
  varies per entry (g[0]=3, g[1]=2, …) rather than RFC 3526's fixed g=2. The expected
  moduli and generators are HeavyThing-actual, as documented in `dh_pool.json`.

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
  confirm `fasm | head -1` reports a `1.7x` version.
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
  `pip3 install --user 'pytest==8.4.0'` and ensure `~/.local/bin` is on your `$PATH`.
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
