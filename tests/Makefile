# =============================================================================
# tests/Makefile -- Standalone build orchestrator for the HeavyThing KAT suite
# =============================================================================
#
# This Makefile builds and runs the Known-Answer-Test (KAT) suite for the
# HeavyThing cryptographic stack. It is fully self-contained inside tests/ and
# is INDEPENDENT of HeavyThing's manual two-step (fasm + ld) top-level build.
#
# Build pipeline (all outputs land under build/, which is git-ignored):
#
#     harness/shim.asm  --fasm-->  build/shim.o
#     build/shim.o      --ar---->  build/libht.a   (static archive of all
#                                                    HeavyThing crypto symbols)
#     harness/kat_<p>.c            +
#     harness/ht_kat_common.c      +  --gcc-->  build/bin/kat_<p>
#     build/libht.a                              (one static binary per
#                                                 primitive <p>)
#
# A Python pytest runner (runner/test_*.py, governed by pytest.ini) then
# subprocess-invokes each build/bin/kat_<p> binary once per JSON vector under
# vectors/ and asserts lowercase-hex equality on the binary's stdout.
#
# -----------------------------------------------------------------------------
# HARD SCOPE RULE (do not violate):
#   This Makefile MUST NOT invoke or interfere with the top-level/parent build
#   system. It never runs `cd ..`, never calls a parent Makefile or shell
#   script, and never writes any file outside build/. The ONLY contact with the
#   parent tree is READ-ONLY and happens *inside FASM*: harness/shim.asm does
#   `include '../../ht.inc'` and `include '../../ht_data.inc'`. This Makefile
#   merely invokes `fasm` on harness/shim.asm; it never reads or writes those
#   parent files itself, and it never modifies any .inc / ht.inc /
#   ht_defaults.inc / ht_data.inc / showcase .asm, nor any `falign`-prefixed
#   public crypto symbol.
# -----------------------------------------------------------------------------
#
# Usage (run from the tests/ directory):
#     make            # = `make all` : build everything, then run pytest
#     make build      # build the shim, archive, and all 14 KAT binaries
#     make test       # build (if needed) then run the pytest suite
#     make clean      # remove build/ in full (sources/vectors untouched)
#
# Prerequisites on $PATH (see README.md / AAP section 0.6.1 for install notes):
#     fasm   1.71+ (1.73.x preferred)  -- Flat Assembler for the shim
#     gcc    4.7+  (C11)               -- compiles the C11 KAT drivers
#     ar, ld (binutils 2.30+)          -- archive + link
#     make   3.81+                     -- this orchestrator
#     python3 3.10+ with pytest 8.4+   -- the test runner
# NOTE: `fasm` may not be packaged on every distro; if `make build` reports
# `fasm: command not found`, install it (apt `fasm`) or drop the official
# flatassembler.net x86_64 tarball's `fasm` binary on $PATH first.
# =============================================================================

# -----------------------------------------------------------------------------
# Toolchain + flags (AAP section 0.5.4)
# -----------------------------------------------------------------------------
FASM      = fasm
CC        = gcc
AR        = ar
# C11, all warnings on (non-fatal: no -Werror), optimized, and -- crucially --
# freestanding: `-nostdlib` drops libc/crt entirely (HeavyThing supplies its own
# syscall + memory layer) and `-static` is mandatory because the FASM object
# uses non-PIC R_X86_64_32S relocations that a default `-pie` link cannot
# resolve. Do NOT remove `-nostdlib` or `-static`.
CFLAGS    = -std=c11 -Wall -Wextra -O2 -nostdlib -static
# `-m 524288` raises FASM's memory ceiling to 512 MB; the shim pulls in the
# whole library with `include_everything = 1`, so the default ceiling is too low.
FASMFLAGS = -m 524288

# Python test runner. `python3 -m pytest` is preferred over a bare `pytest`
# because it does not depend on the pytest console-script being on $PATH and it
# always uses the interpreter named `python3`. Override with e.g.
# `make test PYTEST=pytest` if desired.
PYTEST    = python3 -m pytest

# -----------------------------------------------------------------------------
# Directory + file layout (all build outputs confined to $(BUILD))
# -----------------------------------------------------------------------------
HARNESS    = harness
BUILD      = build
BINDIR     = $(BUILD)/bin

SHIM_SRC   = $(HARNESS)/shim.asm
SHIM_OBJ   = $(BUILD)/shim.o
LIBHT      = $(BUILD)/libht.a
COMMON_SRC = $(HARNESS)/ht_kat_common.c
COMMON_HDR = $(HARNESS)/ht_kat_common.h
SETTINGS   = $(HARNESS)/settings.inc

# One harness binary per primitive. These 14 names map 1:1 to the
# harness/kat_<name>.c driver sources and to the runner/test_*.py modules'
# run_kat("kat_<name>") calls -- keep all three in sync. (AAP sections 0.5.1,
# 0.5.2.)
PRIMS = md5 sha1 sha2 hmac hmac_drbg pbkdf2 scrypt aes htcrypt htxts \
        bigint rsa dsa dh_pool
BINS  = $(addprefix $(BINDIR)/kat_,$(PRIMS))

# -----------------------------------------------------------------------------
# PHONY targets (AAP sections 0.5.4, 0.9.1)
# -----------------------------------------------------------------------------
.PHONY: all build test clean

# Default goal: build everything then run the suite (a bare `make` does both).
all: build test

# `build` produces the static archive (transitively) and all KAT binaries.
build: $(BINS)

# `test` ensures binaries are current, then runs pytest from tests/ so that
# pytest.ini (testpaths = runner, --maxfail=0) governs discovery and reporting.
test: build
	$(PYTEST)

# `clean` removes the entire build tree and nothing else. It never deletes any
# source, vector, or configuration file (AAP section 0.9.1).
clean:
	rm -rf $(BUILD)

# -----------------------------------------------------------------------------
# Output directories
# -----------------------------------------------------------------------------
# build/ (and build/bin/) are created ON DEMAND inside each file-producing
# recipe via `mkdir -p $(@D)` ($(@D) = the directory part of the target). We
# deliberately do NOT use a directory target such as `$(BUILD):` here: the
# output directory is named `build`, which would collide with the PHONY `build`
# target above. That collision makes the order-only prerequisite `| build`
# resolve to the phony target (which depends on the binaries, which depend on
# build/shim.o), producing a "Circular build/shim.o <- build dependency
# dropped" warning. Creating the directory in-recipe sidesteps the clash while
# keeping every output confined to build/ (which is git-ignored and never
# checked in).

# -----------------------------------------------------------------------------
# 1. Assemble the FASM shim -> build/shim.o
# -----------------------------------------------------------------------------
# Runs `fasm -m 524288 harness/shim.asm build/shim.o` from tests/.
#
# FASM resolves an `include` path relative to the directory of the file that
# CONTAINS the directive. So inside harness/shim.asm:
#     include 'settings.inc'      -> tests/harness/settings.inc   (in-tree)
#     include '../../ht.inc'      -> repo-root ht.inc             (read-only)
#     include '../../ht_data.inc' -> repo-root ht_data.inc        (read-only)
# and ht.inc's own internal `include 'sha2.inc'` (etc.) resolve relative to
# ht.inc's directory (the repo root). This is why invoking fasm on
# harness/shim.asm from tests/ works with NO include-path flags and NO `cd`.
# Do NOT `cd harness` -- that would break the '../../ht.inc' resolution.
#
# Prerequisites are the in-tree shim + its local settings include; a change to
# either re-triggers assembly. The out-of-tree '../../ht.inc' / '../../ht_data.inc'
# are intentionally NOT listed as prerequisites: they are read-only parent
# references and listing them would couple this standalone build to parent paths.
$(SHIM_OBJ): $(SHIM_SRC) $(SETTINGS)
	mkdir -p $(@D)
	$(FASM) $(FASMFLAGS) $(SHIM_SRC) $(SHIM_OBJ)

# -----------------------------------------------------------------------------
# 2. Package the shim object into a static archive -> build/libht.a
# -----------------------------------------------------------------------------
# `ar rcs` (r=insert, c=create quietly, s=write index) builds the archive the C
# drivers link against. The static archive is the default; a position-independent
# libht.so is produced only when explicitly required and is NOT part of `build`.
$(LIBHT): $(SHIM_OBJ)
	mkdir -p $(@D)
	$(AR) rcs $(LIBHT) $(SHIM_OBJ)

# -----------------------------------------------------------------------------
# 3. Compile + link each KAT driver -> build/bin/kat_<primitive>
# -----------------------------------------------------------------------------
# Pattern rule: build/bin/kat_md5 from harness/kat_md5.c, build/bin/kat_sha2 from
# harness/kat_sha2.c, and so on for all 14 primitives. Each binary links the
# per-primitive driver, the shared harness helpers (ht_kat_common.c), and the
# static archive. LINK ORDER MATTERS: the archive ($(LIBHT)) MUST come LAST so
# the linker resolves the drivers' undefined HeavyThing symbols by pulling the
# needed objects out of the archive. ht_kat_common.h is a prerequisite (so edits
# to the shared declarations rebuild every binary) but is not passed on the
# command line -- headers are #included, not linked.
#
# ENTRY POINT (read carefully): under `-nostdlib -static` there is no libc crt0,
# so ld has no `_start` from libc, and the FASM object does not provide one
# either. harness/ht_kat_common.c therefore supplies a tiny canonical `_start`
# crt0 stub (a top-level __asm__ block that clears %rbp, loads argc/argv off the
# stack, 16-byte-aligns %rsp -- required so -O2 aligned-SSE spills in main do not
# fault -- calls main, then turns main's return value into an exit(2) syscall).
# Because that `_start` is present and linked here, ld finds the entry symbol
# with NO `-e` flag and NO "cannot find entry symbol _start" warning, so the gcc
# command below is used AS WRITTEN.
#   FALLBACK: if a future toolchain ever still reports `cannot find entry symbol
#   _start`, append `-e main` to the link line (e.g. `make CFLAGS='$(CFLAGS) -e
#   main'`). With `-e main`, main() must never return -- the harness already
#   exits via ht$syscall(60, status). Do NOT "fix" a missing _start by dropping
#   `-nostdlib`: linking libc is forbidden (it would clash with HeavyThing's own
#   syscall + memory model and crash).
$(BINDIR)/kat_%: $(HARNESS)/kat_%.c $(COMMON_SRC) $(COMMON_HDR) $(LIBHT)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $(HARNESS)/kat_$*.c $(COMMON_SRC) $(LIBHT)
