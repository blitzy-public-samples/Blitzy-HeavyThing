"""Shared helpers for the HeavyThing KAT (Known-Answer-Test) pytest runner.

Centralizes JSON vector loading, subprocess invocation of the compiled
``kat_*`` binaries with stdout capture, the hex-equality assertion, pytest
node-id construction, and ``HT_KAT_SLOW`` / available-RAM gating so each
``test_<primitive>.py`` stays small. Pure standard library plus ``pytest``
only -- no third-party deps, no mocking (the primitives are pure functions).
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

# CWD-independent paths. This module is at tests/runner/_harness.py, so
# ``parent.parent`` is tests/. BIN_DIR / VECTORS_DIR MUST match conftest.py's
# bin_dir / vectors_dir fixtures (conftest uses ``.resolve().parent``).
TESTS_DIR = Path(__file__).resolve().parent.parent  # -> tests/
BIN_DIR = TESTS_DIR / "build" / "bin"                # -> tests/build/bin
VECTORS_DIR = TESTS_DIR / "vectors"                  # -> tests/vectors

# Generous per-case subprocess timeout (seconds); heavier KDFs supply 120.
DEFAULT_TIMEOUT = 60

# Gate for the slow KATs (RFC 6070 16,777,216-iter PBKDF2, RFC 7914
# N=1,048,576 scrypt). True only when the env var equals exactly "1".
HT_KAT_SLOW = os.environ.get("HT_KAT_SLOW") == "1"


def load_vectors(name):
    """Return the ``vectors`` array from ``tests/vectors/<name>.json``.

    A missing fixture lets ``FileNotFoundError`` propagate; never return
    ``[]`` (an empty parametrize would hide the authoring error).
    """
    path = VECTORS_DIR / f"{name}.json"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["vectors"]


def run_kat(binary, vector, args=None, timeout=DEFAULT_TIMEOUT):
    """Run ``build/bin/<binary>`` with ``args``; return ``(rc, stdout)``.

    Argv tokens are stringified defensively; a vector ``stdin`` payload is
    threaded to the child (``None`` -> no stdin). No assertion is made here
    (those live at the test site); ``subprocess.TimeoutExpired`` propagates.
    """
    exe = BIN_DIR / binary
    if not exe.exists():
        raise FileNotFoundError(
            f"harness binary not found: {exe} -- "
            "run `make build` in tests/ first"
        )
    cmd = [str(exe)] + [str(a) for a in (args or [])]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=vector.get("stdin"),
    )
    return result.returncode, result.stdout


def assert_hex_equal(actual, expected):
    """Assert stripped, lowercased ``actual`` equals lowercase ``expected``."""
    got = actual.strip().lower()
    assert got == expected, (
        f"hex mismatch: got {got!r} want {expected!r}"
    )


def param_id(vector, prefix=None):
    """Join non-empty ``(prefix, category, id)`` with ``-`` for a node id.

    E.g. ``param_id(v, "sha256")`` -> ``sha256-happy_path-abc``; no prefix
    -> ``happy_path-<id>``. The caller owns the prefix choice.
    """
    parts = (prefix, vector.get("category"), vector.get("id"))
    return "-".join(p for p in parts if p)


def available_ram_gb():
    """Best-effort available RAM in GiB; ``0.0`` on any error (safe default).

    Reads ``MemAvailable`` (kB) from ``/proc/meminfo``; ``0.0`` on any
    failure so the RAM-gated scrypt case is skipped rather than OOMs.
    """
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    return kb / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        return 0.0
    return 0.0


# Skip marker for the slow KATs; applied in test_pbkdf2.py / test_scrypt.py.
requires_slow = pytest.mark.skipif(
    not HT_KAT_SLOW,
    reason="slow KAT; set HT_KAT_SLOW=1 to enable",
)


def requires_ram_gb(n):
    """Return a ``skipif`` marker requiring at least ``n`` GiB available RAM.

    Used by test_scrypt.py's N=1,048,576 case alongside ``requires_slow``.
    """
    return pytest.mark.skipif(
        available_ram_gb() < n,
        reason=f"requires >= {n} GiB available RAM",
    )
