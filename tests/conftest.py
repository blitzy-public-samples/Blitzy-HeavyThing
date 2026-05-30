"""Shared pytest fixtures and build precheck for the HeavyThing KAT suite.

Exposes CWD-independent paths consumed by every ``tests/runner`` module:
``bin_dir`` -> ``tests/build/bin`` (compiled ``kat_*`` harness binaries) and
``vectors_dir`` -> ``tests/vectors`` (committed JSON KAT fixtures). Build the
binaries first (``cd tests && make``); if they are missing the suite fails
fast with one friendly message instead of an ENOENT per parametrized case.
"""

from pathlib import Path

import pytest

# Authoritative, CWD-independent paths derived from this file's own location.
# tests/conftest.py sits directly under tests/, so its parent IS the tests dir.
TESTS_DIR = Path(__file__).resolve().parent
BIN_DIR = TESTS_DIR / "build" / "bin"
VECTORS_DIR = TESTS_DIR / "vectors"

# Single, actionable message emitted when the harness binaries are absent.
_BUILD_HINT = (
    "HeavyThing KAT harness binaries not found in tests/build/bin/. "
    "Run `make` (or `make build`) inside tests/ before running pytest."
)


def _harness_built():
    """True when build/bin/ has at least one compiled ``kat_*`` binary."""
    return BIN_DIR.is_dir() and any(BIN_DIR.glob("kat_*"))


def pytest_collection(session):
    """Abort collection (incl. ``--collect-only``) when binaries are missing.

    ``--version`` / ``--help`` are unaffected since they never trigger
    collection, so this stays out of the way of informational invocations.
    """
    if not _harness_built():
        pytest.exit(_BUILD_HINT, returncode=1)


@pytest.fixture(scope="session")
def bin_dir():
    """Absolute path to ``tests/build/bin`` (the ``kat_*`` binaries)."""
    return BIN_DIR


@pytest.fixture(scope="session")
def vectors_dir():
    """Absolute path to ``tests/vectors`` (committed JSON KAT data)."""
    return VECTORS_DIR


@pytest.fixture(scope="session", autouse=True)
def _require_build():
    """Fail fast once if binaries are unbuilt (see pytest_collection)."""
    if not _harness_built():
        pytest.exit(_BUILD_HINT, returncode=1)
