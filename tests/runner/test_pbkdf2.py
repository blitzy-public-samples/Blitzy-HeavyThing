"""KAT runner for PBKDF2 (``pbkdf2.inc``, the ``pbkdf2$new_<hash>`` /
``pbkdf2$doit`` family) vs RFC 6070 and RFC 7914 §11 vectors.

Each vector in ``tests/vectors/pbkdf2.json`` is fanned out into one
parametrized case that subprocess-invokes
``build/bin/kat_pbkdf2 <hash> <password> <salt_hex> <iterations> <dk_len>``
and asserts the harness's lowercase-hex derived key against ``expected_hex``.
The harness drives ``pbkdf2$new_<hash>`` / ``pbkdf2$init_<hash>`` ->
``pbkdf2$doit`` for ``hash_algorithm`` (sha1, sha224, sha256, sha384, sha512,
or md5); RFC 6070 uses HMAC-SHA-1.

RFC 6070's final 16,777,216-iteration PBKDF2-HMAC-SHA1 case is intentionally
expensive, so it is gated behind ``requires_slow`` and runs only when
``HT_KAT_SLOW=1`` is set, keeping the default suite under a minute. Pure
stdlib + pytest (no mocks: PBKDF2 is a pure function of its inputs).
"""

import pytest

from ._harness import (
    load_vectors, run_kat, assert_hex_equal, param_id, requires_slow,
)

# Load the committed RFC 6070 / RFC 7914 KAT array once at import time; a
# missing or malformed fixture surfaces now, not as an empty parametrize.
VECTORS = load_vectors("pbkdf2")

# Iteration count at or above which a vector is "slow" -- skipped unless
# HT_KAT_SLOW=1 (the RFC 6070 tc4 16,777,216-iteration case).
SLOW_ITERATIONS = 16_777_216


def _params():
    """Build the parametrize list, attaching ``requires_slow`` only to the
    >= 16,777,216-iteration vector and prefixing each node id with the hash
    algorithm (so ``-k "sha1"`` / ``-k "sha256"`` select coherent subsets,
    e.g. ``test_kat[sha1-happy_path-rfc6070_tc1]``).
    """
    params = []
    for vector in VECTORS:
        slow = int(vector["iterations"]) >= SLOW_ITERATIONS
        marks = [requires_slow] if slow else []
        params.append(pytest.param(
            vector,
            id=param_id(vector, prefix=vector["hash_algorithm"]),
            marks=marks,
        ))
    return params


@pytest.mark.parametrize("vector", _params())
def test_kat(vector):
    """Run one PBKDF2 KAT vector through ``kat_pbkdf2`` and assert its output.

    The harness must exit 0; ``expect_mismatch`` vectors (the different-
    password negative) must NOT reproduce ``expected_hex``; every other
    vector must match it exactly. ``timeout=120`` covers the high-iteration
    budget (AAP §0.7.2).
    """
    args = [
        vector["hash_algorithm"],
        vector["password"],
        vector["salt_hex"],
        str(vector["iterations"]),
        str(vector["dk_len"]),
    ]
    rc, out = run_kat("kat_pbkdf2", vector, args=args, timeout=120)
    assert rc == 0, f"kat_pbkdf2 exited {rc} for {vector['id']}"
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
