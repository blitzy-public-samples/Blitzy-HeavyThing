"""Tier-2 regression runner for scrypt (``scrypt.inc``: ``scrypt`` /
``scrypt_iter``) over RFC 7914 §12 input parameter sets.

Each vector in ``tests/vectors/scrypt.json`` is fanned out into one
parametrized case that subprocess-invokes
``build/bin/kat_scrypt <password> <salt_hex> <N> <r> <p> <dk_len>`` and asserts
the harness's lowercase-hex derived key against ``expected_hex``. The harness
drives ``scrypt`` (and, for coverage, ``scrypt_iter``) -- both public symbols
of ``scrypt.inc`` are exercised (AAP §0.3.1: 2 of 2 -> 100%).

The RFC 7914 N=1,048,576 vector needs ~1 GiB of RAM and substantial time, so it
is gated behind BOTH ``requires_slow`` (run only when ``HT_KAT_SLOW=1``) and
``requires_ram_gb(1.0)`` (skip when < 1 GiB is available), keeping the default
suite fast (AAP §0.7.2, §0.9.1).

TIER-2 (NOT an RFC 7914 standards-body KAT): HeavyThing's ``scrypt`` takes only
``(dest, destlen, password, passwordlen, salt, saltlen)`` -- it bakes the cost
parameters and PRF at compile time (``scrypt_N = 1024``, ``scrypt_r = 1``,
``scrypt_p = 1``, and HMAC-SHA512 rather than RFC 7914's HMAC-SHA256) and
ignores any runtime N/r/p, so it produces different bytes than RFC 7914.
Reproducing RFC 7914's published vectors would require variable N/r/p and the
SHA-256 PRF, impossible without editing ``ht_defaults.inc`` / ``scrypt.inc``
(read-only REFERENCE per Rule R2). This primitive is therefore scoped as a
deterministic HeavyThing regression anchor rather than a Tier-1 standards KAT:
the committed ``expected_hex`` values are HeavyThing-ACTUAL self-consistency
outputs, NOT RFC 7914 ReturnedBits. The "Tier-2 Regression Vectors" section in
``tests/README.md`` carries the rationale and ``tests/vectors/scrypt.json``
records the matching ``source`` attribution. Pure stdlib + pytest, no mocks
(scrypt is a pure function of its inputs).
"""

import pytest

from ._harness import (
    load_vectors, run_kat, assert_hex_equal, param_id,
    requires_slow, requires_ram_gb,
)

# Load the committed scrypt KAT array once at import time; a missing or
# malformed fixture surfaces now, not as an empty parametrize.
VECTORS = load_vectors("scrypt")

# RFC 7914 cost parameter at/above which a vector is "heavy": the N=1,048,576
# case, gated behind HT_KAT_SLOW AND a >= 1 GiB available-RAM check.
SLOW_N = 1_048_576
SLOW_MIN_RAM_GB = 1.0


def _params():
    """Build the parametrize list, attaching BOTH skip markers only to the
    N >= 1,048,576 vector so the default suite skips it (shown as ``s``) while
    ``HT_KAT_SLOW=1`` on a >= 1 GiB box runs it. Node ids use ``param_id``
    in single (no-prefix) mode, e.g. ``test_kat[happy_path-rfc7914_empty]``.
    """
    params = []
    for vector in VECTORS:
        if int(vector["N"]) >= SLOW_N:
            marks = [requires_slow, requires_ram_gb(SLOW_MIN_RAM_GB)]
        else:
            marks = []
        params.append(pytest.param(vector, id=param_id(vector), marks=marks))
    return params


@pytest.mark.parametrize("vector", _params())
def test_kat(vector):
    """Run one scrypt KAT vector through ``kat_scrypt`` and assert its output.

    The harness must exit 0; the ``expect_mismatch`` vector (the different-salt
    negative) must NOT reproduce ``expected_hex``; every other vector must
    match it exactly. ``timeout=120`` is generous for the gated heavy
    case (smaller N values complete in well under 5 s -- AAP §0.7.2).
    """
    args = [
        vector["password"],
        vector["salt_hex"],
        str(vector["N"]),
        str(vector["r"]),
        str(vector["p"]),
        str(vector["dk_len"]),
    ]
    rc, out = run_kat("kat_scrypt", vector, args=args, timeout=120)
    assert rc == 0, f"kat_scrypt exited {rc} for {vector['id']}"
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
