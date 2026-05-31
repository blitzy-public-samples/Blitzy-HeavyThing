"""KAT runner for XTS-AES (htxts.inc: htxts$encrypt / htxts$decrypt).

Validates HeavyThing's XTS-mode tweakable encryption against round-trip
identity over a full data unit, plus genuine-encryption negative checks. XTS
keys two halves -- ``key1`` for the data path and ``key2`` for the tweak path
-- with a per-sector ``tweak`` (the IEEE 1619 data-unit number "i"). The
underlying block cipher is HeavyThing's custom htcrypt 64-deep AES-256
cascade, not raw AES, so there is no externally published byte-for-byte KAT
(NIST SP 800-38E / IEEE Std 1619-2018 define the *mode*, not this cipher);
correctness is therefore asserted by ``decrypt(encrypt(sector)) == sector``
and cross-process determinism.

TIER-2 (NOT a NIST SP 800-38E / IEEE 1619 standards-body KAT): those
publications standardize the XTS *mode* over a raw-AES block cipher, whereas
HeavyThing instantiates XTS over its custom htcrypt AES-256 cascade. No
published byte-for-byte vector applies to this cipher, so -- exactly as for
``htcrypt`` itself, a custom primitive validated by round-trip identity --
htxts is validated by round-trip identity plus cross-process determinism rather
than as a Tier-1 standards KAT. The "Tier-2 Regression Vectors" section in
``tests/README.md`` carries the rationale and ``tests/vectors/htxts.json``
records the matching ``source`` attribution.

Each vector in ``tests/vectors/htxts.json`` is fanned out into one
parametrized case that subprocess-invokes the harness as
``kat_htxts <operation> <key1_hex> <key2_hex> <tweak_hex> <data_hex>`` and
asserts its lowercase-hex stdout against ``expected_hex``. The runner stays
generic: ``vector["operation"]`` is passed verbatim as the op selector, so it
covers every code path without special-casing:

* ``encrypt``    -> ``htxts$encrypt``; prints the ciphertext hex.
* ``decrypt``    -> ``htxts$decrypt``; prints the recovered-plaintext hex.
* ``round_trip`` -> encrypt-then-decrypt under one key (the harness saves and
  restores the in-place-mutated tweak); the recovered data unit must equal
  the original ``data_hex`` (so ``expected_hex == data_hex``).

Both public symbols ``htxts$encrypt`` and ``htxts$decrypt`` are exercised (AAP
0.3.1 -- 2 of 2 -> 100%). Pure stdlib + pytest, no mocks (the primitive is a
pure function of its keys, tweak, and data unit).
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# Load the committed XTS-AES KAT array once at import time; a missing or
# malformed fixture surfaces immediately rather than as an empty parametrize.
VECTORS = load_vectors("htxts")

# Node ids carry the operation prefix so ``-k "encrypt"`` / ``-k "round_trip"``
# select coherent subsets, e.g. ``test_kat[round_trip-happy_path-rt_16B]``.
IDS = [param_id(vector, prefix=vector["operation"]) for vector in VECTORS]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_kat(vector):
    """Run one XTS-AES KAT vector through ``kat_htxts`` and assert its output.

    Uniform dispatch across positive and negative vectors:

    1. The harness must exit 0 (clean run; no crash, no usage error).
    2. ``expect_mismatch`` vectors must NOT reproduce ``expected_hex`` -- the
       ciphertext genuinely differs from the plaintext.
    3. Every other vector (round-trip identity, where ``expected_hex`` is the
       original data unit) must match exactly.
    """
    args = [
        vector["operation"],
        vector["key1_hex"],
        vector["key2_hex"],
        vector["tweak_hex"],
        vector["data_hex"],
    ]
    rc, out = run_kat("kat_htxts", vector, args=args)
    assert rc == 0, (
        f"kat_htxts {vector['operation']} exited {rc} for {vector['id']}"
    )
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{vector['id']}: ciphertext unexpectedly equals plaintext"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
