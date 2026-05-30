"""KAT runner for the DH parameter pool (``dh_pool*.inc``) vs RFC 3526 §3 /
RFC 7919.

Validates HeavyThing's compiled-in Diffie-Hellman parameter pool -- the
``dh$pool_p`` / ``dh$pool_g`` / ``dh$pool_count`` data symbols. This is a
*static-data integrity* KAT: no message input and no cryptographic
computation, only a pool index and the value the shipped pool must reproduce
byte-for-byte. Each vector in ``tests/vectors/dh_pool.json`` is fanned out
into one parametrized case that subprocess-invokes
``build/bin/kat_dh_pool <index> [field]`` and asserts the harness's
lowercase-hex stdout against ``expected_hex``:

* ``index="count"`` -> ``dh$pool_count`` (the pool entry count).
* ``field == "p"``  -> ``dh$pool_p[index]`` (the 2048-bit safe-prime modulus).
* ``field == "g"``  -> ``dh$pool_g[index]`` (that entry's generator).

Exercising all three symbols (``pool_count`` bounds the index range) yields
100% of the pool's public data surface (AAP §0.3.1). DEVIATION (per the
``dh_pool.json`` ``source`` field and README note [3]): HeavyThing ships 20
custom 2 Ton Digital 2048-bit safe primes, not the RFC 3526 MODP moduli, and
the generator varies per entry (g[0]=3, g[1]=2, ...), so ``expected_hex`` holds
the HeavyThing-actual values. Pure stdlib + pytest (no mocks: immutable static
data); this module only loads vectors, drives the subprocess, and compares hex.
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# Load the committed DH pool-integrity KAT array once at import time; a missing
# or malformed fixture surfaces now, not as an empty parametrize.
VECTORS = load_vectors("dh_pool")

# Node ids are "<category>-<id>" (the pool has no extra variant dimension), so
# -k filters select coherent subsets, e.g. ``-k "group_2048_4"`` picks one
# group's modulus and generator, and ``-k "pool_count"`` picks the count check.
IDS = [param_id(vector) for vector in VECTORS]


def _args(vector):
    """Build kat_dh_pool argv for a vector.

    The pool index is always the first positional arg and is stringified
    defensively -- it is an int (0..19) for the per-entry modulus/generator
    vectors and the literal string ``"count"`` for the pool-count vector. The
    optional ``field`` (``"p"`` modulus / ``"g"`` generator) is appended only
    when present (the count vector omits it, defaulting the harness to its
    count path).
    """
    args = [str(vector["index"])]
    if vector.get("field"):
        args.append(vector["field"])
    return args


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_kat(vector):
    """Run one DH-pool KAT vector through ``kat_dh_pool`` and assert its hex.

    Uniform dispatch (matching the other ``test_*`` runners): the harness must
    exit 0 (clean run, in-bounds index); ``expect_mismatch`` vectors must NOT
    reproduce ``expected_hex`` (branch kept for cross-module uniformity but
    unused here -- the pool is purely positive static data); every other vector
    (count, each modulus, each generator) must match its known answer exactly
    (R8 full-coverage, R9 zero-tolerance).
    """
    rc, out = run_kat("kat_dh_pool", vector, args=_args(vector))
    assert rc == 0, (
        f"kat_dh_pool index={vector['index']} exited {rc} for {vector['id']}"
    )
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
