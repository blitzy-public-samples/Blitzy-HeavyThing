"""KAT runner for DSA domain parameters (``bigint.inc`` -- the
``bigint$dsa_params`` / ``bigint$verify_dsa_params`` symbols) vs FIPS 186-4
Appendix A DSA parameter-validity rules.

DSA domain parameters are the triple ``(p, q, g)``; the
``bigint$verify_dsa_params`` symbol checks their validity (``q`` prime,
``p`` prime, ``q | (p - 1)``, and ``g^q mod p == 1``). Each vector in
``tests/vectors/dsa.json`` is fanned out into one parametrized case that
subprocess-invokes ``build/bin/kat_dsa <p_hex> <q_hex> <g_hex>`` (big-endian
magnitude hex) and asserts the harness's lowercase-hex stdout against
``expected_hex`` -- a boolean-as-hex verification status:

* ``01`` -> the trio is a valid DSA parameter set (``happy_path`` /
  ``edge_case_single_byte``).
* ``00`` -> the trio is rejected (``negative_composite_q``,
  ``negative_bad_generator``, ``negative_composite_p``).

Because the result is a boolean status rather than a digest, every negative is
encoded directly as ``expected_hex == "00"`` and still flows through the
positive equality branch (verify emits ``00``, the vector expects ``00`` ->
pass); no special inequality logic is required. Exercising
``bigint$verify_dsa_params`` (every vector) together with ``bigint$dsa_params``
(whose captured 3072-bit output backs the ``fips_l3072_n256_generated`` vector)
covers 100% of the DSA subset's public API (AAP §0.3.1). Pure standard library
+ pytest (no mocks: parameter validation is a pure function of the trio); this
module only loads vectors, drives the subprocess, and compares hex.
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# Load the committed FIPS 186-4 DSA KAT array once at import time; a missing or
# malformed fixture surfaces immediately rather than as an empty parametrize.
VECTORS = load_vectors("dsa")

# Node ids are "<category>-<id>" (DSA has no extra variant dimension), so -k
# filters select coherent subsets: ``-k "negative"`` picks the composite-q,
# bad-generator, and composite-p rejection cases, and ``-k "happy_path"``
# picks the valid trios.
IDS = [param_id(vector) for vector in VECTORS]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_kat(vector):
    """Run one DSA-parameter KAT vector through ``kat_dsa`` and assert its hex.

    Argv is the fixed ``<p_hex> <q_hex> <g_hex>`` trio. Uniform dispatch
    (matching every other ``test_*`` runner):

    1. The harness must exit 0 (clean verification run; no usage error/crash).
    2. ``expect_mismatch`` vectors must NOT reproduce ``expected_hex`` (branch
       kept for cross-module uniformity but unused here -- DSA negatives are
       expressed directly as ``expected_hex == "00"``).
    3. Every other vector -- valid trio (``01``) and rejected trio (``00``) --
       must match its known verification status exactly (R8 full-coverage,
       R9 zero-tolerance).
    """
    args = [vector["p_hex"], vector["q_hex"], vector["g_hex"]]
    rc, out = run_kat("kat_dsa", vector, args=args)
    assert rc == 0, f"kat_dsa exited {rc} for {vector['id']}"
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
