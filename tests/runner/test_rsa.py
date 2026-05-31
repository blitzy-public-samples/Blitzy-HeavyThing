"""KAT runner for the RSA private-key operation (``bigint$rsaprivate`` in
``bigint.inc``) vs RFC 8017 (PKCS#1 v2.2) RSADP worked examples.

The RSA private-key primitive recovers the message representative
``m = c^d mod n`` (RFC 8017 §5.1.2, RSADP). Each vector in
``tests/vectors/rsa.json`` is fanned out into one parametrized case that
subprocess-invokes ``build/bin/kat_rsa <n_hex> <e_hex> <d_hex>
<ciphertext_hex>`` (big-endian magnitude hex) and asserts the harness's
lowercase-hex stdout against ``expected_hex`` -- the recovered plaintext:

* ``happy_path`` -> the textbook key ``n = 3233`` and freshly generated
  1024-/2048-bit PKCS#1 keys (public exponent 65537); stdout is the recovered
  message ``m`` and must equal ``expected_hex`` exactly.
* ``edge_case_single_byte`` -> the smallest non-trivial ciphertext (``c = 1``),
  whose recovered representative is likewise ``1``.
* ``negative_wrong_key`` -> ``expect_mismatch`` is set and ``expected_hex`` is
  a deliberately tampered plaintext; the genuine recovery must NOT reproduce
  it, proving the operation truly depends on the private exponent ``d``.

``e_hex`` is carried for context (RSADP itself needs only ``n`` and ``d``); the
harness reconstructs the CRT key and invokes ``bigint$rsaprivate``, exercising
100% of the RSA subset's public API (AAP §0.3.1). Pure standard library +
pytest (no mocks: the primitive is a pure function of ``c``, ``d`` and ``n``);
this module only loads vectors, drives the subprocess, and compares hex.
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# Load the committed RFC 8017 RSADP KAT array once at import time; a missing or
# malformed fixture surfaces immediately rather than as an empty parametrize.
VECTORS = load_vectors("rsa")

# Node ids are "<category>-<id>" (RSA has no extra variant dimension), so -k
# filters select coherent subsets: ``-k "negative"`` picks the wrong-key case
# and ``-k "happy_path"`` the recoverable vectors, e.g.
# test_kat[happy_path-textbook_n3233].
IDS = [param_id(vector) for vector in VECTORS]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_kat(vector):
    """Run one RSA KAT vector through ``kat_rsa`` and assert its hex output.

    Argv is the fixed ``<n_hex> <e_hex> <d_hex> <ciphertext_hex>`` order
    consumed by ``tests/harness/kat_rsa.c``. Uniform dispatch (matching every
    other ``test_*`` runner):

    1. The harness must exit 0 (clean run; no usage error, no crash).
    2. ``expect_mismatch`` vectors (the wrong-key negative) must NOT reproduce
       ``expected_hex`` -- the genuine ``m = c^d mod n`` differs from the
       tampered value.
    3. Every other vector (happy-path and the single-byte edge) must match its
       recovered plaintext exactly (R8 full-coverage, R9 zero-tolerance).
    """
    args = [vector["n_hex"], vector["e_hex"], vector["d_hex"],
            vector["ciphertext_hex"]]
    rc, out = run_kat("kat_rsa", vector, args=args)
    assert rc == 0, f"kat_rsa exited {rc} for {vector['id']}"
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
