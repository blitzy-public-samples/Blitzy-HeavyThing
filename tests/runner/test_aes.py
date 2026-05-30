"""KAT runner for AES (``aes.inc``, the ``aes$`` family).

Validates HeavyThing's AES against NIST FIPS 197 Appendix B (worked AES-128
example) and Appendix C.1/C.2/C.3 (AES-128/192/256 canonical single-block
example vectors), plus encrypt->decrypt round-trip identity. Each vector in
``tests/vectors/aes.json`` is fanned out into one parametrized case that
subprocess-invokes ``build/bin/kat_aes <mode> <key_hex> <plaintext_hex>`` and
asserts the harness's lowercase-hex stdout against ``expected_hex``.

The runner is deliberately generic: ``vector["mode"]`` is passed verbatim as
the harness op selector, so it covers every code path without special-casing:

* ``ecb_encrypt`` -> ``aes$init_encrypt`` + ``aes$encrypt`` (ciphertext hex).
* ``ecb_decrypt`` -> ``aes$init_decrypt`` + ``aes$decrypt`` (plaintext hex).
* ``round_trip``  -> encrypt-then-decrypt under one key; recovered block must
  equal the original ``plaintext_hex`` (round-trip identity).
* ``tls_encrypt`` / ``tls_decrypt`` -> the ``aes$tls`` dispatch table, which
  forwards to the same public functions, so its output matches plain ECB.

The S-box / T-table data symbols (``aes$Se``, ``aes$Sd``, ``aes$Te``,
``aes$Td``, ``aes$data``) are validated implicitly via correct output. The
harness owns key-schedule init and the lookup tables; this module only loads
vectors, drives the subprocess, and asserts. Pure stdlib + pytest (no mocks:
AES is a pure function of key and block).
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# Load the committed FIPS 197 KAT array once at import time. A missing or
# malformed fixture surfaces immediately rather than as an empty parametrize.
VECTORS = load_vectors("aes")

# Node ids carry the mode prefix so ``-k "ecb_encrypt"`` / ``-k "ecb_decrypt"``
# / ``-k "round_trip"`` / ``-k "tls"`` select coherent subsets, e.g.
# ``test_kat[ecb_encrypt-happy_path-fips197_c1_aes128_enc]``.
IDS = [param_id(vector, prefix=vector["mode"]) for vector in VECTORS]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_kat(vector):
    """Run one AES KAT vector through ``kat_aes`` and assert its hex output.

    Uniform dispatch across positive and negative vectors:

    1. The harness must exit 0 (clean run; no crash, no usage error).
    2. ``expect_mismatch`` vectors (e.g. wrong-key decrypt) must NOT reproduce
       ``expected_hex`` -- the genuine output differs from the named value.
    3. Every other vector (KAT equality and round-trip identity, where
       ``expected_hex`` is the original plaintext) must match exactly.
    """
    args = [vector["mode"], vector["key_hex"], vector["plaintext_hex"]]
    rc, out = run_kat("kat_aes", vector, args=args)
    assert rc == 0, f"kat_aes {vector['mode']} exited {rc} for {vector['id']}"
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
