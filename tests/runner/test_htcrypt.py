"""KAT runner for htcrypt (``htcrypt.inc``, the ``htcrypt$`` family).

Validates HeavyThing's htcrypt -- a custom 16-byte block cipher built as a
64-deep AES-256 cascade -- against the only authoritative property it has:
round-trip identity. htcrypt is not a published standard, so there is no
external byte-for-byte KAT; correctness is instead asserted by
``decrypt(encrypt(p)) == p`` (AAP 0.4.2 "Component: htcrypt"). The harness runs
the full round trip (or a ``hide``/``show`` state wrap+unwrap before it) and
emits the recovered plaintext, so ``expected_hex`` equals ``plaintext_hex`` for
every positive case.

Each vector in ``tests/vectors/htcrypt.json`` is fanned out into one
parametrized case that subprocess-invokes the harness as
``kat_htcrypt <operation> <key_type> <secret> <plaintext_hex> [wrong_secret]``
and asserts its lowercase-hex stdout against ``expected_hex``. ``operation`` is
``round_trip`` or ``hide_show`` (a ``htcrypt$hide`` / ``htcrypt$show`` state
wrap before the round trip); ``key_type`` selects the constructor so that
``passphrase`` / ``keymaterial`` / ``raw_keymaterial`` / ``useless`` together
reach all four ``htcrypt$new_*`` entry points plus ``htcrypt$encrypt``,
``htcrypt$decrypt`` and ``htcrypt$destroy`` (AAP 0.3.1 -- 100% public API).
``wrong_secret`` appears only on the negative ``expect_mismatch`` cases, where
decrypt under a different key MUST NOT recover the plaintext, proving the
cipher is genuinely key-dependent.

Pure stdlib + pytest, no mocks (htcrypt is a pure function of key and data).
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# Load the committed htcrypt round-trip KAT array at import time; a missing or
# malformed fixture surfaces now rather than as an empty parametrize.
VECTORS = load_vectors("htcrypt")

# Node ids carry the key_type prefix so ``-k "passphrase"`` / ``-k "negative"``
# select coherent subsets, e.g.
# ``test_kat[passphrase-happy_path-rt_passphrase_single]``.
IDS = [param_id(vector, prefix=vector.get("key_type")) for vector in VECTORS]


def _args(vector):
    """Build ``kat_htcrypt`` argv for a vector, matching ``kat_htcrypt.c``.

    Fixed order ``<operation> <key_type> <secret> <plaintext_hex>``, with an
    optional trailing ``wrong_secret`` appended only when the vector carries it
    (the negative wrong-key path). Optional fields use defensive defaults since
    not every category populates every field.
    """
    args = [
        vector.get("operation", "round_trip"),
        vector.get("key_type", "passphrase"),
        vector.get("secret", ""),
        vector["plaintext_hex"],
    ]
    if "wrong_secret" in vector:
        args.append(vector["wrong_secret"])
    return args


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_kat(vector):
    """Run a htcrypt KAT vector through ``kat_htcrypt`` and assert its output.

    Uniform dispatch (matching every other ``test_*`` runner):

    1. The harness must exit 0 (clean run; no usage error, no crash).
    2. ``expect_mismatch`` vectors (wrong-key decrypt) must NOT reproduce
       ``expected_hex`` -- the recovered bytes genuinely differ from plaintext.
    3. Every other vector (round-trip identity and hide/show, where
       ``expected_hex`` is the original plaintext) must match exactly.
    """
    rc, out = run_kat("kat_htcrypt", vector, args=_args(vector))
    assert rc == 0, f"kat_htcrypt exited {rc} for {vector['id']}"
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{vector['id']}: wrong-key decrypt recovered the plaintext"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
