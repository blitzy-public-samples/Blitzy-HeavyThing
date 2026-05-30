"""KAT runner for bigint arithmetic (``bigint.inc``, the ``bigint$`` family)
vs Knuth TAoCP Vol. 2 §4.3 multiple-precision arithmetic identities.

bigint underpins RSA/DSA/DH, so correctness is asserted via algebraic
identities -- ``(a+b)-b == a``, ``(a*b)/b == a``, ``a mod b``, and
``gcd``-driven ``mod_inverse`` existence. Each vector in
``tests/vectors/bigint.json`` is fanned out into one parametrized case that
subprocess-invokes ``build/bin/kat_bigint <op> <a_hex> [b_hex]`` and asserts
the lowercase-hex stdout against ``expected_hex``. ``op`` is one of
``add``/``sub``/``mul``/``div``/``mod``/``mod_inverse`` (binary) or
``isprime``/``isprime2`` (unary, ``01``/``00``); ``div`` emits the quotient
(the vector's ``remainder_hex`` is informational and unchecked). All
big-number logic is in the C harness + assembly; this module only dispatches
and compares hex -- no mocks (bigint ops are pure functions of their operands).

Two harness bridges live in ``_args`` / ``test_kat``:

* Sign: vectors carry magnitudes unsigned with the sign out-of-band in
  ``a_negative`` / ``b_negative`` / ``expected_negative``; ``kat_bigint``
  reads/writes a leading ``-``, so the runner re-attaches it on both sides.
* ``isprime2``: the harness unary path runs both ``bigint$isprime`` and
  ``bigint$isprime2`` and accepts only the ``isprime`` selector, so those
  vectors dispatch there but keep the ``isprime2`` id prefix for ``-k``.
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# Load the committed Knuth §4.3 identity KAT array once at import time; a
# missing or malformed fixture surfaces now, not as an empty parametrize.
VECTORS = load_vectors("bigint")

# Node ids carry the op prefix so ``-k "mul"``, ``-k "mod_inverse"``, or
# ``-k "isprime2"`` select coherent subsets, e.g.
# ``test_kat[add-happy_path-knuth_add_large]``.
IDS = [param_id(vector, prefix=vector["op"]) for vector in VECTORS]


def _args(vector):
    """Build ``kat_bigint`` argv for a vector.

    The first token is the op selector (``isprime2`` is dispatched to the
    harness ``isprime`` path, which exercises both primality symbols). Each
    operand gets a leading ``-`` when its out-of-band ``*_negative`` flag is
    set; ``b_hex`` is appended only when present (unary ops omit it).
    """
    op = vector["op"]
    selector = "isprime" if op == "isprime2" else op
    a = ("-" if vector.get("a_negative") else "") + vector["a_hex"]
    args = [selector, a]
    b_hex = vector.get("b_hex")
    if b_hex:
        args.append(("-" if vector.get("b_negative") else "") + b_hex)
    return args


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_kat(vector):
    """Run one bigint KAT vector through ``kat_bigint`` and assert its hex.

    Uniform dispatch (matching every other ``test_*`` runner):

    1. The harness must exit 0 (clean run; no usage error, no crash).
    2. ``expect_mismatch`` vectors (the non-coprime ``mod_inverse``, which
       has no solution) must NOT reproduce ``expected_hex``.
    3. Every other vector -- arithmetic identity, edge case, ``div``
       quotient, and ``isprime``/``isprime2`` boolean -- must match exactly.
    """
    rc, out = run_kat("kat_bigint", vector, args=_args(vector))
    assert rc == 0, f"kat_bigint {vector['op']} exited {rc} for {vector['id']}"
    sign = "-" if vector.get("expected_negative") else ""
    expected = sign + vector["expected_hex"]
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != expected, (
            f"{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, expected)
