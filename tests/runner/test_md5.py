"""KAT runner for MD5 (``md5.inc``, the ``md5$`` family) vs RFC 1321 §A.5.

Each vector in ``tests/vectors/md5.json`` is fanned out into one parametrized
case that subprocess-invokes ``build/bin/kat_md5 <input_hex> [split_at]`` and
asserts the harness's lowercase-hex stdout against ``expected_hex``:

* ``happy_path`` / ``edge_case_*`` -> a single ``md5$update`` over
  ``input_hex``; stdout is the canonical 32-hex-char MD5 digest.
* ``chained_update`` -> a second positional ``split_at`` arg drives two
  ``md5$update`` calls split at that byte offset; the digest must still equal
  the single-update result (chunked-feed equivalence, AAP §0.1.4 / §0.4.2).
* ``mgf1`` -> ``expected_hex`` holds an RFC 2437 MGF1 *mask*. The kat_md5
  harness prints the MD5 *digest* and exercises ``md5$mgf1`` internally for
  symbol coverage (the mask itself is not emitted on stdout), so a clean exit
  is the verifiable signal for these vectors -- the mask bytes are not
  asserted here.

Pure standard library + pytest (no mocks: MD5 is a pure function of its
input). All crypto and hex formatting live in the C harness; this module only
loads vectors, drives the subprocess, and compares hex.
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# Load the committed RFC 1321 KAT array once at import time; a missing or
# malformed fixture surfaces immediately rather than as an empty parametrize.
VECTORS = load_vectors("md5")

# Node ids are "<category>-<id>" (MD5 has no extra variant dimension), so -k
# filters like "block_boundary", "chained_update", or "mgf1" select coherent
# subsets, e.g. test_kat[edge_case_block_boundary-block_boundary_64].
IDS = [param_id(vector) for vector in VECTORS]


def _args(vector):
    """Build kat_md5 argv: ``<input_hex>`` plus ``split_at`` when present.

    The ``split_at`` byte offset is supplied only for ``chained_update``
    vectors; every other category passes the single positional ``input_hex``.
    """
    args = [vector["input_hex"]]
    if "split_at" in vector:
        args.append(str(vector["split_at"]))
    return args


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_kat(vector):
    """Run one MD5 KAT vector through ``kat_md5`` and assert its hex output.

    Uniform dispatch across every category:

    1. The harness must exit 0 (clean run; ``md5$mgf1`` is exercised on every
       invocation for symbol coverage).
    2. ``mgf1`` vectors carry an MGF1 mask in ``expected_hex`` that the
       digest-only harness does not emit, so a clean exit is their signal.
    3. ``expect_mismatch`` vectors must NOT reproduce ``expected_hex``.
    4. Every other vector must match its canonical digest exactly.
    """
    rc, out = run_kat("kat_md5", vector, args=_args(vector))
    assert rc == 0, f"kat_md5 exited {rc} for {vector['id']}"
    if vector["category"] == "mgf1":
        return
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
