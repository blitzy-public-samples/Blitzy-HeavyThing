"""KAT runner for the SHA-2 family (``sha2.inc``: ``sha224$`` / ``sha256$`` /
``sha384$`` / ``sha512$``) vs NIST FIPS 180-4 + CAVP vectors.

Four per-variant fixtures (``sha224.json`` / ``sha256.json`` / ``sha384.json``
/ ``sha512.json``) are loaded once each and fanned out into one case per
``(variant, vector)`` pair. Each case subprocess-invokes ``build/bin/kat_sha2
<variant> ...`` and asserts the lowercase-hex stdout against ``expected_hex``:

* ``happy_path`` / ``edge_case_*`` -> ``<variant> <input_hex>`` drives
  ``<variant>$new`` -> ``$update`` -> ``$final`` (the variant digest).
* ``chained_update`` -> a trailing ``split_at`` offset drives two ``$update``
  calls; the digest must equal the single-update result (AAP §0.1.4 / §0.4.2).
* ``mgf1`` -> ``<variant> mgf1 <seed_hex> <mask_len>`` emits the RFC 2437 MGF1
  mask via ``<variant>$mgf1`` (AAP §0.3.1 cross-variant coverage).

A single harness binary handles all four variants via its ``argv[1]``
selector, so this runner passes the variant verbatim as the first argument.
Pure standard library + pytest (no mocks: each variant is a pure function of
its input); this module only loads vectors, drives the subprocess, compares.
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# The four SHA-2 variants, each backed by its own committed vector file; the
# tuple order also fixes the parametrization order (sha224 cases first, ...).
VARIANTS = ("sha224", "sha256", "sha384", "sha512")

# Load every variant's KAT array exactly once (one disk read per file, reused
# for both PARAMS and IDS); a missing/malformed fixture surfaces immediately.
_BY_VARIANT = {variant: load_vectors(variant) for variant in VARIANTS}

# Flat (variant, vector) pairs and matching node ids. Prefixing each id with
# its variant keeps node ids globally unique (the four files reuse identical
# vector ids) and lets ``-k "sha256 and edge_case"`` select coherent subsets,
# e.g. test_kat[sha512-edge_case_block_boundary-block_boundary_128].
PARAMS = [(variant, vector)
          for variant in VARIANTS for vector in _BY_VARIANT[variant]]
IDS = [param_id(vector, prefix=variant)
       for variant in VARIANTS for vector in _BY_VARIANT[variant]]


def _args(variant, vector):
    """Build the ``kat_sha2`` argv for one ``(variant, vector)`` pair.

    ``mgf1`` vectors use the ``mgf1 <seed_hex> <mask_len>`` mask-generation
    mode so the harness emits the generated mask; ``chained_update`` vectors
    append the ``split_at`` byte offset for a two-call ``update`` split; every
    other category passes the single positional ``input_hex`` for a one-shot
    digest. The variant string is always the first argument (the harness's
    code-path selector).
    """
    if vector["category"] == "mgf1":
        return [variant, "mgf1", vector["input_hex"], str(vector["mask_len"])]
    args = [variant, vector["input_hex"]]
    if "split_at" in vector:
        args.append(str(vector["split_at"]))
    return args


@pytest.mark.parametrize("variant,vector", PARAMS, ids=IDS)
def test_kat(variant, vector):
    """Run one SHA-2 KAT vector through ``kat_sha2`` and assert its hex output.

    Uniform dispatch across every category:

    1. The harness must exit 0 (clean run; no usage error, no crash).
    2. ``expect_mismatch`` vectors must NOT reproduce ``expected_hex``.
    3. Every other vector -- digest, ``chained_update``, and ``mgf1`` (whose
       ``expected_hex`` is the generated mask) -- must match exactly.
    """
    rc, out = run_kat("kat_sha2", vector, args=_args(variant, vector))
    assert rc == 0, f"kat_sha2 {variant} exited {rc} for {vector['id']}"
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{variant}/{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
