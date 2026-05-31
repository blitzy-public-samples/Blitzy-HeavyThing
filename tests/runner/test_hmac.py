"""KAT runner for HMAC (``hmac.inc``, the ``hmac$new_<hash>`` family over six
hashes) vs RFC 2202 (MD5, SHA-1), RFC 4231 (SHA-224/256/384/512) and
FIPS 198-1, with negative coverage (tampered MAC, wrong key).

Six per-hash fixtures (``hmac_md5.json`` ... ``hmac_sha512.json``) are loaded
once each and fanned out into one case per ``(hash, vector)`` pair. Each case
subprocess-invokes ``build/bin/kat_hmac <hash> <key_hex> <data_hex>`` (which
drives ``hmac$new_<hash>`` -> ``$key`` -> ``$data`` -> ``$final`` and prints
the lowercase-hex MAC) and asserts that output against ``expected_hex``:

* ``happy_path`` / ``edge_case_*`` / ``state_reset`` -> HMAC(key, data) match.
* ``negative_*`` (``expect_mismatch``) -> the genuine MAC must NOT reproduce
  the named tampered / original-key value.
* ``state_replace_key`` -> ``expected_hex`` is HMAC(key2, data); since the
  harness emits HMAC(arg_key, data), this category is driven with ``key2_hex``.
* ``prf_phash`` / ``prf_phash_xor`` -> ``expected_hex`` is a TLS 1.2 P_hash
  stream; ``kat_hmac`` is invoked in its PRF mode
  (``<hash> <key_hex> phash <seed_hex> <out_len>``, and the ``phash_xor`` form
  with a trailing ``<xor_in_hex>`` preload) so it emits the ``hmac$phash`` /
  ``hmac$phash_xor`` output as lowercase hex, which is asserted against
  ``expected_hex`` exactly like every other category (AAP 0.3.1 / 0.4.2;
  Rule 5 -- every committed vector is subprocess-run and stdout-asserted, none
  skipped).

The bare hash (e.g. ``sha256``) is the harness ``argv[1]`` selector while the
node-id prefix is the file stem (``hmac_sha256``), so ``-k "hmac_sha256 and
negative"`` stays selectable. Pure standard library + pytest (no mocks: HMAC
is a pure function of key and data); this module only loads vectors, drives
the subprocess, and compares hex.
"""

import pytest

from ._harness import load_vectors, run_kat, assert_hex_equal, param_id

# The six HMAC hash variants, each backed by its own committed vector file
# (md5 / sha1 -> RFC 2202; sha224 / sha256 / sha384 / sha512 -> RFC 4231). The
# tuple order also fixes the parametrization order (all md5 cases first, ...).
HASHES = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")

# Load each hash's KAT array exactly once (one disk read per file, reused for
# both PARAMS and IDS); a missing/malformed fixture surfaces immediately
# rather than as an empty parametrize.
_BY_HASH = {hash_name: load_vectors("hmac_" + hash_name)
            for hash_name in HASHES}

# Flat (hash, vector) pairs and matching node ids. Each id is prefixed with the
# file stem "hmac_<hash>" (NOT the bare argv selector) so node ids stay
# globally unique across the six files and ``-k "hmac_sha256 and negative"``
# selects a coherent subset, e.g.
# test_kat[hmac_sha256-negative_wrong_key-negative_wrong_key].
PARAMS = [(hash_name, vector)
          for hash_name in HASHES for vector in _BY_HASH[hash_name]]
IDS = [param_id(vector, prefix="hmac_" + hash_name)
       for hash_name in HASHES for vector in _BY_HASH[hash_name]]


def _args(hash_name, vector):
    """Build the ``kat_hmac`` argv for ``vector``.

    Three argv shapes, selected by category:

    * ``prf_phash`` -> ``[<hash>, <key_hex>, "phash", <seed_hex>, <out_len>]``
    * ``prf_phash_xor`` -> the above with ``"phash_xor"`` and a trailing
      ``<xor_in_hex>`` (the bytes the P_hash stream is XORed into; its length
      must equal ``out_len``).
    * everything else (MAC mode) -> ``[<hash>, <key_hex>, <data_hex>]``.

    ``state_replace_key`` expects HMAC(key2, data) and the harness emits
    HMAC(arg_key, data), so that category is driven with ``key2_hex``; all
    others use ``key_hex``. Defensive ``.get`` keeps an empty/omitted key or
    data field from raising ``KeyError`` (empty fields pass through as ``""``).
    """
    cat = vector["category"]
    if cat == "prf_phash":
        return [hash_name, vector["key_hex"], "phash",
                vector["seed_hex"], str(vector["out_len"])]
    if cat == "prf_phash_xor":
        return [hash_name, vector["key_hex"], "phash_xor",
                vector["seed_hex"], str(vector["out_len"]),
                vector["xor_in_hex"]]
    if cat == "state_replace_key":
        key = vector["key2_hex"]
    else:
        key = vector.get("key_hex", "")
    return [hash_name, key, vector.get("data_hex", "")]


@pytest.mark.parametrize("hash_name,vector", PARAMS, ids=IDS)
def test_kat(hash_name, vector):
    """Run one HMAC KAT vector through ``kat_hmac`` and assert its hex output.

    The harness must exit 0; ``expect_mismatch`` vectors (tampered MAC, wrong
    key) must NOT reproduce ``expected_hex``; every other vector -- digest,
    ``state_reset``, re-keyed ``state_replace_key``, and the ``prf_phash`` /
    ``prf_phash_xor`` TLS P_hash streams (driven via ``kat_hmac``'s PRF mode,
    see ``_args``) -- must match ``expected_hex``.
    """
    rc, out = run_kat("kat_hmac", vector, args=_args(hash_name, vector))
    assert rc == 0, f"kat_hmac {hash_name} exited {rc} for {vector['id']}"
    if vector.get("expect_mismatch"):
        assert out.strip().lower() != vector["expected_hex"], (
            f"{hash_name}/{vector['id']}: unexpectedly matched expected_hex"
        )
    else:
        assert_hex_equal(out, vector["expected_hex"])
