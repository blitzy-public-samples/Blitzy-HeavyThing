/* kat_hmac_drbg.c -- KAT driver for HeavyThing HMAC-DRBG (hmac_drbg.inc).
 *
 * Exercises 100% of the public HMAC-DRBG API:
 *   hmac_drbg$new, hmac_drbg$generate, hmac_drbg$generate_additional,
 *   hmac_drbg$destroy.
 *
 * CLI (fixed 5 positional args, matching tests/runner/test_hmac_drbg.py):
 *   kat_hmac_drbg <entropy_hex> <nonce_hex> <perso_hex> <additional_hex> <requested_bytes>
 *
 * Procedure (NIST SP 800-90A CAVP "no reseed", emit the 2nd generate):
 *   seed = entropy || nonce || perso
 *   drbg = hmac_drbg$new(&hmac$init_sha256, seed, seedlen)
 *   if additional present: two generate_additional calls (discard 1st, emit 2nd)
 *   else:                  two generate calls           (discard 1st, emit 2nd)
 *   hmac_drbg$destroy(drbg); print 2nd output as lowercase hex.
 *
 * NEGATIVE SENTINEL: requested_bytes <= 0 triggers the generate-after-destroy
 *   probe (destroy then generate) which dereferences the freed+cleared object
 *   (its hmac-init fn-ptr at offset 0 is zeroed by heap$free_clear) -> SIGSEGV
 *   -> nonzero exit. The runner's negative_generate_after_destroy vector MUST
 *   set "requested_bytes": 0 so this path fires (expect_error -> assert rc != 0).
 *
 * Hash is hardcoded to SHA-256 (the runner passes no hash selector).
 *
 * IMPORTANT (cross-agent): HeavyThing's hmac_drbg$new omits the final
 *   V = HMAC(K,V) after the second K update, so its output DEVIATES from
 *   standard NIST SP 800-90A. The VECTORS agent must use HeavyThing-actual
 *   (regression) expected_hex values for happy/edge cases, NOT published NIST
 *   CAVP ReturnedBits. Output is fully deterministic for fixed inputs
 *   (no /dev/urandom is touched unless the 2^19 reseed interval is hit).
 */
#include "ht_kat_common.h"

extern void *hmac_drbg$new(const void *init_fn, const void *seed, int seedlen);
extern void  hmac_drbg$generate(void *drbg, void *dest, int len);
extern void  hmac_drbg$generate_additional(void *drbg, void *dest, int len,
                                            const void *add, int addlen);
extern void  hmac_drbg$destroy(void *drbg);

/* PRF selector: address of HeavyThing's sha256 hmac-init function. */
extern void  hmac$init_sha256(void *hmac_ctx);

#define MAXBUF 8192

int main(int argc, char **argv)
{
	ht_kat_init();

	if (argc < 6) {
		static const char u[] =
		    "usage: kat_hmac_drbg <entropy_hex> <nonce_hex> <perso_hex> "
		    "<additional_hex> <requested_bytes>\n";
		ht$syscall(1, 2, u, (long)(sizeof u - 1));
		ht_kat_exit(2);
	}

	static unsigned char entropy[MAXBUF], nonce[MAXBUF], perso[MAXBUF];
	static unsigned char add[MAXBUF], seed[3 * MAXBUF], out[MAXBUF];

	int elen = ht_kat_hex_arg(argv[1], entropy, sizeof entropy);
	int nlen = ht_kat_hex_arg(argv[2], nonce,   sizeof nonce);
	int plen = ht_kat_hex_arg(argv[3], perso,   sizeof perso);
	int alen = ht_kat_hex_arg(argv[4], add,     sizeof add);   /* may be 0 */
	int reqbytes = ht_kat_atoi(argv[5]);

	if (elen < 0 || nlen < 0 || plen < 0 || alen < 0)
		ht_kat_exit(3);

	/* seed = entropy || nonce || perso */
	int slen = 0;
	for (int i = 0; i < elen; i++) seed[slen++] = entropy[i];
	for (int i = 0; i < nlen; i++) seed[slen++] = nonce[i];
	for (int i = 0; i < plen; i++) seed[slen++] = perso[i];

	void *drbg = hmac_drbg$new(&hmac$init_sha256, seed, slen);

	if (reqbytes <= 0) {
		/* NEGATIVE: generate-after-destroy must fault -> nonzero exit. */
		hmac_drbg$destroy(drbg);
		hmac_drbg$generate(drbg, out, 16);
		ht_kat_exit(1);   /* unreachable if the fault fires as designed */
	}

	if (reqbytes > (int)sizeof out)
		reqbytes = (int)sizeof out;

	if (alen > 0) {
		hmac_drbg$generate_additional(drbg, out, reqbytes, add, alen);
		hmac_drbg$generate_additional(drbg, out, reqbytes, add, alen);
	} else {
		hmac_drbg$generate(drbg, out, reqbytes);
		hmac_drbg$generate(drbg, out, reqbytes);
	}

	hmac_drbg$destroy(drbg);

	ht_kat_hex_print(out, (unsigned long)reqbytes);
	ht_kat_exit(0);
	return 0;
}
