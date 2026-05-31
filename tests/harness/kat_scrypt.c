/* kat_scrypt.c - scrypt KAT driver (scrypt.inc): public symbols `scrypt` + `scrypt_iter`.
 * argv: <password> <salt_hex|-> <N> <r> <p> <dk_len>
 *   password is a PLAIN string; salt is hex (or "-" for stdin); N r p dk_len decimal.
 * TIER-2 HeavyThing regression test (NOT an RFC 7914 standards-body KAT):
 *   HeavyThing bakes N, r, p AND the PBKDF2 PRF at COMPILE TIME (ht_defaults.inc:
 *   scrypt_N=1024, scrypt_r=1, scrypt_p=1, scrypt_sha512=1 => HMAC-SHA512). RFC
 *   7914 §12's vectors require runtime-varying N/r/p (16, 1024, 16384, 1048576)
 *   AND an HMAC-SHA256 PRF, neither of which this object can honor; the two
 *   therefore produce different bytes. Reaching the RFC outputs would require
 *   either modifying HeavyThing source (the .inc tree is read-only REFERENCE per
 *   Rule R2) or a per-tuple multi-build matrix outside the single-shim /
 *   single-libht.a build model, so this primitive is scoped as a deterministic
 *   HeavyThing regression anchor (Tier-2) rather than a Tier-1 standards KAT.
 *   The argv N/r/p values are accepted for CLI-shape compatibility with the
 *   runner but DELIBERATELY IGNORED by the computation (output is HeavyThing-
 *   actual: N=1024, r=1, p=1, HMAC-SHA512 PRF); they are nonetheless strictly
 *   validated so malformed/zero/negative CLI parameters are rejected. The
 *   committed tests/vectors/scrypt.json therefore holds HeavyThing-actual
 *   self-consistency values (regression anchors), NOT RFC 7914 KAT outputs -
 *   see its "source" field and the Tier-2 section of tests/README.md.
 * Signatures (verified scrypt.inc lines 65, 446):
 *   scrypt(rdi=dest, esi=destlen, rdx=pass, ecx=passlen, r8=salt, r9d=saltlen)
 *   scrypt_iter(... same 6 ..., r10d=final_pbkdf2_iteration_count)  <- 7th arg in r10
 * Because r10 is NOT a System V arg register, scrypt_iter is reached via a tiny
 * trampoline that copies the 7th (stack) arg into r10d then tail-jumps. */
#include "ht_kat_common.h"

void scrypt(void *dest, int destlen, const void *pass, int passlen,
            const void *salt, int saltlen);
/* trampoline: 7th arg (iter) arrives at 8(%rsp) on entry per the SysV ABI. */
extern void scrypt_iter_tramp(void *dest, int destlen, const void *pass, int passlen,
                              const void *salt, int saltlen, int iter);
__asm__(
    ".globl scrypt_iter_tramp\n"
    "scrypt_iter_tramp:\n"
    "    movl 8(%rsp), %r10d\n"   /* 7th integer arg -> r10d */
    "    jmp  scrypt_iter\n"      /* tail-call; rdi/esi/rdx/ecx/r8/r9d already set */
);

static unsigned char saltb[1<<16];
static unsigned char out[4096], scratch[4096];

int main(int argc, char **argv) {
	ht_kat_init();
	if (argc < 7) {
		static const char u[] = "usage: kat_scrypt <password> <salt_hex|-> <N> <r> <p> <dk_len>  (N/r/p are compile-time in HeavyThing and ignored)\n";
		ht$syscall(1, 2L, (long)u, (long)strlen(u));   /* usage -> stderr */
		ht_kat_exit(2);
	}
	const char *pw = argv[1];
	int pwlen = (int)strlen(pw);
	int slen  = ht_kat_hex_arg(argv[2], saltb, sizeof saltb);
	if (slen < 0) ht_kat_exit(2);
	/* argv[3]=N argv[4]=r argv[5]=p: HeavyThing bakes these at compile time, so
	 * the computation IGNORES them (see file header) -- but they are still
	 * STRICTLY VALIDATED here so malformed / zero / negative CLI parameters are
	 * rejected with a non-zero exit rather than silently accepted. dk_len is a
	 * strict decimal in [1, sizeof out] (oversized is rejected, not clamped). */
	unsigned long nv, rv, pv, dkv;
	if (ht_kat_parse_uint(argv[3], 1, 0x40000000UL, &nv) != 0) ht_kat_exit(2);  /* N: [1, 2^30]    */
	if (ht_kat_parse_uint(argv[4], 1, 0x7fffffffUL, &rv) != 0) ht_kat_exit(2);  /* r: [1, INT_MAX] */
	if (ht_kat_parse_uint(argv[5], 1, 0x7fffffffUL, &pv) != 0) ht_kat_exit(2);  /* p: [1, INT_MAX] */
	if (ht_kat_parse_uint(argv[6], 1, sizeof out, &dkv) != 0) ht_kat_exit(2);   /* dk_len: [1, sizeof out] */
	(void)nv; (void)rv; (void)pv;   /* validated above; computation uses compile-time N/r/p */
	int dklen = (int)dkv;

	/* primary path -> emitted */
	scrypt(out, dklen, pw, pwlen, saltb, slen);

	/* coverage of scrypt_iter: with iter=1 it equals scrypt(); output discarded. */
	scrypt_iter_tramp(scratch, dklen, pw, pwlen, saltb, slen, 1);

	ht_kat_hex_print(out, (unsigned long)dklen);
	ht_kat_exit(0);
	return 0;
}
