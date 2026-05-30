/* kat_scrypt.c - scrypt KAT driver (scrypt.inc): public symbols `scrypt` + `scrypt_iter`.
 * argv: <password> <salt_hex|-> <N> <r> <p> <dk_len>
 *   password is a PLAIN string; salt is hex (or "-" for stdin); N r p dk_len decimal.
 * CRITICAL CAVEAT: HeavyThing bakes N/r/p AND the underlying PRF at COMPILE TIME
 *   (ht_defaults.inc: scrypt_N=1024, scrypt_r=1, scrypt_p=1, scrypt_sha512=1).
 *   The object cannot vary them at runtime, so the argv N/r/p values are accepted
 *   for CLI-shape compatibility with the runner but DELIBERATELY IGNORED. Output is
 *   therefore HeavyThing-actual (N=1024,r=1,p=1, HMAC-SHA512-based PBKDF2), which will
 *   NOT match RFC 7914 vectors (those use HMAC-SHA256 and other N). VECTORS agent must
 *   capture HeavyThing-actual (regression) expected_hex from this binary.
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
		ht$syscall(1, 1L, (long)u, (long)strlen(u));
		ht_kat_exit(2);
	}
	const char *pw = argv[1];
	int pwlen = (int)strlen(pw);
	int slen  = ht_kat_hex_arg(argv[2], saltb, sizeof saltb);
	/* argv[3]=N argv[4]=r argv[5]=p intentionally ignored (compile-time constants) */
	int dklen = (int)ht_kat_atoi(argv[6]);
	if (slen < 0 || dklen <= 0) ht_kat_exit(2);
	if (dklen > (int)sizeof out) dklen = (int)sizeof out;

	/* primary path -> emitted */
	scrypt(out, dklen, pw, pwlen, saltb, slen);

	/* coverage of scrypt_iter: with iter=1 it equals scrypt(); output discarded. */
	scrypt_iter_tramp(scratch, dklen, pw, pwlen, saltb, slen, 1);

	ht_kat_hex_print(out, (unsigned long)dklen);
	ht_kat_exit(0);
	return 0;
}
