/* kat_pbkdf2.c - PBKDF2 KAT driver (pbkdf2.inc), all 13 public symbols.
 * argv: <hash> <password> <salt_hex|-> <iterations> <dk_len>
 *   hash in {md5,sha1,sha224,sha256,sha384,sha512}; password is a PLAIN string
 *   (raw bytes via strlen); salt is hex (or "-" to slurp hex from stdin);
 *   iterations and dk_len are decimal.
 * Coverage (100% of the 13 public symbols):
 *   - 6x pbkdf2$new_<hash>  (one selected per run)
 *   - 6x pbkdf2$init_<hash> (one selected per run; caller-supplied buffer)
 *   - pbkdf2$doit           (driven by both the new- and init-built objects)
 * Primary path (its output is emitted): pbkdf2$new_<hash>(pw,pwlen) -> pbkdf2$doit.
 * Coverage path (output discarded, cheap iter=1): pbkdf2$init_<hash>(buf,pw,pwlen) -> pbkdf2$doit.
 * DEVIATION NOTE: pbkdf2$doit drives the underlying HMAC through function pointers, so
 *   PBKDF2-HMAC-SHA224/384/512 inherit HeavyThing's HMAC deviation and will NOT match
 *   published RFC values; PBKDF2-HMAC-SHA1/SHA256/MD5 DO match RFC 6070 / RFC 7914. */
#include "ht_kat_common.h"

void *pbkdf2$new_md5(const void*, int);    void pbkdf2$init_md5(void*, const void*, int);
void *pbkdf2$new_sha1(const void*, int);   void pbkdf2$init_sha1(void*, const void*, int);
void *pbkdf2$new_sha224(const void*, int); void pbkdf2$init_sha224(void*, const void*, int);
void *pbkdf2$new_sha256(const void*, int); void pbkdf2$init_sha256(void*, const void*, int);
void *pbkdf2$new_sha384(const void*, int); void pbkdf2$init_sha384(void*, const void*, int);
void *pbkdf2$new_sha512(const void*, int); void pbkdf2$init_sha512(void*, const void*, int);
void  pbkdf2$doit(void *obj, void *dest, int keylen, const void *salt, int saltlen, int iter);

static int streq(const char *a, const char *b){ while(*a&&*a==*b){a++;b++;} return *a==*b; }

static unsigned char saltb[1<<16];
static unsigned char out[4096], scratch[4096];
static _Alignas(64) unsigned char hmacbuf[512];   /* >= hmac_size (400) */

int main(int argc, char **argv) {
	ht_kat_init();
	if (argc < 6) {
		static const char u[] = "usage: kat_pbkdf2 <md5|sha1|sha224|sha256|sha384|sha512> <password> <salt_hex|-> <iterations> <dk_len>\n";
		ht$syscall(1, 2L, (long)u, (long)strlen(u));   /* usage -> stderr */
		ht_kat_exit(2);
	}
	const char *h  = argv[1];
	const char *pw = argv[2];
	int pwlen = (int)strlen(pw);
	int slen  = ht_kat_hex_arg(argv[3], saltb, sizeof saltb);
	int iter  = (int)ht_kat_atoi(argv[4]);
	int dklen = (int)ht_kat_atoi(argv[5]);
	if (slen < 0 || iter <= 0 || dklen <= 0) ht_kat_exit(2);
	if (dklen > (int)sizeof out) dklen = (int)sizeof out;

	void *(*f_new)(const void*, int);
	void  (*f_init)(void*, const void*, int);
	if      (streq(h,"md5"))    { f_new=pbkdf2$new_md5;    f_init=pbkdf2$init_md5;    }
	else if (streq(h,"sha1"))   { f_new=pbkdf2$new_sha1;   f_init=pbkdf2$init_sha1;   }
	else if (streq(h,"sha224")) { f_new=pbkdf2$new_sha224; f_init=pbkdf2$init_sha224; }
	else if (streq(h,"sha256")) { f_new=pbkdf2$new_sha256; f_init=pbkdf2$init_sha256; }
	else if (streq(h,"sha384")) { f_new=pbkdf2$new_sha384; f_init=pbkdf2$init_sha384; }
	else if (streq(h,"sha512")) { f_new=pbkdf2$new_sha512; f_init=pbkdf2$init_sha512; }
	else { ht_kat_exit(2); return 2; }

	/* primary path -> emitted */
	void *obj = f_new(pw, pwlen);
	pbkdf2$doit(obj, out, dklen, saltb, slen, iter);

	/* coverage path: exercise init_<hash> + doit cheaply (iter=1), output discarded */
	f_init(hmacbuf, pw, pwlen);
	pbkdf2$doit(hmacbuf, scratch, dklen, saltb, slen, 1);

	ht_kat_hex_print(out, (unsigned long)dklen);
	ht_kat_exit(0);
	return 0;
}
