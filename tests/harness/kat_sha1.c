/* kat_sha1.c - SHA-1 KAT driver (sha1.inc, sha160$ family).
 * argv (digest): <input_hex|-> [split_at]      ("-" => read hex from stdin)
 * argv (MGF1)  : mgf1 <seed_hex|-> <mask_len>
 * Covers sha160$ new/init/update/final/mgf1 (transform via update).
 *
 * Digest mode emits lowercase hex of the 20-byte SHA-1 digest. MGF1 mode emits
 * lowercase hex of the <mask_len>-byte RFC 2437 mask, so sha160$mgf1's KNOWN
 * ANSWER is asserted by the runner rather than merely exercised for coverage.
 * Usage/argument errors are written to stderr (fd 2) and exit non-zero (2). */
#include "ht_kat_common.h"

void *sha160$new(void);
void  sha160$init(void *ctx);
void  sha160$update(void *ctx, const void *buf, long len);
void  sha160$final(void *ctx, void *out, int destroy);
void  sha160$mgf1(const void *seed, long seedlen, void *dst, long dstlen);

#define DLEN 20

static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

static unsigned char in[1 << 20];   /* up to 1 MB input / MGF1 seed */
static unsigned char mask[256];     /* MGF1 mask; >= the largest vector mask_len */

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 2) {
        static const char u[] =
            "usage: kat_sha1 <input_hex|-> [split_at]  |  kat_sha1 mgf1 <seed_hex|-> <mask_len>\n";
        ht$syscall(1, 2L, (long)u, (long)strlen(u));   /* usage -> stderr */
        ht_kat_exit(2);
    }

    /* MGF1 mask-generation mode: emit the mask so its known answer is asserted. */
    if (streq(argv[1], "mgf1")) {
        if (argc < 4) {
            static const char u[] = "usage: kat_sha1 mgf1 <seed_hex|-> <mask_len>\n";
            ht$syscall(1, 2L, (long)u, (long)strlen(u));
            ht_kat_exit(2);
        }
        int  sl = ht_kat_hex_arg(argv[2], in, sizeof in);   /* seed bytes */
        long ml = ht_kat_atoi(argv[3]);                     /* requested mask len */
        if (sl < 0 || ml <= 0 || ml > (long)sizeof mask) ht_kat_exit(2);
        sha160$mgf1(in, sl, mask, ml);
        ht_kat_hex_print(mask, (size_t)ml);
        ht_kat_exit(0);
    }

    /* Digest mode (happy / edge / chained-update). */
    int n = ht_kat_hex_arg(argv[1], in, sizeof in);
    if (n < 0) ht_kat_exit(2);
    long split = (argc >= 3) ? ht_kat_atoi(argv[2]) : -1;

    void *c = sha160$new();
    if (split >= 0 && split <= n) {
        sha160$update(c, in, split);
        sha160$update(c, in + split, n - split);
    } else {
        sha160$update(c, in, n);
    }
    unsigned char d[DLEN];
    sha160$final(c, d, 0);

    sha160$init(c);                            /* explicit re-init coverage */
    sha160$update(c, in, n);
    unsigned char d2[DLEN];
    sha160$final(c, d2, 1);                     /* destroy now (d2 discarded) */

    ht_kat_hex_print(d, DLEN);
    ht_kat_exit(0);
    return 0;
}
