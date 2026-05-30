/* kat_sha1.c - SHA-1 KAT driver (sha1.inc, sha160$ family).
 * argv: <input_hex|-> [split_at]
 * Covers sha160$ new/init/update/final/mgf1 (transform via update). */
#include "ht_kat_common.h"

void *sha160$new(void);
void  sha160$init(void *ctx);
void  sha160$update(void *ctx, const void *buf, long len);
void  sha160$final(void *ctx, void *out, int destroy);
void  sha160$mgf1(const void *seed, long seedlen, void *dst, long dstlen);

#define DLEN 20
static unsigned char in[1 << 20];

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 2) {
        static const char u[] = "usage: kat_sha1 <input_hex|-> [split_at]\n";
        ht$syscall(1, 1L, (long)u, (long)strlen(u));
        ht_kat_exit(2);
    }
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

    sha160$init(c);
    sha160$update(c, in, n);
    unsigned char d2[DLEN];
    sha160$final(c, d2, 1);

    unsigned char mask[32];
    sha160$mgf1(d, DLEN, mask, sizeof mask);

    ht_kat_hex_print(d, DLEN);
    ht_kat_exit(0);
    return 0;
}
