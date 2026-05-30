/* kat_md5.c - MD5 KAT driver (md5.inc).
 * argv: <input_hex|-> [split_at]      ("-" => read hex from stdin)
 * Covers md5$ new/init/update/final/mgf1 (transform reached via update).
 * Emits lowercase hex of the 16-byte digest. */
#include "ht_kat_common.h"

void *md5$new(void);
void  md5$init(void *ctx);
void  md5$update(void *ctx, const void *buf, long len);
void  md5$final(void *ctx, void *out, int destroy);
void  md5$mgf1(const void *seed, long seedlen, void *dst, long dstlen);

#define DLEN 16
static unsigned char in[1 << 20];   /* up to 1 MB input */

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 2) {
        static const char u[] = "usage: kat_md5 <input_hex|-> [split_at]\n";
        ht$syscall(1, 1L, (long)u, (long)strlen(u));
        ht_kat_exit(2);
    }
    int n = ht_kat_hex_arg(argv[1], in, sizeof in);
    if (n < 0) ht_kat_exit(2);
    long split = (argc >= 3) ? ht_kat_atoi(argv[2]) : -1;

    void *c = md5$new();                       /* new() => init() internally */
    if (split >= 0 && split <= n) {
        md5$update(c, in, split);
        md5$update(c, in + split, n - split);  /* chained update */
    } else {
        md5$update(c, in, n);
    }
    unsigned char d[DLEN];
    md5$final(c, d, 0);                         /* keep ctx to exercise init() */

    md5$init(c);                               /* explicit re-init coverage */
    md5$update(c, in, n);
    unsigned char d2[DLEN];
    md5$final(c, d2, 1);                        /* destroy now */

    unsigned char mask[32];
    md5$mgf1(d, DLEN, mask, sizeof mask);       /* mgf1 coverage (output unused) */

    ht_kat_hex_print(d, DLEN);
    ht_kat_exit(0);
    return 0;
}
