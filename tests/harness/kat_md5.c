/* kat_md5.c - MD5 KAT driver (md5.inc).
 * argv (digest): <input_hex|-> [split_at]      ("-" => read hex from stdin)
 * argv (MGF1)  : mgf1 <seed_hex|-> <mask_len>
 * Covers md5$ new/init/update/final/mgf1 (transform reached via update).
 *
 * Digest mode emits lowercase hex of the 16-byte MD5 digest. MGF1 mode emits
 * lowercase hex of the <mask_len>-byte RFC 2437 mask, so md5$mgf1's KNOWN
 * ANSWER is asserted by the runner (assert_hex_equal) rather than merely
 * exercised for symbol coverage. Usage/argument errors are written to stderr
 * (fd 2) and exit non-zero (2). */
#include "ht_kat_common.h"

void *md5$new(void);
void  md5$init(void *ctx);
void  md5$update(void *ctx, const void *buf, long len);
void  md5$final(void *ctx, void *out, int destroy);
void  md5$mgf1(const void *seed, long seedlen, void *dst, long dstlen);

#define DLEN 16

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
            "usage: kat_md5 <input_hex|-> [split_at]  |  kat_md5 mgf1 <seed_hex|-> <mask_len>\n";
        ht$syscall(1, 2L, (long)u, (long)strlen(u));   /* usage -> stderr */
        ht_kat_exit(2);
    }

    /* MGF1 mask-generation mode: emit the mask so its known answer is asserted. */
    if (streq(argv[1], "mgf1")) {
        if (argc < 4) {
            static const char u[] = "usage: kat_md5 mgf1 <seed_hex|-> <mask_len>\n";
            ht$syscall(1, 2L, (long)u, (long)strlen(u));
            ht_kat_exit(2);
        }
        int  sl = ht_kat_hex_arg(argv[2], in, sizeof in);   /* seed bytes */
        unsigned long ml;                                   /* requested mask len */
        /* mask_len must be a strict decimal in [1, sizeof mask]; reject
         * malformed / out-of-range rather than silently coercing. */
        if (sl < 0 || ht_kat_parse_uint(argv[3], 1, sizeof mask, &ml) != 0)
            ht_kat_exit(2);
        md5$mgf1(in, sl, mask, (long)ml);
        ht_kat_hex_print(mask, (size_t)ml);
        ht_kat_exit(0);
    }

    /* Digest mode (happy / edge / chained-update). */
    int n = ht_kat_hex_arg(argv[1], in, sizeof in);
    if (n < 0) ht_kat_exit(2);
    /* Optional split offset: absent => -1 (single update). When present it must
     * be a strict decimal in [0, n]; malformed / out-of-range exits non-zero. */
    long split = -1;
    if (argc >= 3) {
        unsigned long sv;
        if (ht_kat_parse_uint(argv[2], 0, (unsigned long)n, &sv) != 0) ht_kat_exit(2);
        split = (long)sv;
    }

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
    md5$final(c, d2, 1);                        /* destroy now (d2 discarded) */

    ht_kat_hex_print(d, DLEN);
    ht_kat_exit(0);
    return 0;
}
