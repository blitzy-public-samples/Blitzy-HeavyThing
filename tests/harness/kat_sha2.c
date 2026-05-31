/* kat_sha2.c - SHA-2 family KAT driver (sha2.inc).
 * argv (digest): <variant> <input_hex|-> [split_at]
 * argv (MGF1)  : <variant> mgf1 <seed_hex|-> <mask_len>
 *   variant in {sha224,sha256,sha384,sha512}
 * Covers each variant's new/init/update/final/mgf1 (sha256/sha512 transform via update).
 * NOTE: sha224$update / sha384$update are the SAME address as sha256$update /
 * sha512$update in sha2.inc (only the sha256/sha512 names get a prolog => public),
 * so the sha224/sha384 paths call the exported sha256$update / sha512$update.
 *
 * Digest mode emits lowercase hex of the variant digest. MGF1 mode emits
 * lowercase hex of the <mask_len>-byte RFC 2437 mask, so <variant>$mgf1's KNOWN
 * ANSWER is asserted by the runner rather than merely exercised for coverage.
 * Usage/argument errors are written to stderr (fd 2) and exit non-zero (2). */
#include "ht_kat_common.h"

void *sha224$new(void); void sha224$init(void*);
void  sha224$final(void*,void*,int); void sha224$mgf1(const void*,long,void*,long);
void *sha256$new(void); void sha256$init(void*); void sha256$update(void*,const void*,long);
void  sha256$final(void*,void*,int); void sha256$mgf1(const void*,long,void*,long);
void *sha384$new(void); void sha384$init(void*);
void  sha384$final(void*,void*,int); void sha384$mgf1(const void*,long,void*,long);
void *sha512$new(void); void sha512$init(void*); void sha512$update(void*,const void*,long);
void  sha512$final(void*,void*,int); void sha512$mgf1(const void*,long,void*,long);

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static unsigned char in[1 << 20];
static unsigned char mask[256];     /* MGF1 mask; >= the largest vector mask_len (sha512: 135) */

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 3) {
        static const char u[] =
            "usage: kat_sha2 <sha224|sha256|sha384|sha512> <input_hex|-> [split_at]"
            "  |  kat_sha2 <variant> mgf1 <seed_hex|-> <mask_len>\n";
        ht$syscall(1, 2L, (long)u, (long)strlen(u));   /* usage -> stderr */
        ht_kat_exit(2);
    }
    const char *v = argv[1];

    /* Resolve the variant's function-pointer set first, so both the MGF1 and
     * digest paths share it (and an unknown variant is rejected up front). */
    void *(*f_new)(void); void (*f_init)(void*);
    void (*f_update)(void*, const void*, long); void (*f_final)(void*, void*, int);
    void (*f_mgf1)(const void*, long, void*, long);
    int dlen;
    if      (streq(v,"sha224")) { f_new=sha224$new; f_init=sha224$init; f_update=sha256$update; f_final=sha224$final; f_mgf1=sha224$mgf1; dlen=28; }
    else if (streq(v,"sha256")) { f_new=sha256$new; f_init=sha256$init; f_update=sha256$update; f_final=sha256$final; f_mgf1=sha256$mgf1; dlen=32; }
    else if (streq(v,"sha384")) { f_new=sha384$new; f_init=sha384$init; f_update=sha512$update; f_final=sha384$final; f_mgf1=sha384$mgf1; dlen=48; }
    else if (streq(v,"sha512")) { f_new=sha512$new; f_init=sha512$init; f_update=sha512$update; f_final=sha512$final; f_mgf1=sha512$mgf1; dlen=64; }
    else { ht_kat_exit(2); return 2; }

    /* MGF1 mask-generation mode: emit the mask so its known answer is asserted. */
    if (streq(argv[2], "mgf1")) {
        if (argc < 5) {
            static const char u[] = "usage: kat_sha2 <variant> mgf1 <seed_hex|-> <mask_len>\n";
            ht$syscall(1, 2L, (long)u, (long)strlen(u));
            ht_kat_exit(2);
        }
        int  sl = ht_kat_hex_arg(argv[3], in, sizeof in);   /* seed bytes */
        unsigned long ml;                                   /* requested mask len */
        /* mask_len must be a strict decimal in [1, sizeof mask]; reject
         * malformed / out-of-range rather than silently coercing. */
        if (sl < 0 || ht_kat_parse_uint(argv[4], 1, sizeof mask, &ml) != 0)
            ht_kat_exit(2);
        f_mgf1(in, sl, mask, (long)ml);
        ht_kat_hex_print(mask, (size_t)ml);
        ht_kat_exit(0);
    }

    /* Digest mode (happy / edge / chained-update). */
    int n = ht_kat_hex_arg(argv[2], in, sizeof in);
    if (n < 0) ht_kat_exit(2);
    /* Optional split offset: absent => -1 (single update). When present it must
     * be a strict decimal in [0, n]; malformed / out-of-range exits non-zero. */
    long split = -1;
    if (argc >= 4) {
        unsigned long sv;
        if (ht_kat_parse_uint(argv[3], 0, (unsigned long)n, &sv) != 0) ht_kat_exit(2);
        split = (long)sv;
    }

    void *c = f_new();
    if (split >= 0 && split <= n) {
        f_update(c, in, split);
        f_update(c, in + split, n - split);
    } else {
        f_update(c, in, n);
    }
    unsigned char d[64];
    f_final(c, d, 0);

    f_init(c);                                 /* explicit re-init coverage */
    f_update(c, in, n);
    unsigned char d2[64];
    f_final(c, d2, 1);                          /* destroy now (d2 discarded) */

    ht_kat_hex_print(d, dlen);
    ht_kat_exit(0);
    return 0;
}
