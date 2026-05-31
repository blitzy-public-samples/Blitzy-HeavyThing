/* kat_hmac.c - HMAC KAT driver (hmac.inc), all 20 public symbols.
 * MAC mode : <hash> <key_hex|-> <data_hex>   hash in {md5,sha1,sha224,sha256,sha384,sha512}
 *            Emits lowercase hex of the MAC (macsize bytes). Negative cases
 *            (tampered MAC, wrong key) are decided by the runner comparing the
 *            emitted hex, not by exit status, so this path always exits 0.
 * PRF mode : <hash> <key_hex|-> phash     <seed_hex|-> <out_len>
 *            <hash> <key_hex|-> phash_xor <seed_hex|-> <out_len> <xor_in_hex>
 *            Emits lowercase hex of the TLS-1.2 P_hash stream produced by
 *            hmac$phash / hmac$phash_xor, so the KNOWN ANSWER of those two
 *            symbols is asserted by the runner rather than only exercised.
 * Usage / unknown-hash / malformed-argument errors are written to stderr (fd 2)
 * and exit non-zero (2). */
#include "ht_kat_common.h"

void *hmac$new_md5(void);    void hmac$init_md5(void*);
void *hmac$new_sha1(void);   void hmac$init_sha1(void*);
void *hmac$new_sha224(void); void hmac$init_sha224(void*);
void *hmac$new_sha256(void); void hmac$init_sha256(void*);
void *hmac$new_sha384(void); void hmac$init_sha384(void*);
void *hmac$new_sha512(void); void hmac$init_sha512(void*);
void hmac$key(void*, const void*, int);
void hmac$replace_key(void*, const void*, int);
void hmac$data(void*, const void*, long);
void hmac$final(void*, void*);
void hmac$reset(void*);
void hmac$phash(void*, void*, int, const void*, int);
void hmac$phash_xor(void*, void*, int, const void*, int);
void hmac$destroy(void*);

static int streq(const char *a, const char *b){ while(*a&&*a==*b){a++;b++;} return *a==*b; }
static unsigned char keyb[1 << 16];
static unsigned char datab[1 << 20];
static unsigned char prfout[4096];   /* TLS P_hash output (>= every vector's out_len) */

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 4) {
        static const char u[] =
            "usage: kat_hmac <md5|sha1|sha224|sha256|sha384|sha512> <key_hex|-> <data_hex>\n"
            "   or: kat_hmac <hash> <key_hex|-> phash     <seed_hex|-> <out_len>\n"
            "   or: kat_hmac <hash> <key_hex|-> phash_xor <seed_hex|-> <out_len> <xor_in_hex>\n";
        ht$syscall(1, 2L, (long)u, (long)strlen(u));   /* usage -> stderr */
        ht_kat_exit(2);
    }
    const char *h = argv[1];

    /* Resolve the hash variant up front; both the MAC and PRF paths need it. */
    void *(*f_new)(void); void (*f_init)(void*); int macsize;
    if      (streq(h,"md5"))    { f_new=hmac$new_md5;    f_init=hmac$init_md5;    macsize=16; }
    else if (streq(h,"sha1"))   { f_new=hmac$new_sha1;   f_init=hmac$init_sha1;   macsize=20; }
    else if (streq(h,"sha224")) { f_new=hmac$new_sha224; f_init=hmac$init_sha224; macsize=28; }
    else if (streq(h,"sha256")) { f_new=hmac$new_sha256; f_init=hmac$init_sha256; macsize=32; }
    else if (streq(h,"sha384")) { f_new=hmac$new_sha384; f_init=hmac$init_sha384; macsize=48; }
    else if (streq(h,"sha512")) { f_new=hmac$new_sha512; f_init=hmac$init_sha512; macsize=64; }
    else { ht_kat_exit(2); return 2; }

    /* key arg honours the advertised "-" stdin convention (ht_kat_hex_arg). */
    int klen = ht_kat_hex_arg(argv[2], keyb, sizeof keyb);
    if (klen < 0) ht_kat_exit(2);

    /* TLS-1.2 P_hash (PRF) modes: emit hmac$phash / hmac$phash_xor output so its
     * KNOWN ANSWER is asserted by the runner, not merely exercised for coverage.
     * The "phash" / "phash_xor" selector in argv[3] cannot collide with a hex
     * <data_hex> (it carries non-hex letters), so it unambiguously selects PRF
     * mode over the default MAC mode:
     *   kat_hmac <hash> <key_hex|-> phash     <seed_hex|-> <out_len>
     *   kat_hmac <hash> <key_hex|-> phash_xor <seed_hex|-> <out_len> <xor_in_hex>
     * hmac$phash{,_xor}(obj, out, out_len, seed, seedlen) requires the key to be
     * set first; phash_xor XORs the P_hash stream INTO out, so out is preloaded
     * with the xor_in bytes (whose length must equal out_len). */
    if (streq(argv[3], "phash") || streq(argv[3], "phash_xor")) {
        int is_xor = streq(argv[3], "phash_xor");
        if (argc < (is_xor ? 7 : 6)) ht_kat_exit(2);
        int slen = ht_kat_hex_arg(argv[4], datab, sizeof datab);   /* seed (may be "-") */
        unsigned long olen;                                        /* requested output length */
        /* out_len must be a strict decimal in [1, sizeof prfout]; reject
         * malformed / out-of-range rather than silently coercing. */
        if (slen < 0 || ht_kat_parse_uint(argv[5], 1, sizeof prfout, &olen) != 0)
            ht_kat_exit(2);

        void *po = f_new();
        hmac$key(po, keyb, klen);
        if (is_xor) {
            int xlen = ht_kat_hex_decode(argv[6], prfout, sizeof prfout);  /* preload xor_in */
            if (xlen < 0 || xlen != (int)olen) ht_kat_exit(2);
            hmac$phash_xor(po, prfout, (int)olen, datab, slen);
        } else {
            hmac$phash(po, prfout, (int)olen, datab, slen);
        }
        hmac$destroy(po);
        ht_kat_hex_print(prfout, (size_t)olen);
        ht_kat_exit(0);
    }

    /* MAC mode (default): <hash> <key_hex|-> <data_hex>. */
    int dlen = ht_kat_hex_arg(argv[3], datab, sizeof datab);
    if (dlen < 0) ht_kat_exit(2);

    unsigned char mac[64], scratch[64];

    /* primary, clean path -> this is the emitted MAC */
    void *o = f_new();                 /* new (+init internal) */
    hmac$key(o, keyb, klen);           /* key */
    hmac$data(o, datab, dlen);         /* data */
    hmac$final(o, mac);                /* final (auto-resets the object) */

    /* coverage of the remaining symbols; outputs discarded */
    hmac$reset(o);                     /* reset */
    hmac$data(o, datab, dlen);
    hmac$final(o, scratch);
    hmac$replace_key(o, keyb, klen);   /* replace_key */
    hmac$data(o, datab, dlen);
    hmac$final(o, scratch);
    hmac$phash(o, scratch, macsize, datab, dlen);       /* phash (key still set) */
    hmac$phash_xor(o, scratch, macsize, datab, dlen);   /* phash_xor */
    f_init(o);                         /* init_<hash> explicit */
    hmac$key(o, keyb, klen);
    hmac$data(o, datab, dlen);
    hmac$final(o, scratch);
    hmac$destroy(o);                   /* destroy */

    ht_kat_hex_print(mac, macsize);
    ht_kat_exit(0);
    return 0;
}
