/* kat_dsa.c - DSA parameter KAT driver (bigint.inc DSA subset).
 * argv: <p_hex> <q_hex> <g_hex>
 *   Verifies the DSA domain parameter trio and prints "01" (valid) or
 *   "00" (invalid). p,q,g are big-endian magnitude hex.
 *
 * Special generation mode (covers bigint$dsa_params; SLOW, HT_KAT_SLOW gated
 * by the runner): if argv[1] == "generate", a fresh dsa_size (3072-bit)
 * parameter set is generated with bigint$dsa_params and then checked with
 * bigint$verify_dsa_params; prints "01" on self-consistency.
 *
 * Coverage (AAP 0.3.1, 100% public API of the DSA subset):
 *   bigint$verify_dsa_params, bigint$dsa_params.
 *
 * Signatures (verified bigint.inc):
 *   bigint$verify_dsa_params(rdi=p, rsi=q, rdx=g) -> eax bool (checks p,q prime
 *     via isprime2, (p-1) mod q == 0, and g^q mod p == 1; no bit-size policy,
 *     so a small valid trio verifies TRUE).
 *   bigint$dsa_params(rdi=p, rsi=q, rdx=g) : all three WRITE-ONLY; sizes fixed
 *     by dsa_size=3072 / dsa_subgroup_size=256 atop bigint.inc. */
#include "ht_kat_common.h"

extern void *bigint$new(void);
extern void *bigint$new_encoded(const void *buf, long len);
extern void  bigint$destroy(void *bi);
extern int   bigint$verify_dsa_params(void *p, void *q, void *g);
extern void  bigint$dsa_params(void *p, void *q, void *g);

static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

static unsigned char bp[2048], bq[512], bg[2048];

static void emit_bool(int v) {
    unsigned char o = (unsigned char)(v ? 1 : 0);
    ht_kat_hex_print(&o, 1);
}

/* usage(): write the usage line to stderr (fd 2) and exit non-zero (2). */
static void usage(void) {
    static const char u[] =
        "usage: kat_dsa <p_hex> <q_hex> <g_hex>   (or: kat_dsa generate)\n";
    ht$syscall(1, 2L, (long)u, (long)strlen(u));   /* usage -> stderr */
    ht_kat_exit(2);
}

int main(int argc, char **argv) {
    ht_kat_init();

    if (argc >= 2 && streq(argv[1], "generate")) {
        void *p = bigint$new(), *q = bigint$new(), *g = bigint$new();
        bigint$dsa_params(p, q, g);                 /* SLOW: 3072-bit */
        int ok = bigint$verify_dsa_params(p, q, g); /* must be valid  */
        bigint$destroy(p); bigint$destroy(q); bigint$destroy(g);
        emit_bool(ok);
        ht_kat_exit(0);
    }

    if (argc < 4) usage();

    /* Decode all three parameters first and reject any malformed/oversized hex
     * BEFORE constructing bigints: an invalid input must exit 2, not be tested
     * as a zero-valued parameter. No bigint is allocated on the failure path. */
    int lp = ht_kat_hex_decode(argv[1], bp, sizeof bp);
    int lq = ht_kat_hex_decode(argv[2], bq, sizeof bq);
    int lg = ht_kat_hex_decode(argv[3], bg, sizeof bg);
    if (lp < 0 || lq < 0 || lg < 0) usage();

    void *p = bigint$new_encoded(bp, lp);
    void *q = bigint$new_encoded(bq, lq);
    void *g = bigint$new_encoded(bg, lg);

    int ok = bigint$verify_dsa_params(p, q, g);

    bigint$destroy(p); bigint$destroy(q); bigint$destroy(g);
    emit_bool(ok);
    ht_kat_exit(0);
    return 0;
}
