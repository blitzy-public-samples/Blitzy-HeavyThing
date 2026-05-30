/* kat_dh_pool.c - Diffie-Hellman static pool integrity driver (dh_pool*.inc).
 * argv: <index> [field]            field : p (default) | g
 *   Emits the big-endian lowercase hex of dh$pool_p[index] (the safe prime)
 *   or dh$pool_g[index] (the generator). "count" as argv[1] emits the pool
 *   entry count.
 *
 * Coverage (AAP 0.3.1, 100% of the DH-pool surface): dh$pool_p, dh$pool_g,
 * dh$pool_count (the count).
 *
 * Pool layout (verified dh_pool_2k.inc, loaded because dh_bits == 2048):
 *   dh$pool_p : dq of 20 pointers to static bigint objects (dhp2k1..dhp2k20),
 *               each a 2048-bit safe prime in HeavyThing bigint format
 *               (dq wordcount, words_ptr, negative, monty ; words little-endian).
 *   dh$pool_g : dq of 20 pointers to dhg3/dhg2 bigints. *** g VARIES across
 *               entries (index 0 -> dhg3 == 3, index 1 -> dhg2 == 2, a 3/2
 *               mix) -- this is NOT RFC 3526 (which fixes g == 2), and the
 *               primes are 2 Ton Digital custom safe primes, NOT the RFC 3526
 *               MODP moduli. The VECTORS file must carry HeavyThing-ACTUAL
 *               values (produced by running this driver), not RFC 3526 data.
 *   dh$pool_p_size == 20 is a FASM compile-time '=' constant (NOT a linkable
 *               runtime symbol), so the count is the documented constant below.
 *
 * Because each entry is already a bigint object, bigint$encode/$bytecount are
 * applied to the pool pointer directly. */
#include "ht_kat_common.h"

#define DH_POOL_COUNT 20

extern void *dh$pool_p[];
extern void *dh$pool_g[];
extern long  bigint$encode(void *bi, void *buf);
extern long  bigint$bytecount(void *bi);

static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

static unsigned char outbuf[512];

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 2) {
        static const char u[] = "usage: kat_dh_pool <index|count> [p|g]\n";
        (void)ht$syscall(1, 2, (void *)u, (long)(sizeof u - 1));
        ht_kat_exit(2);
    }

    if (streq(argv[1], "count")) {
        unsigned char c = (unsigned char)DH_POOL_COUNT;
        ht_kat_hex_print(&c, 1);
        ht_kat_exit(0);
    }

    int i = ht_kat_atoi(argv[1]);
    if (i < 0 || i >= DH_POOL_COUNT) {
        static const char e[] = "index out of range\n";
        (void)ht$syscall(1, 2, (void *)e, (long)(sizeof e - 1));
        ht_kat_exit(2);
    }

    const char *field = (argc >= 3) ? argv[2] : "p";
    void *bi = streq(field, "g") ? dh$pool_g[i] : dh$pool_p[i];

    long w = bigint$encode(bi, outbuf);
    ht_kat_hex_print(outbuf, (size_t)w);
    ht_kat_exit(0);
    return 0;
}
