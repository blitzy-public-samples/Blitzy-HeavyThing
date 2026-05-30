/* kat_rsa.c - RSA private-key operation KAT driver (bigint$rsaprivate).
 * argv: <n_hex> <e_hex> <d_hex> <ciphertext_hex>
 *   Performs the RSA private-key (decrypt/sign) primitive m = c^d mod n via
 *   HeavyThing's CRT routine bigint$rsaprivate, and prints m as big-endian
 *   lowercase hex.
 *
 * bigint$rsaprivate needs the CRT factors (p, q, dmodp, dmodq, invqmodp) and a
 * Montgomery powmod context attached to p and q. The public test vector only
 * gives (n, e, d, c), so this driver FIRST factors n from (n, e, d) using the
 * deterministic probabilistic algorithm of NIST SP 800-56B Appendix C / B.3.3
 * (Boneh): k = e*d - 1 = 2^t * r (r odd); for trial bases g = 2,3,..., compute
 * the square-root chain of g^r mod n; a nontrivial square root of 1 yields
 * p = gcd(y-1, n), then q = n / p.
 *
 * Coverage (AAP 0.3.1, 0.5.2): bigint$rsaprivate (the PRIMARY path required by
 * the AAP -- the simpler monty$doit(c, d, n) fallback is intentionally NOT
 * used). Also exercises monty$new/$doit/$destroy, bigint$divide/$multiply/
 * $subtract/$inversemod/$modby/$square_into/$bitget/$shr transitively.
 *
 * Signatures (verified bigint.inc / X509.inc):
 *   bigint$rsaprivate(rdi=rsaprivate-struct, rsi=source/dest bigint) in place.
 *   rsaprivate_size=96: n@0,e@8,d@16,p@24,q@32,dmodp@40,dmodq@48,invqmodp@56,
 *                       x@64,y@72,z@80,other@88.
 *   monty$new(rdi=exponent bigint, rsi=n odd)->ctx ;
 *   monty$doit(rdi=ctx, rsi=dest, rdx=src) dest = src^exp mod n ;
 *   the ctx is attached to the p/q bigint at bigint_monty_powmod_ofs (24). */
#include "ht_kat_common.h"

extern void *bigint$new(void);
extern void *bigint$new_encoded(const void *buf, long len);
extern void *bigint$new_copy(void *src);
extern void  bigint$destroy(void *bi);
extern void  bigint$assign(void *dest, void *src);
extern void  bigint$add(void *dest, void *src);
extern void  bigint$subtract(void *dest, void *src);
extern void  bigint$multiply(void *dest, void *a);          /* dest *= a       */
extern void  bigint$divide(void *rem, void *quot, void *num, void *den);
extern void  bigint$modby(void *dest, void *divisor);
extern void  bigint$inversemod(void *dest, void *src, void *modulus);
extern void  bigint$square_into(void *dest, void *src);
extern int   bigint$bitget(void *bi, int bit);
extern void  bigint$shr(void *bi, int bits);
extern int   bigint$is_one(void *bi);
extern int   bigint$is_zero(void *bi);
extern int   bigint$compare(void *a, void *b);
extern long  bigint$encode(void *bi, void *buf);

extern void *monty$new(void *exponent, void *modulus);
extern void  monty$doit(void *ctx, void *dest, void *src);
extern void  monty$destroy(void *ctx);

#define BIGINT_MONTY_POWMOD_OFS 24

static unsigned char ibuf[1024];
static unsigned char obuf[1024];

static void *small_bi(unsigned v) {
    unsigned char b[1]; b[0] = (unsigned char)v;
    return bigint$new_encoded(b, 1);
}

/* Euclidean gcd -> fresh bigint (avoids bigint$gcd's odd-operand assumption). */
static void *bi_gcd(void *a0, void *b0) {
    void *a = bigint$new_copy(a0);
    void *b = bigint$new_copy(b0);
    while (!bigint$is_zero(b)) {
        void *r = bigint$new_copy(a);
        bigint$modby(r, b);       /* r = a mod b */
        bigint$destroy(a);
        a = b;
        b = r;
    }
    bigint$destroy(b);
    return a;                     /* gcd(a0,b0) */
}

/* Factor n from (e,d). Returns 1 and sets *pp,*pq on success, else 0. */
static int rsa_factor(void *n, void *e, void *d, void **pp, void **pq) {
    void *one = small_bi(1);
    void *k = bigint$new_copy(e);
    bigint$multiply(k, d);        /* k = e*d        */
    bigint$subtract(k, one);      /* k = e*d - 1    */

    int t = 0;
    while (bigint$bitget(k, t) == 0) t++;   /* k = 2^t * r */
    void *r = bigint$new_copy(k);
    bigint$shr(r, t);             /* r odd          */

    void *mctx = monty$new(r, n); /* g^r mod n      */
    void *nm1 = bigint$new_copy(n);
    bigint$subtract(nm1, one);    /* n-1            */

    void *y = bigint$new();
    void *x = bigint$new();
    int found = 0;
    void *factor = (void *)0;

    for (unsigned g = 2; g <= 100 && !found; g++) {
        void *gb = small_bi(g);
        monty$doit(mctx, y, gb);  /* y = g^r mod n  */
        bigint$destroy(gb);
        if (bigint$is_one(y)) continue;
        if (bigint$compare(y, nm1) == 0) continue;
        for (int j = 0; j < t; j++) {
            bigint$square_into(x, y);   /* x = y^2     */
            bigint$modby(x, n);         /* x = y^2 % n */
            if (bigint$is_one(x)) {
                void *ym1 = bigint$new_copy(y);
                bigint$subtract(ym1, one);
                factor = bi_gcd(ym1, n);
                bigint$destroy(ym1);
                found = 1;
                break;
            }
            if (bigint$compare(x, nm1) == 0) break;  /* sqrt hit -1 -> next g */
            bigint$assign(y, x);        /* y = x */
        }
    }

    int ok = 0;
    if (found && factor) {
        void *q = bigint$new();
        void *rem = bigint$new();
        bigint$divide(rem, q, n, factor);   /* q = n / p */
        bigint$destroy(rem);
        *pp = factor;
        *pq = q;
        ok = 1;
    }
    bigint$destroy(one); bigint$destroy(k); bigint$destroy(r);
    monty$destroy(mctx); bigint$destroy(nm1);
    bigint$destroy(y); bigint$destroy(x);
    return ok;
}

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 5) {
        static const char u[] =
            "usage: kat_rsa <n_hex> <e_hex> <d_hex> <ciphertext_hex>\n";
        (void)ht$syscall(1, 2, (void *)u, (long)(sizeof u - 1));
        ht_kat_exit(2);
    }

    int ln = ht_kat_hex_decode(argv[1], ibuf, sizeof ibuf);
    void *n = bigint$new_encoded(ibuf, ln < 0 ? 0 : ln);
    int le = ht_kat_hex_decode(argv[2], ibuf, sizeof ibuf);
    void *e = bigint$new_encoded(ibuf, le < 0 ? 0 : le);
    int ld = ht_kat_hex_decode(argv[3], ibuf, sizeof ibuf);
    void *d = bigint$new_encoded(ibuf, ld < 0 ? 0 : ld);
    int lc = ht_kat_hex_decode(argv[4], ibuf, sizeof ibuf);
    void *c = bigint$new_encoded(ibuf, lc < 0 ? 0 : lc);

    void *p = (void *)0, *q = (void *)0;
    if (!rsa_factor(n, e, d, &p, &q)) {
        static const char ef[] = "rsa_factor: failed to factor n\n";
        (void)ht$syscall(1, 2, (void *)ef, (long)(sizeof ef - 1));
        ht_kat_exit(1);
    }

    /* dmodp = d mod (p-1), dmodq = d mod (q-1) */
    void *one = small_bi(1);
    void *pm1 = bigint$new_copy(p); bigint$subtract(pm1, one);
    void *qm1 = bigint$new_copy(q); bigint$subtract(qm1, one);
    void *dmodp = bigint$new_copy(d); bigint$modby(dmodp, pm1);
    void *dmodq = bigint$new_copy(d); bigint$modby(dmodq, qm1);

    /* invqmodp = q^-1 mod p */
    void *invqmodp = bigint$new();
    bigint$inversemod(invqmodp, q, p);

    /* Montgomery powmod contexts attached to p and q at offset 24 */
    void *mp = monty$new(dmodp, p);
    void *mq = monty$new(dmodq, q);
    *(void **)((char *)p + BIGINT_MONTY_POWMOD_OFS) = mp;
    *(void **)((char *)q + BIGINT_MONTY_POWMOD_OFS) = mq;

    /* scratch bigints */
    void *x = bigint$new(), *y = bigint$new(), *z = bigint$new();

    /* assemble rsaprivate struct (96 bytes = 12 qwords) */
    void *rp[12];
    rp[0] = n; rp[1] = e; rp[2] = d; rp[3] = p; rp[4] = q;
    rp[5] = dmodp; rp[6] = dmodq; rp[7] = invqmodp;
    rp[8] = x; rp[9] = y; rp[10] = z; rp[11] = (void *)0;

    /* c <- c^d mod n  (CRT) */
    extern void bigint$rsaprivate(void *rsapriv, void *srcdest);
    bigint$rsaprivate(rp, c);

    long w = bigint$encode(c, obuf);
    ht_kat_hex_print(obuf, (size_t)w);
    ht_kat_exit(0);
    return 0;
}
