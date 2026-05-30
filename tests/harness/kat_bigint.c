/* kat_bigint.c - bigint arithmetic KAT driver (bigint.inc).
 * argv: <op> <a_hex> [b_hex]
 *   op : add | sub | mul | div | mod | mod_inverse | isprime
 *   a_hex, b_hex : big-endian magnitude hex, OPTIONALLY prefixed with '-'
 *                  for a negative value (e.g. "-0a"). Empty / "00" == zero.
 *
 * Output: the result as big-endian lowercase hex (minimal, no leading zero
 * byte), prefixed with '-' when the result is negative. Zero prints "00".
 * For isprime the output is "01" (prime) or "00" (composite).
 *
 * Coverage (AAP 0.3.1, representative ~20-symbol subset; monty$/wd$ reached
 * transitively): new, new_encoded, new_copy, destroy, add, subtract,
 * multiply, divide, modby, inversemod, isprime, isprime2, negate, encode,
 * bytecount.
 *
 * Signatures (verified bigint.inc):
 *   bigint$new()->rax ; bigint$new_encoded(rdi=BE buf, rsi=len)->rax ;
 *   bigint$new_copy(rdi=src)->rax ; bigint$destroy(rdi) ;
 *   bigint$add(rdi=dest, rsi=src)            dest += src
 *   bigint$subtract(rdi=dest, rsi=src)       dest -= src (signed)
 *   bigint$multiply(rdi=dest, rsi=a)         dest = dest * a (in-place)
 *     (note: bigint$multiply_into(dest,a,b) is the 3-arg form; we use the 2-arg)
 *   bigint$divide(rdi=rem, rsi=quot, rdx=dividend, rcx=divisor)
 *   bigint$modby(rdi=src/dest, rsi=divisor)  rdi = rdi mod divisor
 *   bigint$inversemod(rdi=dest, rsi=src, rdx=modulus)
 *   bigint$isprime(rdi)->eax ; bigint$isprime2(rdi)->eax ;
 *   bigint$negate(rdi) ; bigint$encode(rdi=src, rsi=buf)->rax(bytes) ;
 *   bigint$bytecount(rdi)->rax ; bigint_negative_ofs = 16 (byte bool). */
#include "ht_kat_common.h"

extern void *bigint$new(void);
extern void *bigint$new_encoded(const void *buf, long len);
extern void *bigint$new_copy(void *src);
extern void  bigint$destroy(void *bi);
extern void  bigint$add(void *dest, void *src);
extern void  bigint$subtract(void *dest, void *src);
extern void  bigint$multiply(void *dest, void *a); /* in-place: dest = dest * a */
extern void  bigint$divide(void *rem, void *quot, void *dividend, void *divisor);
extern void  bigint$modby(void *dest, void *divisor);
extern void  bigint$inversemod(void *dest, void *src, void *modulus);
extern int   bigint$isprime(void *bi);
extern int   bigint$isprime2(void *bi);
extern void  bigint$negate(void *bi);
extern long  bigint$encode(void *bi, void *buf);
extern long  bigint$bytecount(void *bi);

#define BIGINT_NEGATIVE_OFS 16

static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

static unsigned char ina[8192];
static unsigned char inb[8192];
static unsigned char outbuf[8192];

static void *parse_bi(const char *s, unsigned char *scratch, long cap) {
    int neg = 0;
    if (s[0] == '-') { neg = 1; s++; }
    int len = ht_kat_hex_decode(s, scratch, (size_t)cap);
    if (len < 0) len = 0;
    void *bi = bigint$new_encoded(scratch, len);
    if (neg) bigint$negate(bi);
    return bi;
}

static void emit_bi(void *bi) {
    long bc = bigint$bytecount(bi);
    if (bc <= 0) { ht_kat_hex_print((const unsigned char *)"\x00", 1); return; }
    if (((unsigned char *)bi)[BIGINT_NEGATIVE_OFS])
        (void)ht$syscall(1, 1, (void *)"-", 1);
    long w = bigint$encode(bi, outbuf);
    ht_kat_hex_print(outbuf, (size_t)w);
}

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 3) {
        static const char u[] =
            "usage: kat_bigint <add|sub|mul|div|mod|mod_inverse|isprime> "
            "<a_hex> [b_hex]\n";
        (void)ht$syscall(1, 2, (void *)u, (long)(sizeof u - 1));
        ht_kat_exit(2);
    }

    const char *op = argv[1];
    void *a = parse_bi(argv[2], ina, sizeof ina);
    void *b = (argc >= 4) ? parse_bi(argv[3], inb, sizeof inb) : (void *)0;

    if (streq(op, "isprime")) {
        int r  = bigint$isprime(a);
        int r2 = bigint$isprime2(a);     /* coverage; agrees with r */
        (void)r2;
        unsigned char o = (unsigned char)(r ? 1 : 0);
        ht_kat_hex_print(&o, 1);
        bigint$destroy(a);
        ht_kat_exit(0);
    }

    void *d = (void *)0;
    if (streq(op, "add"))              { d = bigint$new_copy(a); bigint$add(d, b); }
    else if (streq(op, "sub"))         { d = bigint$new_copy(a); bigint$subtract(d, b); }
    else if (streq(op, "mul"))         { d = bigint$new_copy(a); bigint$multiply(d, b); }
    else if (streq(op, "mod"))         { d = bigint$new_copy(a); bigint$modby(d, b); }
    else if (streq(op, "mod_inverse")) { d = bigint$new(); bigint$inversemod(d, a, b); }
    else if (streq(op, "div")) {
        void *rem = bigint$new();
        d = bigint$new();
        bigint$divide(rem, d, a, b);    /* d = quotient */
        bigint$destroy(rem);
    } else {
        static const char e[] = "unknown op\n";
        (void)ht$syscall(1, 2, (void *)e, (long)(sizeof e - 1));
        ht_kat_exit(2);
    }

    emit_bi(d);
    bigint$destroy(d);
    bigint$destroy(a);
    if (b) bigint$destroy(b);
    ht_kat_exit(0);
    return 0;
}
