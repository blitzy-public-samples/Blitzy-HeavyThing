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

/* Operand magnitude cap (bytes). HeavyThing bigints hold at most
 * bigint_maxwords = 512 64-bit words (= 4096 bytes); a value/result needing
 * >= 512 words trips bigint.inc's `.kakked: breakpoint` (SIGTRAP). Capping
 * each operand at 1024 bytes keeps the worst case -- multiply, whose product
 * is ~ bytecount(a)+bytecount(b) -- at <= 2048 bytes (256 words), well within
 * that limit, so every accepted operation is computed correctly and no input
 * can drive HeavyThing into the breakpoint. ina/inb are sized to the cap, so
 * decode_operand()'s `sizeof` out_size argument rejects any larger operand via
 * ht_kat_hex_decode() -> -1 -> usage() -> exit 2 before allocation. The cap is
 * generous: the largest committed kat_bigint vector operand is 64 bytes. */
#define BIGINT_OPERAND_MAX 1024
static unsigned char ina[BIGINT_OPERAND_MAX];
static unsigned char inb[BIGINT_OPERAND_MAX];
/* Worst-case output is multiply: bytecount(a)+bytecount(b) <= 1024+1024 =
 * 2048 bytes, far below HeavyThing's 4096-byte (512-word) bigint capacity.
 * outbuf is sized generously and emit_bi() additionally guards on bytecount
 * (defense-in-depth) so bigint$encode can never write past it. */
static unsigned char outbuf[16384 + 16];

/* usage(): write the usage line to stderr (fd 2) and exit non-zero (2). */
static void usage(void) {
    static const char u[] =
        "usage: kat_bigint <add|sub|mul|div|mod|mod_inverse|isprime> <a_hex> [b_hex]\n";
    ht$syscall(1, 2L, (long)u, (long)strlen(u));   /* usage -> stderr */
    ht_kat_exit(2);
}

/* decode_operand(): decode a signed-hex operand into scratch[] WITHOUT
 * allocating. Sets *neg for a leading '-'. Exits 2 (usage) on malformed or
 * oversized hex, so a bad vector never becomes a silent zero bigint and no
 * bigint can leak on the failure path. Returns the decoded byte length. */
static long decode_operand(const char *s, unsigned char *scratch, long cap, int *neg) {
    *neg = 0;
    if (s[0] == '-') { *neg = 1; s++; }
    int len = ht_kat_hex_decode(s, scratch, (size_t)cap);
    if (len < 0) usage();
    return len;
}

/* make_bi(): construct a bigint from already-validated operand bytes. */
static void *make_bi(const unsigned char *buf, long len, int neg) {
    void *bi = bigint$new_encoded(buf, len);
    if (neg) bigint$negate(bi);
    return bi;
}

static void emit_bi(void *bi) {
    long bc = bigint$bytecount(bi);
    if (bc <= 0) { ht_kat_hex_print((const unsigned char *)"\x00", 1); return; }
    /* Guard BEFORE writing anything: never let bigint$encode write past outbuf,
     * even for an unexpectedly large result (defense-in-depth on top of the
     * worst-case buffer size). Checked before the sign byte so no partial
     * output precedes the abort. */
    if (bc > (long)sizeof outbuf) ht_kat_exit(2);
    if (((unsigned char *)bi)[BIGINT_NEGATIVE_OFS])
        (void)ht$syscall(1, 1, (void *)"-", 1);
    long w = bigint$encode(bi, outbuf);
    ht_kat_hex_print(outbuf, (size_t)w);
}

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 3) usage();

    const char *op = argv[1];

    /* Classify arity and validate the selector + operand count BEFORE decoding
     * or allocating anything. isprime is unary (exactly one operand); every
     * other op is binary (exactly two). An unknown op, a missing second operand,
     * or an extra operand exits 2 with NO allocation -- so no NULL is ever
     * passed into a bigint routine (CRITICAL) and no bigint is leaked. */
    int unary  = streq(op, "isprime");
    int binary = streq(op,"add") || streq(op,"sub") || streq(op,"mul")
              || streq(op,"div") || streq(op,"mod") || streq(op,"mod_inverse");
    if (!unary && !binary) usage();          /* unknown op             */
    if (unary  && argc != 3) usage();        /* isprime: one operand   */
    if (binary && argc != 4) usage();        /* binary ops: two operands */

    /* Decode all operands first (validates hex; exits 2 on bad input); only
     * then allocate bigints, so a decode failure leaks nothing. */
    int nega = 0, negb = 0;
    long la = decode_operand(argv[2], ina, sizeof ina, &nega);
    void *a = make_bi(ina, la, nega);
    void *b = (void *)0;
    if (binary) {
        long lb = decode_operand(argv[3], inb, sizeof inb, &negb);
        b = make_bi(inb, lb, negb);
    }

    if (unary) {                             /* isprime */
        int r  = bigint$isprime(a);
        int r2 = bigint$isprime2(a);         /* coverage; agrees with r */
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
    else /* div (the only remaining validated binary op) */ {
        void *rem = bigint$new();
        d = bigint$new();
        bigint$divide(rem, d, a, b);         /* d = quotient */
        bigint$destroy(rem);
    }

    emit_bi(d);
    bigint$destroy(d);
    bigint$destroy(a);
    bigint$destroy(b);                        /* non-NULL for every binary op */
    ht_kat_exit(0);
    return 0;
}
