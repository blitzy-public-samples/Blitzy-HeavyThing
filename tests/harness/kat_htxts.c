/* kat_htxts.c - XTS-mode KAT driver (htxts.inc).
 * argv: <operation> <key1_hex> <key2_hex> <tweak_hex> <data_hex>
 *   operation : encrypt | decrypt | round_trip
 *   key1_hex, key2_hex : key material; concatenated (key1 then key2) and
 *               zero-padded into 8192 bytes for htcrypt$new_raw_keymaterial.
 *   tweak_hex : the per-sector tweak; exactly 16 bytes (zero-padded if short).
 *   data_hex  : sector bytes; decoded into a 2048-byte buffer (zero-padded).
 *               htxts always processes htxts_blocksize == 2048 bytes
 *               (128 sub-blocks of 16). "-" reads the hex from stdin.
 *
 * Output: the first n bytes (n == decoded data length) of the result as
 * lowercase hex. A correct round_trip therefore reproduces the input exactly.
 *
 * Coverage (AAP 0.3.1, 100 percent public API): htxts$encrypt, htxts$decrypt.
 *
 * Signatures (verified from htxts.inc):
 *   htxts$encrypt(rdi=htcrypt_ctx, rsi=2048-byte buf, rdx=16-byte tweak)
 *   htxts$decrypt(rdi=htcrypt_ctx, rsi=2048-byte buf, rdx=16-byte tweak)
 *   Both mutate the tweak IN PLACE (AES-encrypt then per-block LFSR), so the
 *   original tweak is saved and restored before the decrypt half of a
 *   round_trip. The underlying cipher is htcrypt's 64-round cascade, NOT a
 *   single AES, so this is HeavyThing-specific XTS (no external published KAT);
 *   correctness is by round-trip identity and cross-process determinism. */
#include "ht_kat_common.h"

extern void *htcrypt$new_raw_keymaterial(const void *km8192);
extern void  htcrypt$destroy(void *ctx);
extern void  htxts$encrypt(void *ctx, void *buf2048, void *tweak16);
extern void  htxts$decrypt(void *ctx, void *buf2048, void *tweak16);

static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

/* usage(): write the usage line to stderr (fd 2) and exit non-zero (2). */
static void usage(void) {
    static const char u[] =
        "usage: kat_htxts <encrypt|decrypt|round_trip> "
        "<key1_hex> <key2_hex> <tweak_hex> <data_hex>\n";
    ht$syscall(1, 2L, (long)u, (long)strlen(u));   /* usage -> stderr */
    ht_kat_exit(2);
}

static int valid_op(const char *op) {
    return streq(op, "encrypt") || streq(op, "decrypt") || streq(op, "round_trip");
}

static unsigned char km[8192];
static _Alignas(16) unsigned char buf[2048];
static _Alignas(16) unsigned char tweak[16];
static _Alignas(16) unsigned char tweak_save[16];

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 6) usage();

    const char *op = argv[1];
    /* Validate the operation BEFORE decoding or allocating: an unknown value
     * must NOT fall through to the encrypt path -- it exits 2. */
    if (!valid_op(op)) usage();

    /* key1 || key2 -> 8192-byte raw keymaterial (zero-padded). Every decode is
     * checked: malformed or oversized hex exits 2 rather than silently running
     * as a zero/truncated key, tweak, or message. */
    for (int i = 0; i < 8192; i++) km[i] = 0;
    int l1 = ht_kat_hex_decode(argv[2], km, sizeof km);
    if (l1 < 0) usage();
    int l2 = ht_kat_hex_decode(argv[3], km + l1, sizeof km - l1);
    if (l2 < 0) usage();

    /* tweak -> 16 bytes (zero-padded). */
    for (int i = 0; i < 16; i++) tweak[i] = 0;
    if (ht_kat_hex_decode(argv[4], tweak, sizeof tweak) < 0) usage();

    /* data -> 2048-byte buffer (zero-padded); n == real length. */
    for (int i = 0; i < 2048; i++) buf[i] = 0;
    int n = ht_kat_hex_arg(argv[5], buf, sizeof buf);
    if (n < 0) usage();

    void *ctx = htcrypt$new_raw_keymaterial(km);

    if (streq(op, "decrypt")) {
        htxts$decrypt(ctx, buf, tweak);
    } else if (streq(op, "round_trip")) {
        for (int i = 0; i < 16; i++) tweak_save[i] = tweak[i];
        htxts$encrypt(ctx, buf, tweak);
        for (int i = 0; i < 16; i++) tweak[i] = tweak_save[i]; /* restore */
        htxts$decrypt(ctx, buf, tweak);
    } else { /* encrypt (op validated to be exactly encrypt here) */
        htxts$encrypt(ctx, buf, tweak);
    }

    htcrypt$destroy(ctx);
    ht_kat_hex_print(buf, (size_t)n);
    ht_kat_exit(0);
    return 0;
}
