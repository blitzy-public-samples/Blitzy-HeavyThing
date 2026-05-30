/* kat_htcrypt.c - htcrypt KAT driver (htcrypt.inc).
 * argv: <operation> <key_type> <secret> <plaintext_hex> [wrong_secret]
 *   operation : round_trip | hide_show
 *   key_type  : passphrase | keymaterial | raw_keymaterial | useless
 *   secret    : passphrase STRING (passphrase) OR key-material HEX
 *               (keymaterial/raw_keymaterial, zero-padded to 8192 bytes);
 *               ignored for useless.
 *   plaintext_hex : message bytes, processed as 16-byte blocks (zero-padded);
 *               only the original byte count is emitted, so a correct round-trip
 *               reproduces the input EXACTLY. "-" reads the hex from stdin.
 *   wrong_secret  : (negative) decrypt under a different key -> must NOT recover.
 *
 * htcrypt is a custom 64x-cascaded-AES256 cipher with no published KAT; the
 * authoritative property is the round-trip identity decrypt(encrypt(p)) == p
 * (AAP 0.4.2). hide/show wrap/unwrap the WHOLE htcrypt state with an external
 * AES context (for portable serialization); after hide+show the context is
 * restored and still round-trips plaintext.
 *
 * Coverage (AAP 0.3.1, 100% public API): htcrypt$new_passphrase,
 *   htcrypt$new_keymaterial, htcrypt$new_raw_keymaterial, htcrypt$new_useless,
 *   htcrypt$encrypt, htcrypt$decrypt, htcrypt$hide, htcrypt$show, htcrypt$destroy.
 *
 * Signatures (verified from htcrypt.inc):
 *   new_passphrase(rdi=pass, esi=len)->ctx ; new_keymaterial(rdi=8KB)->ctx ;
 *   new_raw_keymaterial(rdi=8KB)->ctx ; new_useless()->ctx ;
 *   encrypt/decrypt(rdi=ctx, rsi=block16) in place ;
 *   hide(rdi=ctx, rsi=aes_enc_ctx) ; show(rdi=ctx, rsi=aes_dec_ctx) ;
 *   destroy(rdi=ctx). */
#include "ht_kat_common.h"

void *htcrypt$new_passphrase(const void *pass, int len);
void *htcrypt$new_keymaterial(const void *km8192);
void *htcrypt$new_raw_keymaterial(const void *km8192);
void *htcrypt$new_useless(void);
void  htcrypt$encrypt(void *ctx, void *block16);
void  htcrypt$decrypt(void *ctx, void *block16);
void  htcrypt$hide(void *ctx, void *aes_enc_ctx);
void  htcrypt$show(void *ctx, void *aes_dec_ctx);
void  htcrypt$destroy(void *ctx);
void  aes$init_encrypt(void *ctx, const void *key, int keylen_bytes);
void  aes$init_decrypt(void *ctx, const void *key, int keylen_bytes);

static int streq(const char *a, const char *b){ while(*a&&*a==*b){a++;b++;} return *a==*b; }

static unsigned char km[8192];
static unsigned char pt[4096];
static _Alignas(16) unsigned char aes_enc[288];
static _Alignas(16) unsigned char aes_dec[288];
/* fixed 32-byte key for the hide/show AES wrapping context */
static const unsigned char hidekey[32] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
};

static void *build_ctx(const char *key_type, const char *secret) {
    if (streq(key_type, "passphrase"))
        return htcrypt$new_passphrase(secret, (int)strlen(secret));
    if (streq(key_type, "useless"))
        return htcrypt$new_useless();
    /* keymaterial / raw_keymaterial: secret is hex, zero-padded to 8192 bytes */
    for (int i = 0; i < 8192; i++) km[i] = 0;
    ht_kat_hex_decode(secret, km, sizeof km);   /* count ignored; zero-padded */
    if (streq(key_type, "raw_keymaterial"))
        return htcrypt$new_raw_keymaterial(km);
    return htcrypt$new_keymaterial(km);
}

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 5) {
        static const char u[] =
            "usage: kat_htcrypt <round_trip|hide_show> "
            "<passphrase|keymaterial|raw_keymaterial|useless> "
            "<secret> <plaintext_hex> [wrong_secret]\n";
        ht$syscall(1, 1L, (long)u, (long)strlen(u));
        ht_kat_exit(2);
    }
    const char *op = argv[1];
    const char *kt = argv[2];
    const char *secret = argv[3];
    int n = ht_kat_hex_arg(argv[4], pt, sizeof pt);
    if (n < 0) ht_kat_exit(2);
    int m = ((n + 15) / 16) * 16;
    for (int i = n; i < m; i++) pt[i] = 0;          /* zero-pad final block */

    void *ctx = build_ctx(kt, secret);

    if (streq(op, "hide_show")) {
        aes$init_encrypt(aes_enc, hidekey, 32);
        aes$init_decrypt(aes_dec, hidekey, 32);
        htcrypt$hide(ctx, aes_enc);                 /* wrap entire state    */
        htcrypt$show(ctx, aes_dec);                 /* unwrap -> restored   */
        for (int off = 0; off < m; off += 16) htcrypt$encrypt(ctx, pt + off);
        for (int off = 0; off < m; off += 16) htcrypt$decrypt(ctx, pt + off);
        htcrypt$destroy(ctx);
        ht_kat_hex_print(pt, n);
        ht_kat_exit(0);
    }

    /* round_trip (default): encrypt all blocks ... */
    for (int off = 0; off < m; off += 16) htcrypt$encrypt(ctx, pt + off);

    if (argc >= 6) {                                /* negative: wrong key  */
        void *wctx = build_ctx(kt, argv[5]);
        for (int off = 0; off < m; off += 16) htcrypt$decrypt(wctx, pt + off);
        htcrypt$destroy(wctx);
        htcrypt$destroy(ctx);
        ht_kat_hex_print(pt, n);                    /* must differ from input */
        ht_kat_exit(0);
    }

    for (int off = 0; off < m; off += 16) htcrypt$decrypt(ctx, pt + off);
    htcrypt$destroy(ctx);
    ht_kat_hex_print(pt, n);                         /* == original plaintext */
    ht_kat_exit(0);
    return 0;
}
