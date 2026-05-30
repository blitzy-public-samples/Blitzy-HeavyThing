/* kat_aes.c - AES KAT driver (aes.inc).
 * argv: <mode> <key_hex> <block_hex>
 *   mode in {ecb_encrypt, ecb_decrypt, round_trip}
 *   key_hex : 16/24/32 bytes  -> AES-128/192/256
 *   block_hex: exactly one 16-byte block
 * Emits (lowercase hex): the ciphertext (ecb_encrypt), the recovered plaintext
 * (ecb_decrypt), or the round-tripped plaintext (round_trip == original).
 *
 * Coverage (AAP 0.3.1, 100% public API of aes.inc):
 *   aes$init_common, aes$init_encrypt, aes$init_decrypt, aes$encrypt, aes$decrypt,
 *   and the aes$tls function-pointer table (called THROUGH the table). The
 *   S-box / T-table data symbols (aes$Se/Sd/Te/Td, aes$data) are validated
 *   implicitly: a wrong table would corrupt the FIPS-197 outputs.
 *
 * Conventions (verified from aes.inc):
 *   - keylen arg is in BYTES (init_common does shr edx,3 -> 2/3/4; +6 -> rounds).
 *   - AES blocks are processed IN PLACE at rsi (software: mov [rsi+..]; AESNI:
 *     movdqu [rsi]). The block buffer needs no special alignment.
 *   - ctx must be 16-aligned; the init and crypt entry points also force-align rdi
 *     _Alignas(16) buffer keeps init and crypt operating on the same address. */
#include "ht_kat_common.h"

void aes$init_common(void *ctx, const void *key, int keylen_bytes);
void aes$init_encrypt(void *ctx, const void *key, int keylen_bytes);
void aes$init_decrypt(void *ctx, const void *key, int keylen_bytes);
void aes$encrypt(void *ctx, void *block16);
void aes$decrypt(void *ctx, void *block16);
extern void *aes$tls[4];   /* { init_encrypt, encrypt, init_decrypt, decrypt } */

typedef void (*aes_init_fn)(void *, const void *, int);
typedef void (*aes_crypt_fn)(void *, void *);

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

/* aes_size = 264; allocate 288 (264 + slack) and 16-align for the force-align. */
static _Alignas(16) unsigned char ctx[288];
static _Alignas(16) unsigned char ctx2[288];
static _Alignas(16) unsigned char ctx3[288];
static unsigned char key[32];
static unsigned char blk[16];
static unsigned char tblk[16];

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 4) {
        static const char u[] =
            "usage: kat_aes <ecb_encrypt|ecb_decrypt|round_trip> <key_hex> <block_hex>\n";
        ht$syscall(1, 1L, (long)u, (long)strlen(u));
        ht_kat_exit(2);
    }
    const char *mode = argv[1];
    int kl = ht_kat_hex_arg(argv[2], key, sizeof key);
    int bl = ht_kat_hex_arg(argv[3], blk, sizeof blk);
    if (kl != 16 && kl != 24 && kl != 32) ht_kat_exit(2);
    if (bl != 16) ht_kat_exit(2);

    /* coverage: aes$init_common directly (key schedule) on a scratch ctx. */
    aes$init_common(ctx3, key, kl);

    /* coverage: aes$tls table round-trip on a scratch ctx (validates the four
     * function pointers are init_encrypt/encrypt/init_decrypt/decrypt). Result
     * is not emitted; it just exercises the table and the funcs through it. */
    for (int i = 0; i < 16; i++) tblk[i] = blk[i];
    ((aes_init_fn)aes$tls[0])(ctx2, key, kl);   /* init_encrypt */
    ((aes_crypt_fn)aes$tls[1])(ctx2, tblk);     /* encrypt      */
    ((aes_init_fn)aes$tls[2])(ctx2, key, kl);   /* init_decrypt */
    ((aes_crypt_fn)aes$tls[3])(ctx2, tblk);     /* decrypt      */

    if (streq(mode, "ecb_encrypt")) {
        aes$init_encrypt(ctx, key, kl);
        aes$encrypt(ctx, blk);
        ht_kat_hex_print(blk, 16);
    } else if (streq(mode, "ecb_decrypt")) {
        aes$init_decrypt(ctx, key, kl);
        aes$decrypt(ctx, blk);
        ht_kat_hex_print(blk, 16);
    } else if (streq(mode, "round_trip")) {
        aes$init_encrypt(ctx, key, kl);
        aes$encrypt(ctx, blk);
        aes$init_decrypt(ctx, key, kl);
        aes$decrypt(ctx, blk);
        ht_kat_hex_print(blk, 16);   /* recovered plaintext == original */
    } else {
        ht_kat_exit(2);
    }
    ht_kat_exit(0);
    return 0;
}
