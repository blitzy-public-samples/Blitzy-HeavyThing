/* kat_hmac.c - HMAC KAT driver (hmac.inc), all 20 public symbols.
 * argv: <hash> <key_hex|-> <data_hex>     hash in {md5,sha1,sha224,sha256,sha384,sha512}
 * Emits lowercase hex of the MAC (macsize bytes). Always exits 0 (negative cases are
 * decided by the runner comparing output hex, not by exit status). */
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

int main(int argc, char **argv) {
    ht_kat_init();
    if (argc < 4) {
        static const char u[] = "usage: kat_hmac <md5|sha1|sha224|sha256|sha384|sha512> <key_hex|-> <data_hex>\n";
        ht$syscall(1, 1L, (long)u, (long)strlen(u));
        ht_kat_exit(2);
    }
    const char *h = argv[1];
    int klen = ht_kat_hex_decode(argv[2], keyb, sizeof keyb);
    int dlen = ht_kat_hex_arg(argv[3], datab, sizeof datab);
    if (klen < 0 || dlen < 0) ht_kat_exit(2);

    void *(*f_new)(void); void (*f_init)(void*); int macsize;
    if      (streq(h,"md5"))    { f_new=hmac$new_md5;    f_init=hmac$init_md5;    macsize=16; }
    else if (streq(h,"sha1"))   { f_new=hmac$new_sha1;   f_init=hmac$init_sha1;   macsize=20; }
    else if (streq(h,"sha224")) { f_new=hmac$new_sha224; f_init=hmac$init_sha224; macsize=28; }
    else if (streq(h,"sha256")) { f_new=hmac$new_sha256; f_init=hmac$init_sha256; macsize=32; }
    else if (streq(h,"sha384")) { f_new=hmac$new_sha384; f_init=hmac$init_sha384; macsize=48; }
    else if (streq(h,"sha512")) { f_new=hmac$new_sha512; f_init=hmac$init_sha512; macsize=64; }
    else { ht_kat_exit(2); return 2; }

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
