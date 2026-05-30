/* ------------------------------------------------------------------------
 * HeavyThing KAT (Known-Answer-Test) suite
 * tests/harness/ht_kat_common.c
 *
 * Shared freestanding helpers + the canonical crt0 `_start` entry stub used by
 * every tests/harness/kat_*.c driver. The KAT harness links C against
 * HeavyThing's pure-x86_64 assembly crypto stack and is therefore compiled and
 * linked as a self-contained, libc-free program:
 *
 *     gcc -std=c11 -Wall -Wextra -O2 -nostdlib -static -Iharness \
 *         -o build/bin/kat_<name> harness/kat_<name>.c \
 *         harness/ht_kat_common.c build/libht.a
 *
 * Built -nostdlib -static, there is no libc crt0 and the FASM shim object
 * (archived into build/libht.a) provides no `_start`, so we supply a tiny
 * canonical `_start` here. With `_start` present, ld finds the entry symbol --
 * no "cannot find entry symbol _start" warning, no -e flag needed. The kernel
 * enters at a 16-byte-aligned RSP, while the SysV C ABI expects RSP % 16 == 8
 * at a call site, so we align RSP before calling main to keep -O2 movaps stack
 * spills inside main from faulting.
 *
 * No hosted C standard library is available: there is no <stdio.h>,
 * <stdlib.h> or <string.h>, no malloc/printf/exit. HeavyThing supplies its own
 * memory subsystem and a raw syscall primitive (ht$syscall) instead. This
 * translation unit therefore includes only the sibling header
 * ht_kat_common.h, which pulls in the freestanding <stddef.h> for size_t and
 * declares ht$syscall plus the prototypes of the helpers defined below.
 * Public falign-prefixed crypto labels are HeavyThing's public API and are
 * neither renamed, wrapped, nor moved here.
 *
 * Reference interop pattern: examples/hello_world_c1/hello.c (repo root,
 * READ-ONLY) -- forward-declared HeavyThing symbols (whose names contain '$'),
 * ht$init_args(0, 0) first, exit via ht$syscall(60, ...). Nothing outside
 * tests/ is referenced or modified.
 *
 * See AAP 0.4.4 (shared utilities, C side) and 0.5.5 (cross-file test deps).
 * ------------------------------------------------------------------------ */
#include "ht_kat_common.h"

/* ht$init_args -- HeavyThing's runtime / memory-subsystem initializer, defined
 * in assembly and provided at link time by build/libht.a (the ar archive of
 * the FASM-assembled shim, whose include_everything = 1 emits every symbol).
 *
 * It is declared here rather than in ht_kat_common.h because the header's
 * published surface is the ht_kat_* helper API plus ht$syscall; ht$init_args
 * is an implementation detail used only by ht_kat_init below. The prototype
 * matches examples/hello_world_c1/hello.c exactly. A declaration is mandatory:
 * modern GCC rejects an implicit function declaration as a hard error, so
 * calling ht$init_args undeclared would fail to compile. Passing 0 for the
 * char** argument is a null pointer constant (argv = NULL), not an int->pointer
 * conversion, so it is accepted cleanly under -Wall -Wextra. */
void ht$init_args(int, char **);

/* crt0 entry stub. At process entry the kernel arranges [rsp] = argc,
 * [rsp+8] = argv[0], ..., with RSP 16-byte aligned. We marshal argc/argv into
 * the SysV integer-argument registers (edi/rsi), keep RSP 16-byte aligned, call
 * main, then turn main's return value into an exit(2) syscall. Written as a
 * top-level __asm__ block -- the bare `asm` keyword is rejected under
 * -std=c11. */
__asm__(
    ".globl _start\n"
    "_start:\n"
    "    xor  %ebp, %ebp\n"        /* clear frame pointer (ABI)        */
    "    mov  (%rsp), %edi\n"      /* argc                              */
    "    lea  8(%rsp), %rsi\n"     /* argv                              */
    "    and  $-16, %rsp\n"        /* 16-byte align RSP                 */
    "    call main\n"
    "    mov  %eax, %edi\n"        /* exit(main_ret)                    */
    "    mov  $60, %eax\n"
    "    syscall\n"
);

/* ht_kat_init -- bring up HeavyThing's memory subsystem exactly once, before
 * any crypto primitive is invoked. Every driver calls this at startup. */
void ht_kat_init(void) { ht$init_args(0, 0); }

/* strlen -- freestanding length of a NUL-terminated byte string, excluding the
 * terminator. Provided locally because the harness links -nostdlib (no libc
 * strlen) and GCC -O2 may also synthesize implicit strlen calls for certain
 * code shapes. The optimize("no-tree-loop-distribute-patterns") attribute
 * stops GCC from rewriting this very loop into a self-referential strlen
 * call; the prototype matches the GCC built-in exactly so it compiles cleanly
 * under -Wall (-Wbuiltin-declaration-mismatch). */
__attribute__((optimize("no-tree-loop-distribute-patterns")))
size_t strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t)(p - s); }

/* ht_kat_atoi -- freestanding base-10 parser used by drivers to read numeric
 * KAT parameters from the command line (PBKDF2 iteration counts / derived-key
 * lengths, scrypt N/r/p, HMAC-DRBG requested byte counts, DH pool indices,
 * ...). An optional leading '+'/'-' sign is honoured and ASCII digits are
 * consumed until the first non-digit. The accumulator is a long (64-bit on
 * x86_64) so large counts -- RFC 6070's 16,777,216 iterations or RFC 7914's
 * N = 1,048,576 -- are represented without truncation. A NULL pointer, an
 * empty string, or a string with no leading digits yields 0. */
long ht_kat_atoi(const char *s) {
    long value = 0;
    int neg = 0;
    if (!s) return 0;
    if (*s == '+' || *s == '-') { neg = (*s == '-'); s++; }
    while (*s >= '0' && *s <= '9') {
        value = value * 10 + (long)(*s - '0');
        s++;
    }
    return neg ? -value : value;
}

/* hexval -- numeric value of a single hex digit (0..15), or -1 if the
 * character is not a hexadecimal digit. */
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ht_kat_hex_decode -- decode a NUL-terminated lowercase/uppercase hex string
 * into out[], writing at most out_size bytes. Returns the number of bytes
 * written on success, or -1 on error (a non-hex character, an odd number of
 * nibbles, or a result that would exceed out_size). A NULL or empty input
 * decodes to 0 bytes. */
int ht_kat_hex_decode(const char *hex, unsigned char *out, size_t out_size) {
    size_t n = 0;
    if (!hex) return 0;
    while (hex[0] && hex[1]) {
        int hi = hexval(hex[0]), lo = hexval(hex[1]);
        if (hi < 0 || lo < 0) return -1;
        if (n >= out_size) return -1;
        out[n++] = (unsigned char)((hi << 4) | lo);
        hex += 2;
    }
    if (hex[0]) return -1;        /* odd number of nibbles */
    return (int)n;
}

/* ht_kat_hex_arg -- NULL-tolerant wrapper over ht_kat_hex_decode for the common
 * driver pattern of decoding an argv slot that may be absent: a NULL pointer is
 * treated as an empty (zero-byte) input so a driver can pass a possibly-missing
 * argument directly without a prior NULL check. Returns the decoded byte count,
 * or -1 on malformed hex or insufficient out_size. (ht_kat_hex_decode already
 * maps NULL -> 0, so the contract is expressed by delegation.) */
int ht_kat_hex_arg(const char *hex, unsigned char *out, size_t out_size) {
    return ht_kat_hex_decode(hex, out, out_size);
}

/* ht_kat_hex_print -- write the lowercase hex encoding of buf[0..len) to
 * standard output (fd 1) via the write syscall, followed by a single '\n'.
 * Two lowercase hex characters are emitted per input byte; output is buffered
 * in 512-byte chunks to bound the number of syscalls. The Python runner
 * captures stdout and compares it, after .strip(), against the vector's
 * expected hex, so the trailing newline is harmless. */
void ht_kat_hex_print(const unsigned char *buf, size_t len) {
    static const char hx[] = "0123456789abcdef";
    unsigned char chunk[512];
    size_t c = 0;
    for (size_t i = 0; i < len; i++) {
        chunk[c++] = (unsigned char)hx[buf[i] >> 4];
        chunk[c++] = (unsigned char)hx[buf[i] & 0xf];
        if (c >= sizeof(chunk)) { ht$syscall(1, 1, (long)chunk, (long)c); c = 0; }
    }
    if (c) ht$syscall(1, 1, (long)chunk, (long)c);
    unsigned char nl = '\n';
    ht$syscall(1, 1, (long)&nl, 1L);
}

/* ht_kat_exit -- terminate the process immediately with the given status via
 * the Linux exit syscall (libc exit() is unavailable under -nostdlib). The
 * Python runner observes this status as the subprocess return code. */
void ht_kat_exit(int status) { ht$syscall(60, status); }
