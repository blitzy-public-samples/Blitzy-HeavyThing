/* ------------------------------------------------------------------------
 * HeavyThing KAT (Known-Answer-Test) suite
 * tests/harness/ht_kat_common.h
 *
 * Shared freestanding C11 declarations used by every tests/harness/kat_*.c
 * driver. The KAT harness links C against HeavyThing's pure-x86_64 assembly
 * crypto stack and is therefore compiled and linked as a self-contained,
 * libc-free program:
 *
 *     gcc -std=c11 -Wall -Wextra -O2 -nostdlib -static \
 *         -o build/bin/kat_<name> harness/kat_<name>.c \
 *         harness/ht_kat_common.c build/libht.a
 *
 * Because the harness is built with -nostdlib, the hosted C standard library
 * is unavailable: there is no <stdio.h>, <stdlib.h> or <string.h>, no malloc,
 * no printf, and no libc _start. HeavyThing supplies its own memory subsystem
 * and a raw syscall primitive instead. This header consequently pulls in only
 * <stddef.h> (a freestanding header, ISO C11 4 p6 / 7.19) for size_t, and
 * declares:
 *
 *   - ht$syscall : the HeavyThing raw-syscall primitive, defined in assembly
 *                  and provided at link time by build/libht.a; and
 *   - a small set of helpers (ht_kat_*, plus a freestanding strlen) that are
 *     implemented in the sibling translation unit tests/harness/ht_kat_common.c
 *     and linked alongside each driver.
 *
 * Reference interop pattern: examples/hello_world_c1/hello.c (repo root,
 * READ-ONLY), which declares HeavyThing entry points as plain externs using
 * their literal names. HeavyThing public symbols contain a '$' character and
 * are used here verbatim; this header neither renames, wraps, nor moves any
 * HeavyThing symbol. Nothing outside tests/ is referenced or modified.
 *
 * See AAP 0.4.4 (shared utilities, C side) and 0.5.5 (cross-file test
 * dependencies).
 * ------------------------------------------------------------------------ */

#ifndef HT_KAT_COMMON_H
#define HT_KAT_COMMON_H

#include <stddef.h>     /* size_t -- the only permitted include (freestanding) */

/* ------------------------------------------------------------------------
 * HeavyThing primitive (defined in assembly, linked from build/libht.a)
 * ------------------------------------------------------------------------ */

/* ht$syscall -- HeavyThing's raw Linux syscall wrapper.
 *
 * Defined in ht.inc as a variadic, deliberately non-efficient HLL->syscall
 * bridge intended exactly for -nostdlib C consumers: the first argument is the
 * syscall number and the remaining arguments are the syscall's parameters in
 * order. The return value is the kernel's raw result (a negative errno on
 * failure), returned here as a long.
 *
 * The harness uses it for the two syscalls it needs:
 *     write(2): ht$syscall(1, fd, buf, len)   -- e.g. ht$syscall(1, 1, buf, len)
 *     exit(2):  ht$syscall(60, status)
 *
 * It is re-declared here so that drivers may call it directly without each
 * repeating a local extern. The '...' prototype matches HeavyThing's variadic
 * implementation, which reads its arguments from the integer-argument
 * registers and does not depend on the variadic SSE-count in %al. */
extern long ht$syscall(long number, ...);

/* ------------------------------------------------------------------------
 * Freestanding C standard-library replacement
 * (implemented in tests/harness/ht_kat_common.c)
 * ------------------------------------------------------------------------ */

/* strlen -- length of a NUL-terminated byte string, excluding the terminator.
 *
 * Provided locally because the harness links with -nostdlib and therefore has
 * no libc strlen; GCC may also emit implicit calls to strlen for certain code
 * shapes even in freestanding mode, so a definition must exist. The prototype
 * matches the GCC built-in exactly (size_t result, const char * argument) to
 * compile cleanly under -Wall (-Wbuiltin-declaration-mismatch). */
size_t strlen(const char *s);

/* ------------------------------------------------------------------------
 * Harness lifecycle helpers
 * (implemented in tests/harness/ht_kat_common.c)
 * ------------------------------------------------------------------------ */

/* ht_kat_init -- initialize HeavyThing's runtime exactly once.
 *
 * Calls ht$init_args(0, NULL) to bring up HeavyThing's internal memory
 * subsystem before any crypto primitive is invoked. Every driver must call
 * this once at startup. */
void ht_kat_init(void);

/* ht_kat_exit -- terminate the process immediately with the given status.
 *
 * Wraps ht$syscall(60, status) (the Linux exit syscall). Used instead of the
 * (unavailable) libc exit() so a driver can report success (0) or a usage /
 * decode error (non-zero) that the Python runner observes via the subprocess
 * return code. The call does not return in practice; it is declared plain
 * void (not _Noreturn) so the sibling definition in ht_kat_common.c, whose
 * body terminates via the external ht$syscall, compiles without the
 * 'noreturn function does return' diagnostic. */
void ht_kat_exit(int status);

/* ------------------------------------------------------------------------
 * Argument parsing and hex I/O helpers
 * (implemented in tests/harness/ht_kat_common.c)
 * ------------------------------------------------------------------------ */

/* ht_kat_parse_uint -- STRICT base-10 unsigned parser with range checking.
 *
 * Freestanding replacement for the libc strtoul family, used by drivers to read
 * numeric KAT parameters supplied on the command line (PBKDF2 iteration counts
 * and derived-key lengths, scrypt N/r/p and dk_len, HMAC-DRBG requested byte
 * counts, HMAC PRF output lengths, hash split-offsets / MGF1 mask lengths, DH
 * pool indices, ...). Unlike a lenient atoi, this parser is DELIBERATELY STRICT:
 * a KAT harness validates machine-readable fixture metadata, so any malformed or
 * out-of-range parameter must be rejected outright rather than silently coerced.
 *
 * On success the parsed value is written to *out and 0 is returned. On ANY of
 * the following the function returns -1 and leaves *out unmodified, so the
 * caller can report a clean non-zero usage/validation exit:
 *   - s is NULL or the empty string;
 *   - s contains any character that is not an ASCII decimal digit '0'..'9'
 *     (this rejects a leading '+'/'-' sign AND any trailing garbage such as the
 *     "1junk" / "20junk" forms, i.e. there is no leading-prefix tolerance);
 *   - the accumulated value would overflow an unsigned long (64-bit on x86_64);
 *   - the parsed value is < minv or > maxv (inclusive range).
 *
 * The accumulator is an unsigned long, so large in-range counts -- RFC 6070's
 * 16,777,216 PBKDF2 iterations or RFC 7914's N = 1,048,576 -- parse without
 * truncation. Leading zeros are accepted (unambiguous decimal); the canonical
 * value 0 is accepted when minv == 0 (e.g. HMAC-DRBG's requested_bytes == 0
 * generate-after-destroy sentinel). Implemented with the (~0UL) overflow guard
 * and no libc dependency, so it is safe under -nostdlib. */
int ht_kat_parse_uint(const char *s, unsigned long minv, unsigned long maxv,
                      unsigned long *out);

/* ht_kat_hex_decode -- decode a NUL-terminated lowercase/uppercase hex string
 * into the byte buffer out[].
 *
 * Writes at most out_size bytes. Returns the number of bytes written on
 * success, or -1 on error (odd input length, a non-hex character, or a result
 * that would exceed out_size). An empty input string decodes to 0 bytes. */
int ht_kat_hex_decode(const char *hex, unsigned char *out, size_t out_size);

/* ht_kat_hex_arg -- decode a hex command-line argument (e.g. argv[n]) into
 * out[], tolerating a missing argument and supporting the documented "-"
 * read-from-stdin convention.
 *
 * Convenience wrapper over ht_kat_hex_decode for the common driver pattern of
 * decoding an argv slot that may be absent or deferred to stdin:
 *
 *   - A NULL pointer is treated as an empty (zero-byte) input, so a driver can
 *     pass a possibly-missing argument directly without a prior NULL check.
 *   - The single-character argument "-" means "read the hex from standard
 *     input" (file descriptor 0). Every kat_*.c driver that advertises an
 *     "<..._hex|->" argument relies on this so the Python runner can thread a
 *     large or awkward-to-quote payload via subprocess stdin instead of argv.
 *     The stdin bytes are read as a hex text string (an optional trailing
 *     newline / whitespace is ignored) and decoded to raw bytes exactly as a
 *     hex argv value would be.
 *   - Any other string is decoded as hex via ht_kat_hex_decode.
 *
 * Returns the decoded byte count, or -1 on malformed hex, a stdin read error,
 * or input that would exceed out_size -- consistent with ht_kat_hex_decode. */
int ht_kat_hex_arg(const char *hex, unsigned char *out, size_t out_size);

/* ht_kat_hex_print -- write the lowercase hex encoding of buf[0..len) to
 * standard output (file descriptor 1).
 *
 * Emits two lowercase hex characters per input byte via ht$syscall(1, 1, ...)
 * (the write syscall to fd 1). This is how each driver reports its computed
 * digest / ciphertext; the Python runner captures stdout and compares it,
 * after .strip(), against the vector's expected hex. */
void ht_kat_hex_print(const unsigned char *buf, size_t len);

#endif /* HT_KAT_COMMON_H */
