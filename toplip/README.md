# toplip

Command-line file encryption and decryption utility that combines a modified scrypt-SHA512 KDF, cascaded AES-256 via `htcrypt`, and XTS-AES via `htxts`, with optional base64 output and PNG, JFIF, or EXIF-JPG media-carrier embedding.

## Overview

`toplip` is a single-binary showcase application built on the HeavyThing library. Its two explicit design goals are aggressive resistance to passphrase brute-forcing and plausible deniability: a ciphertext blob has no magic bytes, no length prefix, no alignment markers, and is indistinguishable from a random byte stream of the same length (Source: /toplip/toplip.asm:76–107,225–261). The payload format provides for up to four cascaded encryption streams so that a second, alternate passphrase set can legitimately decrypt to a different file without revealing whether additional payloads exist (Source: /toplip/toplip.asm:88–90,253–260).

The program is one translation unit of 3795 lines that includes the standard three-file HeavyThing contract (`ht_defaults.inc` first, `ht.inc` next, `ht_data.inc` as the sealing include at end of file) and no local companion `.inc` files (Source: /toplip/toplip.asm:409–410,3795). Two run modes are selected by CLI: encrypt is the default; `-d` switches to decrypt (Source: /toplip/toplip.asm:30,419). Three output transports are available: direct write to stdout, base64 encoding via `-b`, and in-place embedding inside a PNG or JPG media file via `-m mediafile` (Source: /toplip/toplip.asm:29,32–35,66–67).

## Architecture Fit

`toplip` is a leaf application binary, not a library subsystem. It participates in the HeavyThing three-file include contract documented in [`../docs/architecture.md`](../docs/architecture.md) and exposes no public ABI for external callers — every `public` label in the source is an internal entry point used by `_start` itself.

Dependencies in:

| Dependency | Role |
|---|---|
| [`../ht_defaults.inc`](../ht_defaults.inc) | first include; alignment, profiling, feature flags (Source: /toplip/toplip.asm:409) |
| [`../ht.inc`](../ht.inc) | second include; pulls the full HeavyThing library (Source: /toplip/toplip.asm:410) |
| [`../ht_data.inc`](../ht_data.inc) | final include; seals the data segment (Source: /toplip/toplip.asm:3795) |
| [`../aes.inc`](../aes.inc) | AES-256 block cipher |
| [`../htcrypt.inc`](../htcrypt.inc) | cascaded-AES-256 wrapper that holds up to 256 contexts per call |
| [`../htxts.inc`](../htxts.inc) | XTS-AES layer built on top of `htcrypt` for payload encryption |
| [`../scrypt.inc`](../scrypt.inc) | modified scrypt-SHA512 KDF generating the initial 8192-byte key pool |
| [`../hmac.inc`](../hmac.inc) | HMAC-SHA256 for TLSv1.2 PRF and HMAC-DRBG; HMAC-SHA512 for the per-payload integrity tag |
| [`../hmac_drbg.inc`](../hmac_drbg.inc) | HMAC-DRBG(SHA256) optional key-material mixer |
| [`../rng.inc`](../rng.inc) | PRNG for the SALT, IV blocks, preamble, padding, and trailing garbage |
| [`../png.inc`](../png.inc) | PNG chunk parser used by media-carrier mode |
| [`../base64_latin1.inc`](../base64_latin1.inc) | base64 encode and decode |
| [`../privmapped.inc`](../privmapped.inc) | private file mapping for input reads |
| [`../buffer.inc`](../buffer.inc) | in-memory growable byte buffer |
| [`../list.inc`](../list.inc) | linked list of input-file records |
| [`../heap.inc`](../heap.inc) | general allocator |
| [`../crc.inc`](../crc.inc) | CRC-32 for PNG ancillary-chunk emission |

Dependencies out: none. `toplip` is a terminal consumer of the library and is not imported by any other source file in the repository.

## Key Components

`toplip` is unusual among HeavyThing tools in that the entire program lives in one `.asm` file with no local companion `.inc` files; every globals declaration, helper label, and state machine is inline.

| File | Purpose |
|---|---|
| [`./toplip.asm`](./toplip.asm) | complete program: 400-line design-rationale header, `globals { }` block, `inputfile` record lifecycle, scrypt-based key derivation and mixing, per-file encrypt and decrypt pipelines, media-carrier emitters, forward and reverse CLI parsers, banner and usage string, `_start` entry (Source: /toplip/toplip.asm:1–3795) |

### Internal labels

The following internal entry points are listed here as a reading guide; they are not a public API and are subject to change without notice:

| Label | Line | Role |
|---|---|---|
| `inputfile$new` | 514 | allocate a per-file record and reset per-file CLI defaults (Source: /toplip/toplip.asm:514,543–546) |
| `inputfile$destroy` | 567 | tear down an input-file record |
| `inputfile$new_bogus` | 614 | synthesise a decoy input-file record used for plausible-deniability padding |
| `inputfile$load` | 668 | read a file via `privmapped`; on decrypt, also decode base64 or extract embedded payload from media |
| `inputfile$keygen` | 1009 | run scrypt-SHA512, dispatch the selected key mixer (`.nomix`, `.drbgmix`, `.tlsprfmix`), build up to 256 `htcrypt` contexts (Source: /toplip/toplip.asm:1009,1138–1139) |
| `inputfile$extents` | 1377 | compute stream offsets in the output |
| `inputfile$headeriv` | 1392 | encode the CBC-style HEADER and IV pair for a payload |
| `inputfile$encrypt` | 1536 | XTS-AES encrypt the per-file payload via `htxts` |
| `inputfile$decrypt` | 1858 | XTS-AES decrypt the per-file payload via `htxts`, validate minimum size |
| `argscan` | 2681 | forward CLI parser; flag dispatch via `string$equals` against cleartext constants (Source: /toplip/toplip.asm:2681,2908–2918) |
| `mainargopts` | 2926 | reverse walker that attaches per-inputfile flags to the final positional argument |
| `termreset` | 3052 | restore termios (re-enable ECHO) on normal exit via `TCSETSF` (Source: /toplip/toplip.asm:3052–3058) |
| `outmedia$identify` | 3068 | detect PNG, JFIF, or EXIF-JPG signature on a `privmapped` media carrier |
| `outmedia$merge` | 3194 | emit the ciphertext inside an ancillary PNG chunk or a sequence of APP12 JPG segments (Source: /toplip/toplip.asm:3194–3456) |
| `output` | 444 | stdout, base64, and media-output multiplexer |
| `output_flush` | 459 | drain the output buffer with format-specific tails |
| `_start` | 3460 | program entry; first action is `call ht$init` (Source: /toplip/toplip.asm:3460–3463) |

## Calling Convention

`toplip` is a standalone executable; it exposes no library-level ABI for external callers. Every internal label listed above follows the HeavyThing `subsystem$function` naming convention (for example `inputfile$keygen`, `outmedia$merge`). The full register contract, `prolog` and `epilog` macro expectations, 16-byte stack-alignment requirement, and program exit-code conventions are not restated here; see [`../docs/calling-convention.md`](../docs/calling-convention.md).

### CLI Reference

`toplip` accepts a mix of global flags and per-inputfile flags. Global flags set program-wide mode. Per-inputfile flags attach to the inputfile they precede when encountered left-to-right during `argscan`, and `mainargopts` walks the argv in reverse to attach any trailing per-file flags to the main (final) inputfile (Source: /toplip/toplip.asm:2681,2926). Per-file flags are reset to defaults at the start of each new inputfile record by `inputfile$new` (Source: /toplip/toplip.asm:543–546).

| Flag | Argument | Default | Scope | Purpose |
|---|---|---|---|---|
| `-b` | — | off | global | base64 I/O; encrypt emits base64 to stdout, decrypt reads base64 from the input file (Source: /toplip/toplip.asm:29,66–67) |
| `-d` | — | encrypt | global | switch to decrypt mode (Source: /toplip/toplip.asm:30) |
| `-r` | — | prompt | global | generate and display 48-byte base64 one-time passphrases instead of prompting (Source: /toplip/toplip.asm:31,1025–1027) |
| `-m` | `mediafile` | off | global | embed encrypted output inside a PNG, JFIF, or EXIF JPG; on decrypt this is auto-detected from the input (Source: /toplip/toplip.asm:32–35) |
| `-1` | — | cascaded on | per inputfile | disable cascaded AES-256; the `htcrypt` context count falls back to a single AES-256 (Source: /toplip/toplip.asm:36–37,1104–1109) |
| `-c` | `COUNT` | 1 | per inputfile | number of passphrases to cascade for this inputfile (Source: /toplip/toplip.asm:38–41,412,423) |
| `-i` | `ITER` | 1 | per inputfile | iteration count for scrypt's internal PBKDF2-SHA512; accepts decimal or hex (Source: /toplip/toplip.asm:42–47,413,424) |
| `-drbg` | — | PRF | per inputfile | mix 8192-byte key material with HMAC-DRBG(SHA256) instead of TLSv1.2 PRF(SHA256) (Source: /toplip/toplip.asm:48–50) |
| `-nomix` | — | PRF | per inputfile | skip mixing; use raw scrypt output as the key material (Source: /toplip/toplip.asm:51–52) |
| `-alt` | `inputfile` | — | encrypt only | add a plausible-deniability payload; may be specified up to 3 times for 4 total input files (Source: /toplip/toplip.asm:53–58) |
| `-noalt` | — | padded | encrypt only | do not add random decoy payloads; by default decoys are inserted so the payload count is hidden (Source: /toplip/toplip.asm:59–65) |

## Usage

The three-file include contract is visible at the top and bottom of `toplip.asm`: `../ht_defaults.inc` on line 409, `../ht.inc` on line 410, and `../ht_data.inc` on line 3795. Assembly code blocks below use the `nasm` fence tag for GitHub highlighting; the actual assembler is FASM. See [`../docs/building.md`](../docs/building.md) for the full build reference.

Minimal skeleton showing the canonical HeavyThing include order and entry-point call (drawn directly from `toplip.asm`):

```nasm
include '../ht_defaults.inc'
include '../ht.inc'

falign
public _start
_start:
        ; every HeavyThing program begins with ht$init
        call    ht$init
        ; program body goes here

include '../ht_data.inc'
```

Build the shipped tool with a single `fasm` and `ld` invocation:

```bash
fasm -m 524288 toplip.asm && ld -o toplip toplip.o
```

Representative runtime invocations cover the main modes. Each invocation below uses placeholder filenames:

```bash
# Encrypt a plaintext file with a single interactive passphrase; ciphertext to stdout.
./toplip secret.txt > secret.bin

# Encrypt with 2 cascaded passphrases and 4096 PBKDF2-SHA512 iterations per scrypt call.
./toplip -c 2 -i 0x1000 secret.txt > secret.bin

# Encrypt and emit base64 so the output can be pasted into a text channel.
./toplip -b secret.txt > secret.b64

# Encrypt with a plausible-deniability decoy payload; two distinct passphrase sets required.
./toplip -alt decoy.txt secret.txt > ambiguous.bin

# Encrypt and embed the ciphertext inside a PNG ancillary chunk.
./toplip -m photo.png secret.txt > photo_with_secret.png

# Decrypt a base64 ciphertext back to plaintext on stdout.
./toplip -d -b < secret.b64 > secret.txt

# Decrypt a media-carrier file; the carrier type is auto-detected.
./toplip -d photo_with_secret.png > secret.txt
```

Running `./toplip` with no arguments prints the banner followed by the embedded usage string to stderr and exits with status 1 (Source: /toplip/toplip.asm:3466,3729–3739,3750–3791).

## Configuration

Runtime behaviour is entirely CLI-driven; `toplip` does not read a configuration file at run time. Compile-time behaviour is inherited from [`../ht_defaults.inc`](../ht_defaults.inc). See [`../docs/security.md`](../docs/security.md) for cryptographic implications of these settings.

Relevant compile-time knobs:

| `ht_defaults.inc` knob | Relevance to `toplip` |
|---|---|
| `rng_heavy_init` | controls the depth of HMAC-DRBG seeding at library init; determines the entropy of every PRNG-sourced field (SALT, IV blocks, preamble, padding, garbage) |
| `scrypt_sha512` | must be enabled; the KDF design explicitly depends on scrypt's SHA-512 variant to produce the 8192-byte key pool (Source: /toplip/toplip.asm:100–107,137–155) |
| `bigint_maxwords` | indirectly consumed by scrypt and HMAC as they build on bigint and buffer primitives |
| `include_everything` | not required for `toplip`; the default `if used` elision applies because all label references are internal |

Program-internal globals and their startup defaults (Source: /toplip/toplip.asm:417–440):

| Global | Default | Purpose |
|---|---|---|
| `do_enc` | `1` | encrypt mode flag; cleared by `-d` |
| `do_b64` | `0` | base64 I/O flag; set by `-b` |
| `do_pwd` | `0` | one-time passphrase generator flag; set by `-r` |
| `do_cascaded` | `1` | cascaded AES-256 enabled; cleared per-file by `-1` |
| `pcount` | `1` | one passphrase per inputfile; overridden by `-c` |
| `piter` | `1` | one PBKDF2-SHA512 iteration; overridden by `-i` |
| `pmix` | `2` | key-material mixer: `0` nomix, `1` HMAC-DRBG(SHA256), `2` TLSv1.2 PRF(SHA256) default |
| `noalt` | `0` | decoy padding on; set by `-noalt` to suppress decoy payloads |

The on-disk output has a fixed layout that is deliberately not self-describing. The first 32 bytes are a PRNG SALT, followed by eight 16-byte blocks at offsets 32 through 159; two of these blocks are used per payload as the HEADER and IV, and the remaining unused blocks are filled with PRNG output. From offset 160 onward, one to four `htxts`-encrypted payloads are concatenated; each payload consists of a 64-byte PRNG preamble, the padded plaintext, an HMAC-SHA512 tag over the plaintext, and 1 to 15 bytes of trailing PRNG garbage (Source: /toplip/toplip.asm:225–261). No part of this layout contains a magic number, length prefix, or alignment marker.

## Limitations

- **AES-256 is the only block cipher** exposed; no 128-bit variant, no alternative cipher (Source: /toplip/toplip.asm:137–139,194–196).
- **Modified scrypt-SHA512 is the only KDF**; no Argon2, no plain PBKDF2, no bcrypt (Source: /toplip/toplip.asm:100–107).
- **The key-derivation pipeline is not NIST or FIPS approved**; the source comments explicitly disclaim this (Source: /toplip/toplip.asm:154–155).
- **Base64 and media-carrier modes buffer the entire crypto stream in memory**, and `-alt` decoys are likewise held in memory before emission (Source: /toplip/toplip.asm:69–72).
- **Linux x86_64 only**: the process uses `TCGETS` and `TCSETSF` ioctls plus Linux syscall numbers directly and has no portability shim (Source: /toplip/toplip.asm:3468–3492).
- **The XTS-AES payload is not authenticated in an AEAD sense**; integrity is provided by an appended HMAC-SHA512 over the plaintext only (Source: /toplip/toplip.asm:238–240).
- **No pre-encryption compression** is performed; applying `gzip`, `zstd`, or similar to the plaintext before encryption is left to the caller.
- **Media-carrier capacity is bounded** by the underlying container: a single PNG ancillary chunk for PNG carriers, or a sequence of APP12 segments of at most 65525 bytes each for JPG carriers (Source: /toplip/toplip.asm:3195–3456).
- **Stack-resident key material is zeroised with PRNG fill** after use, which is best-effort; other in-heap intermediate state relies on the library's heap-zero policy (Source: /toplip/toplip.asm:1113–1117).
- **Not a drop-in replacement for GPG, age, or `openssl enc`**: `toplip` is a targeted showcase of the HeavyThing crypto stack with an explicit plausible-deniability posture, and its output format interoperates with nothing else.
- **Passphrase prompts are read interactively from the controlling terminal** with ECHO disabled; non-interactive pipelines must use `-r` to have per-run 48-byte passphrases generated and printed to stderr.

## See Also

- [`../README.md`](../README.md) — project landing page and the three-file include contract summary
- [`../crypto/README.md`](../crypto/README.md) — AES, scrypt, HMAC, and RNG primitives consumed by `toplip`
- [`../docs/security.md`](../docs/security.md) — cryptographic primitive scope, standards references, and posture
- [`../docs/architecture.md`](../docs/architecture.md) — three-file include contract, initialisation lifecycle, exit codes
- [`../docs/building.md`](../docs/building.md) — FASM invocation, link command, troubleshooting
- [`../docs/calling-convention.md`](../docs/calling-convention.md) — register contract and `subsystem$function` label convention
- [`../dhtool/README.md`](../dhtool/README.md) — another crypto-focused HeavyThing showcase tool
- [`./toplip.asm`](./toplip.asm) — the complete source; the header comments on lines 22–406 are the authoritative design rationale

---

Licensed under GPLv3. See [`../LICENSE`](../LICENSE).

