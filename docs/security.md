# HeavyThing Security Notes

## Overview

This document enumerates the scope of HeavyThing's cryptographic primitives,
the network-security protocol implementations that depend on them, and the
known caveats that operators must account for. HeavyThing is a self-contained
x86_64 assembly-language library that implements its own cryptographic
primitives, TLS stack, and SSH stack from first principles; it does not link
against OpenSSL, BoringSSL, mbedTLS, libgcrypt, or any other external
cryptographic library, and the entire protocol and primitive stack is compiled
in via the chain at `/ht.inc:141-167` (Source: /ht.inc:141-167).

HeavyThing makes deliberate, narrow design choices that trade broad
interoperability for a small auditable surface. The library supports AES as
the only block cipher, TLS 1.2 as the only TLS version, and SSH2 as the only
SSH version (Source: /tls.inc:22-23, /ssh.inc:22-23). Elliptic-curve primitives
are intentionally absent for reasons documented in `/tls.inc:56-72`. The
sections below describe what is present, what is not, and how each piece
should be operated.

## Cryptographic Primitive Scope

The following table enumerates every primitive available to an application
linked against HeavyThing. The Implementation column names the `.inc` file
that contains the primitive; the Standard column names the governing
specification where one exists; the Notes column records authorship or
lineage of the implementation.

| Primitive | Implementation | Standard | Notes |
|---|---|---|---|
| AES-128 / AES-192 / AES-256 | `/aes.inc` | FIPS-197 | AESNI-accelerated when the CPU supports it, falls back to a software implementation derived from Wei Dai with the 2006 Bonneau and Mironov timing countermeasures applied (Source: /aes.inc:22-34) |
| SHA-160 (SHA-1) | `/sha1.inc` | FIPS-180-4 | Present only because older TLS 1.0/1.1 compatibility historically required it (Source: /sha1.inc:22-28) |
| SHA-224 / SHA-256 / SHA-384 / SHA-512 | `/sha2.inc` | FIPS-180-4 | Translated loosely from Wei Dai's public-domain implementation; optimised for non-SSE4 / non-AVX / non-AVX2 hardware (Source: /sha2.inc:22-30) |
| MD5 | `/md5.inc` | RFC 1321 | Exposed as `md5$new`, `md5$init`, `md5$update`, `md5$transform`, `md5$final`, `md5$mgf1` (Source: /md5.inc:32,48,87,162,371,483) and additionally wrapped as HMAC-MD5 and PBKDF2-HMAC-MD5 for legacy TLS 1.0/1.1 interoperability; guts are Marc Bevand's public-domain code (Source: /md5.inc:22-26) |
| HMAC | `/hmac.inc` | RFC 2104 | Function-pointer dispatch; state buffer sized to accommodate SHA-512 so the same struct works for every digest (Source: /hmac.inc:22-32) |
| HMAC-DRBG | `/hmac_drbg.inc` | NIST SP 800-90A | Caller supplies initial seed; reseed interval is `1 shl 19` = 524288 generations (Source: /hmac_drbg.inc:41-44); reseeds pull `hmac$hashsize` bytes from `/dev/urandom` (Source: /hmac_drbg.inc:23-29) |
| PBKDF2 | `/pbkdf2.inc` | RFC 2898 | Thin wrapper over HMAC; supports every HMAC variant (Source: /pbkdf2.inc:22-23) |
| scrypt | `/scrypt.inc` | RFC 7914 | Colin Percival reference-style implementation; supported with `r = 1` and `p = 1` only; default `scrypt_N = 1024` (Source: /scrypt.inc:22-40) |
| Diffie-Hellman (DH) | `/bigint.inc`, `/dh_pool.inc` | RFC 2631, RFC 4419 | Precomputed safe primes shipped in `/dh_pool.inc` families; bigint arithmetic is library-private (Source: /ht.inc:162-164) |
| htcrypt | `/htcrypt.inc` | Library-specific | Cascaded AES-256 using 256 independent contexts derived from an 8 KiB modified-scrypt / HMAC-SHA512 key schedule with an additional 1024-round AES-256 grind; not used by TLS or SSH (Source: /ht.inc:150) |
| htxts | `/htxts.inc` | Library-specific | AES-XTS-style wrapper layered over htcrypt; block size 2048 bytes; not used by TLS or SSH (Source: /ht.inc:151) |

RSA and DSA are implemented inside `/tls.inc`, `/ssh.inc`, and `/X509.inc` as
the minimum subset needed to validate signatures and load PEM / SSH host-key
files; `/X509.inc` documents itself as "just enough X509 goods to deal with
the TLS/SSH that I require" (Source: /X509.inc:22). SSH server host keys are
supported as `ssh-rsa` and `ssh-dss`, with the compile-time choice exposed
through the three `ssh_kexinit_both`, `ssh_kexinit_rsa`, and `ssh_kexinit_dsa`
tables (Source: /ssh.inc:126-150).

## Random Number Generation

HeavyThing exposes two distinct random-number paths. Callers must select the
correct path for the task at hand; conflating the two is the most likely
operational mistake an integrator can make.

The fast path is a combined SFMT (SIMD-oriented Fast Mersenne Twister) plus
Agner Fog's Mother-Of-All generator, transcoded from Agner Fog's GPL
randoma package (Source: /rng.inc:22-30). Its public entry points are
`rng$int`, `rng$intmax`, `rng$u32`, `rng$u64`, `rng$double`, `rng$block`, and
`rng$block_nzb` (Source: /rng.inc:572-996). The state-size subsequence that
would allow an attacker to reconstruct the full sequence is 1408 bytes
(Source: /rng.inc:38-45). This generator is NOT cryptographically secure in
continuous-output mode: exposing 1408 contiguous output bytes is sufficient
to reconstruct internal state, and callers must therefore either discard bits
between reads or use the heavy path for long-term keying material
(Source: /rng.inc:38-50).

The `rng$block` and `rng$block_nzb` labels used by the TLS and SSH stacks
automatically discard bits so that no complete subsequence is exposed across
the wire (Source: /rng.inc:49-50). These labels are appropriate for nonces,
challenge data, and short-lived randomisers, but are NOT appropriate for
long-term keying material.

The heavy path is HMAC-DRBG (`/hmac_drbg.inc`). It is gated by the
`rng_heavy_init` knob in `/ht_defaults.inc`, which defaults to 1
(Source: /ht_defaults.inc:94). When enabled, `rng$init` seeds the fast
generator from HMAC-DRBG output at startup. For key material generation
independent of `rng$init`, callers must invoke HMAC-DRBG directly and supply
their own seed (Source: /hmac_drbg.inc:22-29).

The `rng_paranoid` knob controls whether the seed source is `/dev/random`
(blocking) or `/dev/urandom` (non-blocking); the default is 0, meaning
`/dev/urandom` is used (Source: /ht_defaults.inc:98).

The RNG is NOT thread-safe: the fast generator's state is a process-global
buffer (Source: /rng.inc:52). Applications that fork worker processes before
calling the RNG inherit the parent's state; applications that thread must
serialise access externally or maintain per-thread state.

## Known Caveats

The following caveats are inherent to HeavyThing's design. They are
documented here so operators can decide whether HeavyThing's posture is
appropriate for a given deployment.

| Caveat | Source | Mitigation |
|---|---|---|
| SHA-160 / SHA-1 is known-weak | /sha1.inc:22-28 | Present only for TLS 1.0/1.1 interoperability; new application code must use SHA-256 or higher |
| MD5 is cryptographically broken | RFC 6151; /md5.inc:22-26 | Exposed primarily inside HMAC-MD5 and PBKDF2-HMAC-MD5 for legacy compatibility; standalone digest labels are present but must not be used for new data-integrity purposes |
| Software AES may leak via cache-timing when AESNI is absent | /aes.inc:26-34 | Wei Dai timing countermeasure is applied; the AESNI path is preferred when the CPU reports AESNI |
| CBC-mode TLS requires constant-time MAC verification to avoid padding-oracle attacks | /tls.inc (CBC-only suite list, /tls.inc:145-166) | HeavyThing's TLS implementation uses the documented countermeasure pattern; AEAD cipher suites are not implemented |
| SSH CBC-mode is vulnerable to the Plaintext Recovery Attack by default | /ssh.inc:46-60 | Triple-layer mitigation: bad-length handling runs for a random time so bad-length and bad-HMAC cannot be distinguished; normal operation never produces HMAC errors, so on an HMAC error the length requirement is randomised; in client mode an `SSH_MSG_IGNORE` carrying random data is sent before the password (see the paper at isg.rhul.ac.uk / ~kp / SandPfinal.pdf cited in /ssh.inc:48-49) |
| The fast RNG (SFMT + Mother-Of-All) is not cryptographically secure for continuous output | /rng.inc:32-50 | Use HMAC-DRBG via `/hmac_drbg.inc` for long-term keying material; the TLS and SSH stacks use `rng$block` / `rng$block_nzb`, which internally discard bits |
| RNG state is not thread-safe | /rng.inc:52 | Callers must serialise access or maintain per-thread state |
| TLS 1.3 is not implemented | /tls.inc:22-23 | Operators requiring TLS 1.3 must use a different stack |
| HeavyThing's TLS does not perform X509 chain validation | /tls.inc:25-35 | Documented as explicit garbage-in / garbage-out policy; operators deploying HeavyThing as a TLS client must pin known-good certificates out-of-band and must not rely on CA trust |
| HeavyThing's SSH client does not verify the server host key against a known-hosts database | /ssh.inc:79-83 | Host-key fingerprinting hooks are marked in `/ssh.inc` for applications to implement; the library verifies the host signature but does not maintain a known-hosts file |
| On PEM reload, old X509 objects are intentionally never freed | /tls.inc:92-124 | Deliberate design to avoid quiescing in-flight connections during certificate rotation; acceptable because rotations are expected approximately once per year or two; replacing a PEM with an invalid file while the server is running will likely crash in-flight handshakes |

## TLS Support Matrix

HeavyThing implements TLS 1.2 only (Source: /tls.inc:22-23). The
implementation is a deliberate minimalist subset: it supports AES-CBC cipher
suites exclusively. AEAD suites (GCM, CCM) are not implemented; elliptic-curve
cipher suites are not implemented. The design notes at `/tls.inc:47-72`
document the rationale: AES hardware acceleration is sufficiently fast that
GCM offers no meaningful throughput gain for HeavyThing's target workload;
CCM was not supported by browsers at the time; elliptic-curve cipher suites
are rejected on grounds of the Dual_EC_DRBG revelations and the concerns
about the NIST curves publicly raised by Bruce Schneier (Source: /tls.inc:64-72).

### Cipher Suites by Build Mode

Three build modes produce three different suite lists. The mode is selected
by the `tls_minimalist` and `tls_perfect_forward_secrecy_only` knobs in
`/ht_defaults.inc`.

| Cipher Suite | Default Build | PFS-Only Build | Minimalist Build |
|---|---|---|---|
| TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 (0x00, 0x6a) | Yes | Yes | No |
| TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x00, 0x6b) | Yes | Yes | No |
| TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 (0x00, 0x32) | Yes | Yes | No |
| TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x00, 0x67) | Yes | Yes | No |
| TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x00, 0x32, DSS-SHA variant) | Yes | Yes | No |
| TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x00, 0x33) | Yes | Yes | No |
| TLS_DHE_DSS_WITH_AES_256_CBC_SHA (0x00, 0x38) | Yes | Yes | No |
| TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x00, 0x39) | Yes | Yes | No |
| TLS_RSA_WITH_AES_256_CBC_SHA256 (0x00, 0x3d) | Yes | No | No |
| TLS_RSA_WITH_AES_128_CBC_SHA256 (0x00, 0x3c) | Yes | No | No |
| TLS_RSA_WITH_AES_256_CBC_SHA (0x00, 0x35) | Yes | No | No |
| TLS_RSA_WITH_AES_128_CBC_SHA (0x00, 0x2f) | Yes | No | Yes (only suite) |

The Default build offers twelve suites (Source: /tls.inc:145-160); the
PFS-Only build (selected by `tls_perfect_forward_secrecy_only = 1`) drops the
four static-RSA key-exchange suites and offers eight (Source:
/tls.inc:154-160); the Minimalist build (selected by `tls_minimalist = 1`)
offers only `TLS_RSA_WITH_AES_128_CBC_SHA` (Source: /tls.inc:162-164). Note
that `/tls.inc:148` carries a source-comment typo: the suite hex `0x00, 0x32`
is tagged `TLS_DHE_DSS_WITH_AES_128_CBC_SHA256`, whereas the IANA-registered
meaning of `0x00, 0x32` is `TLS_DHE_DSS_WITH_AES_128_CBC_SHA`; the table
above records both rows as they appear in the source per the Minimal Change
Clause.

Commented-out GCM suites (`0x00, 0xa3 / 0x9f / 0xa2 / 0x9e / 0x9d / 0x9c`)
appear at `/tls.inc:138-143` as placeholders for a future implementation;
they are not currently wired in.

### Key Exchange Methods

Only three TLS key-exchange methods are supported (Source: /tls.inc:170-172).

| Internal Constant | Value | Key Exchange |
|---|---|---|
| `tls_kex_dhe_dss` | 1 | Ephemeral Diffie-Hellman with DSS server-key signature |
| `tls_kex_dhe_rsa` | 2 | Ephemeral Diffie-Hellman with RSA server-key signature |
| `tls_kex_rsa` | 3 | Static RSA (no forward secrecy) |

DHE key exchanges reuse precomputed safe primes from `/dh_pool.inc` with a
random index selected per connection (Source: /tls.inc:74-76). DH parameter
bit-width is governed by `dh_bits` and the private-key bit-width by
`dh_privatekey_size` in `/ht_defaults.inc`.

### TLS Configuration Knobs

| Knob | Default | Effect |
|---|---|---|
| `tls_minimalist` | 0 | When 1, restricts the cipher list to `TLS_RSA_WITH_AES_128_CBC_SHA` only and strips most of the handshake state machine (Source: /ht_defaults.inc:319) |
| `tls_perfect_forward_secrecy_only` | 0 | When 1, restricts the cipher list to the eight DHE suites only (Source: /ht_defaults.inc:308) |
| `tls_server_cipher_order` | 1 | When 1, the server imposes its cipher ordering rather than the client's (Source: /ht_defaults.inc:300) |
| `tls_server_rsa_blinding` | 0 | Controls RSA blinding countermeasure against remote timing attack; see `/tls.inc:37-45` for rationale (Source: /ht_defaults.inc:314) |
| `tls_pem_refresh_interval` | 3600 | Seconds between checks of each loaded PEM file's mtime for hot-reload (Source: /ht_defaults.inc:304) |
| `tls_blacklist` | 86400 | Seconds that a remote IP stays blacklisted after a crypto error in server mode; the underlying blacklist is `/blacklist.inc` (Source: /ht_defaults.inc:327) |
| `tls_server_sessioncache` | 3600 | Server-side TLS session cache lifetime in seconds, per RFC 5246 (Source: /ht_defaults.inc:334) |
| `tls_server_ocsp_stapling` | 1 | When 1, the server staples OCSP responses per RFC 6066 (Source: /ht_defaults.inc:343) |
| `tls_client_sessioncache` | 3600 | Client-side TLS session cache lifetime in seconds (Source: /ht_defaults.inc:381) |

## SSH Support Matrix

HeavyThing implements SSH protocol version 2.0 only. The ident string sent
on every connection is `SSH-2.0-HeavyThing\r\n` (Source: /ssh.inc:96-100).
When a remote has been blacklisted, the alternate ident string
`SSH-2.0-HeavyThing ::You are blacklisted, find something else to do::\r\n`
is sent instead (Source: /ssh.inc:107-111).

The implementation is narrow by design: the selection of supported
algorithms is documented at `/ssh.inc:25-62` as "not RFC-compliant" in the
sense that several of the RFC's REQUIRED cipher suites, KEX methods, and
MAC algorithms are intentionally omitted.

### Supported Algorithms

| Category | Algorithm | Source |
|---|---|---|
| Key exchange | `diffie-hellman-group-exchange-sha256` (only) | /ssh.inc:128-130 |
| Server host key | `ssh-rsa` (when `ssh_kexinit_rsa` is selected) | /ssh.inc:136-141 |
| Server host key | `ssh-dss` (when `ssh_kexinit_dsa` is selected) | /ssh.inc:144-149 |
| Server host key | both `ssh-rsa` and `ssh-dss` (when `ssh_kexinit_both` is selected; client mode always advertises both) | /ssh.inc:128-133 |
| Cipher, both directions | `aes256-cbc` (only) | /ssh.inc:156-158 |
| MAC, both directions | `hmac-sha2-256` (only) | /ssh.inc:160-162 |
| Compression | `zlib@openssh.com`, `zlib`, and `none` | /ssh.inc:163-180 |

Compression is controlled by two knobs. When `ssh_do_compression = 1` (the
default), compression is offered (Source: /ht_defaults.inc:405). When
`ssh_force_compression = 1` (the default), the `none` compression mode is
withdrawn so that peers cannot opt out (Source: /ht_defaults.inc:411).

### Channel Model

Only a single channel per connection is supported. The channel type is
selected by the `ssh_clientmode_ofs` field: `1` opens a shell channel, `2`
opens an sftp subsystem channel; server mode accepts either (Source:
/ssh.inc:63-68). Stderr is multiplexed into stdout (Source: /ssh.inc:70-72).

### SSH Configuration Knobs

| Knob | Default | Effect |
|---|---|---|
| `ssh_dh_dynamic` | 0 | When 1, DH parameters are generated on-the-fly per connection instead of being drawn from `/dh_pool.inc` (Source: /ht_defaults.inc:402) |
| `ssh_do_compression` | 1 | When 1, zlib compression is offered during key exchange (Source: /ht_defaults.inc:405) |
| `ssh_force_compression` | 1 | When 1, compression is required; `none` is withdrawn from the offered list (Source: /ht_defaults.inc:411) |
| `ssh_blacklist` | 86400 | Seconds that a remote IP stays blacklisted after an authentication or crypto failure in server mode (Source: /ht_defaults.inc:417); the blacklist object is created at `/ht.inc:564-572` |

## X509 and PEM Handling

`/X509.inc` implements the minimum subset of X509 required by HeavyThing's
TLS and SSH stacks; the header comment at `/X509.inc:22` plainly states
"just enough X509 goods to deal with the TLS/SSH that I require"
(Source: /X509.inc:22-44).

Two load paths are provided:

- `X509$new_pem` reads a PEM file that is expected to contain the private
  key plus the certificate and any intermediates (Source: /X509.inc:3782).
- `X509$new_ssh` reads an SSH-style host-key file, typically
  `/etc/ssh/ssh_host_rsa_key`, and optionally accepts an alternate path
  (Source: /X509.inc:3490).

Each loaded X509 object carries `X509_mtime_ofs` at offset 40 and
`X509_checktime_ofs` at offset 48 (Source: /X509.inc:53-54). These fields
support hot-reload: the PEM file's mtime is polled every
`tls_pem_refresh_interval` seconds and the X509 object is reconstructed if
the on-disk file has changed. As documented in Known Caveats, the old X509
object is deliberately leaked rather than freed (Source: /tls.inc:92-124),
so the process resident-set will grow by roughly one certificate's worth
per rotation.

Certificate chain validation is NOT performed by the TLS stack. HeavyThing
treats each loaded X509 as authoritative for its serving identity; clients
do not walk certificate chains up to a trust anchor. Operators deploying
HeavyThing as a TLS client must pin the expected certificate set out-of-band.

## Operational Guidance

The following recommendations apply to production deployments of HeavyThing
or any application built on it.

| Concern | Recommendation |
|---|---|
| PEM rotation | Replace the PEM file in place; the server detects the mtime change within `tls_pem_refresh_interval` seconds (default 3600) and reconstructs the X509 object on its next `tls$pemrevalidate` tick (Source: /ht.inc:552-554, /ht_defaults.inc:304) |
| IP blacklisting | Enable `tls_blacklist` and `ssh_blacklist` (both default to 86400 seconds); the blacklist is backed by `/blacklist.inc` and is coupled to the epoll global time (Source: /blacklist.inc:22-24, /ht_defaults.inc:327,417) |
| OCSP stapling | Leave `tls_server_ocsp_stapling = 1` (the default); HeavyThing fetches OCSP responses via its own webclient and staples them into the handshake (Source: /ht_defaults.inc:343) |
| OCSP refresh tuning | `X509_ocsp_refresh = 7200000` milliseconds (two hours) between refreshes; `X509_ocsp_retry = 300000` milliseconds (five minutes) between retries on failure (Source: /ht_defaults.inc:356,360) |
| Session caching | Enable `tls_server_sessioncache` and `tls_client_sessioncache` (both default to 3600 seconds) to reduce per-connection handshake cost (Source: /ht_defaults.inc:334,381) |
| Forward secrecy | Prefer the DHE_* cipher suites; set `tls_perfect_forward_secrecy_only = 1` to reject the static-RSA suites outright (Source: /ht_defaults.inc:308) |
| DH parameter size | `dh_bits = 2048` (reduced from the earlier default of 4096 on community feedback) and `dh_privatekey_size = 256` (Source: /ht_defaults.inc:280-293) |
| DSA parameter size | `dsa_size = 3072` with `dsa_subgroup_size = 256` (Source: /ht_defaults.inc:275-277) |
| Primality testing rigour | `millerrabinerrorrate = 64` iterations, selectable from 64, 80, 128, 160, or 256 (Source: /ht_defaults.inc:272) |
| Minimalist builds | For appliances that only serve a single cipher path, consider `tls_minimalist = 1`; the tools `/rwasa/rwasa_tlsmin.asm` and `/webslap/webslap_tlsmin.asm` are built with this setting (Source: /ht_defaults.inc:319) |
| scrypt tuning | `scrypt_N = 1024` with `scrypt_sha512 = 1`; `r = p = 1` only (Source: /ht_defaults.inc:386-389, /scrypt.inc:35-40) |
| BREACH mitigation | `webserver_breach_mitigation = 48` controls the randomised byte padding injected into HTTP responses (Source: /ht_defaults.inc:499) |
| HSTS | `webserver_hsts = 1` sets the `Strict-Transport-Security` header on HTTPS responses (Source: /ht_defaults.inc:485) |

## What Is NOT Provided

The following capabilities are intentionally absent from HeavyThing. This
list is not exhaustive, but it enumerates the omissions most likely to
affect an integration decision.

- TLS 1.3 is not implemented (Source: /tls.inc:22-23).
- AEAD cipher suites (GCM, CCM, ChaCha20-Poly1305) are not implemented in
  TLS; commented-out GCM placeholders are visible at `/tls.inc:138-143`.
- Elliptic-curve primitives (Ed25519, X25519, NIST P-curves, secp256k1) are
  not implemented (Source: /tls.inc:64-72).
- Modern memory-hard password KDFs (Argon2, bcrypt) are not implemented;
  PBKDF2 and scrypt are the supported password-hashing options.
- HKDF as an isolated primitive is not implemented.
- TLS client certificate authentication is not supported.
- X509 certificate chain validation is not performed (Source: /tls.inc:25-35).
- Client-side SSH host-key verification against a known-hosts database is
  not performed; the library verifies the host signature but does not
  maintain a known-hosts file (Source: /ssh.inc:79-83).
- SSH subsystems other than shell and sftp are not supported
  (Source: /ssh.inc:63-68).
- Hardware Security Module (HSM), PKCS#11, and TPM integration is not
  provided.
- libc is not linked; syscalls are issued directly. This precludes use of
  libc-provided cryptographic loaders such as `getrandom(3)` in its libc
  form, although the `/dev/urandom` and `/dev/random` paths are used.
- The target platform is Linux x86_64 only; other operating systems and
  architectures are not supported.

## See Also

- `./architecture.md` — the three-file include contract, include dependency graph, subsystem boundaries, and event-loop lifecycle
- `./building.md` — FASM invocation, link step, and compile-time configuration knob catalogue
- `./calling-convention.md` — register contract for invoking crypto primitives and the `subsystem$function` label-naming convention
- `./contributing.md` — how to add a new primitive or protocol module and wire it into `/ht.inc`
- `../crypto/README.md` — cryptography subsystem overview with per-primitive calling conventions
- `../net/README.md` — networking subsystem overview, including the epoll event loop and TLS / SSH layering
- `../rwasa/README.md` — rwasa web server, the primary TLS-server consumer in the repository
- `../toplip/README.md` — toplip utility, the primary consumer of htcrypt and htxts
- `../ht.inc` — crypto and protocol include chain at `/ht.inc:141-167`
- `../ht_defaults.inc` — authoritative source for every configuration knob referenced above
- `../LICENSE` — GPLv3 terms that govern the library, its primitives, and every application linked against it
