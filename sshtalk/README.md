# sshtalk

SSH2-transport terminal chat and demo server with in-library user authentication and full TUI rendering, built end-to-end from the HeavyThing library as a showcase of its SSH, TUI, and authentication subsystems.

## Overview

sshtalk listens on a hardcoded TCP port (4001), authenticates inbound SSH2 clients against a local scrypt-hashed user database (`./sshtalk.userdb` in the working directory), and presents a full-screen TUI chat experience composed of a bottom status bar, a main chat panel, and a buddy-list plus help side column. All SSH2 transport, TUI rendering over the SSH channel, authentication, chatroom state, and multi-session management run in a single process on top of the library's `epoll`-driven event loop; there is no per-session fork. The program is positioned as a showcase of the HeavyThing library (Source: /sshtalk/sshtalk.asm:27-35). In-source branding identifies the program as `sshtalk v1.12 © 2015 2 Ton Digital`, advertises `100% handcrafted in x86_64 assembler` and `Zero external dependencies`, and references `Info/Source: https://2ton.com.au/sshtalk` (Source: /sshtalk/sshtalk.asm:309-315).

## Architecture Fit

sshtalk is a leaf application. It consumes the HeavyThing library but is not referenced by any other module in the repository.

Incoming dependencies (what sshtalk uses):

- `../ht_defaults.inc` and `../ht.inc` are included in that order at the top of the entry file (Source: /sshtalk/sshtalk.asm:22-23); `../ht_data.inc` is the final directive (Source: /sshtalk/sshtalk.asm:326). This follows the three-file include contract; see [`../docs/architecture.md`](../docs/architecture.md) for the authoritative description.
- `../ssh.inc` provides the SSH2 server protocol (KEX, encryption, MAC, channel multiplexing). sshtalk calls `ssh$new_server` directly (Source: /sshtalk/sshtalk.asm:243-245).
- `../tui_ssh.inc` renders the TUI tree over the SSH channel and sits at the application end of the io chain (Source: /sshtalk/sshtalk.asm:237-239).
- `../tui_simpleauth.inc` provides the authentication dialog widget. sshtalk overrides its vtable to delegate authentication and new-user creation to the local userdb module (Source: /sshtalk/sshtalk.asm:69-73).
- `../tui_splash.inc` decorates the authentication dialog with a startup splash (Source: /sshtalk/sshtalk.asm:234-235).
- `../tui_object.inc` and the full TUI widget family (`tui_label`, `tui_panel`, `tui_statusbar`, `tui_newsticker`, `tui_vspacer`, `tui_bell`, `tui_textbox`, `tui_alert`, and others) are pulled in transitively via `../ht.inc`.
- `../epoll.inc` provides the event loop. sshtalk builds its own three-layer io chain and hands control to `epoll$run` (Source: /sshtalk/sshtalk.asm:255-281).
- `heap.inc`, `stringmap` (from `maps.inc`), `formatter.inc`, `buffer.inc`, `file.inc`, `scrypt.inc`, `hmac.inc`, and string helpers are consumed transitively via the userdb, chatroom, and screen modules.

Outgoing dependencies: none.

Object-lifetime note. The top-of-chain `tui_ssh` wrapper is constructed once in `_start` and holds the template UI tree composed of `screen` at the top, wrapped by `tui_simpleauth`, wrapped by `tui_splash` (Source: /sshtalk/sshtalk.asm:66-239). Per-session screen state is produced via `screen$clone` (Source: /sshtalk/screen.inc:411); the listening `epoll` transport object is long-lived while each accepted SSH connection obtains its own accepted-fd io state. For the library-wide object-ownership model see [`../docs/architecture.md`](../docs/architecture.md).

IO chain wiring. sshtalk constructs the classic HeavyThing three-tier io chain at startup and hands it to `epoll$inbound`:

```text
tui_ssh  (application layer)
   ^
   v
ssh      (protocol layer)
   ^
   v
epoll    (transport layer)
```

The `tui_ssh` to `ssh` link is wired at `io_child_ofs` on the tui_ssh object and `io_parent_ofs` on the ssh object (Source: /sshtalk/sshtalk.asm:252-253). The `ssh` to `epoll` link is wired at the corresponding offsets on the middle ssh object and the listening epoll object (Source: /sshtalk/sshtalk.asm:261-262). The middle epoll object uses `epoll$default_vtable` because it performs no application work; it only pumps its own io chain (Source: /sshtalk/sshtalk.asm:257). For the library-wide IO chaining model see [`../docs/architecture.md`](../docs/architecture.md).

## Key Components

| File | Purpose |
|------|---------|
| [`./sshtalk.asm`](./sshtalk.asm) | Program entry point `_start`; initialises the library, userdb, chatrooms, screen formatters, and statusbar; builds the three-widget UI chain (`screen` to `tui_simpleauth` to `tui_splash` to `tui_ssh`); wires the io chain (app to ssh to epoll); binds TCP 4001; calls `epoll$run`. (Source: /sshtalk/sshtalk.asm:22-326) |
| [`./userdb.inc`](./userdb.inc) | User database: flat-file format (`sshtalk.userdb` in the working directory), pipe-delimited `username|password|buddy1|buddy2|...` records, scrypt-based password hashing, and a `userdb$vtable` that overrides the `tui_simpleauth` authentication and new-user methods. (Source: /sshtalk/userdb.inc:22-43) |
| [`./chatroom.inc`](./chatroom.inc) | Chatroom object management: a global stringmap of named rooms, unnamed 1:1 rooms for direct chats, participant lists, and automatic teardown when the last user leaves. (Source: /sshtalk/chatroom.inc:22-50) |
| [`./chatpanel.inc`](./chatpanel.inc) | Scrolling chat message panel widget (a `tui_panel` descendant): height-locked text areas, own-user messages right-aligned with a spinning cursor, others left-aligned, with a 100-message redraw-cost cap. (Source: /sshtalk/chatpanel.inc:22-45) |
| [`./screen.inc`](./screen.inc) | Per-session main screen composition and the largest local module. Layout manager for the statusbar, main chat area, buddy list, and help panel; keybinding dispatcher in `screen$firekeyevent`; focus and modal-dialog management. (Source: /sshtalk/screen.inc:22-58) |
| [`./statusbar.inc`](./statusbar.inc) | Bottom status bar widget. Overrides the default `tui_statusbar` timer to display live connection and user counts formatted as `C: n  U: k/t`. (Source: /sshtalk/statusbar.inc:22-24) |

## Calling Convention

sshtalk is a standalone executable with no command-line flags; all behavior is either compile-time (knobs in `../ht_defaults.inc`) or fixed at the source level. Library register and stack rules, the `subsystem$function` label-naming convention, and the `prolog`/`epilog` macro contract are documented in [`../docs/calling-convention.md`](../docs/calling-convention.md); the invocation and runtime file-system contract are covered below.

### Invocation

Run the compiled binary directly: `./sshtalk` with no arguments. There is no `argc`/`argv` parsing in `_start` (Source: /sshtalk/sshtalk.asm:47-66). The process reads from and writes to several fixed file-system paths at startup; see the next subsection.

### Runtime File-System Contract

| Path | Role | Behavior |
|------|------|----------|
| `/etc/ssh/ssh_host_rsa_key` and `.pub` | SSH RSA host key pair | Loaded by `ssh$new_server`. The `/etc/ssh` directory is selected because `rdi` is zeroed immediately before the call (Source: /sshtalk/sshtalk.asm:243-245). |
| `/etc/ssh/ssh_host_dsa_key` and `.pub` | SSH DSA host key pair | Loaded together with the RSA pair by the same `ssh$new_server` call (Source: /sshtalk/sshtalk.asm:243-245). |
| `./sshtalk.userdb` | Pipe-delimited user database | Read at startup by `userdb$init` from the current working directory (Source: /sshtalk/userdb.inc:43, 71-93). Persisted by `userdb$save` after every successful add-buddy action (Source: /sshtalk/screen.inc:1575). |
| `tcp/0.0.0.0:4001` | Listen endpoint | The port `4001` is passed to `inaddr_any`; it is a hardcoded constant (Source: /sshtalk/sshtalk.asm:264-272). |
| `stderr` | Error path output | On SSH host-key load failure the program writes `/etc/ssh host keys and/or contents error.` and exits with status 1 (Source: /sshtalk/sshtalk.asm:288-293, 324). |

### userdb File Format

The user database is plain text with one record per line. Records are pipe-delimited: `username|password|buddy1|buddy2|...`. Lines beginning with a space or `#` are comments and ignored. Parsing is handled by `userdb$init` (Source: /sshtalk/userdb.inc:71-130). Field rules enforced by `userdb$newuser` (Source: /sshtalk/userdb.inc:427-461):

- `username` must be at least 2 characters and must not contain a pipe character.
- `password` must be at least 4 characters at entry time. The stored value is the scrypt-derived digest as a 32-byte hex string, not the plaintext. Scrypt uses the UTF-8 password bytes as both the key and the salt input (Source: /sshtalk/userdb.inc:384, 393).
- An empty `password` field indicates a buddy-list-only reference: the user exists by name but cannot authenticate interactively.
- Error messages surfaced to the client are `Username too short.`, `Password too short.`, `Username already taken.`, and `Username cannot contain pipes.` (Source: /sshtalk/userdb.inc:458-461).

Scrypt parameters are compile-time from `../ht_defaults.inc`: `N=1024`, `r=1`, `p=1`, with `scrypt_sha512=1` selecting the faster internal PBKDF2-SHA512 path (Source: /ht_defaults.inc:386-389).

### UI Chain Construction

`_start` builds a three-widget chain that is passed to `tui_ssh`:

- `screen` (the main application screen) is created via `screen$new` (Source: /sshtalk/sshtalk.asm:66).
- `tui_simpleauth` wraps `screen` and is constructed with the new-user flag enabled. The first qword of the simpleauth object is overwritten with `userdb$vtable`, so authentication and new-user creation are delegated to the userdb module (Source: /sshtalk/sshtalk.asm:69-73, /sshtalk/userdb.inc:56-65).
- `tui_splash` wraps `tui_simpleauth` to add the startup splash (Source: /sshtalk/sshtalk.asm:234-235).
- `tui_ssh$new` wraps the splash into the SSH-aware TUI renderer; this is the application-layer head of the io chain (Source: /sshtalk/sshtalk.asm:237-239).

The splash itself is decorated with an internal widget tree built in-place before `tui_splash$new` is called:

- A top-of-splash `tui_vspacer` and a stack of centered `tui_label` widgets carrying the branding cleartext `.s1` through `.s7`, `.s8`, and `.s9`. Centering is set via `tui_align_center` on the top child (Source: /sshtalk/sshtalk.asm:75-187).
- A hostname-conditional author-credit block. When `uname$nodename` starts with `slave.` (via `string$starts_with`) or equals `cdev` (via `string$equals`), the alternate author label `.s10_2ton` and an availability label `.s11_2ton` are appended; otherwise only the standard `.s10` label is rendered (Source: /sshtalk/sshtalk.asm:188-213).
- A bottom-third `tui_newsticker` carrying the `.tickertext` string in `lightgray` on `black` (Source: /sshtalk/sshtalk.asm:223-232).

### Keybindings

All keybindings are dispatched by `screen$firekeyevent` (Source: /sshtalk/screen.inc:1447-1510). The virtual-method `screen$keyevent` is a no-op stub (Source: /sshtalk/screen.inc:1162-1165); all real handling runs through `screen$firekeyevent`.

| Keystroke | Action |
|-----------|--------|
| `Ctrl-A` | Add buddy. Context-sensitive: on a 1:1 chat with an unknown remote, adds silently and saves the userdb; otherwise opens the Add Buddy modal (Source: /sshtalk/screen.inc:1467-1468, 1515-1575). |
| `Ctrl-R` | Remove buddy (Source: /sshtalk/screen.inc:1477-1478). |
| `Ctrl-J` | Join or create a named room (Source: /sshtalk/screen.inc:1473-1474, 1230-1260). |
| `Ctrl-W` | Close the currently focused chat (Source: /sshtalk/screen.inc:1475-1476). |
| `Ctrl-C` | Exit. `screen$firekeyevent` explicitly lets `esi=3` fall through so that `tui_ssh` terminates the SSH session (Source: /sshtalk/screen.inc:1459-1460). |
| `Up` / `Down` | Scroll the focused chat panel history. Passed to the focused child via `tui_vfirekeyevent` (Source: /sshtalk/screen.inc:1480-1484). |
| `Tab` | Cycle input focus forward through chat panels and the buddy list (Source: /sshtalk/screen.inc:1469-1470, /sshtalk/screen.inc:1809). |
| `Shift-Tab` | Cycle input focus backward (Source: /sshtalk/screen.inc:1471-1472, /sshtalk/screen.inc:1896). |
| `Esc` | Close the active modal dialog; no effect outside a modal (Source: /sshtalk/screen.inc:1493-1510). |

Note: `Ctrl-B` fires a terminal bell via `tui_bell$nvdoit` and is handled inside `screen$firekeyevent` at the `.belltest` label (Source: /sshtalk/screen.inc:1463-1464, 1486-1491); it is not advertised in the in-app help text.

## Usage

The following abridged fragment illustrates the three-file include contract, the initialisation sequence, and the handoff to `epoll$run`. The full implementation is in [`./sshtalk.asm`](./sshtalk.asm) lines 22-326.

```nasm
; sshtalk _start (abridged from sshtalk.asm)
include '../ht_defaults.inc'
include '../ht.inc'

include 'userdb.inc'
include 'chatroom.inc'
include 'chatpanel.inc'
include 'screen.inc'
include 'statusbar.inc'

public _start
_start:
    call    ht$init                 ; library init
    call    userdb$init             ; load sshtalk.userdb from CWD
    call    chatroom$init           ; init global chatrooms map
    call    screen$init_formatters  ; connect/disconnect syslog formatters
    call    statusbar$init          ; init statusbar formatter
    ; ... build tui chain: screen -> tui_simpleauth -> tui_splash -> tui_ssh
    ; ... build io chain:  tui_ssh <-> ssh_server <-> epoll
    call    epoll$run               ; never returns

include '../ht_data.inc'
```

### Build

```bash
# From the sshtalk/ directory:
fasm -m 524288 sshtalk.asm && ld -o sshtalk sshtalk.o
```

The assembler is FASM (Flat Assembler) by Tomasz Grysztar. The `-m 524288` flag raises FASM's internal symbol pool to approximately 512 MB, which is required for the library's combined include tree. For toolchain prerequisites, the `if used | defined include_everything` conditional-compilation rules, and the full build flow, see [`../docs/building.md`](../docs/building.md).

### Preflight

1. Ensure `/etc/ssh/ssh_host_rsa_key` (and `.pub`) and `/etc/ssh/ssh_host_dsa_key` (and `.pub`) exist and are readable by the running process. The host-key directory is fixed at `/etc/ssh` in the source (Source: /sshtalk/sshtalk.asm:243-245); unprivileged runs typically require a local copy of the key set arranged via symlinks or filesystem namespacing.
2. Create a `sshtalk.userdb` file in the current working directory with at least one account. Additional accounts may be created by the running program when `tui_simpleauth` is presented with a new username (delegation to `userdb$newuser` via the overridden vtable).
3. Confirm nothing else is bound to TCP `4001` on the listening interface.
4. Start the binary: `./sshtalk`. Connect from another terminal with: `ssh -p 4001 <username>@<host>`.

## Configuration

sshtalk has no runtime configuration file or flags. All tunable behavior is set at compile time via `../ht_defaults.inc` or is fixed as an `equ` constant in one of the local `.inc` files. Rebuild from source to change any of the values below.

Compile-time knobs from `../ht_defaults.inc`:

| Knob | Default | Effect on sshtalk | Source |
|------|---------|-------------------|--------|
| `ssh_do_compression` | `1` | Enables `zlib@openssh.com` compression negotiation in the SSH server. | `/ht_defaults.inc:405` |
| `ssh_force_compression` | `1` | Forces compression on; disconnects clients that refuse `zlib@openssh.com`. | `/ht_defaults.inc:411` |
| `ssh_blacklist` | `86400` | Seconds to blacklist an IP after a bad-HMAC event (24 hours). | `/ht_defaults.inc:417` |
| `ssh_dh_dynamic` | `0` | When `0`, Diffie-Hellman parameters come from the static `dh_pool*.inc` tables; when `1`, they are generated dynamically per connection. | `/ht_defaults.inc:402` |
| `dh_bits` | `2048` | Default DH group size used by SSH KEX. | `/ht_defaults.inc:281` |
| `dh_privatekey_size` | `256` | DH private-exponent size in bits. | `/ht_defaults.inc:293` |
| `scrypt_N` | `1024` | scrypt cost parameter used by `userdb$authenticate` for password hashing. | `/ht_defaults.inc:387` |
| `scrypt_r` | `1` | scrypt block-size parameter. | `/ht_defaults.inc:388` |
| `scrypt_p` | `1` | scrypt parallelisation parameter. | `/ht_defaults.inc:389` |
| `scrypt_sha512` | `1` | Selects the SHA-512 internal PBKDF2 variant for scrypt. | `/ht_defaults.inc:386` |
| `rng_heavy_init` | `1` | Seeds the RNG from rdtsc, gettimeofday, and `/dev/urandom` at `ht$init`; required for SSH key and IV generation. | `/ht_defaults.inc:94` |
| `epoll_minfds` | `4096` | Minimum file-descriptor slot count. sshtalk exits with status 97 if the soft `RLIMIT_NOFILE` cannot be raised to this; see [`../docs/architecture.md`](../docs/architecture.md) for the exit-code table. | `/ht_defaults.inc:130` |
| `epoll_readsize` | `32768` | Per-read buffer size on each accepted connection. | `/ht_defaults.inc:152` |
| `epoll_stacksize` | `4096` | Epoll event array size per iteration. | `/ht_defaults.inc:148` |
| `tui_ssh_alternatescreen` | `1` | When `1`, `tui_ssh` uses the terminal's alternate-screen buffer and restores the caller's terminal state on exit. | `/ht_defaults.inc:224` |
| `profiling` | `0` | When set to `1`, the `if profiling` block in `_start` links in `tui_profiler$new` as a top-level terminal window. | `/ht_defaults.inc:62`, `/sshtalk/sshtalk.asm:274-278` |

### In-source constants

| Constant | Value | Location |
|----------|-------|----------|
| TCP listen port | `4001` | `/sshtalk/sshtalk.asm:267` |
| SSH host-key directory | `/etc/ssh` (selected by `xor edi, edi` before `ssh$new_server`) | `/sshtalk/sshtalk.asm:243-245` |
| User database filename | `sshtalk.userdb` (in CWD) | `/sshtalk/userdb.inc:43` |
| `user_size` | `40` bytes | `/sshtalk/userdb.inc:39` |
| `chatroom_size` | `24` bytes | `/sshtalk/chatroom.inc:35` |
| `chatpanel_history_max` | `100` (per-panel message history cap) | `/sshtalk/chatpanel.inc:37` |
| `screen_size` | `tui_object_size + 88` | `/sshtalk/screen.inc:58` |
| 2 Ton Digital hostname prefixes | `slave.` prefix match or `cdev` exact match | `/sshtalk/sshtalk.asm:188-213, 321-322` |

### Branding cleartext strings

Cleartext strings that define the visible branding. Operators forking sshtalk typically modify these rather than touching code logic.

| Label | Content (summary) | Location |
|-------|-------------------|----------|
| `.s1` through `.s7` | Program name, year, author, positioning lines, and project URL on the splash. | `/sshtalk/sshtalk.asm:309-315` |
| `.s8`, `.s9` | Single-line cipher-suite advertisement shown on the splash. The `.s8` string begins with `4096 bit` while the compiled `dh_bits` default is `2048` (Source: /ht_defaults.inc:281); `.s8` is a stale marketing line and does not drive KEX behavior. | `/sshtalk/sshtalk.asm:316-317` |
| `.tickertext` | Bottom-of-splash newsticker content including the `size: 135x35 min` guidance and the enumerated list of tested terminal emulators. | `/sshtalk/sshtalk.asm:323` |
| `.errorstring` | stderr message written on SSH host-key load failure. | `/sshtalk/sshtalk.asm:324` |
| `.hostname_slave`, `.hostname_cdev` | Hostname patterns that trigger the alternate author-credit block. | `/sshtalk/sshtalk.asm:321-322` |

## Limitations

- Single-binary, single-process architecture. All sessions are multiplexed through `epoll` inside one process. There is no per-connection fork and no privilege drop; the process runs under whichever UID started it (Source: /sshtalk/sshtalk.asm:255-281).
- No command-line flags. The listen port, SSH host-key directory, and user-database filename are hardcoded at the source level; changing any of them requires rebuilding (Source: /sshtalk/sshtalk.asm:47-66, 243-245, 267; /sshtalk/userdb.inc:43).
- The hardcoded host-key directory is `/etc/ssh`. Running as an unprivileged user typically requires local host-key copies and symlinks because `/etc/ssh/ssh_host_rsa_key` is normally mode `0600` owned by root (Source: /sshtalk/sshtalk.asm:243-245).
- SSH2 only. The handshake advertises the identification string `SSH-2.0-HeavyThing`; there is no SSH1 support anywhere in the library. See [`../docs/security.md`](../docs/security.md) for the full SSH support matrix.
- The SSH cipher and KEX set is narrow. The in-source branding line states `Connection: 4096 bit diffie-hellman-group-exchange-sha256, ssh-rsa, aes256-cbc, hmac-sha2-256, zlib[@openssh.com]` (Source: /sshtalk/sshtalk.asm:316-317). There is no `aes256-ctr`, no AEAD (`chacha20-poly1305`, `aes256-gcm`), no `curve25519-sha256`, and no `ed25519`. See [`../docs/security.md`](../docs/security.md) for the authoritative matrix.
- In-memory chatroom state is non-persistent. `chatroom$init` creates an empty `stringmap` at startup; all named rooms and in-memory message history are lost on restart (Source: /sshtalk/chatroom.inc:45-50).
- Chat panel history cap. Each `chatpanel` retains at most 100 messages and older messages are dropped on redraw, not archived. The cap is a redraw-cost bound (Source: /sshtalk/chatpanel.inc:37-45).
- Minimum terminal size. The in-source newsticker text states `size: 135x35 min`; smaller terminals (for example the default SSH client 80x25) display a compressed version of the splash and authentication screen. The program remains operable, but layout guarantees hold only at 135x35 or larger (Source: /sshtalk/sshtalk.asm:323).
- Terminal compatibility. Best results are with VT100/ANSI terminals that support alternate-screen mode. The newsticker text enumerates the tested terminals: iTerm2, Terminal.app on macOS; SecureCRT with ANSI colors on Windows; standard Linux terminals (Source: /sshtalk/sshtalk.asm:323).
- Scrypt parameters are modest. `N=1024, r=1, p=1` produces a fast hash that is appropriate for a demo but weak by 2020s password-hashing standards. Increase `scrypt_N` in `../ht_defaults.inc` for production use (Source: /ht_defaults.inc:386-389).
- No TLS, no FastCGI, no federation. sshtalk speaks SSH2 only. There is no IRC bridge, no multi-server federation, and no web UI. Users from separate sshtalk instances cannot chat with each other.
- No end-to-end encryption beyond the SSH transport. Messages are readable inside the sshtalk process memory and are retransmitted in cleartext across user sessions. The SSH2 transport layer is the only confidentiality mechanism.
- Exit-code behavior. Normal operation never returns from `epoll$run`. The `/etc/ssh host keys and/or contents error.` path exits with status 1 (Source: /sshtalk/sshtalk.asm:288-293, 324); library-internal startup failures return the standard HeavyThing exit codes 96 through 99. The exit-code table is authoritative in [`../docs/architecture.md`](../docs/architecture.md).
- Known cryptographic caveats. CBC padding-oracle considerations apply to `aes256-cbc` in the SSH record layer, and SHA-1 collision weaknesses apply to `ssh-rsa` host-key signing. See [`../docs/security.md`](../docs/security.md) for the full caveat list and operational guidance.
- IPv4 only. The listener reserves an on-stack `sockaddr_in` and calls `inaddr_any`, so it binds `0.0.0.0:4001`; there is no IPv6 listener and no option to bind to a specific interface at compile time (Source: /sshtalk/sshtalk.asm:264-268).
- Compression is mandatory by default. With `ssh_force_compression = 1` as the compiled default, clients that refuse `zlib@openssh.com` are disconnected during KEX; modern OpenSSH clients configured without that method fail to connect. Rebuild with `ssh_force_compression = 0` to accept such clients (Source: /ht_defaults.inc:411).
- No per-user password-attempt rate limiting. The `ssh_blacklist` knob blacklists a source IP for 24 hours after a bad-HMAC event at the SSH record layer (Source: /ht_defaults.inc:417), but repeated failed password attempts after a successful transport handshake are not specifically throttled.
- userdb line format has no escape mechanism. Usernames cannot contain pipe characters because `userdb$newuser` validates them (Source: /sshtalk/userdb.inc:441), and password digests are hex-encoded and so cannot contain pipes or newlines, but buddy names are written verbatim; a manually edited record containing a pipe inside a buddy name corrupts the next parse of the database.
- Hostname-dependent branding. When `uname$nodename` starts with `slave.` or equals `cdev`, the splash silently swaps in alternate author-credit labels. This is cosmetic only, but it is triggered at startup without operator opt-in (Source: /sshtalk/sshtalk.asm:188-213).

Full cryptographic and network posture: [`../docs/security.md`](../docs/security.md). Full build-prerequisite and toolchain detail: [`../docs/building.md`](../docs/building.md).

## See Also

- Project overview and three-file include contract: [`../README.md`](../README.md).
- TUI subsystem (widget framework used throughout sshtalk's screen, chatpanel, and statusbar): [`../tui/README.md`](../tui/README.md).
- Networking subsystem (SSH2 transport and epoll io chain): [`../net/README.md`](../net/README.md).
- Cryptography subsystem (scrypt for the userdb and SSH KEX primitives): [`../crypto/README.md`](../crypto/README.md).
- Security posture, cipher suites, caveats, and operational guidance: [`../docs/security.md`](../docs/security.md).
- Library architecture, include dependency graph, event-loop lifecycle, and exit codes 96 through 99: [`../docs/architecture.md`](../docs/architecture.md).
- Register ABI, label-naming convention, and the `prolog`/`epilog` macro contract: [`../docs/calling-convention.md`](../docs/calling-convention.md).
- Build instructions and toolchain prerequisites: [`../docs/building.md`](../docs/building.md).
- Contributor guide: [`../docs/contributing.md`](../docs/contributing.md).
- Related showcase applications:
  - [`../rwasa/README.md`](../rwasa/README.md) (HTTPS web server).
  - [`../webslap/README.md`](../webslap/README.md) (HTTP load tester).
  - [`../toplip/README.md`](../toplip/README.md) (file encryption utility).
  - [`../dhtool/README.md`](../dhtool/README.md) (DH parameter tool).
- Runnable examples: [`../examples/README.md`](../examples/README.md).

---

Licensed under GPLv3. See [`../LICENSE`](../LICENSE).
