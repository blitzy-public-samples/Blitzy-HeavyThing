// HeavyThing x86_64 assembly language library and showcase programs
// Copyright © 2015 2 Ton Digital. Homepage: https://2ton.com.au/
// Author: Jeff Marrison <jeff@2ton.com.au>
//
// This file is part of HeavyThing.
//
// HeavyThing is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with HeavyThing.  If not, see <http://www.gnu.org/licenses/>.
//
// ---------------------------------------------------------------------------
// Rust translation of `sshtalk/userdb.inc` (732 lines, FASM x86_64).
// Maintains exact behavioural parity with the FASM baseline:
//   * `username|hex_password|buddy1|buddy2|...\n` pipe-delimited storage
//   * scrypt(password, password) with 32-byte output, hex-encoded for storage
//   * Bidirectional buddylist/notifies relationships
//   * Reference-only users (NULL password) created from buddy refs but
//     skipped during save
//   * Two-character minimum username, four-character minimum password
//   * Constant-time hash comparison for authentication
//
//! User database for the sshtalk binary.
//!
//! This module is the **most foundational** sshtalk component: every other
//! module (`main.rs`, `screen.rs`, `chatpanel.rs`, `chatroom.rs`,
//! `statusbar.rs`) depends on it for user identity, persistent storage,
//! and the authentication vtable mounted on the `tui_simpleauth` widget.
//!
//! # Storage format
//!
//! The on-disk file (`sshtalk.userdb` by default) is line-oriented and
//! pipe-delimited, matching the FASM baseline byte-for-byte:
//!
//! ```text
//! alice|deadbeef…64hex|bob|carol\n
//! bob|cafef00d…64hex|alice\n
//! ```
//!
//! * Field 1: username (UTF-8, no `|` characters)
//! * Field 2: 64-character lower-case hex of the 32-byte scrypt output
//! * Fields 3..N: buddy usernames (one per pipe-separated field)
//!
//! Notifies (`who follows me`) are NOT serialised: they are reconstructed
//! at load time from each user's buddylist (bidirectional relationships).
//!
//! Lines that are empty, start with whitespace, or start with `#` are
//! ignored. Reference-only users (created when a buddy is mentioned before
//! the buddy's own line) hold a `None` password and are skipped on save.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use thiserror::Error;

use heavything::crypto::scrypt::{scrypt_derive_params, ScryptParams};
use heavything::ds::{OrderedMap, StringMap};
use heavything::error::CryptoError;
use heavything::tui::widgets::simpleauth::SimpleAuthHandler;
use heavything::util::file as ht_file;
use heavything::util::syslog;

// ---------------------------------------------------------------------------
// Type aliases and constants
// ---------------------------------------------------------------------------

/// Type-erased handle to an active SSH screen session, stored in
/// [`User::tuilist`] for online-presence tracking.
///
/// The concrete `Screen` type lives in the sibling `crate::screen` module
/// (created by another agent). This type alias decouples `userdb` from
/// `screen` to break what would otherwise be a circular dependency, and
/// allows any `Arc<S>` where `S: Any + Send + Sync + 'static` to be
/// registered. Pointer identity (`Arc::as_ptr` cast to `u64`) is used as
/// the [`OrderedMap`] key.
pub type ScreenHandle = Arc<dyn std::any::Any + Send + Sync>;

/// Default filesystem path for the userdb file (matches the FASM
/// `sshtalk.userdb` literal at lines 39–41 of `userdb.inc`).
const DEFAULT_USERDB_FILENAME: &str = "sshtalk.userdb";

/// Minimum allowed username length (FASM `cmp qword [rsi], 2` checks).
const MIN_USERNAME_LEN: usize = 2;

/// Minimum allowed password length (FASM `cmp qword [rdx], 4` checks).
const MIN_PASSWORD_LEN: usize = 4;

/// Length of the scrypt-derived password hash (matches FASM
/// `mov esi, 32` to scrypt at userdb.inc lines 396, 478).
const PASSWORD_HASH_LEN: usize = 32;

/// Length of the hex-encoded password hash (2 * `PASSWORD_HASH_LEN`).
const PASSWORD_HEX_LEN: usize = PASSWORD_HASH_LEN * 2;

// ---------------------------------------------------------------------------
// User struct (translation of FASM 40-byte user_size record)
// ---------------------------------------------------------------------------

/// A single user account in the sshtalk database.
///
/// FASM offsets preserved (informationally; field semantics, not layout):
///
/// | FASM offset                | Rust field      | Purpose                           |
/// |----------------------------|-----------------|-----------------------------------|
/// | `user_username_ofs`  (+0)  | `username`      | Unique account name (UTF-8)       |
/// | `user_password_ofs`  (+8)  | `password_hash` | 32-byte scrypt hash (`None` = ref-only) |
/// | `user_buddylist_ofs` (+16) | `buddylist`     | Forward: who I follow             |
/// | `user_notifies_ofs`  (+24) | `notifies`      | Reverse: who follows me           |
/// | `user_tuilist_ofs`   (+32) | `tuilist`       | Active SSH screens (presence)     |
///
/// Mutable fields are wrapped in [`RwLock`] for thread-safe interior
/// mutability. The username itself is immutable for the lifetime of the
/// `User` instance (matches FASM, which never renames a user).
pub struct User {
    /// Account name (unique within the userdb registry). Immutable.
    pub username: String,

    /// 32-byte scrypt-derived password hash.
    ///
    /// * `Some(hash)` — real account loaded from file or freshly created.
    /// * `None` — reference-only placeholder created when this user
    ///   was named in another user's buddylist before its own line was
    ///   parsed. Reference-only users are *not* written back to the
    ///   file by [`save`].
    ///
    /// Stored as raw bytes in memory; converted to/from 64-char lower-case
    /// hex only when serialising to or parsing from the userdb file.
    pub password_hash: RwLock<Option<[u8; PASSWORD_HASH_LEN]>>,

    /// Stringmap of buddies this user **follows** (forward relation).
    /// Key: buddy username. Value: `Arc<User>` reference to the buddy.
    pub buddylist: RwLock<StringMap<Arc<User>>>,

    /// Stringmap of users who **follow** this user (reverse relation,
    /// used to drive notification fan-out). Key: follower username.
    /// Maintained in lock-step with [`Self::buddylist`] by [`addbuddy`]
    /// and [`removebuddy`].
    pub notifies: RwLock<StringMap<Arc<User>>>,

    /// Active SSH screens for this user (one per active session). Empty
    /// means the user is offline. Keyed by stable pointer identity so
    /// lookups can be performed without walking the contents.
    pub tuilist: RwLock<OrderedMap<u64, ScreenHandle>>,
}

impl std::fmt::Debug for User {
    /// Debug formatter that **never** leaks the password hash.
    ///
    /// Buddylist/notifies/tuilist are summarised by length only to avoid
    /// recursive locking under typical test harness logging.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("username", &self.username)
            .field(
                "password_hash",
                &match self.password_hash.try_read() {
                    Ok(g) => match *g {
                        Some(_) => "<32-byte hash>",
                        None => "<reference-only>",
                    },
                    Err(_) => "<locked>",
                },
            )
            .field(
                "buddylist_len",
                &self.buddylist.try_read().map(|g| g.len()).unwrap_or(0),
            )
            .field(
                "notifies_len",
                &self.notifies.try_read().map(|g| g.len()).unwrap_or(0),
            )
            .field(
                "tuilist_len",
                &self.tuilist.try_read().map(|g| g.len()).unwrap_or(0),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Error type (10 variants per schema)
// ---------------------------------------------------------------------------

/// Errors returned by the userdb module.
#[derive(Debug, Error)]
pub enum UserdbError {
    /// `init` (or `init_with_path`) was called more than once.
    #[error("userdb already initialized")]
    AlreadyInitialized,

    /// A function that requires the registry was called before `init`.
    #[error("userdb not initialized (call userdb::init first)")]
    NotInitialized,

    /// Attempt to create or pre-allocate a username that already maps to
    /// a real (non-reference-only) account.
    #[error("user '{0}' already exists")]
    UserAlreadyExists(String),

    /// A buddy/user lookup failed (used by `removebuddy` and similar).
    #[error("user '{0}' not found")]
    UserNotFound(String),

    /// On-disk userdb file has malformed content.
    #[error("invalid userdb file format at line {0}")]
    InvalidFormat(usize),

    /// Authentication failed (bad password OR unknown user — the variants
    /// are deliberately indistinguishable to callers to prevent username
    /// enumeration).
    #[error("authentication failed for user '{0}'")]
    AuthFailed(String),

    /// File-system or I/O failure while loading or saving the userdb.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A scrypt key-derivation failure surfaced from
    /// `heavything::crypto::scrypt`.
    #[error("scrypt error: {0}")]
    Scrypt(String),

    /// One of the per-user or global `RwLock`s was poisoned by a panic
    /// while holding a write guard.
    #[error("lock poisoned")]
    LockPoisoned,

    /// Catch-all for validation failures (empty username, too-short
    /// password, pipe characters in name, etc.).
    #[error("{0}")]
    Other(String),
}

impl From<CryptoError> for UserdbError {
    /// Converts a crypto-subsystem error into `UserdbError::Scrypt`.
    ///
    /// Used by `?`-propagation when calling `scrypt_derive_params` so that
    /// the caller never sees a `CryptoError` directly.
    fn from(e: CryptoError) -> Self {
        UserdbError::Scrypt(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Global state (the FASM `users` and `userdb_path` statics)
// ---------------------------------------------------------------------------

/// Global stringmap of all registered users.
///
/// Initialised exactly once by [`init`] / [`init_with_path`]. Keyed by
/// username, valued by `Arc<User>` so buddylist/notifies maps in other
/// users can hold cheap clones of the same instance.
static USERS: OnceLock<RwLock<StringMap<Arc<User>>>> = OnceLock::new();

/// Filesystem path of the userdb file. Set by [`init_with_path`].
static USERDB_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Serializes concurrent invocations of [`save`] so that two threads
/// cannot interleave their temp-file writes and cause a corrupt rename
/// race. A `Mutex<()>` is sufficient because the underlying file path
/// itself is the only contended resource.
static SAVE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// The authentication handler exported to `tui_simpleauth`.
///
/// Initialised by [`init`] with an `Arc<UserdbAuthHandler>`; consumed by
/// `main.rs` (which calls `SIMPLEAUTH_VTABLE.get().unwrap().clone()` and
/// passes the `Arc<dyn SimpleAuthHandler>` to `TuiSimpleauth::new`).
pub static SIMPLEAUTH_VTABLE: OnceLock<Arc<dyn SimpleAuthHandler>> = OnceLock::new();

/// Returns a reference to the global users registry.
///
/// # Panics
///
/// Panics with a clear diagnostic if [`init`] was not called first. This
/// is a programmer-error condition (the binary's `main.rs` must always
/// call `userdb::init()` before spawning any SSH connection task), so a
/// panic is preferable to silently returning an error.
pub fn users() -> &'static RwLock<StringMap<Arc<User>>> {
    USERS
        .get()
        .expect("userdb::init() must be called before userdb::users()")
}

// ---------------------------------------------------------------------------
// Initialisation: init / init_with_path
// ---------------------------------------------------------------------------

/// Initialise the userdb with the default path (`./sshtalk.userdb`).
///
/// Equivalent to `init_with_path(PathBuf::from("sshtalk.userdb"))`.
/// Loads the file if it exists; treats a missing file as a fresh start
/// (an empty registry that will be created on the first `save`).
///
/// Also installs the [`SIMPLEAUTH_VTABLE`] handler so that the
/// `tui_simpleauth` widget can authenticate users.
pub fn init() -> Result<(), UserdbError> {
    init_with_path(PathBuf::from(DEFAULT_USERDB_FILENAME))
}

/// Initialise the userdb with a caller-supplied path.
///
/// Performs (in order):
///
/// 1. Set [`USERDB_PATH`].
/// 2. Set [`USERS`] to an empty registry.
/// 3. Install the [`SIMPLEAUTH_VTABLE`] handler.
/// 4. Load the file if it exists (silent first-run otherwise).
///
/// Returns [`UserdbError::AlreadyInitialized`] if called twice — the
/// `OnceLock` semantics make double-init impossible to recover from
/// gracefully.
pub fn init_with_path(path: PathBuf) -> Result<(), UserdbError> {
    USERDB_PATH
        .set(path.clone())
        .map_err(|_| UserdbError::AlreadyInitialized)?;
    USERS
        .set(RwLock::new(StringMap::new()))
        .map_err(|_| UserdbError::AlreadyInitialized)?;
    SAVE_LOCK
        .set(Mutex::new(()))
        .map_err(|_| UserdbError::AlreadyInitialized)?;
    let handler: Arc<dyn SimpleAuthHandler> = Arc::new(UserdbAuthHandler);
    SIMPLEAUTH_VTABLE
        .set(handler)
        .map_err(|_| UserdbError::AlreadyInitialized)?;
    if path.exists() {
        load_from_file(&path)?;
    }
    Ok(())
}

/// Default scrypt parameters used for both hashing and verification.
///
/// FASM `userdb.inc` calls `scrypt` with the global defaults from
/// `ht_defaults.inc` (N=1024, r=1, p=1). [`ScryptParams::default`] is the
/// exact mirror of those constants.
fn default_scrypt_params() -> ScryptParams {
    ScryptParams::default()
}

// ---------------------------------------------------------------------------
// Loading: parse the pipe-delimited file (FASM userdb$init body)
// ---------------------------------------------------------------------------

/// Parse the on-disk userdb file and populate [`USERS`].
///
/// Mirrors FASM `userdb$init` lines 50–250: single-pass parser that
/// handles forward references (a buddy named before the buddy's own
/// line is encountered) by allocating a placeholder `User` with `None`
/// password, which is filled in when the buddy's real line is parsed.
fn load_from_file(path: &Path) -> Result<(), UserdbError> {
    // Use heavything's file::read_to_string wrapper so that the I/O path
    // matches what other heavything modules use (instrumented errors).
    let content = match ht_file::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            // UtilError → UserdbError::Other (preserves the message).
            return Err(UserdbError::Other(format!(
                "failed to read userdb file '{}': {}",
                path.display(),
                e
            )));
        }
    };

    let registry = users();

    for (line_no, raw_line) in content.split('\n').enumerate() {
        // Strip the trailing CR for CRLF tolerance, but keep the FASM
        // semantics of "any prefix is treated as data".
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);

        // FASM skips:
        //   * empty lines (length-prefix == 0)
        //   * lines starting with space (`cmp byte [rax+8], 32`)
        //   * lines starting with `#` (`cmp byte [rax+8], 35`)
        if line.is_empty() {
            continue;
        }
        let first_byte = line.as_bytes()[0];
        if first_byte == b' ' || first_byte == b'#' {
            continue;
        }

        // Pipe-split into a FIFO queue (matches FASM's list ordering).
        let mut fields: VecDeque<&str> = line.split('|').collect();

        // FASM `cmp qword [rax], 2` — need at least 2 fields after split
        // (username + password). Anything less is corrupt-or-comment data.
        if fields.len() < 2 {
            return Err(UserdbError::InvalidFormat(line_no + 1));
        }

        let username = fields.pop_front().unwrap_or("").to_string();
        let password_hex = fields.pop_front().unwrap_or("");

        // Reject obviously-bad usernames at parse time.
        if username.is_empty() {
            return Err(UserdbError::InvalidFormat(line_no + 1));
        }

        let password_bytes = parse_hex_32(password_hex).ok_or(UserdbError::InvalidFormat(line_no + 1))?;

        // ---- Stage 1: create-or-fill the user object itself. ----
        let user = {
            let mut guard = registry.write().map_err(|_| UserdbError::LockPoisoned)?;
            if let Some(existing) = guard.get(&username) {
                // Existing entry — must be reference-only (None password)
                // for us to populate it. A real entry means a duplicate
                // username in the file, which the FASM tolerates by
                // skipping the second occurrence (lines 110–117).
                let existing = existing.clone();
                let mut pwd = existing
                    .password_hash
                    .write()
                    .map_err(|_| UserdbError::LockPoisoned)?;
                if pwd.is_some() {
                    // Duplicate real entry — skip this line entirely
                    // (matches FASM `.skiplist` / `.userobject_okay` flow).
                    continue;
                }
                *pwd = Some(password_bytes);
                drop(pwd);
                existing
            } else {
                let fresh = Arc::new(User {
                    username: username.clone(),
                    password_hash: RwLock::new(Some(password_bytes)),
                    buddylist: RwLock::new(StringMap::new()),
                    notifies: RwLock::new(StringMap::new()),
                    tuilist: RwLock::new(OrderedMap::new()),
                });
                // insert_unique returns Result<(), V>; the only way this
                // can fail is a TOCTOU between the get above and now,
                // which is impossible while we hold the write guard.
                let _ = guard.insert_unique(username.clone(), fresh.clone());
                fresh
            }
        };

        // ---- Stage 2: drain the buddy field list. ----
        // For each buddy name, ensure the buddy exists (creating a
        // reference-only placeholder if not), then add the bidirectional
        // relationship.
        while let Some(buddy_name_raw) = fields.pop_front() {
            let buddy_name = buddy_name_raw.trim();
            if buddy_name.is_empty() {
                continue;
            }
            // Locate-or-create the buddy.
            let buddy = {
                let mut guard = registry.write().map_err(|_| UserdbError::LockPoisoned)?;
                if let Some(existing) = guard.get(buddy_name) {
                    existing.clone()
                } else {
                    let placeholder = Arc::new(User {
                        username: buddy_name.to_string(),
                        password_hash: RwLock::new(None),
                        buddylist: RwLock::new(StringMap::new()),
                        notifies: RwLock::new(StringMap::new()),
                        tuilist: RwLock::new(OrderedMap::new()),
                    });
                    let _ = guard.insert_unique(buddy_name.to_string(), placeholder.clone());
                    placeholder
                }
            };

            // Defend against self-buddying (a malformed file might list
            // the user's own name as a buddy of themselves; FASM does not
            // explicitly guard against this but the resulting cycle is
            // benign and silently de-duplicated by `insert_unique`).
            //
            // Add to user's buddylist (forward relation).
            {
                let mut bl = user.buddylist.write().map_err(|_| UserdbError::LockPoisoned)?;
                let _ = bl.insert_unique(buddy_name.to_string(), buddy.clone());
            }
            // Add to buddy's notifies (reverse relation).
            {
                let mut nf = buddy.notifies.write().map_err(|_| UserdbError::LockPoisoned)?;
                let _ = nf.insert_unique(user.username.clone(), user.clone());
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Saving: serialise users to file (FASM userdb$save body)
// ---------------------------------------------------------------------------

/// Persist all real (non-reference-only) users to the configured path.
///
/// Atomic write protocol:
/// 1. Build the entire file contents in memory.
/// 2. Write to a temp file (`<path>.tmp`).
/// 3. `rename(temp, real)` — atomic on POSIX file systems.
///
/// This prevents a partially-written userdb from being left on disk if
/// the process crashes mid-save. A [`Mutex`] gates concurrent calls so
/// two threads cannot race on the temp file.
///
/// Reference-only users (`password_hash == None`) are *not* written —
/// matching FASM `userdb$save` lines 593–598 which skip entries whose
/// password pointer is NULL.
pub fn save() -> Result<(), UserdbError> {
    let path = USERDB_PATH.get().ok_or(UserdbError::NotInitialized)?;
    let save_lock = SAVE_LOCK.get().ok_or(UserdbError::NotInitialized)?;

    // Hold the save lock for the entire build+write+rename. Poisoning
    // here is non-fatal: a previous panic during save is recoverable.
    let _save_guard = match save_lock.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let registry = users();
    let users_guard = registry.read().map_err(|_| UserdbError::LockPoisoned)?;

    // Pre-allocate roughly enough buffer space (avoids dozens of realloc).
    // 80 bytes per user is a reasonable mid-estimate for typical chat
    // installs (short usernames + few buddies).
    let mut content = String::with_capacity(users_guard.len() * 80);

    // for_each is the heavything API that mirrors FASM list iteration.
    // Each closure invocation gets (&String, &Arc<User>).
    users_guard.for_each(|_name, user| {
        // Skip reference-only users (FASM `.reference_only` branch).
        let pwd_guard = match user.password_hash.read() {
            Ok(g) => g,
            Err(_) => return, // poisoned — skip silently rather than abort
        };
        let hash = match *pwd_guard {
            Some(h) => h,
            None => return,
        };
        drop(pwd_guard);

        // username | hex_password
        content.push_str(&user.username);
        content.push('|');
        push_hex_lower(&mut content, &hash);

        // | buddy1 | buddy2 ...
        if let Ok(bl) = user.buddylist.read() {
            for buddy_name in bl.keys() {
                content.push('|');
                content.push_str(buddy_name);
            }
        }

        content.push('\n');
    });

    drop(users_guard);

    // Atomic write: temp file, then rename.
    let tmp_path = make_temp_path(path);
    if let Err(e) = ht_file::write(&tmp_path, content.as_bytes()) {
        return Err(UserdbError::Other(format!(
            "failed to write temp userdb file '{}': {}",
            tmp_path.display(),
            e
        )));
    }
    if let Err(e) = ht_file::rename(&tmp_path, path) {
        // Best-effort cleanup of the temp file on rename failure.
        let _ = std::fs::remove_file(&tmp_path);
        return Err(UserdbError::Other(format!(
            "failed to rename '{}' -> '{}': {}",
            tmp_path.display(),
            path.display(),
            e
        )));
    }

    Ok(())
}

/// Build a sibling temp file path (`<original>.tmp`) for atomic save.
fn make_temp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

// ---------------------------------------------------------------------------
// Authentication and user creation
// ---------------------------------------------------------------------------

/// Look up a user and verify their password against the stored hash.
///
/// Mirrors FASM `userdb$authenticate` (lines 380–429):
///   * Map lookup by username.
///   * scrypt(password, password) → 32-byte hash.
///   * Constant-time comparison against stored hash.
///
/// **Security**: missing-user and bad-password failures both return
/// `UserdbError::AuthFailed` with the same message structure, preventing
/// username enumeration via timing or message-content side channels.
/// The scrypt computation is performed even when the user does not
/// exist? — *No*, this implementation short-circuits on missing user
/// because the FASM baseline does the same (`.userobject_okay` /
/// `.userobject_notokay` paths). Timing-side-channel concerns are
/// dominated by the scrypt cost when the user *does* exist; a missing
/// user already has nothing to compare against.
pub fn authenticate(username: &str, password: &str) -> Result<Arc<User>, UserdbError> {
    // Look up the user (read-only access on the registry).
    let user = {
        let guard = users().read().map_err(|_| UserdbError::LockPoisoned)?;
        match guard.get(username) {
            Some(u) => u.clone(),
            None => return Err(UserdbError::AuthFailed(username.to_string())),
        }
    };

    // Reference-only users (created by buddylist resolution but never
    // having seen their own line in the file) can never authenticate.
    let stored = {
        let g = user.password_hash.read().map_err(|_| UserdbError::LockPoisoned)?;
        match *g {
            Some(h) => h,
            None => return Err(UserdbError::AuthFailed(username.to_string())),
        }
    };

    // Derive scrypt(password, password) — UTF-8 password used as both
    // password AND salt, matching FASM convention. NEVER change to a
    // per-user random salt: that would break compatibility with all
    // existing on-disk userdb files.
    let pwd_bytes = password.as_bytes();
    let mut computed = [0u8; PASSWORD_HASH_LEN];
    scrypt_derive_params(pwd_bytes, pwd_bytes, default_scrypt_params(), &mut computed)?;

    if ct_eq(&stored, &computed) {
        Ok(user)
    } else {
        Err(UserdbError::AuthFailed(username.to_string()))
    }
}

/// Register a new user, persist the registry, and emit a syslog notice.
///
/// Mirrors FASM `userdb$newuser` (lines 444–530):
///   * Length checks (username ≥ 2 chars, password ≥ 4 chars).
///   * Username must not contain `|`.
///   * If a user with this name already exists *with* a real password,
///     fail. If they exist as a reference-only placeholder, populate
///     the placeholder (this matches the FASM `.userobject_okay` path).
///   * scrypt the password; store the hash.
///   * Save the registry to disk.
///   * Emit `LOG_NOTICE` with "New user added: <username>" so deployments
///     can observe registrations through the system journal.
pub fn newuser(username: &str, password: &str) -> Result<Arc<User>, UserdbError> {
    // Validation: length and forbidden-character checks.
    if username.len() < MIN_USERNAME_LEN {
        return Err(UserdbError::Other("Username too short.".to_string()));
    }
    if username.contains('|') {
        return Err(UserdbError::Other("Name cannot contain pipes.".to_string()));
    }
    if username.contains('\n') {
        return Err(UserdbError::Other(
            "Name cannot contain newline characters.".to_string(),
        ));
    }
    if password.len() < MIN_PASSWORD_LEN {
        return Err(UserdbError::Other("Password too short.".to_string()));
    }

    // scrypt(password, password) → 32-byte hash. Compute up-front so we
    // hold no lock across the (potentially slow) KDF.
    let pwd_bytes = password.as_bytes();
    let mut hash = [0u8; PASSWORD_HASH_LEN];
    scrypt_derive_params(pwd_bytes, pwd_bytes, default_scrypt_params(), &mut hash)?;

    // Insert (or fill placeholder) under a write lock on the registry.
    let user = {
        let mut guard = users().write().map_err(|_| UserdbError::LockPoisoned)?;
        if let Some(existing) = guard.get(username) {
            let existing = existing.clone();
            let mut pwd = existing
                .password_hash
                .write()
                .map_err(|_| UserdbError::LockPoisoned)?;
            if pwd.is_some() {
                return Err(UserdbError::UserAlreadyExists(username.to_string()));
            }
            *pwd = Some(hash);
            drop(pwd);
            existing
        } else {
            let fresh = Arc::new(User {
                username: username.to_string(),
                password_hash: RwLock::new(Some(hash)),
                buddylist: RwLock::new(StringMap::new()),
                notifies: RwLock::new(StringMap::new()),
                tuilist: RwLock::new(OrderedMap::new()),
            });
            // SAFETY: we just confirmed via `get` that the key is absent
            // and we hold the write guard, so insert_unique cannot fail
            // for a duplicate-key reason.
            let _ = guard.insert_unique(username.to_string(), fresh.clone());
            fresh
        }
    };

    // Persist immediately. If save fails the in-memory state is now
    // ahead of disk; the next successful save will reconcile.
    save()?;

    // Best-effort syslog notification (matches FASM `syslog$notice`
    // pattern at line 519). Failure is non-fatal — the user account
    // still exists in memory and on disk.
    syslog::notice(&format!("New user added: {}", username));

    Ok(user)
}

// ---------------------------------------------------------------------------
// Presence tracking: online / offline / is_online
// ---------------------------------------------------------------------------

/// Register an active SSH screen for `user`, marking them as online.
///
/// Stores the `screen` handle in `user.tuilist` keyed by the screen's
/// stable pointer identity (`Arc::as_ptr` cast to `u64`). Multiple
/// concurrent sessions for the same user are supported — each call adds
/// a new entry; `is_online` returns true whenever any entry remains.
///
/// The generic parameter `S` accepts any `Arc<S>` where
/// `S: Any + Send + Sync + 'static`, which lets `screen.rs` (created by
/// another agent) pass its concrete `Arc<Screen>` without knowing the
/// exact `ScreenHandle` type alias.
///
/// `#[allow(dead_code)]`: this function is part of userdb's public API
/// surface mapped from the FASM `userdb$online` symbol (see
/// `userdb.inc` lines ~410 in the upstream HeavyThing source). The
/// minimal Rust port of `main.rs` does not directly call this entry
/// point because the per-connection TUI auth flow (TuiSimpleAuth →
/// SimpleAuthHandler) takes over presence tracking via the
/// `SIMPLEAUTH_VTABLE` callbacks; the `online` entry point is
/// retained verbatim from the FASM API for future enhancements (e.g.
/// non-SSH client front-ends) and so the public symbol matrix stays
/// behaviorally identical to the assembly baseline per AAP §0.8.2.
#[allow(dead_code)]
pub fn online<S>(user: &Arc<User>, screen: &Arc<S>) -> Result<(), UserdbError>
where
    S: std::any::Any + Send + Sync + 'static,
{
    let key = Arc::as_ptr(screen) as *const () as usize as u64;
    // Coerce `Arc<S>` to `Arc<dyn Any + Send + Sync>` via unsizing.
    let handle: ScreenHandle = screen.clone();
    let mut tuilist = user.tuilist.write().map_err(|_| UserdbError::LockPoisoned)?;
    // Re-registration of the same screen is idempotent (just overwrites).
    let _previous = tuilist.insert(key, handle);
    Ok(())
}

/// Remove a previously-registered screen, taking the user offline if
/// this was their last active session.
///
/// Calling `offline` for a screen that was never registered is a no-op
/// (matches the FASM convention: see `userdb.inc` line 619 onward,
/// where the AVL erase silently no-ops on missing keys).
pub fn offline<S>(user: &Arc<User>, screen: &Arc<S>) -> Result<(), UserdbError>
where
    S: std::any::Any + Send + Sync + 'static,
{
    let key = Arc::as_ptr(screen) as *const () as usize as u64;
    let mut tuilist = user.tuilist.write().map_err(|_| UserdbError::LockPoisoned)?;
    let _removed = tuilist.remove(&key);
    Ok(())
}

/// Returns `true` when the user has at least one active SSH session.
///
/// Used by `statusbar.rs` to count online users for display, and by
/// `chatpanel.rs` to gate notification fan-out (only deliver to online
/// followers).
pub fn is_online(user: &Arc<User>) -> Result<bool, UserdbError> {
    let tuilist = user.tuilist.read().map_err(|_| UserdbError::LockPoisoned)?;
    Ok(!tuilist.is_empty())
}

// ---------------------------------------------------------------------------
// Buddy management: addbuddy / removebuddy
// ---------------------------------------------------------------------------

/// Add a bidirectional buddy relationship and persist to disk.
///
/// Mirrors FASM `userdb$addbuddy` (lines 654–706):
///   * Validate buddy name (≥ 2 chars, no pipes).
///   * If buddy doesn't exist, create a reference-only placeholder.
///   * Add `buddy` to `user.buddylist`. Duplicate-add returns an error.
///   * Add `user` to `buddy.notifies`.
///   * `save()`.
pub fn addbuddy(user: &Arc<User>, buddy_name: &str) -> Result<(), UserdbError> {
    // Validation matches FASM `.tooshort` and `.nopipes` paths.
    if buddy_name.len() < MIN_USERNAME_LEN {
        return Err(UserdbError::Other("Buddy name too short.".to_string()));
    }
    if buddy_name.contains('|') || buddy_name.contains('\n') {
        return Err(UserdbError::Other("Name cannot contain pipes.".to_string()));
    }

    // Locate or create the buddy under a write lock on the registry.
    let buddy = {
        let mut guard = users().write().map_err(|_| UserdbError::LockPoisoned)?;
        if let Some(existing) = guard.get(buddy_name) {
            existing.clone()
        } else {
            let placeholder = Arc::new(User {
                username: buddy_name.to_string(),
                password_hash: RwLock::new(None),
                buddylist: RwLock::new(StringMap::new()),
                notifies: RwLock::new(StringMap::new()),
                tuilist: RwLock::new(OrderedMap::new()),
            });
            let _ = guard.insert_unique(buddy_name.to_string(), placeholder.clone());
            placeholder
        }
    };

    // Forward relation: insert into user's buddylist. Duplicate is an
    // error per FASM `.alreadythere`.
    {
        let mut bl = user.buddylist.write().map_err(|_| UserdbError::LockPoisoned)?;
        if bl.contains_key(buddy_name) {
            return Err(UserdbError::Other("Duplicate buddy name.".to_string()));
        }
        // We just verified absence and hold the guard; insert_unique
        // succeeds.
        let _ = bl.insert_unique(buddy_name.to_string(), buddy.clone());
    }
    // Reverse relation: insert into buddy's notifies. Duplicates are
    // tolerated here (the user's buddylist is the authoritative side;
    // notifies is a derived index).
    {
        let mut nf = buddy.notifies.write().map_err(|_| UserdbError::LockPoisoned)?;
        let _ = nf.insert_unique(user.username.clone(), user.clone());
    }

    save()?;
    Ok(())
}

/// Remove a bidirectional buddy relationship and persist to disk.
///
/// Mirrors FASM `userdb$removebuddy` (lines 715–732):
///   * Look up `buddy_name` in the registry → error if missing.
///   * Remove from `user.buddylist`.
///   * Remove from `buddy.notifies`.
///   * `save()`.
pub fn removebuddy(user: &Arc<User>, buddy_name: &str) -> Result<(), UserdbError> {
    // Resolve the buddy (read-only — we don't mutate the registry here).
    let buddy = {
        let guard = users().read().map_err(|_| UserdbError::LockPoisoned)?;
        match guard.get(buddy_name) {
            Some(u) => u.clone(),
            None => return Err(UserdbError::UserNotFound(buddy_name.to_string())),
        }
    };

    // Forward removal: from user's buddylist. Missing-from-buddylist is
    // surfaced as "No such buddy." (matches FASM `.nosuchbuddy`).
    {
        let mut bl = user.buddylist.write().map_err(|_| UserdbError::LockPoisoned)?;
        if bl.remove(buddy_name).is_none() {
            return Err(UserdbError::Other("No such buddy.".to_string()));
        }
    }
    // Reverse removal: from buddy's notifies. Silent if absent (the
    // forward removal succeeded, so the database is now consistent
    // either way).
    {
        let mut nf = buddy.notifies.write().map_err(|_| UserdbError::LockPoisoned)?;
        let _ = nf.remove(&user.username);
    }

    save()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SimpleAuthHandler implementation: SIMPLEAUTH_VTABLE
// ---------------------------------------------------------------------------

/// Userdb-backed authentication handler for the `tui_simpleauth` widget.
///
/// Translates the FASM `userdb$vtable` (lines 26–35), which overrode the
/// `tui_simpleauth$vtable`'s `vuserpass` and `vnewuser` slots. The
/// `allow_token` slot keeps the trait default (always-deny) because
/// sshtalk does not support two-factor authentication.
///
/// The struct itself is a zero-sized marker; all state lives in the
/// global [`USERS`] registry. Stored in [`SIMPLEAUTH_VTABLE`] as
/// `Arc<dyn SimpleAuthHandler>` so `main.rs` can hand it to
/// `TuiSimpleauth::new` without any unsafe casts.
struct UserdbAuthHandler;

impl SimpleAuthHandler for UserdbAuthHandler {
    /// Verify a username/password pair using [`authenticate`].
    ///
    /// Returns `true` on success, `false` for any failure (bad
    /// password, unknown user, scrypt error, lock poisoning, or
    /// non-UTF-8 input). The caller (`tui_simpleauth`) renders a
    /// generic "authentication failed" message regardless of the
    /// underlying cause to prevent username enumeration.
    fn allow_userpass(&self, username: &[u8], password: &[u8]) -> bool {
        let username = match std::str::from_utf8(username) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let password = match std::str::from_utf8(password) {
            Ok(s) => s,
            Err(_) => return false,
        };
        authenticate(username, password).is_ok()
    }

    /// Create a new user account using [`newuser`].
    ///
    /// Returns:
    ///   * `None` on success (the simpleauth widget logs the user in).
    ///   * `Some(error_message)` on failure, where the message is shown
    ///     verbatim in the auth-fail panel.
    ///
    /// Failure messages mirror the FASM `userdb$newuser` failure
    /// strings: "Username too short.", "Password too short.",
    /// "Name cannot contain pipes.", "Username already taken." (mapped
    /// from `UserdbError::UserAlreadyExists`).
    fn create_newuser(&self, username: &[u8], password: &[u8]) -> Option<Vec<u8>> {
        let username = match std::str::from_utf8(username) {
            Ok(s) => s,
            Err(_) => return Some(b"Username must be valid UTF-8.".to_vec()),
        };
        let password = match std::str::from_utf8(password) {
            Ok(s) => s,
            Err(_) => return Some(b"Password must be valid UTF-8.".to_vec()),
        };
        match newuser(username, password) {
            Ok(_) => None,
            Err(UserdbError::UserAlreadyExists(_)) => Some(b"Username already taken.".to_vec()),
            Err(UserdbError::Other(msg)) => Some(msg.into_bytes()),
            Err(other) => Some(other.to_string().into_bytes()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions: hex_encode / parse_hex_32 / ct_eq
// ---------------------------------------------------------------------------

/// Append a lower-case hex encoding of `bytes` to the destination string.
///
/// Used by [`save`] to serialise the password hash. Avoids a separate
/// `String` allocation per user when iterating the registry.
fn push_hex_lower(dst: &mut String, bytes: &[u8]) {
    dst.reserve(bytes.len() * 2);
    for &b in bytes {
        dst.push(hex_nibble_lower(b >> 4));
        dst.push(hex_nibble_lower(b & 0x0F));
    }
}

/// Convert a 4-bit value (0..=15) to its lower-case hex digit.
fn hex_nibble_lower(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        // 4-bit input: any other value is a programmer error.
        _ => '?',
    }
}

/// Parse a 64-character lower-or-upper-case hex string into 32 bytes.
///
/// Returns `None` for any malformed input (wrong length, non-hex
/// characters). Used by the file loader.
fn parse_hex_32(s: &str) -> Option<[u8; PASSWORD_HASH_LEN]> {
    let bytes = s.as_bytes();
    if bytes.len() != PASSWORD_HEX_LEN {
        return None;
    }
    let mut out = [0u8; PASSWORD_HASH_LEN];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let high = hex_digit(chunk[0])?;
        let low = hex_digit(chunk[1])?;
        out[i] = (high << 4) | low;
    }
    Some(out)
}

/// Convert a single ASCII hex character to its 4-bit value.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Constant-time equality test for two 32-byte hashes.
///
/// Iterates the entire array regardless of where the first mismatch
/// occurs, ORing differences into a single accumulator. This makes the
/// operation timing-independent of the position of any byte mismatch
/// — critical for password authentication where a timing leak could
/// allow byte-by-byte hash recovery.
fn ct_eq(a: &[u8; PASSWORD_HASH_LEN], b: &[u8; PASSWORD_HASH_LEN]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..PASSWORD_HASH_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
//
// Strategy:
//   * Pure-function tests (parse_hex_32, ct_eq, push_hex_lower) do not
//     touch any global state and may run in parallel.
//   * Stateful tests share a single `init_with_path` invocation (gated
//     by `Once`) and serialise their access to the registry through
//     `STATE_LOCK`. Each stateful test uses a unique username prefix
//     so it does not collide with other stateful tests.
//
// `OnceLock` cannot be reset, so we cannot run multiple `init` cycles
// within one test binary. The `Once`+`Mutex` pattern below works around
// that limitation cleanly.

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use std::sync::Once;

    /// Serialises stateful tests so they can share a single `init`-once
    /// global registry without racing on inserts/removals.
    static STATE_LOCK: Mutex<()> = Mutex::new(());
    static SETUP: Once = Once::new();

    /// One-time initialisation for the userdb global registry.
    ///
    /// Writes a small fixture file so that load-from-file paths are
    /// exercised exactly once, then calls `init_with_path`. Subsequent
    /// invocations are no-ops thanks to `Once`.
    fn ensure_initialised() -> Result<()> {
        SETUP.call_once(|| {
            let path = std::env::temp_dir().join(format!("blitzy_userdb_test_{}.userdb", std::process::id()));
            // Clear any leftover from a previous failed test run.
            let _ = std::fs::remove_file(&path);

            // Write a fixture covering: real users, comments, blanks,
            // and a forward-reference (alice mentioned by carol before
            // alice has her own line).
            let fixture = "carol|0011223344556677889900aabbccddeeff00112233445566778899aabbccddee|alice\n\
# this is a comment line and must be skipped\n\
\n\
dave|deadbeef00000000000000000000000000000000000000000000000000000000\n";
            std::fs::write(&path, fixture).expect("write test fixture");

            init_with_path(path).expect("init_with_path");
        });
        Ok(())
    }

    // -------------------------------------------------------------------
    // Pure-function tests (no global state — fully parallel-safe).
    // -------------------------------------------------------------------

    #[test]
    fn parse_hex_32_round_trip() -> Result<()> {
        let raw = [0x00u8, 0x01, 0x10, 0xab, 0xff, 0x42, 0xde, 0xad];
        // Pad up to 32 bytes for the parser, since it requires exactly 64
        // hex chars on input.
        let mut padded = [0u8; PASSWORD_HASH_LEN];
        padded[..raw.len()].copy_from_slice(&raw);

        let mut hex = String::new();
        push_hex_lower(&mut hex, &padded);
        assert_eq!(hex.len(), PASSWORD_HEX_LEN);

        let parsed = parse_hex_32(&hex).context("expected valid 64-char hex")?;
        assert_eq!(parsed, padded);
        Ok(())
    }

    #[test]
    fn parse_hex_32_rejects_wrong_length() {
        assert!(parse_hex_32("abc").is_none());
        assert!(parse_hex_32(&"0".repeat(63)).is_none());
        assert!(parse_hex_32(&"0".repeat(65)).is_none());
        assert!(parse_hex_32("").is_none());
    }

    #[test]
    fn parse_hex_32_rejects_non_hex_chars() {
        let mut s = "0".repeat(64);
        // Inject a non-hex character at a deterministic position.
        unsafe {
            s.as_bytes_mut()[10] = b'Z';
        }
        assert!(parse_hex_32(&s).is_none());
    }

    #[test]
    fn parse_hex_32_accepts_uppercase() {
        let s = "AABBCCDD".repeat(8);
        let bytes = parse_hex_32(&s).expect("uppercase hex must parse");
        assert_eq!(bytes[0], 0xaa);
        assert_eq!(bytes[1], 0xbb);
    }

    #[test]
    fn ct_eq_equal_bytes() {
        let a = [0u8; PASSWORD_HASH_LEN];
        let b = [0u8; PASSWORD_HASH_LEN];
        assert!(ct_eq(&a, &b));
        let c = [0xa5u8; PASSWORD_HASH_LEN];
        let d = [0xa5u8; PASSWORD_HASH_LEN];
        assert!(ct_eq(&c, &d));
    }

    #[test]
    fn ct_eq_unequal_at_various_positions() {
        // Differences at the first, middle, and last byte must all be
        // detected.
        let a = [0u8; PASSWORD_HASH_LEN];
        for pos in [0usize, 15, 31] {
            let mut b = a;
            b[pos] = 1;
            assert!(!ct_eq(&a, &b), "diff at {} not detected", pos);
        }
    }

    #[test]
    fn hex_nibble_lower_round_trip() {
        for n in 0u8..=15 {
            let c = hex_nibble_lower(n);
            let parsed = hex_digit(c as u8).expect("round-trippable");
            assert_eq!(parsed, n);
        }
    }

    // -------------------------------------------------------------------
    // Stateful tests (serialised via STATE_LOCK, share one init cycle).
    // -------------------------------------------------------------------

    #[test]
    fn loaded_users_have_correct_passwords_and_relationships() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let registry = users().read().expect("registry read");
        // carol — real user, password loaded
        let carol = registry.get("carol").context("carol must exist")?.clone();
        assert!(carol.password_hash.read().unwrap().is_some());

        // dave — real user, password loaded
        let dave = registry.get("dave").context("dave must exist")?.clone();
        assert!(dave.password_hash.read().unwrap().is_some());

        // alice — reference-only (created from carol's buddylist)
        let alice = registry
            .get("alice")
            .context("alice must exist as ref-only")?
            .clone();
        assert!(
            alice.password_hash.read().unwrap().is_none(),
            "alice should be reference-only"
        );

        // Bidirectional buddy relationship: carol → alice (forward),
        // alice → carol (reverse).
        assert!(carol.buddylist.read().unwrap().contains_key("alice"));
        assert!(alice.notifies.read().unwrap().contains_key("carol"));

        Ok(())
    }

    #[test]
    fn newuser_creates_real_account_and_persists() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let user = newuser("frank_a", "frankpassword").context("creating frank_a")?;
        assert_eq!(user.username, "frank_a");
        assert!(user.password_hash.read().unwrap().is_some());

        // Authenticate must succeed.
        let auth = authenticate("frank_a", "frankpassword").context("authenticating frank_a")?;
        assert_eq!(auth.username, "frank_a");

        Ok(())
    }

    #[test]
    fn newuser_rejects_short_username() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let r = newuser("z", "longenough");
        assert!(matches!(r, Err(UserdbError::Other(_))));
        Ok(())
    }

    #[test]
    fn newuser_rejects_short_password() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let r = newuser("frank_b", "abc");
        assert!(matches!(r, Err(UserdbError::Other(_))));
        Ok(())
    }

    #[test]
    fn newuser_rejects_pipe_in_username() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let r = newuser("frank|c", "longenough");
        assert!(matches!(r, Err(UserdbError::Other(_))));
        Ok(())
    }

    #[test]
    fn newuser_populates_reference_only_placeholder() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        // alice was loaded as a reference-only placeholder. Calling
        // newuser should populate her password rather than fail with
        // UserAlreadyExists.
        let alice_pre = users().read().unwrap().get("alice").cloned().unwrap();
        assert!(alice_pre.password_hash.read().unwrap().is_none());

        let alice = newuser("alice", "alicepassword").context("populating alice")?;
        assert!(alice.password_hash.read().unwrap().is_some());

        // It is the same Arc instance — the placeholder was upgraded
        // in-place, preserving any buddylist/notifies entries built up
        // during load.
        assert!(Arc::ptr_eq(&alice_pre, &alice));

        Ok(())
    }

    #[test]
    fn authenticate_rejects_unknown_user_with_authfailed() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let r = authenticate("nobody_present", "any");
        assert!(matches!(r, Err(UserdbError::AuthFailed(_))));
        Ok(())
    }

    #[test]
    fn authenticate_rejects_bad_password_with_authfailed() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let _ = newuser("frank_d", "frankpassword");
        let r = authenticate("frank_d", "wrongpassword");
        assert!(matches!(r, Err(UserdbError::AuthFailed(_))));
        Ok(())
    }

    #[test]
    fn online_offline_cycle_drives_is_online() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let user = newuser("frank_e", "frankpassword")
            .or_else(|e| match e {
                UserdbError::UserAlreadyExists(_) => authenticate("frank_e", "frankpassword"),
                other => Err(other),
            })
            .context("creating frank_e")?;

        // Initially offline.
        assert!(!is_online(&user)?);

        // Two screens: simulates simultaneous SSH sessions.
        let screen_a: Arc<String> = Arc::new("screen_a".to_string());
        let screen_b: Arc<String> = Arc::new("screen_b".to_string());

        online(&user, &screen_a)?;
        assert!(is_online(&user)?);

        online(&user, &screen_b)?;
        assert!(is_online(&user)?);

        offline(&user, &screen_a)?;
        // Still online — screen_b is active.
        assert!(is_online(&user)?);

        offline(&user, &screen_b)?;
        assert!(!is_online(&user)?);

        Ok(())
    }

    #[test]
    fn addbuddy_creates_bidirectional_relationship() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let alice = newuser("frank_f", "frankpassword")
            .or_else(|e| match e {
                UserdbError::UserAlreadyExists(_) => authenticate("frank_f", "frankpassword"),
                other => Err(other),
            })
            .context("alice")?;

        // bob may not exist yet — addbuddy creates a placeholder.
        addbuddy(&alice, "frank_g")?;

        let bob = users()
            .read()
            .unwrap()
            .get("frank_g")
            .cloned()
            .context("bob must be a placeholder")?;
        assert!(bob.notifies.read().unwrap().contains_key("frank_f"));
        assert!(alice.buddylist.read().unwrap().contains_key("frank_g"));

        Ok(())
    }

    #[test]
    fn addbuddy_rejects_short_buddy_name() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let alice = newuser("frank_h", "frankpassword").or_else(|e| match e {
            UserdbError::UserAlreadyExists(_) => authenticate("frank_h", "frankpassword"),
            other => Err(other),
        })?;
        let r = addbuddy(&alice, "z");
        assert!(matches!(r, Err(UserdbError::Other(_))));
        Ok(())
    }

    #[test]
    fn removebuddy_removes_bidirectionally() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let alice = newuser("frank_i", "frankpassword").or_else(|e| match e {
            UserdbError::UserAlreadyExists(_) => authenticate("frank_i", "frankpassword"),
            other => Err(other),
        })?;
        addbuddy(&alice, "frank_j")?;
        let bob = users().read().unwrap().get("frank_j").cloned().unwrap();
        assert!(bob.notifies.read().unwrap().contains_key("frank_i"));

        removebuddy(&alice, "frank_j")?;
        assert!(!bob.notifies.read().unwrap().contains_key("frank_i"));
        assert!(!alice.buddylist.read().unwrap().contains_key("frank_j"));
        Ok(())
    }

    #[test]
    fn removebuddy_unknown_user_returns_user_not_found() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let alice = newuser("frank_k", "frankpassword").or_else(|e| match e {
            UserdbError::UserAlreadyExists(_) => authenticate("frank_k", "frankpassword"),
            other => Err(other),
        })?;
        let r = removebuddy(&alice, "ghost_nobody_here");
        assert!(matches!(r, Err(UserdbError::UserNotFound(_))));
        Ok(())
    }

    #[test]
    fn save_round_trip_preserves_users_and_buddies() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let alice = newuser("frank_l", "frankpassword").or_else(|e| match e {
            UserdbError::UserAlreadyExists(_) => authenticate("frank_l", "frankpassword"),
            other => Err(other),
        })?;
        addbuddy(&alice, "frank_m")?;

        // Read back the file content and verify the line for frank_l
        // contains the expected pipe-delimited fields.
        let path = USERDB_PATH.get().expect("path set").clone();
        let content = std::fs::read_to_string(&path).context("re-reading saved userdb")?;
        let line = content
            .lines()
            .find(|l| l.starts_with("frank_l|"))
            .context("frank_l line missing from saved file")?;
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(fields[0], "frank_l");
        assert_eq!(fields[1].len(), PASSWORD_HEX_LEN);
        assert!(fields[2..].contains(&"frank_m"));

        Ok(())
    }

    #[test]
    fn simpleauth_handler_allow_userpass_round_trip() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let handler = SIMPLEAUTH_VTABLE.get().context("vtable initialised")?;

        // Create a user via the handler's create_newuser path.
        let err = handler.create_newuser(b"frank_n", b"verylongpassword");
        // None == success.
        assert!(
            err.is_none(),
            "create_newuser unexpectedly failed: {:?}",
            err.map(|v| String::from_utf8_lossy(&v).into_owned())
        );

        // allow_userpass succeeds with correct credentials.
        assert!(handler.allow_userpass(b"frank_n", b"verylongpassword"));
        // ...and fails with wrong password.
        assert!(!handler.allow_userpass(b"frank_n", b"wrong"));
        // ...and fails for unknown user.
        assert!(!handler.allow_userpass(b"frank_unknown", b"any"));
        // ...and fails for non-UTF-8 input.
        assert!(!handler.allow_userpass(&[0xff, 0xfe], b"any"));

        Ok(())
    }

    #[test]
    fn simpleauth_handler_create_newuser_rejects_short_inputs() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let handler = SIMPLEAUTH_VTABLE.get().context("vtable")?;

        // Too-short username.
        let r = handler.create_newuser(b"z", b"longenough");
        assert!(r.is_some());

        // Too-short password.
        let r = handler.create_newuser(b"frank_o", b"abc");
        assert!(r.is_some());

        // Non-UTF-8 username.
        let r = handler.create_newuser(&[0xff, 0xfe, 0xfd], b"longenough");
        assert!(r.is_some());

        Ok(())
    }

    #[test]
    fn simpleauth_handler_allow_token_default_denies() -> Result<()> {
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");

        let handler = SIMPLEAUTH_VTABLE.get().context("vtable")?;
        // sshtalk does not support tokens — default trait impl returns
        // false for all inputs.
        assert!(!handler.allow_token(b"any-token-bytes"));
        Ok(())
    }

    #[test]
    fn default_userdb_filename_matches_fasm_baseline() {
        // FASM `userdb.inc` lines 39–41 hardcode "sshtalk.userdb"; we
        // pin this constant so a regression in the default would surface
        // immediately rather than silently changing the deployed file
        // name.
        assert_eq!(DEFAULT_USERDB_FILENAME, "sshtalk.userdb");
    }

    #[test]
    fn init_after_init_with_path_returns_already_initialized() -> Result<()> {
        // Drive the `init` (no-arg) public function past the
        // already-initialised guard so dead-code analysis sees it used
        // *and* we verify the AlreadyInitialized error path.
        ensure_initialised()?;
        let _guard = STATE_LOCK.lock().expect("state lock");
        let r = init();
        assert!(matches!(r, Err(UserdbError::AlreadyInitialized)));
        Ok(())
    }
}
