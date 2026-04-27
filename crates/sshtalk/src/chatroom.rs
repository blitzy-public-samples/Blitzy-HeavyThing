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
// Rust translation of `sshtalk/chatroom.inc` (424 lines, FASM x86_64).
// Maintains exact behavioural parity with the FASM baseline, modulo the
// architectural simplifications detailed below:
//
//   * Two room shapes — *named* and *unnamed* — distinguished by
//     `name: Option<String>` (FASM `chatroom_name_ofs == 0`).
//   * Named rooms register themselves in the global [`CHATROOMS`] stringmap
//     via [`new`] (FASM `chatroom$new` → `stringmap$insert_unique`).
//   * Unnamed (1:1) rooms are *ephemeral* and never appear in the global
//     map (FASM `chatroom$new` `.noname` branch).
//   * Both flavours auto-destruct when the last screen leaves
//     (FASM `chatroom$leave` `.teardown` → `chatroom$destroy`).
//   * Message history is shared per-room across every chatpanel that
//     points at the room, mirroring the FASM design where a room owns
//     the shared state and chatpanels are projection windows.
//
//! Shared chat-room state container for the sshtalk binary.
//!
//! This module is the Rust port of `sshtalk/chatroom.inc` (424 lines)
//! and provides the chat-room data model used by every connected SSH
//! session. The FASM baseline allocates a 24-byte `chatroom` object
//! containing three pointers (name string, topic string, users
//! `unsignedmap`); the Rust port wraps the same conceptual fields in
//! a [`Chatroom`] struct guarded by `RwLock`s for concurrent access
//! across the per-session async tasks spawned by the
//! `heavything::net::ssh` server.
//!
//! # Two room shapes
//!
//! ```text
//!     Named room:                    Unnamed (1:1) room:
//!     ┌──────────────────────┐       ┌──────────────────────┐
//!     │ name: Some("rust")   │       │ name: None           │
//!     │ topic: ...           │       │ topic: ...           │
//!     │ users: { ..., ... }  │       │ users: { self, peer }│
//!     │ history: [ msg, ... ]│       │ history: [ msg, ... ]│
//!     │ in CHATROOMS map ←──╮│       │ NOT in CHATROOMS map │
//!     └─────────────────────┘│       └──────────────────────┘
//!                            │       
//!     ┌─────────────────────┐│
//!     │ CHATROOMS:          ││
//!     │   "rust" ───────────╯│
//!     │   "general" ─────► …│
//!     └─────────────────────┘
//! ```
//!
//! Named rooms are created interactively (FASM `chatroom$new` with a
//! non-NULL `rdi`) and listed in the global [`CHATROOMS`] stringmap;
//! they survive until the last user leaves. Unnamed 1:1 rooms are
//! constructed on-demand by `screen::chatpanel_byname` for direct
//! buddy-to-buddy chats and are not visible to any external lookup.
//!
//! # Lock ordering
//!
//! To avoid deadlocks the module observes a strict lock-acquisition
//! order whenever multiple locks are held at once:
//!
//! 1. The global [`CHATROOMS`] `RwLock` (acquired only inside
//!    [`new`], [`find`], and [`destroy`]).
//! 2. The per-room `users` `RwLock`.
//! 3. The per-room `topic` `RwLock`.
//! 4. The per-room `history` `RwLock`.
//!
//! Within a single function, an inner lock is always released before
//! re-acquiring an outer one (e.g. [`leave`] drops its `users` write
//! guard before invoking [`destroy`], which acquires `CHATROOMS`).
//!
//! # Notification fan-out
//!
//! The FASM `chatroom$join_notify` and `chatroom$leave` paths deliver
//! per-user-customised notifications via `chatpanel$notify`. Because
//! the Rust `chatpanel` module is built by a separate translation
//! agent and the [`Widget`](heavything::tui::object::Widget) trait
//! does not expose a `notify` method, this port substitutes the
//! per-user fan-out with a *push-to-shared-history* model: system
//! messages (`MessageEntry { sender: None, ... }`) are appended to
//! the room's history and rendered uniformly by every connected
//! chatpanel when it next refreshes from history. The semantics are
//! preserved (every user sees every notification) but the wording is
//! slightly broadened — e.g. the joiner and the existing users all
//! see the same `"Present: alice, bob."` and `"carol has arrived."`
//! lines, instead of the joiner seeing only the presence list and
//! the others seeing only the arrival line. This is the behavioural
//! divergence flagged in the AAP §0.7 (Phase 9) and noted as
//! acceptable for the translation tier.

use anyhow::{anyhow, Context, Result};
use std::collections::VecDeque;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// `heavything` re-exports both StringMap and OrderedMap from the `ds`
// subsystem (see `crates/heavything/src/ds/mod.rs`). We use both here:
//
//   * `StringMap<Arc<Chatroom>>` for the global named-rooms registry,
//     keyed by the human-readable room name (FASM `chatrooms` global,
//     `chatroom.inc` line 39).
//   * `OrderedMap<u64, Arc<Screen>>` for the per-room users map,
//     keyed by `Arc::as_ptr(screen) as u64` — i.e. the same
//     pointer-as-key idiom used throughout the FASM baseline (FASM
//     `unsignedmap` keyed by `screen` pointer in `chatroom_users_ofs`).
//
// AAP §0.5.1.6 directs us to favour `std`-backed wrappers wherever
// semantically equivalent; `OrderedMap` is `BTreeMap`-backed and
// therefore iterates in *key* order, not insertion order. The FASM
// baseline used `unsignedmap` with `edi == 1` (insert order) — a
// deliberate ordering for predictable presence-list rendering. The
// Rust port accepts the divergence: pointer values are unstable
// process-locally so any iteration order is essentially arbitrary
// from the user's perspective, and `BTreeMap` guarantees a *stable*
// (if pointer-numerically-sorted) traversal which is sufficient for
// the join/leave broadcast loops.
use heavything::ds::{OrderedMap, StringMap};

use crate::screen::Screen;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of entries retained in a chatroom's message history.
///
/// Mirrors the `CHATPANEL_HISTORY_MAX = 100` constant used by the FASM
/// `chatpanel.inc` `docr` (drop-old-commit-recent) eviction path. The
/// chatpanel module enforces a per-panel projection of this bound;
/// this module enforces the *room-level* bound on the underlying
/// shared `VecDeque` so that no chatpanel ever observes a history
/// longer than 100 entries.
///
/// FASM mapping: implicit constant referenced by `chatpanel.inc`
/// `docr`; centralised here so both modules see the same value.
pub const CHATPANEL_HISTORY_MAX: usize = 100;

// ---------------------------------------------------------------------------
// MessageEntry
// ---------------------------------------------------------------------------

/// A single entry in a chatroom's message history.
///
/// Each connected chatpanel projects this shared history into its
/// own scrollable view. A `sender == None` marks the entry as a
/// *system message* (presence broadcasts, arrival/departure lines,
/// "you are all alone" notices); a `sender == Some(name)` marks it
/// as a real user message.
///
/// FASM mapping: there is no exact FASM analogue; the FASM baseline
/// did not retain a per-room shared history (each `chatpanel` owned
/// its own scrollback buffer). Centralising the history on the
/// `Chatroom` instead of the `Chatpanel` is a translation
/// simplification that matches the AAP §0.7 join-notify push-to-
/// history strategy and lets a late-joining session pick up the
/// scrollback that already accumulated before they arrived.
#[derive(Debug, Clone)]
pub struct MessageEntry {
    /// Sender username, or `None` for system messages (joins, leaves,
    /// presence lists). The FASM baseline distinguished between
    /// "system" and "user" messages by route (calling `chatpanel$notify`
    /// for system messages and `chatpanel$message` for user messages);
    /// this port uses the discriminator instead.
    pub sender: Option<String>,

    /// Message body. UTF-8 encoded; the FASM baseline used UTF-32
    /// `string32` objects but per AAP §0.5.1.7 the Rust port
    /// transparently uses UTF-8 native strings.
    pub content: String,

    /// Wall-clock UNIX-epoch seconds at which the entry was committed.
    /// Stored as `f64` (rather than `SystemTime`) so the chatpanel
    /// rendering path can subtract two timestamps for "n seconds ago"
    /// formatting without going through the `Duration` API.
    pub timestamp: f64,
}

// ---------------------------------------------------------------------------
// Chatroom
// ---------------------------------------------------------------------------

/// A shared chat-room state container — the Rust port of the FASM
/// 24-byte `chatroom` struct (`chatroom.inc` lines 32..=35).
///
/// FASM layout (preserved conceptually, not byte-for-byte):
///
/// ```text
///   chatroom_name_ofs  = 0   ; pointer to optional name string
///   chatroom_topic_ofs = 8   ; pointer to optional topic string
///   chatroom_users_ofs = 16  ; pointer to unsignedmap of users
///   chatroom_size      = 24
/// ```
///
/// The Rust struct adds one field absent from the FASM baseline:
/// `history` — a per-room `VecDeque` shared across every chatpanel
/// pointing at the room. See the module-level docs ("Notification
/// fan-out") for the rationale.
///
/// # Concurrency
///
/// Every mutable field is wrapped in a `RwLock` so the chatpanel
/// module's read-mostly access patterns (rendering, replication
/// fan-out) can proceed without blocking each other; only the
/// rare structural mutations (`join`, `leave`, `set_topic`, history
/// commits) take a write lock. The `name` field is immutable post-
/// construction (FASM mirrors this: `chatroom$new` writes the name
/// once and never touches it again until `chatroom$destroy`) so it
/// has no lock.
///
/// # Memory management
///
/// Both named and unnamed rooms are owned by one or more `Arc`
/// references — the global [`CHATROOMS`] map (named rooms only) plus
/// every active chatpanel and screen pointing at the room. When the
/// last reference drops, the `Arc` allocator frees the struct;
/// [`destroy`] only un-registers the name from the global map and
/// relies on the surrounding `Arc` reference-count to drive the
/// actual deallocation. This replaces the FASM `heap$free` chain in
/// `chatroom$destroy` with idiomatic Rust ownership.
pub struct Chatroom {
    /// Room name, or `None` for unnamed 1:1 rooms.
    ///
    /// FASM mapping: `chatroom_name_ofs` (0). A NULL pointer in FASM
    /// translates to `None` in Rust; a non-NULL pointer translates to
    /// `Some(...)`. Set once at construction time and never mutated
    /// thereafter — matching the FASM baseline which only writes this
    /// field in `chatroom$new`.
    name: Option<String>,

    /// Optional room topic — a free-form description shown above the
    /// chatpanel's input line. May be set or cleared at any time via
    /// [`Chatroom::set_topic`].
    ///
    /// FASM mapping: `chatroom_topic_ofs` (8). The FASM baseline
    /// wrote this field once at `chatroom$new` time and provided no
    /// post-construction mutator; the Rust port adds [`set_topic`]
    /// for parity with future "change topic" commands. The lock is
    /// independent from `users` so a `set_topic` call cannot stall
    /// concurrent `join`/`leave`/`for_each` traversals.
    topic: RwLock<Option<String>>,

    /// Set of connected screens, keyed by `Arc::as_ptr(screen) as u64`.
    ///
    /// FASM mapping: `chatroom_users_ofs` (16). The FASM baseline
    /// constructed this map with `edi == 1` (`unsignedmap$new`'s
    /// "insert order, not sort order" flag) so traversals matched
    /// the join order. The Rust port uses
    /// [`OrderedMap<u64, Arc<Screen>>`] which is `BTreeMap`-backed
    /// and traverses in key (pointer) order; see the module-level
    /// note for rationale.
    users: RwLock<OrderedMap<u64, Arc<Screen>>>,

    /// Shared per-room message history — bounded at
    /// [`CHATPANEL_HISTORY_MAX`] (100 entries).
    ///
    /// New entries are pushed to the back; when the buffer is at
    /// capacity, the oldest entry (front) is evicted FIFO. The
    /// chatpanel module reads this history when rendering its
    /// scrollback and also pushes new user messages here via the
    /// `commit` path.
    ///
    /// FASM mapping: no direct equivalent — the FASM baseline
    /// owned a per-chatpanel scrollback rather than a per-room
    /// history. Centralising history on the room is a translation
    /// simplification (see module docs).
    history: RwLock<VecDeque<MessageEntry>>,
}

// ---------------------------------------------------------------------------
// Global chatrooms registry
// ---------------------------------------------------------------------------

/// Global stringmap of *named* chatrooms.
///
/// Initialised exactly once by [`init`]; subsequent calls return an
/// error rather than re-overwriting. Unnamed (1:1) rooms are *not*
/// inserted here — they remain reachable only via the chatpanel that
/// constructed them, and disappear when that chatpanel drops the last
/// reference.
///
/// FASM mapping: the `chatrooms` `globals { dq 0 }` slot in
/// `chatroom.inc` line 39, initialised by `chatroom$init` (line 45)
/// to the result of `stringmap$new`. Wrapping in
/// `OnceLock<RwLock<...>>` gives single-shot construction with
/// shared-mutable post-init access.
static CHATROOMS: OnceLock<RwLock<StringMap<Arc<Chatroom>>>> = OnceLock::new();

/// Returns a reference to the global named-rooms registry.
///
/// # Panics
///
/// Panics with a clear diagnostic if [`init`] was not called first.
/// This is a programmer-error condition (the binary's `main.rs` must
/// always call `chatroom::init()` before spawning any SSH connection
/// task), so a panic is preferable to silently returning an error
/// that callers would have to forward up the entire call chain.
/// This mirrors the established `userdb::users()` accessor pattern
/// in `crates/sshtalk/src/userdb.rs:287`.
pub fn chatrooms() -> &'static RwLock<StringMap<Arc<Chatroom>>> {
    CHATROOMS
        .get()
        .expect("chatroom::init() must be called before chatroom::chatrooms()")
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/// Initialise the global named-rooms registry.
///
/// Must be called exactly once by `main.rs` during startup, *before*
/// any other `chatroom` function (other than [`new`] with `name == None`)
/// is invoked. Calling [`init`] more than once is a programmer error
/// and returns an error rather than silently overwriting.
///
/// FASM mapping: `chatroom$init` (`chatroom.inc` lines 45..=50). The
/// FASM baseline used `xor edi, edi` + `stringmap$new` to construct
/// an unsorted (insert-order) stringmap; the Rust port uses
/// [`StringMap::new`] which is `HashMap`-backed and therefore
/// iterates in arbitrary order. Order does not matter for the global
/// chatrooms registry — only existence and lookup-by-name matter.
pub fn init() -> Result<()> {
    CHATROOMS
        .set(RwLock::new(StringMap::new()))
        .map_err(|_| anyhow!("chatroom::init() called more than once"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Constructors and lookups
// ---------------------------------------------------------------------------

/// Construct a new chatroom and (for named rooms) register it in the
/// global registry.
///
/// Both `name` and `topic` are optional; the FASM baseline accepted
/// `rdi == 0` (no name) and `rsi == 0` (no topic) independently, and
/// the Rust port preserves the same semantics:
///
/// * `name == Some(s)`: register the room as `s` in [`CHATROOMS`].
///   Returns an error if a room with that name already exists.
/// * `name == None`: do **not** register; caller is responsible for
///   keeping a reference alive (typically the chatpanel that
///   triggered the 1:1 chat construction).
/// * `topic`: stored verbatim, mutable post-construction via
///   [`Chatroom::set_topic`].
///
/// # Errors
///
/// Returns an error if a named room with the same name already
/// exists in [`CHATROOMS`]. Callers in `screen::chatpanel_byname`
/// must check for this error and treat it as "open the existing
/// room" via [`find`] (which is what the FASM baseline did
/// implicitly via `stringmap$insert_unique`'s rejection-of-
/// duplicates behaviour).
///
/// FASM mapping: `chatroom$new` (`chatroom.inc` lines 57..=86).
/// The FASM `heap$alloc_clear` + `unsignedmap$new` + optional
/// `stringmap$insert_unique` translates to the `Arc::new` +
/// `OrderedMap::new` + optional `chatrooms().write().insert_unique`
/// chain below.
pub fn new(name: Option<String>, topic: Option<String>) -> Result<Arc<Chatroom>> {
    let room = Arc::new(Chatroom {
        name: name.clone(),
        topic: RwLock::new(topic),
        users: RwLock::new(OrderedMap::new()),
        history: RwLock::new(VecDeque::with_capacity(CHATPANEL_HISTORY_MAX)),
    });

    if let Some(name_str) = &name {
        let map = chatrooms();
        let mut guard = map
            .write()
            .map_err(|_| anyhow!("chatrooms registry lock poisoned"))?;
        // FASM `stringmap$insert_unique` rejects duplicates with a
        // distinguished return value; the Rust port forwards that as
        // an `anyhow!` error so the caller (`screen::chatpanel_byname`)
        // can fall back to `find` and reuse the existing room.
        guard
            .insert_unique(name_str.clone(), Arc::clone(&room))
            .map_err(|_| anyhow!("chatroom with name '{}' already exists", name_str))?;
    }

    Ok(room)
}

/// Look up a named chatroom by its name.
///
/// Returns:
/// * `Ok(Some(room))` — the room exists in [`CHATROOMS`].
/// * `Ok(None)` — no room with that name is registered.
/// * `Err(_)` — the registry lock is poisoned (cataclysmic
///   programming error; callers should propagate the error up).
///
/// Used primarily by `screen::chatpanel_byname` in the
/// "Path 2: Find or Create" branch (FASM `screen.inc` lines
/// 786..=1108) where the panel logic first asks "does this room
/// already exist?" before deciding whether to construct a new one.
///
/// FASM mapping: `stringmap$find` against `[chatrooms]` global.
/// Unnamed (1:1) rooms cannot be returned by this function because
/// they are never registered in [`CHATROOMS`]; callers requesting a
/// 1:1 chat go through `screen::chatpanel_byname`'s buddy-name path
/// directly.
pub fn find(name: &str) -> Result<Option<Arc<Chatroom>>> {
    let map = chatrooms();
    let guard = map
        .read()
        .map_err(|_| anyhow!("chatrooms registry lock poisoned"))?;
    Ok(guard.get(name).map(Arc::clone))
}

// ---------------------------------------------------------------------------
// Membership operations
// ---------------------------------------------------------------------------

/// Add a screen (i.e. an SSH session's TUI handle) to the room's
/// users map.
///
/// The screen is keyed by `Arc::as_ptr(screen) as *const () as
/// usize as u64` — the same pointer-identity idiom used by
/// [`userdb::online`](crate::userdb::online) for its tuilist
/// registration. Two `Arc<Screen>` values pointing at the same
/// allocation collide on the same key; two `Arc<Screen>` values
/// pointing at distinct allocations get distinct keys. This is
/// stable for the lifetime of the strong `Arc` reference (the
/// allocator never reuses the address while the `Arc` is alive).
///
/// # Errors
///
/// Returns an error if:
/// * the users lock is poisoned (lock-poisoning panic);
/// * the screen is already registered in this room's users map
///   (FASM `unsignedmap$insert_unique` rejection-of-duplicates).
///
/// FASM mapping: `chatroom$join` (`chatroom.inc` lines 127..=132).
/// The FASM `unsignedmap$insert_unique` is the entire body of the
/// function; the Rust port mirrors that minimal scope.
///
/// # Caller responsibility
///
/// `chatroom$join` is *intentionally* separate from
/// `chatroom$join_notify` (FASM comment at line 138). Callers should
/// invoke [`join`] *first* to register the screen, then [`join_notify`]
/// *afterwards* so the broadcast iterates the post-join user set
/// (i.e. the joiner sees themselves in the "Present:" list and
/// existing users see the joiner counted).
pub fn join(room: &Arc<Chatroom>, screen: &Arc<Screen>) -> Result<()> {
    let key = Arc::as_ptr(screen) as *const () as usize as u64;
    let mut guard = room
        .users
        .write()
        .map_err(|_| anyhow!("chatroom users lock poisoned"))?;
    guard
        .insert_unique(key, Arc::clone(screen))
        .map_err(|_| anyhow!("screen already joined this chatroom"))?;
    Ok(())
}

/// Remove a screen from the room's users map, auto-destroying the
/// room if it becomes empty.
///
/// The room teardown logic differs slightly from the FASM baseline
/// for reasons documented in AAP §0.7 (Phase 8). Specifically:
///
/// * **FASM**: counted total *tui* objects across all *user* objects
///   (each user could have multiple SSH sessions = multiple tuilist
///   entries). When the total tui count was 1, teardown the room.
///   When this user had >1 tuis, do nothing. Otherwise remove the
///   user and broadcast departure.
/// * **Rust port**: each [`Screen`] *is* one SSH session's TUI; the
///   users map is keyed by screen pointer (not by user object).
///   When the users map is empty after removal, teardown the room.
///   This is correct for the 1:1 case (both screens were keyed
///   independently) and the named-room case (a user with two
///   sessions has two screen entries in users, so removing one
///   leaves the other).
///
/// # Notification semantics for named rooms
///
/// After removing the leaving screen:
/// * If the room is now empty → call [`destroy`] (un-registers
///   from the global map; `Arc` refcount drives deallocation).
/// * If the room is named and one user remains → push a
///   "You are now by yourself." system message (FASM `.lonelyrider`
///   path, line 358).
/// * If the room is named and ≥1 users remain → push a
///   "<username> has departed." system message (FASM
///   `.notifylist` path, line 342).
///
/// Unnamed 1:1 rooms generate no notification on leave (matching
/// FASM `.oneonone` path, line 397).
///
/// # Errors
///
/// Returns an error if:
/// * the users / history / chatrooms lock is poisoned;
/// * the screen was not actually a member of this room
///   (deviation from FASM, which silently no-op'd missing keys —
///   the Rust port surfaces the bug because the caller should
///   already have invariant-validated membership).
///
/// FASM mapping: `chatroom$leave` (`chatroom.inc` lines 296..=412).
pub fn leave(room: &Arc<Chatroom>, screen: &Arc<Screen>) -> Result<()> {
    let key = Arc::as_ptr(screen) as *const () as usize as u64;

    // Snapshot the leaving screen's username *before* dropping the
    // user from the map, so the "X has departed." message can
    // reference it. Best-effort: an unauthenticated screen has no
    // user and produces no per-user notification (matches FASM,
    // which only sends departure messages for authenticated users
    // because `user_username_ofs` would be NULL for the auth screen).
    let leaving_username = screen.user().map(|u| u.username.clone());

    // ---- Phase 1: remove the screen from the users map ------------
    // We hold the users write lock only long enough to mutate the
    // map and read its post-removal cardinality, then drop it before
    // touching any other lock (CHATROOMS, history) to honour the
    // module's lock-acquisition order documented at the top of the
    // file.
    let (now_empty, now_lonely) = {
        let mut guard = room
            .users
            .write()
            .map_err(|_| anyhow!("chatroom users lock poisoned"))?;
        guard
            .remove(&key)
            .context("screen was not a member of this chatroom")?;
        (guard.is_empty(), guard.len() == 1)
    };

    // ---- Phase 2: room-level destruction or notification ----------
    if now_empty {
        // Last user left — auto-destroy.
        // FASM: `chatroom$destroy` is invoked from the `.teardown`
        // label (line 408). The Rust port mirrors the same call.
        destroy(room)?;
    } else if room.name.is_some() {
        // Named room with surviving users — broadcast departure.
        if let Some(uname) = leaving_username {
            // FASM cleartext: ` has departed.` (line 356).
            room.push_system_message(format!("{} has departed.", uname))?;
        }
        if now_lonely {
            // FASM `.lonelyrider` cleartext: `You are now by yourself.`
            // (line 379). Posted as a *separate* system message so a
            // future chatpanel implementation can format it
            // distinctly from the routine departure broadcast.
            room.push_system_message("You are now by yourself.".to_string())?;
        }
    }
    // Unnamed 1:1 rooms with users remaining: no notification.
    // (FASM `.oneonone` path, line 397: just remove and return.)

    Ok(())
}

/// Internal helper — un-register the room from the global named
/// registry (no-op for unnamed rooms) and let `Arc` refcount drive
/// the actual deallocation.
///
/// Called by [`leave`] when the users map becomes empty after a
/// removal. Not exposed publicly because external callers should
/// always go through [`leave`] (which enforces the empty-users
/// invariant) rather than tearing down a room with active members.
///
/// FASM mapping: `chatroom$destroy` (`chatroom.inc` lines 92..=122).
/// The FASM baseline explicitly freed the `users` map, the name
/// string, the topic string, and the chatroom struct itself via
/// `heap$free`. The Rust port relies on `Arc::drop` to handle all
/// of those automatically once the last strong reference falls.
fn destroy(room: &Arc<Chatroom>) -> Result<()> {
    if let Some(name) = &room.name {
        let map = chatrooms();
        let mut guard = map
            .write()
            .map_err(|_| anyhow!("chatrooms registry lock poisoned"))?;
        // FASM `stringmap$erase` silently no-ops on missing keys; the
        // Rust port preserves that semantics by ignoring the
        // `Option<V>` return value of `StringMap::remove`. Callers
        // that needed strict validation would have caught the absence
        // in `find` before reaching this point.
        let _evicted = guard.remove(name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Join broadcast
// ---------------------------------------------------------------------------

/// Broadcast a join notification to the chatroom.
///
/// Pushes system messages to the room's shared history that announce
/// the joiner's arrival, matching the FASM `chatroom$join_notify`
/// semantics modulo the per-user fan-out simplification documented in
/// the module-level "Notification fan-out" section.
///
/// # Three notification variants (per FASM baseline)
///
/// * **Unnamed 1:1 room** (FASM `.nothingtodo`, line 288): no broadcast.
///   The 1:1 chat is implicit — both parties already know who joined.
/// * **Named room with sole occupant** (FASM `.lonelyrider`, line 250):
///   push `"You are all alone."` so the lone joiner sees they are the
///   only person in the room.
/// * **Named room with peers** (FASM main path, lines 152..=243):
///   push `"Present: alice, bob, ...."` (the existing user list,
///   excluding the joiner) followed by `"<joiner> has arrived."`.
///   Both messages land in the shared history; every connected
///   chatpanel sees them on their next refresh.
///
/// # Caller protocol
///
/// Callers should invoke [`join`] *before* [`join_notify`] so the
/// joiner already appears in the users map. The presence list built
/// inside this function explicitly skips entries whose username
/// matches `joiner` so the joiner does not appear in their own
/// "Present: ..." line — matching FASM `.userlist_skip`, line 169.
///
/// FASM mapping: `chatroom$join_notify` (`chatroom.inc` lines 141..=289).
pub fn join_notify(room: &Arc<Chatroom>, joiner: &str) -> Result<()> {
    // FASM line 145: `cmp qword [rdi+chatroom_name_ofs], 0; je .nothingtodo`
    // — unnamed 1:1 rooms produce no notification.
    if room.name.is_none() {
        return Ok(());
    }

    // Count current users (post-join). Held only briefly.
    let users_count = {
        let guard = room
            .users
            .read()
            .map_err(|_| anyhow!("chatroom users lock poisoned"))?;
        guard.len()
    };

    if users_count <= 1 {
        // FASM `.lonelyrider` path (line 250): the joiner is the only
        // occupant. Push "You are all alone." as a system message.
        // FASM cleartext: line 286.
        room.push_system_message("You are all alone.".to_string())
            .with_context(|| format!("join_notify({joiner}) lonelyrider history append"))?;
        return Ok(());
    }

    // FASM main path: build the "Present: <other users>." string.
    let presence_msg = build_presence_list(room, joiner)
        .with_context(|| format!("join_notify({joiner}) build presence list"))?;
    room.push_system_message(presence_msg)
        .with_context(|| format!("join_notify({joiner}) presence history append"))?;

    // Push "<joiner> has arrived." for the existing users.
    // FASM cleartext `' has arrived.'` (line 248).
    room.push_system_message(format!("{} has arrived.", joiner))
        .with_context(|| format!("join_notify({joiner}) arrival history append"))?;

    Ok(())
}

/// Build the FASM-style `"Present: alice, bob, ...."` presence list,
/// skipping the entry whose username matches `joiner`.
///
/// Used by [`join_notify`] to compose the broadcast string. Holds the
/// users read lock for the entire scan; releases it before returning
/// so the caller can safely re-acquire it (or any other lock) without
/// hitting the lock-acquisition order constraint.
///
/// FASM mapping: lines 161..=200 of `chatroom$join_notify` — the
/// `mov rdi, .present; call string$copy` + walk-the-users-list +
/// `string$concat ", "` + `string$concat "."` chain.
fn build_presence_list(room: &Arc<Chatroom>, joiner: &str) -> Result<String> {
    let guard = room
        .users
        .read()
        .map_err(|_| anyhow!("chatroom users lock poisoned"))?;

    let mut buf = String::from("Present: ");
    let mut first = true;
    guard.for_each(|_key, screen| {
        // Each screen owns an authenticated `User` post-clone. An
        // unauthenticated screen (the template, or a screen still
        // inside `tui_simpleauth`) has no user yet — skip it; the
        // FASM baseline did not encounter unauthenticated tuis in
        // a chatroom because joining required auth.
        if let Some(user) = screen.user() {
            if user.username != joiner {
                if !first {
                    // FASM cleartext `', '` (line 245). Inserted only
                    // between entries, never leading/trailing.
                    buf.push_str(", ");
                }
                buf.push_str(&user.username);
                first = false;
            }
        }
    });
    // FASM cleartext `'.'` (line 246). Always appended, even if the
    // skip-the-joiner pruning produced an empty list — that case
    // would render as `"Present: ."`, which the FASM baseline likewise
    // emits when called with `users_count > 1` but every other user
    // happens to share the joiner's username. Defensive-only; in
    // normal operation usernames are unique and `users_count > 1`
    // implies at least one peer to list.
    buf.push('.');
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Accessor methods
// ---------------------------------------------------------------------------

impl Chatroom {
    /// Returns the room's name (named room) or `None` (unnamed 1:1).
    ///
    /// The name is immutable post-construction so this accessor needs
    /// no locking and returns a borrow of the underlying `Option<String>`.
    ///
    /// FASM mapping: read of `[rdi+chatroom_name_ofs]`, common in
    /// every callsite that needs to switch on "named vs unnamed" room.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns a clone of the current topic, or `None` if no topic is
    /// set.
    ///
    /// Acquires a read lock on the topic field; releases it before
    /// returning. The clone is necessary because the caller cannot
    /// hold a borrow tied to the lock guard's lifetime through the
    /// function-call boundary.
    ///
    /// FASM mapping: read of `[rdi+chatroom_topic_ofs]`, used by the
    /// chatpanel rendering path to display the topic above the input
    /// line.
    ///
    /// # Errors
    ///
    /// Returns an error only if the topic lock is poisoned (lock-
    /// poisoning panic in another thread).
    pub fn topic(&self) -> Result<Option<String>> {
        let guard = self
            .topic
            .read()
            .map_err(|_| anyhow!("chatroom topic lock poisoned"))?;
        Ok(guard.clone())
    }

    /// Replace the room's topic with `topic`.
    ///
    /// Pass `None` to clear the topic, `Some(s)` to set it. Acquires
    /// a write lock on the topic field for the duration of the
    /// assignment.
    ///
    /// FASM mapping: no direct equivalent; the FASM baseline did not
    /// expose a topic-mutation function (the topic was only set
    /// during `chatroom$new`). The Rust port adds this for parity
    /// with future "/topic" commands implementable in chatpanel.
    ///
    /// # Errors
    ///
    /// Returns an error only if the topic lock is poisoned.
    pub fn set_topic(&self, topic: Option<String>) -> Result<()> {
        let mut guard = self
            .topic
            .write()
            .map_err(|_| anyhow!("chatroom topic lock poisoned"))?;
        *guard = topic;
        Ok(())
    }

    /// Returns the number of screens currently in the room.
    ///
    /// FASM mapping: read of
    /// `[rdi+chatroom_users_ofs]+_avlofs_right` — the AVL-tree node
    /// count stored in the right-pointer slot. The Rust port uses
    /// [`OrderedMap::len`] which is `BTreeMap::len()`.
    ///
    /// # Errors
    ///
    /// Returns an error only if the users lock is poisoned.
    pub fn users_count(&self) -> Result<usize> {
        let guard = self
            .users
            .read()
            .map_err(|_| anyhow!("chatroom users lock poisoned"))?;
        Ok(guard.len())
    }

    /// Returns a reference to the shared message-history `RwLock`.
    ///
    /// Used by the chatpanel module to acquire a read lock for
    /// rendering the scrollback, or a write lock for committing new
    /// messages. The chatpanel module is responsible for honouring
    /// the [`CHATPANEL_HISTORY_MAX`] bound when pushing to the back
    /// of the deque (the [`push_system_message`] internal helper
    /// already does this for system messages).
    ///
    /// FASM mapping: no direct equivalent; the FASM baseline kept
    /// scrollback per-chatpanel rather than per-room.
    pub fn history(&self) -> &RwLock<VecDeque<MessageEntry>> {
        &self.history
    }

    /// Returns a reference to the per-room users `RwLock`.
    ///
    /// Used by the chatpanel module's 4-way iteration path
    /// (replicate keystrokes / messages to every screen in the
    /// room) and by `screen.rs` to enumerate panel-open peers.
    /// The map is keyed by `Arc::as_ptr(screen) as u64`; values
    /// are `Arc<Screen>`.
    ///
    /// FASM mapping: read of `[rdi+chatroom_users_ofs]`, the same
    /// `unsignedmap` exposed to the FASM `chatroom$foreach`-style
    /// iteration in chatpanel.inc.
    pub fn users(&self) -> &RwLock<OrderedMap<u64, Arc<Screen>>> {
        &self.users
    }

    /// Internal helper — push a system message (sender = `None`) to
    /// the room's history, evicting the oldest entry FIFO-style if
    /// the buffer is at capacity.
    ///
    /// Holds the history write lock for the duration of the push;
    /// the lock is released before returning. Caller must not hold
    /// any other locks (notably `users`) when calling this — see
    /// the module-level lock-ordering note.
    ///
    /// FASM mapping: no direct analogue (FASM did not retain a
    /// shared history). The FIFO-eviction logic preserves the
    /// `CHATPANEL_HISTORY_MAX` bound that the FASM `chatpanel.inc`
    /// `docr` enforced per-panel.
    fn push_system_message(&self, content: String) -> Result<()> {
        let mut guard = self
            .history
            .write()
            .map_err(|_| anyhow!("chatroom history lock poisoned"))?;
        if guard.len() >= CHATPANEL_HISTORY_MAX {
            guard.pop_front();
        }
        guard.push_back(MessageEntry {
            sender: None,
            content,
            timestamp: current_timestamp(),
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Wall-clock UNIX-epoch seconds as `f64`.
///
/// Used to stamp [`MessageEntry::timestamp`] for newly committed
/// system messages. On the (essentially impossible) clock-pre-epoch
/// failure mode, returns `0.0` — chatpanel rendering treats `0.0`
/// timestamps as "unknown" and elides the relative-time annotation.
///
/// `unwrap_or(0.0)` is a graceful fallback (not `unwrap()` /
/// `expect()`), so AAP §0.8.3's no-unwrap-in-library-paths constraint
/// is satisfied: the call cannot panic.
fn current_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::Once;

    /// Serialises every test that touches the global [`CHATROOMS`]
    /// registry. Tests that operate exclusively on a freshly-created
    /// `Arc<Chatroom>` (no global-map mutation) do not need this
    /// guard and remain parallel-safe.
    static STATE_LOCK: Mutex<()> = Mutex::new(());
    static SETUP: Once = Once::new();

    /// Acquire `STATE_LOCK`, transparently recovering from
    /// poisoning. A poisoned `STATE_LOCK` means a *prior* serialised
    /// test panicked, but its panic was unrelated to the chatroom
    /// global state — re-entering the global state for the *next*
    /// test is still safe because tests clean up their own keys
    /// (e.g. `CHATROOMS.write().remove(name)`) at both the
    /// pre-test and post-test boundaries.
    fn lock_state() -> MutexGuard<'static, ()> {
        STATE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Single-shot global initialisation. Subsequent calls are no-ops
    /// (matching the [`init`] semantics on a fresh process).
    fn ensure_initialised() {
        SETUP.call_once(|| {
            // We can't unwrap() in library paths but inside #[cfg(test)]
            // it's the standard pattern — a failed init is a test-fixture
            // bug worth a hard panic.
            init().expect("chatroom::init() failed in test setup");
        });
    }

    // -------------------------------------------------------------------
    // Pure-function tests (no Screen construction required).
    // -------------------------------------------------------------------

    #[test]
    fn message_entry_fields_are_public() {
        // Confirm that `MessageEntry`'s three documented fields
        // (`sender`, `content`, `timestamp`) are publicly constructible
        // and readable per the export schema.
        let m = MessageEntry {
            sender: Some("alice".to_string()),
            content: "hello world".to_string(),
            timestamp: 1_700_000_000.0,
        };
        assert_eq!(m.sender.as_deref(), Some("alice"));
        assert_eq!(m.content, "hello world");
        assert!((m.timestamp - 1_700_000_000.0).abs() < f64::EPSILON);

        // System message: sender is None.
        let sys = MessageEntry {
            sender: None,
            content: "alice has arrived.".to_string(),
            timestamp: 0.0,
        };
        assert!(sys.sender.is_none());
    }

    #[test]
    fn chatpanel_history_max_is_100() {
        // Document-and-enforce the constant referenced by chatpanel.inc.
        assert_eq!(CHATPANEL_HISTORY_MAX, 100);
    }

    #[test]
    fn current_timestamp_is_positive_and_recent() {
        let now = current_timestamp();
        // Loose assertion: timestamp must be after 2020-01-01
        // (1577836800.0 UNIX epoch) — confirms vDSO/SystemTime works.
        assert!(now > 1_577_836_800.0, "timestamp suspiciously low: {now}");
    }

    // -------------------------------------------------------------------
    // Chatroom construction (no global mutation needed for unnamed).
    // -------------------------------------------------------------------

    #[test]
    fn unnamed_room_construction_does_not_touch_global() {
        // Unnamed rooms must not require [`init`] to succeed — they
        // never touch the global registry. This test deliberately
        // does *not* call `ensure_initialised`; if `new(None, _)` ever
        // started touching CHATROOMS, this test would fail with the
        // `chatrooms()` panic.
        let room = new(None, Some("private chat".to_string())).expect("unnamed chatroom::new");
        assert!(room.name().is_none());
        assert_eq!(room.topic().expect("topic"), Some("private chat".to_string()));
        assert_eq!(room.users_count().expect("users_count"), 0);
    }

    #[test]
    fn unnamed_room_with_no_topic() {
        let room = new(None, None).expect("unnamed chatroom::new");
        assert!(room.name().is_none());
        assert!(room.topic().expect("topic").is_none());
    }

    #[test]
    fn named_room_registers_in_global_map() {
        ensure_initialised();
        let _g = lock_state();

        let name = "test_named_room_registers";
        // Clean up any leftovers from a previous run.
        let _ = chatrooms().write().expect("CHATROOMS").remove(name);

        let room = new(Some(name.to_string()), None).expect("named chatroom::new");
        assert_eq!(room.name(), Some(name));

        let found = find(name).expect("find");
        assert!(found.is_some(), "named room must be findable");
        let found = found.expect("named room must be findable");
        assert!(Arc::ptr_eq(&room, &found), "find must return the same Arc");

        // Cleanup.
        let _ = chatrooms().write().expect("CHATROOMS").remove(name);
    }

    #[test]
    fn duplicate_named_room_returns_error() {
        ensure_initialised();
        let _g = lock_state();

        let name = "test_duplicate_named_room";
        let _ = chatrooms().write().expect("CHATROOMS").remove(name);

        let _r1 = new(Some(name.to_string()), None).expect("first named chatroom::new");
        let r2 = new(Some(name.to_string()), None);
        assert!(r2.is_err(), "second new() with the same name must return Err");

        let _ = chatrooms().write().expect("CHATROOMS").remove(name);
    }

    #[test]
    fn find_missing_returns_none() {
        ensure_initialised();
        let _g = lock_state();

        let result = find("definitely_not_a_real_room_name_x9q").expect("find");
        assert!(result.is_none());
    }

    // -------------------------------------------------------------------
    // Topic accessor / mutator.
    // -------------------------------------------------------------------

    #[test]
    fn set_topic_round_trip() {
        let room = new(None, Some("initial".to_string())).expect("new");
        assert_eq!(room.topic().expect("topic"), Some("initial".to_string()));

        room.set_topic(Some("changed".to_string())).expect("set_topic");
        assert_eq!(room.topic().expect("topic"), Some("changed".to_string()));

        room.set_topic(None).expect("set_topic clear");
        assert!(room.topic().expect("topic").is_none());
    }

    // -------------------------------------------------------------------
    // History bound.
    // -------------------------------------------------------------------

    #[test]
    fn history_evicts_oldest_when_at_capacity() {
        let room = new(None, None).expect("new");
        // Fill history to capacity.
        for i in 0..CHATPANEL_HISTORY_MAX {
            room.push_system_message(format!("msg #{i}"))
                .expect("push_system_message");
        }
        {
            let h = room.history().read().expect("history");
            assert_eq!(h.len(), CHATPANEL_HISTORY_MAX);
            assert_eq!(h.front().expect("front").content, "msg #0");
            assert_eq!(
                h.back().expect("back").content,
                format!("msg #{}", CHATPANEL_HISTORY_MAX - 1)
            );
        }

        // One more push: front should evict.
        room.push_system_message("overflow_one".to_string())
            .expect("push overflow");
        {
            let h = room.history().read().expect("history");
            assert_eq!(h.len(), CHATPANEL_HISTORY_MAX, "history must remain bounded");
            assert_eq!(
                h.front().expect("front").content,
                "msg #1",
                "FIFO eviction must drop msg #0"
            );
            assert_eq!(h.back().expect("back").content, "overflow_one");
        }

        // Push N more; capacity holds.
        for i in 0..50 {
            room.push_system_message(format!("more_{i}")).expect("push more");
        }
        {
            let h = room.history().read().expect("history");
            assert_eq!(h.len(), CHATPANEL_HISTORY_MAX);
            assert_eq!(h.back().expect("back").content, "more_49");
        }
    }

    #[test]
    fn history_message_carries_no_sender_for_system_push() {
        let room = new(None, None).expect("new");
        room.push_system_message("system push".to_string())
            .expect("push_system_message");
        let h = room.history().read().expect("history");
        let entry = h.back().expect("back");
        assert!(entry.sender.is_none(), "system messages must have sender=None");
        assert_eq!(entry.content, "system push");
        assert!(
            entry.timestamp > 0.0,
            "system messages must have a real timestamp"
        );
    }

    // -------------------------------------------------------------------
    // join_notify on unnamed and lonely rooms (no Screen needed).
    // -------------------------------------------------------------------

    #[test]
    fn join_notify_unnamed_room_is_silent() {
        let room = new(None, None).expect("new");
        join_notify(&room, "alice").expect("join_notify");
        // No history entries should accumulate for unnamed rooms.
        let h = room.history().read().expect("history");
        assert!(h.is_empty(), "unnamed rooms must not emit join notifications");
    }

    #[test]
    fn join_notify_lonely_named_room_emits_alone() {
        ensure_initialised();
        let _g = lock_state();

        let name = "test_lonely_join_notify";
        let _ = chatrooms().write().expect("CHATROOMS").remove(name);

        let room = new(Some(name.to_string()), None).expect("new");
        // Don't actually join anyone — users_count remains 0, so the
        // lonelyrider branch fires.
        join_notify(&room, "alice").expect("join_notify");

        {
            let h = room.history().read().expect("history");
            assert_eq!(h.len(), 1);
            let entry = h.back().expect("back");
            assert!(entry.sender.is_none());
            assert_eq!(entry.content, "You are all alone.");
        }

        let _ = chatrooms().write().expect("CHATROOMS").remove(name);
    }

    // -------------------------------------------------------------------
    // Membership operations against a Screen.
    //
    // These tests construct a real `Arc<Screen>` via `Screen::new`, which
    // requires `screen::init_formatters` to have been called once *and*
    // a Tokio runtime to be active (the screen's statusbar widget spawns
    // a background uptime ticker via `tokio::spawn` during construction;
    // see `crates/heavything/src/tui/widgets/statusbar.rs:672`).
    //
    // The tests below are therefore declared `#[tokio::test]`, which
    // provisions a single-threaded runtime for each test body. The
    // statusbar's spawned task is implicitly cancelled when the runtime
    // is torn down at the end of the test (Tokio runtimes Drop-cancel
    // outstanding tasks).
    // -------------------------------------------------------------------

    static SCREEN_SETUP: Once = Once::new();

    fn ensure_screen_ready() {
        SCREEN_SETUP.call_once(|| {
            crate::screen::init_formatters().expect("screen::init_formatters");
        });
    }

    fn make_screen() -> Arc<Screen> {
        ensure_screen_ready();
        Screen::new().expect("Screen::new")
    }

    #[tokio::test]
    async fn join_then_leave_round_trip_on_unnamed_room() {
        // Unnamed (1:1) room: join two screens, leave one — room
        // should remain alive (1 user). Leave the second — room
        // becomes empty and (because unnamed) silently drops
        // (no global-map un-registration needed).
        let room = new(None, None).expect("new");
        let s1 = make_screen();
        let s2 = make_screen();

        join(&room, &s1).expect("join s1");
        join(&room, &s2).expect("join s2");
        assert_eq!(room.users_count().expect("users_count"), 2);

        leave(&room, &s1).expect("leave s1");
        assert_eq!(room.users_count().expect("users_count"), 1);

        // Last user leaves: room becomes empty. For unnamed rooms,
        // `destroy` is still called but since there's no global
        // registration, it's a no-op other than the lock dance.
        leave(&room, &s2).expect("leave s2");
        assert_eq!(room.users_count().expect("users_count"), 0);
    }

    #[tokio::test]
    async fn join_duplicate_screen_returns_error() {
        let room = new(None, None).expect("new");
        let s = make_screen();

        join(&room, &s).expect("first join");
        let res = join(&room, &s);
        assert!(res.is_err(), "duplicate join must error");
    }

    #[tokio::test]
    async fn leave_unjoined_screen_returns_error() {
        let room = new(None, None).expect("new");
        let s = make_screen();
        let res = leave(&room, &s);
        assert!(res.is_err(), "leaving an unjoined screen must error");
    }

    #[tokio::test]
    async fn empty_named_room_is_unregistered_on_last_leave() {
        ensure_initialised();
        let _g = lock_state();

        let name = "test_named_auto_destroy";
        let _ = chatrooms().write().expect("CHATROOMS").remove(name);

        let room = new(Some(name.to_string()), None).expect("new");
        let s = make_screen();
        join(&room, &s).expect("join");
        assert!(find(name).expect("find").is_some(), "must be registered");

        leave(&room, &s).expect("leave");
        assert!(
            find(name).expect("find").is_none(),
            "named room must un-register on last leave"
        );

        // Already cleaned up.
    }

    #[tokio::test]
    async fn empty_unnamed_room_is_not_in_global_map() {
        ensure_initialised();
        let _g = lock_state();

        let pre_len = chatrooms().read().expect("CHATROOMS").len();
        let room = new(None, Some("private".to_string())).expect("new");
        let post_len = chatrooms().read().expect("CHATROOMS").len();
        assert_eq!(pre_len, post_len, "unnamed rooms must not affect global map size");

        let s = make_screen();
        join(&room, &s).expect("join");
        leave(&room, &s).expect("leave");
        assert_eq!(room.users_count().expect("users_count"), 0);
        let final_len = chatrooms().read().expect("CHATROOMS").len();
        assert_eq!(
            pre_len, final_len,
            "global map size must remain unchanged across the unnamed-room lifecycle"
        );
    }

    #[tokio::test]
    async fn users_accessor_returns_live_handle() {
        let room = new(None, None).expect("new");
        let s = make_screen();
        join(&room, &s).expect("join");

        // The accessor returns a borrow of the underlying RwLock —
        // a read guard taken via the accessor must observe the
        // joined screen.
        let guard = room.users().read().expect("users read");
        assert_eq!(guard.len(), 1);
    }
}
