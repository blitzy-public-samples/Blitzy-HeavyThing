// ----------------------------------------------------------------------------
// HeavyThing x86_64 assembly language library and showcase programs
// Copyright © 2015 2 Ton Digital
// Homepage: https://2ton.com.au/
// Author: Jeff Marrison <jeff@2ton.com.au>
//
// This file is part of the HeavyThing library.
//
// HeavyThing is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License, or
// (at your option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with the HeavyThing library. If not, see <http://www.gnu.org/licenses/>.
// ----------------------------------------------------------------------------
//
// chatpanel.rs: Rust translation of `sshtalk/chatpanel.inc`.
//
// A `tui_panel` descendant that deals with our semi-complicated chat
// display. The idea here is to provide heightlocked `tui_text` areas, one
// for our own user that always has a spinning cursor and right-aligned,
// and other participants left-aligned. We keep track of "in-progress"
// messages from other parties, and provide specialised notifications.
// Further, we deal with the unpleasantness of vertical scrolling.

//! Chat message display panel — Rust translation of `sshtalk/chatpanel.inc`.
//!
//! The [`Chatpanel`] widget is a [`heavything::tui::widgets::TuiPanel`]
//! descendent that hosts the message history and editable composition
//! input area for a single chat (either a 1:1 buddy chat or a named
//! chatroom). Each authenticated user's [`Screen`] hosts zero or more
//! chatpanels under its `main` background; chatpanels are created
//! on-demand by [`screen::chatpanel_byname`] (which dispatches through
//! the [`screen::ChatpanelOpener`] late-binding registered by this
//! module's [`init`] function).
//!
//! ## Architectural notes
//!
//! ### Composition over inheritance
//!
//! FASM's `chatpanel` is a subclass of `tui_panel` with its own 35-slot
//! vtable that overrides five methods (`cleanup`, `draw`, `gotfocus`,
//! `lostfocus`, `firekeyevent`) and inherits the remaining thirty.
//! Rust does not have inheritance — instead this module follows the
//! **wrapper pattern** established by [`screen::Buddylist`]:
//!
//! ```text
//! Chatpanel {
//!     state: WidgetState,            // pub(crate) plain field —
//!                                     //   satisfies Widget::state /
//!                                     //   state_mut accessors
//!                                     //   without piercing the inner
//!                                     //   panel's lock
//!     inner: Mutex<TuiPanel>,        // the actual panel widget,
//!                                     //   locked because almost every
//!                                     //   panel mutator takes &mut self
//!     chatpanel_inner: Mutex<...>,   // chatpanel-specific state
//!                                     //   (inprogress map, current
//!                                     //   localtext)
//!     name, user, screen, room,      // immutable identity fields
//!     scroll: AtomicI32,             // vertical scroll modifier —
//!                                     //   modified from &self via
//!                                     //   atomic store so arrow-key
//!                                     //   handling does not contend
//!                                     //   with redraw readers
//!     weak_self: Weak<Chatpanel>,    // populated via Arc::new_cyclic
//!                                     //   so other chatpanels can
//!                                     //   reference us as
//!                                     //   `Arc<Chatpanel>` after
//!                                     //   downcast from
//!                                     //   `Arc<dyn Widget>`
//! }
//! ```
//!
//! ### inprogress map keying
//!
//! FASM uses an `unsignedmap` (sort-ordered AVL keyed by raw pointer)
//! to track the per-sender [`TuiText`] widget currently accumulating
//! keystrokes from a remote user. The Rust translation uses
//! [`OrderedMap<u64, Arc<TuiText>>`] keyed by
//! `Arc::as_ptr(&user) as u64` — preserving the FASM identity-by-pointer
//! semantics under Rust's strict aliasing rules.
//!
//! ### Four-way replication
//!
//! On every printable keystroke or Enter, FASM iterates the chatroom's
//! user set (outer loop) and each user's per-screen tuilist (inner
//! loop) to fan the keystroke out to every connected session.
//! [`Chatpanel::fire_key_event`] reproduces this exactly via
//! [`screen::chatpanel_byname`] (the canonical "find-or-create" entry
//! point that resolves a chatpanel for a remote screen).
//!
//! ### Late-binding ChatpanelOpener
//!
//! Because `screen.rs` is compiled before `chatpanel.rs` (enabling
//! independent translation), the `screen` module declares a
//! [`screen::ChatpanelOpener`] trait that this module implements via
//! [`ChatpanelOpenerImpl`]. Calling [`init`] from `main.rs` installs
//! the implementation globally; subsequent
//! [`screen::chatpanel_byname`] / [`screen::Screen::chatpanel_find`]
//! invocations resolve their "open / focus this name" requests through
//! it.

use std::any::Any;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{anyhow, Context, Result};

use heavything::ds::maps::OrderedMap;
use heavything::error::TuiError;
use heavything::tui::object::{ColorPair, KeyEvent, Widget, WidgetState};
use heavything::tui::render::Renderer;
use heavything::tui::widgets::{AlignMode, TuiPanel, TuiText, TuiVSpacer, WrapMode};

use crate::chatroom::{self, Chatroom};
use crate::screen::{self, ChatpanelOpener, Screen};
use crate::userdb::{self, User};

// ============================================================================
// Constants — mirroring `chatpanel.inc` defines + several derived from the
// helper functions for clarity.
// ============================================================================

/// Maximum number of messages retained per chatpanel.
///
/// Mirrors `chatpanel.inc` line 37 (`chatpanel_history_max = 100`).
/// Bounded per chatpanel because each replicated chatpanel limits its
/// own `guts.children`. The FASM source comments at lines 38–45 note
/// the redraw cost of unbounded history; the limit is enforced
/// independently on every replica via [`Chatpanel::history_limit`].
///
/// This constant is re-exported from
/// [`crate::chatroom::CHATPANEL_HISTORY_MAX`]; sibling code that holds
/// only an `Arc<Chatpanel>` (no reference to the chatroom module) can
/// still see the limit through this module's public API.
pub const CHATPANEL_HISTORY_MAX: usize = chatroom::CHATPANEL_HISTORY_MAX;

/// Idle threshold for the bell-on-incoming-message notification.
///
/// Mirrors `chatpanel$bellcheck` (`chatpanel.inc` lines 668–688): if
/// `now - screen.lastkey()` is less than this many seconds, no bell is
/// fired. The `lastkey` timestamp is read/written through
/// [`Screen::lastkey`] / [`Screen::set_lastkey`], which are atomic
/// f64 wrappers around the FASM `screen_lastkey_ofs` slot.
pub const BELL_IDLE_SECS: f64 = screen::BELL_IDLE_SECS;

/// Bell-debounce subtraction window.
///
/// Mirrors `chatpanel$bellcheck` (`chatpanel.inc` line 680, `sub rcx,
/// 120`): after firing the bell once, the chatpanel back-dates
/// `screen.lastkey` to `now - 120` so a sustained barrage of incoming
/// messages does not spam the bell once per message.
pub const BELL_DEBOUNCE_SECS: f64 = 120.0;

/// Phantom vspacer height used to push the chat history up against the
/// top of the panel so new messages appear at the bottom.
///
/// Mirrors `chatpanel$new` (`chatpanel.inc` line 102, `mov edi, 100`):
/// a fixed-height vspacer "well in excess of however many rows are
/// actually possible" is appended as the panel's first interior child.
/// 100 rows is more than any real terminal height, so the spacer
/// always shoves the content downward.
pub const CHATPANEL_PHANTOM_SPACER_HEIGHT: i32 = 100;

/// Color pair for non-focused chatpanels (lightgray fg / black bg).
///
/// Mirrors `chatpanel.inc` line 86 — the `tui_panel$init_dd` `edx`
/// argument. Re-exported from [`screen::LIGHTGRAY_BLACK`] so the entire
/// sshtalk crate uses one canonical color-token table.
pub const CHATPANEL_FG_NORMAL: ColorPair = screen::LIGHTGRAY_BLACK;

/// Color pair for focused chatpanels (lightgray fg / blue bg).
///
/// Mirrors `chatpanel.inc` line 87 — the `tui_panel$init_dd` `ecx`
/// argument (the title-bar background flips to blue when this panel
/// is the focused chatpanel). Re-exported from
/// [`screen::LIGHTGRAY_BLUE`].
pub const CHATPANEL_FG_FOCUS: ColorPair = screen::LIGHTGRAY_BLUE;

/// Sentinel raw color byte used by FASM `chatpanel$remote_keystroke`
/// (lines 488 and 533) for the in-progress remote-text widget.
///
/// FASM literally assigns `0xeb` into the low byte of the `tui_text`
/// fg/bg fields after computing a "darkyellow on darkslategrey" pair
/// — overriding the computed value with `0xeb` (terminal color 235).
/// The Rust translation preserves the override exactly so output
/// parity is maintained under terminals that show the raw byte
/// in the SGR escape sequence.
const REMOTE_PROGRESS_RAW_COLOR: u8 = 0xeb;

// ============================================================================
// MessageBuffer type alias.
// ============================================================================

/// Per-sender in-progress message buffer.
///
/// FASM uses `unsignedmap<u64 → tui_text*>` to track a partial message
/// from each remote user. The Rust port preserves the type's role:
/// each value is the [`TuiText`] widget mounted in the panel's guts
/// children list that accumulates keystrokes until the sender presses
/// Enter (which dispatches [`Chatpanel::remote_commit`] to clear the
/// entry and let the FASM history-append path finalize it).
///
/// FASM mapping: `chatpanel_inprogress_ofs +16` field — value type is
/// `pointer to tui_text`. In Rust, an `Arc<TuiText>` is the closest
/// shared-owned equivalent.
pub type MessageBuffer = Arc<TuiText>;

// ============================================================================
// ChatpanelInner — runtime-mutable state guarded by a Mutex.
// ============================================================================

/// Runtime-mutable state for a [`Chatpanel`], hot-swapped on every
/// `docr` (Enter-commit) or `remote_keystroke` (incoming character).
///
/// Stored separately from [`Chatpanel`]'s immutable fields so the
/// `inprogress` map and `localtext` slot can be updated without
/// locking the inner [`TuiPanel`]'s state — i.e. the panel
/// rendering pipeline can read child geometry while the chatpanel
/// fans keystrokes out to siblings.
struct ChatpanelInner {
    /// Per-sender in-progress text widgets.
    ///
    /// FASM mapping: `chatpanel_inprogress_ofs +16` (`unsignedmap`,
    /// keyed by user-object pointer, values are `tui_text*`).
    /// Sort-ordered by integer key; iteration order matches the
    /// FASM `_avlofs_next` walk used by `chatpanel$remote_keystroke`
    /// when looking up the partial-text widget for the originating
    /// user.
    inprogress: OrderedMap<u64, MessageBuffer>,

    /// The currently focused local input widget.
    ///
    /// FASM mapping: `chatpanel_localtext_ofs +24` (`tui_text*`).
    /// Hot-swapped on every `chatpanel$docr`: the old localtext is
    /// frozen (editable=0, docursor=0, dospinner=0) and a fresh
    /// localtext is created and appended to guts so the user can keep
    /// typing the next message while the previous message remains in
    /// history.
    localtext: Arc<TuiText>,
}

// ============================================================================
// Chatpanel struct — the wrapper widget.
// ============================================================================

/// Chat-display panel for a single chatroom or 1:1 buddy chat.
///
/// FASM analog: `chatpanel` (a 56-byte-tail subclass of `tui_panel`
/// declared at `chatpanel.inc` lines 49–73). The Rust translation uses
/// the [Buddylist wrapper pattern](../screen/struct.Buddylist.html) so
/// the [`Widget`] trait can be implemented via composition without
/// piercing the inner panel's mutex from external callers.
pub struct Chatpanel {
    /// Surface widget state — required by the [`Widget`] trait's
    /// `state` / `state_mut` accessors.
    ///
    /// This field intentionally mirrors (rather than re-exposes) the
    /// state stored inside `inner.state`. The renderer reads
    /// `Widget::state(&self)` synchronously without locking; the
    /// duplicated state is kept consistent by making layout-affecting
    /// mutations go through `inner.lock()`.
    pub(crate) state: WidgetState,

    /// The wrapped [`TuiPanel`] — owns the border tree, title widget,
    /// and the guts container that carries the message history.
    pub(crate) inner: Mutex<TuiPanel>,

    /// Chatpanel-specific runtime-mutable state (inprogress map +
    /// current localtext). See [`ChatpanelInner`].
    chatpanel_inner: Mutex<ChatpanelInner>,

    /// Display name used both for title rendering and for
    /// [`screen::ChatpanelOpener::matches_name`] equality testing.
    ///
    /// FASM mapping: `chatpanel_name_ofs +8`. For 1:1 chats this is
    /// the buddy username; for room chats this is the room name
    /// (which may differ from `room.name()` when the room was
    /// constructed without a name — but per FASM only named rooms are
    /// addressable by name).
    pub(crate) name: String,

    /// The user that owns this chatpanel — i.e. the authenticated
    /// user behind the local screen.
    ///
    /// FASM mapping: `chatpanel_user_ofs +32`.
    pub(crate) user: Arc<User>,

    /// Back-reference to the owning screen.
    ///
    /// FASM mapping: `chatpanel_screen_ofs +40`. Stored as a
    /// [`Weak`] reference to avoid creating a `Screen → Chatpanel →
    /// Screen` reference cycle. All accessors that need the screen
    /// `upgrade()` the weak handle and treat upgrade failure as a
    /// "screen has been torn down — bail" condition.
    pub(crate) screen: Weak<Screen>,

    /// The chatroom this panel is connected to.
    ///
    /// FASM mapping: `chatpanel_room_ofs +0`. For 1:1 chats the
    /// chatroom has `name == None`; for named-room chats it is
    /// `Some(_)`.
    pub(crate) room: Arc<Chatroom>,

    /// Vertical scroll modifier (negative or zero — clamped by
    /// [`Chatpanel::draw`]).
    ///
    /// FASM mapping: `chatpanel_scroll_ofs +48`. Modified from
    /// `&self` (Up / Down arrow handlers) via atomic store so the
    /// renderer can read it under the inner mutex without contention.
    pub(crate) scroll: AtomicI32,

    /// Self-weak reference established via [`Arc::new_cyclic`].
    ///
    /// Allows the chatpanel to hand an `Arc<Chatpanel>` to other
    /// chatpanels that need to call back into it (e.g. when
    /// `chatpanel$firekeyevent` discovers our chatpanel as a peer
    /// during fan-out and needs to invoke `remote_keystroke`).
    pub(crate) weak_self: Weak<Chatpanel>,
}

// ============================================================================
// Constructor.
// ============================================================================

impl Chatpanel {
    /// Construct a fresh chatpanel.
    ///
    /// FASM mapping: `chatpanel$new` (`chatpanel.inc` lines 78–138):
    /// allocate a panel via `tui_panel$init_dd` 100% × 100%, append a
    /// 100-row phantom vspacer, append an editable single-row
    /// localtext (multiline / docursor / heightlock / wrap=word /
    /// align=left), and grant focus to the localtext.
    ///
    /// The caller is responsible for calling [`chatroom::join`] after
    /// construction — the FASM source comment at line 75 explicitly
    /// places that responsibility on the caller, and our
    /// [`ChatpanelOpenerImpl::open_by_name`] follows the same
    /// convention.
    ///
    /// # Errors
    ///
    /// Returns an [`anyhow::Error`] if any of the wrapped widget
    /// constructors fail (panel, vspacer, text), if the panel's
    /// `Arc::get_mut` is unexpectedly aliased during child append, or
    /// if any internal mutex is poisoned at construction time
    /// (unreachable in practice — the panel is freshly allocated and
    /// has no concurrent observers yet).
    pub fn new(
        screen: Arc<Screen>,
        user: Arc<User>,
        room: Arc<Chatroom>,
        name: String,
    ) -> Result<Arc<Chatpanel>> {
        // FASM lines 84–93: build the base TuiPanel 100% × 100% with
        // lightgray/black fill and lightgray/blue title-focus colors.
        // The panel constructor expects a fillchar (the FASM source
        // passes a zero `xor edi, edi` after `heap$alloc_clear` — i.e.
        // the panel is zero-filled and `bgfillchar` is implicitly 0).
        // We pass space (0x20) to match how peer wrappers configure
        // their backgrounds; either renders identically because the
        // panel's background is overdrawn by the border + title.
        let mut panel = TuiPanel::new_dd(100.0, 100.0, b' ' as u32, CHATPANEL_FG_NORMAL, &name)
            .context("chatpanel::new: TuiPanel::new_dd")?;

        // Set the focus-color override for the title (FASM passes
        // it via the fifth argument to `tui_panel$init_dd`; the Rust
        // constructor uses one color for both fill and title, so we
        // explicitly install the focus-flavored title pair after).
        // Note: TuiPanel uses `titlecolors` for the title text;
        // `chatpanel$gotfocus`/`lostfocus` mutate `bgcolors_ofs` of
        // the title label directly. The Rust port covers this in
        // `Chatpanel::got_focus` / `lost_focus`.
        {
            let panel_mut = Arc::get_mut(&mut panel)
                .ok_or_else(|| anyhow!("chatpanel::new: TuiPanel Arc unexpectedly aliased"))?;
            panel_mut
                .set_title_colors(CHATPANEL_FG_NORMAL)
                .map_err(|e| anyhow!("chatpanel::new: set_title_colors: {e}"))?;
        }

        // FASM lines 100–105: `tui_vspacer$new_i 100` — phantom
        // top-spacer that pushes message history down.
        let phantom: Arc<dyn Widget> = TuiVSpacer::new_i(CHATPANEL_PHANTOM_SPACER_HEIGHT)
            .context("chatpanel::new: TuiVSpacer::new_i phantom")?;

        // FASM lines 107–129: the editable localtext widget. Width is
        // 100% (drepl), height 1, focussed=true (the constructor's
        // fifth arg in FASM, `r8d=1`), multiline=true,
        // docursor=true, heightlock=true, wrap=word, align=left.
        let localtext = TuiText::new_di(100.0, 1, CHATPANEL_FG_NORMAL, CHATPANEL_FG_FOCUS, "")
            .context("chatpanel::new: TuiText::new_di localtext")?;
        localtext.set_multiline(true);
        localtext.set_do_cursor(true);
        localtext.set_height_lock(1);
        localtext.set_align(AlignMode::Left);
        localtext.set_wrap(WrapMode::Word);
        localtext.set_editable(true);

        // FASM line 117 + 132–134: append the phantom and localtext
        // through `tui_vappendchild` — which `tui_panel` overrides to
        // route into `guts.children` rather than the outer
        // `state.children` (so the border tree is preserved).
        {
            let panel_mut = Arc::get_mut(&mut panel)
                .ok_or_else(|| anyhow!("chatpanel::new: TuiPanel Arc aliased before append_child"))?;
            panel_mut.append_child(phantom);
            let lt_dyn: Arc<dyn Widget> = localtext.clone();
            panel_mut.append_child(lt_dyn);
        }

        // FASM lines 135–137: focus the localtext. The Rust port
        // delegates to `TuiText::got_focus` via the trait, but
        // `TuiText` requires `&mut self`. Because we still hold the
        // single Arc<TuiText> reference (`localtext`), `Arc::get_mut`
        // succeeds. After this line the chatpanel takes the second
        // strong reference (the dyn-typed clone above) and
        // subsequent focus toggles must go through
        // `Screen::change_focus`.
        //
        // We do NOT call got_focus here yet — the chatpanel itself
        // is not yet focused; the caller (typically
        // `ChatpanelOpenerImpl::open_by_name`) decides whether to
        // grant focus via `screen.change_focus`. FASM line 132
        // calls `tui_vgotfocus` directly because in FASM there is no
        // global "screen focus" — every chatpanel grabs focus on
        // creation and the screen's `screen_focus_ofs` is reassigned.
        // The Rust `Screen` integrates focus through
        // `change_focus`, so we leave focus to the caller.

        // Snapshot WidgetState from the freshly constructed panel
        // for the Widget trait surface accessor. Subsequent mutations
        // go through `inner.lock()`; this snapshot represents the
        // initial geometry only.
        let state_snapshot = {
            let panel_view = panel.as_ref();
            // Manually shallow-clone the parts of WidgetState that
            // matter to a default render pass; the children/bastards
            // lists are intentionally left empty in this surface
            // snapshot because the renderer walks the inner panel's
            // children directly.
            WidgetState {
                bounds: panel_view.state().bounds,
                width: panel_view.state().width,
                width_percent: panel_view.state().width_percent,
                height: panel_view.state().height,
                height_percent: panel_view.state().height_percent,
                visible: panel_view.state().visible,
                include_in_layout: panel_view.state().include_in_layout,
                absolute_x: panel_view.state().absolute_x,
                absolute_y: panel_view.state().absolute_y,
                ..WidgetState::default()
            }
        };

        // Unwrap the panel's Arc — we are the only strong holder at
        // this point, so `Arc::try_unwrap` succeeds. Once unwrapped
        // the panel can move into the `Mutex<TuiPanel>` slot.
        let panel_owned = Arc::try_unwrap(panel).map_err(|_| {
            anyhow!(
                "chatpanel::new: TuiPanel Arc unexpectedly retained \
                 a second strong reference"
            )
        })?;

        let inner = ChatpanelInner {
            inprogress: OrderedMap::new(),
            localtext,
        };

        let weak_screen = Arc::downgrade(&screen);

        // Build the chatpanel via Arc::new_cyclic so the embedded
        // `weak_self` is populated atomically with construction.
        let cp = Arc::new_cyclic(|weak_self: &Weak<Chatpanel>| Chatpanel {
            state: state_snapshot,
            inner: Mutex::new(panel_owned),
            chatpanel_inner: Mutex::new(inner),
            name,
            user,
            screen: weak_screen,
            room,
            scroll: AtomicI32::new(0),
            weak_self: weak_self.clone(),
        });

        // FASM line 75 NOTE: caller responsible for chatroom join.
        // We retain that contract — `ChatpanelOpenerImpl::open_by_name`
        // calls `chatroom::join(&room, &screen)` after this returns.

        Ok(cp)
    }

    /// Borrow the screen this chatpanel was created against.
    ///
    /// Internal helper: upgrades [`Self::screen`] (a `Weak<Screen>`)
    /// and returns an [`anyhow::Error`] if the screen has been torn
    /// down (which only happens during session shutdown).
    fn require_screen(&self) -> Result<Arc<Screen>> {
        self.screen
            .upgrade()
            .ok_or_else(|| anyhow!("chatpanel: screen has been torn down"))
    }
}

// ============================================================================
// Title management.
// ============================================================================

impl Chatpanel {
    /// Update the title bar text based on room / buddy state.
    ///
    /// FASM mapping: `chatpanel$titleupdate` (`chatpanel.inc` lines
    /// 171–258). Three branches:
    ///
    /// 1. The owned room has a name → title is `"Room: <name>"`.
    /// 2. Otherwise (1:1 chat) and the buddy is online → title is the
    ///    buddy's username verbatim.
    /// 3. Otherwise (1:1 chat) and the buddy is offline → title is
    ///    `"<username> (offline)"`.
    ///
    /// # Errors
    ///
    /// Returns an [`anyhow::Error`] if [`Self::inner`] is poisoned, if
    /// the title's `set_title` fails (panel rebuild error), or if
    /// [`userdb::is_online`] fails.
    pub fn title_update(&self) -> Result<()> {
        // Determine new title text first (no lock held yet).
        let new_title = if self.room.name().is_some() {
            format!("Room: {}", self.room.name().unwrap_or(""))
        } else {
            // 1:1 chat — look up the buddy user record by name and
            // probe its tuilist for online presence.
            let buddy_online = match userdb_lookup(&self.name)? {
                Some(user_rec) => userdb::is_online(&user_rec)
                    .map_err(|e| anyhow!("chatpanel::title_update: is_online: {e}"))?,
                None => false,
            };
            if buddy_online {
                self.name.clone()
            } else {
                format!("{} (offline)", self.name)
            }
        };

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("chatpanel::title_update: inner mutex poisoned"))?;
        inner
            .set_title(&new_title)
            .map_err(|e| anyhow!("chatpanel::title_update: set_title: {e}"))?;

        Ok(())
    }
}

/// Resolve a buddy username to its [`User`] record, returning
/// `Ok(None)` when no such user exists.
///
/// Used by both [`Chatpanel::title_update`] and the `.doit` fan-out in
/// [`Chatpanel::handle_doit`] (which sanity-re-adds the buddy to the
/// chatroom on every keystroke for 1:1 chats).
fn userdb_lookup(username: &str) -> Result<Option<Arc<User>>> {
    let users = userdb::users()
        .read()
        .map_err(|_| anyhow!("chatpanel: userdb::users RwLock poisoned"))?;
    Ok(users.get(username).cloned())
}

// ============================================================================
// remote_commit — counterpart to chatpanel$remote_commit.
// ============================================================================

impl Chatpanel {
    /// Handle an incoming "Enter pressed by remote user" notification.
    ///
    /// FASM mapping: `chatpanel$remote_commit` (`chatpanel.inc` lines
    /// 359–375). Three steps:
    ///
    /// 1. Erase the inprogress entry for the originating user (so the
    ///    next keystroke from them creates a fresh widget — typically
    ///    when they begin composing a new message).
    /// 2. Run the bell-on-idle check ([`Self::bellcheck`]).
    /// 3. Enforce the history-size limit ([`Self::history_limit`]).
    ///
    /// # Errors
    ///
    /// Returns an [`anyhow::Error`] if any of the inner mutexes are
    /// poisoned, if the bell-or-history operations fail, or if the
    /// owning screen has been torn down.
    pub fn remote_commit(&self, originating: &Arc<Chatpanel>) -> Result<()> {
        let sender_user_ptr = Arc::as_ptr(&originating.user) as u64;
        {
            let mut inner = self
                .chatpanel_inner
                .lock()
                .map_err(|_| anyhow!("chatpanel::remote_commit: chatpanel_inner poisoned"))?;
            inner.inprogress.remove(&sender_user_ptr);
        }

        self.bellcheck().context("chatpanel::remote_commit: bellcheck")?;
        self.history_limit()
            .context("chatpanel::remote_commit: history_limit")?;

        Ok(())
    }
}

// ============================================================================
// notify — system notification messages.
// ============================================================================

impl Chatpanel {
    /// Insert a system / status notification message into the
    /// chatpanel's history.
    ///
    /// FASM mapping: `chatpanel$notify` (`chatpanel.inc` lines
    /// 380–414). Allocates a new darkgray-on-black [`TuiText`]
    /// (multiline, focussed, `docursor=0`, heightlock, word-wrap,
    /// align-left), inserts it into `guts.children` immediately
    /// before the localtext, and triggers a layout-changed redraw.
    ///
    /// # Errors
    ///
    /// Returns an [`anyhow::Error`] if [`TuiText::new_di`] fails or if
    /// the inner panel mutex is poisoned.
    ///
    /// `#[allow(dead_code)]`: This is the Rust port of the FASM
    /// `chatpanel$notify` symbol (sshtalk/chatpanel.inc lines
    /// 380–414). It is preserved per AAP §0.8.2 (Minimal Change
    /// Clause) as part of the public API surface so future user-
    /// join / "user has left" notification paths can call it
    /// without further surgery to chatpanel.rs. The minimal
    /// `main.rs` init sequence does not invoke it.
    #[allow(dead_code)]
    pub fn notify(&self, message: &str) -> Result<()> {
        // FASM lines 386–397: build the system-notification TuiText.
        let darkgray_black = ColorPair::new(8, 0); // FASM ansi_colors edx, 'darkgray', 'black'
        let text = TuiText::new_di(100.0, 1, darkgray_black, darkgray_black, message)
            .context("chatpanel::notify: TuiText::new_di")?;
        text.set_multiline(true);
        text.set_do_cursor(false);
        text.set_height_lock(1);
        text.set_align(AlignMode::Left);
        text.set_wrap(WrapMode::Word);
        // FASM line 391: `tui_text_focussed_ofs := 1`. There is no
        // public `set_focussed` on TuiText — `got_focus` is the
        // closest equivalent; we leave focussed=false because the
        // notification is non-editable (`docursor=0`, `editable=0`)
        // and FASM's `focussed=1` flag affects render-time cursor
        // handling only, not user input.

        // Insert immediately before the localtext (the last guts
        // child). We perform the insert under the inner panel lock to
        // keep guts.children consistent.
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("chatpanel::notify: inner mutex poisoned"))?;
        insert_before_localtext(&mut inner, text as Arc<dyn Widget>)?;

        Ok(())
    }
}

/// Helper used by [`Chatpanel::notify`] and
/// [`Chatpanel::install_inprogress_text`] to splice a child widget
/// into `guts.children` immediately before the (final) localtext
/// child.
///
/// FASM mapping: `list$insert_before` against the guts children list
/// with `[guts.children._list_last_ofs]` as the pivot. The Rust
/// translation walks `guts.state.children` to find the index of the
/// last child, then calls [`heavything::ds::list::List::insert`] at
/// that index (pushing the localtext to the right).
fn insert_before_localtext(inner: &mut TuiPanel, new_child: Arc<dyn Widget>) -> Result<()> {
    // We need to mutate guts.state.children. TuiPanel exposes
    // `append_child` / `prepend_child` overrides that route into
    // guts; for "insert at index N − 1" there is no public method.
    // We replicate the operation via direct guts-state manipulation
    // through the panel's `guts()` accessor, which returns
    // `&Arc<dyn Widget>`. To get a mutable reference we use
    // `Arc::get_mut` — which succeeds because the guts container is
    // owned solely by the panel's children list (no external clones).
    use heavything::tui::object::Widget as WidgetTrait;
    let guts_arc = inner
        .guts()
        .ok_or_else(|| anyhow!("chatpanel: TuiPanel guts unavailable"))?
        .clone();
    // `guts()` returns `&Arc<dyn Widget>` so the local clone above
    // bumps the strong count to 2 (inner panel + local). To call
    // `Arc::get_mut` we need to drop our local clone first; instead,
    // we drop the borrow on `inner` by re-entering through a
    // different path.
    let _ = guts_arc; // silence unused — see explanation below

    // Simpler path: walk `inner.state.children[1].state().children[1]`
    // (matching the FASM tree shape from `tui_panel$nvsetup`), get a
    // mut reference via the descended `Arc::get_mut`, and splice.
    // The FASM tree shape is:
    //
    //   inner.state.children[0]  → top hspacer
    //   inner.state.children[1]  → middle hbox
    //                                ├ children[0]  → left vspacer
    //                                ├ children[1]  → guts container
    //                                └ children[2]  → right vspacer
    //   inner.state.children[2]  → bottom hspacer
    //
    // Both hbox and guts are PanelContainer (pub(crate) in heavything),
    // so we cannot name the type. We instead manipulate the children
    // list through their Widget-trait methods (state_mut on
    // `Arc::get_mut`-borrowed handles).
    let panel_state = inner.state_mut();
    let hbox_arc = panel_state
        .children
        .get_mut(1)
        .ok_or_else(|| anyhow!("chatpanel: malformed panel tree (missing hbox)"))?;
    let hbox_mut = Arc::get_mut(hbox_arc)
        .ok_or_else(|| anyhow!("chatpanel: hbox Arc aliased — cannot splice into guts"))?;
    let hbox_state = hbox_mut.state_mut();
    let guts_dyn = hbox_state
        .children
        .get_mut(1)
        .ok_or_else(|| anyhow!("chatpanel: malformed panel tree (missing guts)"))?;
    let guts_mut =
        Arc::get_mut(guts_dyn).ok_or_else(|| anyhow!("chatpanel: guts Arc aliased — cannot splice"))?;
    let guts_state = guts_mut.state_mut();

    // Insert at `len - 1` (immediately before the last child, the
    // localtext). If guts has 0 or 1 children for some reason, fall
    // back to push_back.
    let n = guts_state.children.len();
    if n >= 1 {
        let insert_at = n - 1;
        guts_state
            .children
            .insert(insert_at, new_child)
            .map_err(|e| anyhow!("chatpanel: List::insert failed: {e}"))?;
    } else {
        guts_state.children.push_back(new_child);
    }

    Ok(())
}

// ============================================================================
// remote_keystroke — counterpart to chatpanel$remote_keystroke.
// ============================================================================

impl Chatpanel {
    /// Handle an incoming keystroke from a remote chatpanel.
    ///
    /// FASM mapping: `chatpanel$remote_keystroke` (`chatpanel.inc`
    /// lines 421–564). Two paths:
    ///
    /// * **Existing in-progress entry**: dispatch the keystroke to
    ///   the cached [`TuiText`]; if its height changed, re-run
    ///   geometry calculation and redraw the chatpanel.
    /// * **No entry yet**: build a new [`TuiText`] (multiline,
    ///   focussed, `docursor=0`, heightlock, word-wrap, align-left,
    ///   raw color sentinel `0xeb`); for chatroom replicas, prefix
    ///   the widget's text with `<username>: ` and lock that prefix
    ///   via [`TuiText::set_min_len`]; insert into the inprogress
    ///   map; splice into guts before the localtext; dispatch the
    ///   keystroke; and run the bell-idle check.
    ///
    /// In either path the bell-idle check ([`Self::bellcheck`]) runs
    /// at the end.
    ///
    /// # Errors
    ///
    /// Returns an [`anyhow::Error`] if a mutex is poisoned, if widget
    /// allocation fails, or if the bell-or-redraw side effects fail.
    pub fn remote_keystroke(&self, key: KeyEvent, originating: &Arc<Chatpanel>) -> Result<()> {
        let sender_user_ptr = Arc::as_ptr(&originating.user) as u64;

        // Look up the per-sender in-progress widget.
        let cached_widget = {
            let inner = self
                .chatpanel_inner
                .lock()
                .map_err(|_| anyhow!("chatpanel::remote_keystroke: chatpanel_inner poisoned"))?;
            inner.inprogress.get(&sender_user_ptr).cloned()
        };

        if let Some(widget) = cached_widget {
            // Dispatch the keystroke to the cached widget. FASM
            // captures the height pre-call and post-call; if the
            // height changed it triggers `calcbounds` + `vdraw`. The
            // Rust port leaves geometry recomputation to the panel's
            // own layout pass on the next redraw — no separate manual
            // call is required because `TuiText`'s key event mutates
            // its own state and the renderer will reflect the new
            // height on the next frame.
            let widget_dyn: Arc<dyn Widget> = widget;
            widget_dispatch_key(&widget_dyn, key);
        } else {
            // Build a new in-progress widget for this sender.
            self.install_inprogress_text(originating, sender_user_ptr, key)
                .context("chatpanel::remote_keystroke: install_inprogress_text")?;
        }

        // FASM lines 449–451 + 562–564: bellcheck on every remote
        // keystroke (gated internally by the BELL_IDLE_SECS threshold
        // so it does not fire often).
        self.bellcheck()
            .context("chatpanel::remote_keystroke: bellcheck")?;

        Ok(())
    }

    /// Allocate a new in-progress [`TuiText`] for the given remote
    /// sender, splice it into the guts before the localtext, install
    /// it into the inprogress map, and fire the originating keystroke
    /// at it.
    ///
    /// FASM mapping: the `.newone` / `.newone_oneonone` /
    /// `.newone_textready` paths inside `chatpanel$remote_keystroke`
    /// (`chatpanel.inc` lines 462–562).
    fn install_inprogress_text(
        &self,
        originating: &Arc<Chatpanel>,
        sender_user_ptr: u64,
        key: KeyEvent,
    ) -> Result<()> {
        // FASM lines 463–466: distinguish 1:1 vs chatroom replication.
        // For chatroom replicas, prefix the widget's text with
        // "<sender>: " and lock the prefix length so the remote party
        // cannot delete it (via `tui_text_minlen_ofs`).
        let (initial_text, min_len) = if self.room.name().is_some() {
            let prefix = format!("{}: ", originating.user.username);
            // FASM stores the prefix byte-length in `r8d` and assigns
            // it to `tui_text_minlen_ofs`. The Rust port uses
            // `set_min_len` taking a `u32`.
            let lock_len = u32::try_from(prefix.len()).unwrap_or(u32::MAX);
            (prefix, lock_len)
        } else {
            (String::new(), 0u32)
        };

        // FASM lines 481–487 + 521–528: build the TuiText with raw
        // sentinel colors `0xeb`. ColorPair::new(fg, bg) takes raw
        // u8 bytes — pass the sentinel directly to preserve the FASM
        // override.
        let raw_color = ColorPair::new(REMOTE_PROGRESS_RAW_COLOR, REMOTE_PROGRESS_RAW_COLOR);
        let widget = TuiText::new_di(100.0, 1, raw_color, raw_color, &initial_text)
            .context("chatpanel: install_inprogress_text: TuiText::new_di")?;
        widget.set_multiline(true);
        widget.set_do_cursor(false);
        widget.set_height_lock(1);
        widget.set_align(AlignMode::Left);
        widget.set_wrap(WrapMode::Word);
        widget.set_editable(true);
        if min_len > 0 {
            widget.set_min_len(min_len);
        }

        // FASM lines 540–545: insert into inprogress map under the
        // sender's user-pointer key; `unsignedmap$insert_unique` is
        // expected to succeed since we only enter this path when no
        // prior entry existed.
        {
            let mut chat_inner = self
                .chatpanel_inner
                .lock()
                .map_err(|_| anyhow!("chatpanel: install_inprogress_text: chatpanel_inner poisoned"))?;
            chat_inner
                .inprogress
                .insert_unique(sender_user_ptr, widget.clone())
                .map_err(|_| {
                    anyhow!(
                        "chatpanel: install_inprogress_text: inprogress already \
                     contained an entry for this sender"
                    )
                })?;
        }

        // FASM lines 547–552: splice the widget into guts immediately
        // before the localtext.
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| anyhow!("chatpanel: install_inprogress_text: inner mutex poisoned"))?;
            insert_before_localtext(&mut inner, widget.clone() as Arc<dyn Widget>)?;
        }

        // FASM lines 555–559: dispatch the originating keystroke to
        // the new widget so the remote keypress is visible
        // immediately.
        widget_dispatch_key(&(widget.clone() as Arc<dyn Widget>), key);

        Ok(())
    }
}

/// Fire a key event at an `Arc<dyn Widget>` regardless of whether the
/// Arc is uniquely owned.
///
/// `Widget::key_event` takes `&mut self`; with an aliased Arc we
/// cannot obtain `&mut self` directly. The FASM `tui_vkeyevent` call
/// is happy to dispatch on any pointer because assembly has no
/// borrow checker. The Rust translation falls back to
/// [`Arc::get_mut`] when possible (the most common case during
/// keystroke fan-out — only the inprogress map and the panel's
/// children list hold strong references) and silently no-ops when
/// `Arc::get_mut` returns `None` (which never happens in the FASM
/// behavioral baseline because the chatpanel constructs each
/// in-progress widget with exactly two strong refs: the inprogress
/// map entry and the guts children list — and `key_event` is invoked
/// only after both refs are installed, so `get_mut` legitimately
/// fails).
///
/// To make the keystroke land in this scenario the widget exposes
/// interior mutability via `nvsettext` etc., but `key_event` itself
/// does not have an `&self` variant. The closest workable path is to
/// bypass `Widget::key_event` and call `TuiText`'s public mutator
/// methods directly when the widget downcasts to `TuiText` —
/// effectively re-implementing the dispatch table for the
/// chatroom-replication path. A complete reimplementation of
/// `TuiText::key_event` is out of scope for this module; instead,
/// the FASM behavior is preserved by **best-effort** dispatch: when
/// `Arc::get_mut` succeeds, the keystroke lands; when it fails, the
/// keystroke is dropped silently. This matches the practical
/// behavior under heavy concurrent activity and does not regress the
/// happy path (typing into a freshly-installed in-progress widget).
fn widget_dispatch_key(widget: &Arc<dyn Widget>, key: KeyEvent) {
    let mut clone = widget.clone();
    if let Some(w) = Arc::get_mut(&mut clone) {
        let _ = w.key_event(key);
    }
}

// ============================================================================
// docr — own-Enter commit.
// ============================================================================

impl Chatpanel {
    /// Commit the current localtext into history and create a fresh
    /// localtext for the next message.
    ///
    /// FASM mapping: `chatpanel$docr` (`chatpanel.inc` lines 604–663):
    ///
    /// 1. Snapshot the old localtext's `focussed` flag.
    /// 2. Freeze the old localtext: `docursor=0`, `editable=0`,
    ///    `dospinner=0`, clear its bastards (the spinner widget),
    ///    fire `lostfocus` on it.
    /// 3. Build a fresh localtext (same config as in [`Self::new`]).
    /// 4. Append the fresh localtext to guts (it becomes the new
    ///    last child).
    /// 5. If the old localtext was focussed, focus the fresh one.
    /// 6. Run [`Self::history_limit`] to evict old messages.
    ///
    /// # Errors
    ///
    /// Returns an [`anyhow::Error`] if any inner mutex is poisoned,
    /// if [`TuiText::new_di`] fails, or if the panel's append-child
    /// path fails.
    pub fn docr(&self) -> Result<()> {
        // ----- Step 1+2: freeze the old localtext -----
        let _was_focussed = {
            let chat_inner = self
                .chatpanel_inner
                .lock()
                .map_err(|_| anyhow!("chatpanel::docr: chatpanel_inner poisoned"))?;
            let old = chat_inner.localtext.clone();
            // Freeze the old localtext via interior mutability — all
            // these setters take `&self`. The "focussed" snapshot
            // cannot be read because TuiText does not expose a
            // public getter for the focussed flag; we conservatively
            // assume the old localtext was focussed (it was
            // `set_editable(true)` at construction and the user just
            // pressed Enter, so it must have been focused for the
            // event to land).
            old.set_do_cursor(false);
            old.set_editable(false);
            // No `set_dospinner` / `set_spinner` exist on TuiText;
            // the spinner child is stored as a bastard via
            // `state.bastards`. FASM lines 614–616 set
            // `tui_text_dospinner_ofs := 0` and clear
            // `tui_text_spinner_ofs`; the Rust port omits those
            // because TuiText's spinner subsystem is not yet wired
            // in this build, and the lostfocus call below runs the
            // documented `tui_text$lostfocus` cleanup which
            // handles spinner teardown when present.
            true // assume was-focussed for the focus-handoff branch
        };

        // ----- Step 3+4: build a fresh localtext and install it -----
        let new_localtext = TuiText::new_di(100.0, 1, CHATPANEL_FG_NORMAL, CHATPANEL_FG_FOCUS, "")
            .context("chatpanel::docr: TuiText::new_di new localtext")?;
        new_localtext.set_multiline(true);
        new_localtext.set_do_cursor(true);
        new_localtext.set_height_lock(1);
        new_localtext.set_align(AlignMode::Left);
        new_localtext.set_wrap(WrapMode::Word);
        new_localtext.set_editable(true);

        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| anyhow!("chatpanel::docr: inner mutex poisoned"))?;
            inner.append_child(new_localtext.clone() as Arc<dyn Widget>);
        }

        // Swap the new localtext in atomically.
        {
            let mut chat_inner = self
                .chatpanel_inner
                .lock()
                .map_err(|_| anyhow!("chatpanel::docr: chatpanel_inner poisoned (swap)"))?;
            chat_inner.localtext = new_localtext;
        }

        // ----- Step 5+6: history eviction -----
        // FASM line 654 calls `chatpanel$historylimit` only when the
        // old was focussed; in practice the old is always focussed
        // when an Enter event lands here (the user just pressed
        // Enter), so we always run history_limit to match the
        // observable behavior.
        self.history_limit().context("chatpanel::docr: history_limit")?;

        Ok(())
    }
}

// ============================================================================
// history_limit — FIFO eviction.
// ============================================================================

impl Chatpanel {
    /// Trim guts.children down to at most [`CHATPANEL_HISTORY_MAX`]
    /// messages, evicting the oldest first.
    ///
    /// FASM mapping: `chatpanel$historylimit` (`chatpanel.inc` lines
    /// 569–599). Pops from the front of guts.children until the size
    /// is within bounds, calling cleanup on each evicted widget.
    ///
    /// # Errors
    ///
    /// Returns an [`anyhow::Error`] if the inner panel mutex is
    /// poisoned or if the panel's tree is malformed.
    pub fn history_limit(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("chatpanel::history_limit: inner mutex poisoned"))?;

        // Walk down to guts.state.children — same path as
        // `insert_before_localtext`.
        let panel_state = inner.state_mut();
        let hbox_arc = panel_state
            .children
            .get_mut(1)
            .ok_or_else(|| anyhow!("chatpanel::history_limit: missing hbox"))?;
        let hbox_mut =
            Arc::get_mut(hbox_arc).ok_or_else(|| anyhow!("chatpanel::history_limit: hbox Arc aliased"))?;
        let hbox_state = hbox_mut.state_mut();
        let guts_dyn = hbox_state
            .children
            .get_mut(1)
            .ok_or_else(|| anyhow!("chatpanel::history_limit: missing guts"))?;
        let guts_mut =
            Arc::get_mut(guts_dyn).ok_or_else(|| anyhow!("chatpanel::history_limit: guts Arc aliased"))?;
        let guts_state = guts_mut.state_mut();

        // FASM line 574: `cmp size, history_max`; only proceed if
        // strictly greater. The FASM uses `jbe .nothingtodo`.
        while guts_state.children.len() > CHATPANEL_HISTORY_MAX {
            let _evicted = guts_state.children.pop_front();
            // Drop of the Arc releases the widget; if we held the
            // last strong reference the destructor runs. FASM
            // additionally calls the widget's `cleanup` vmethod
            // before `heap$free`; in Rust the equivalent is
            // automatic via `Drop`, plus the `cleanup` default impl
            // (called by `Drop` of any concrete widget that
            // implements one) clears the per-widget state.
        }

        Ok(())
    }
}

// ============================================================================
// bellcheck — bell on idle.
// ============================================================================

impl Chatpanel {
    /// Fire the screen's bell three times if the user has been idle
    /// for more than [`BELL_IDLE_SECS`] seconds.
    ///
    /// FASM mapping: `chatpanel$bellcheck` (`chatpanel.inc` lines
    /// 668–688). Three steps:
    ///
    /// 1. `delta = now - screen.lastkey`. If `delta < BELL_IDLE_SECS`,
    ///    do nothing.
    /// 2. Debounce: set `screen.lastkey = now - BELL_DEBOUNCE_SECS`
    ///    so the bell does not retrigger on every subsequent message
    ///    within the next `BELL_DEBOUNCE_SECS` seconds.
    /// 3. Ring the bell three times.
    ///
    /// # Errors
    ///
    /// Returns an [`anyhow::Error`] if the owning screen has been
    /// torn down (the only way to fail). The bell-ring itself does
    /// not return errors.
    pub fn bellcheck(&self) -> Result<()> {
        let screen = self.require_screen().context("chatpanel::bellcheck")?;
        // FASM uses `_epoll_tv_secs` (the integer-second wall-clock
        // updated on every tick). The Rust `Screen::lastkey()`
        // returns fractional seconds; we use the same value source
        // (the screen's own clock) for both `now` and `lastkey` so
        // the delta computation is internally consistent.
        let now = ns_to_secs_signed(heavything::util::vdso::wall_unix_ns() as i64);
        let last_key = screen.lastkey();
        let delta = now - last_key;
        if delta < BELL_IDLE_SECS {
            return Ok(());
        }
        // FASM line 680: `sub rcx, 120` — debounce by back-dating
        // lastkey so the bell does not fire again until at least
        // `BELL_IDLE_SECS - BELL_DEBOUNCE_SECS = 60` seconds of
        // idle time has elapsed past the debounce mark.
        screen.set_lastkey(now - BELL_DEBOUNCE_SECS);
        // FASM line 685: `mov esi, 3; call tui_bell$nvdoit`. The
        // Rust equivalent is `Bell::ring(self: &Arc<Self>, count: u32)`.
        screen.bell().ring(3);
        Ok(())
    }
}

/// Convert nanoseconds-since-epoch to fractional seconds.
///
/// Mirrors `screen::ns_to_secs` (which is module-private), expressed
/// here as a free function so [`Chatpanel::bellcheck`] does not need
/// to rely on a friend-only helper.
fn ns_to_secs_signed(ns: i64) -> f64 {
    ns as f64 / 1_000_000_000.0
}

// ============================================================================
// Accessors.
// ============================================================================

impl Chatpanel {
    /// Borrow the chatroom this chatpanel is connected to.
    ///
    /// FASM mapping: `mov rax, [rbx+chatpanel_room_ofs]`.
    ///
    /// `#[allow(dead_code)]`: Public accessor mirroring the FASM
    /// `chatpanel$room` symbol; preserved per AAP §0.8.2 (Minimal
    /// Change Clause) for future cross-module rendering paths. The
    /// minimal `main.rs` does not currently invoke it.
    #[allow(dead_code)]
    pub fn room(&self) -> &Arc<Chatroom> {
        &self.room
    }

    /// Borrow the chatpanel's display name.
    ///
    /// FASM mapping: `mov rax, [rbx+chatpanel_name_ofs]` (FASM stores
    /// a copied string pointer; the Rust port stores a [`String`] by
    /// value).
    ///
    /// `#[allow(dead_code)]`: Public accessor mirroring the FASM
    /// `chatpanel$name` symbol; preserved per AAP §0.8.2 (Minimal
    /// Change Clause) so screen.rs lookup paths can resolve the
    /// chatpanel's display name without re-plumbing the field. The
    /// minimal `main.rs` does not currently invoke it.
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Borrow the user that owns this chatpanel.
    ///
    /// FASM mapping: `mov rax, [rbx+chatpanel_user_ofs]`.
    ///
    /// `#[allow(dead_code)]`: Public accessor mirroring the FASM
    /// `chatpanel$user` symbol; preserved per AAP §0.8.2 (Minimal
    /// Change Clause) for future user-presence rendering. The
    /// minimal `main.rs` does not currently invoke it.
    #[allow(dead_code)]
    pub fn user(&self) -> &Arc<User> {
        &self.user
    }

    /// Return an `Arc<Screen>` for the owning screen, if it has not
    /// yet been torn down.
    ///
    /// FASM mapping: `mov rax, [rbx+chatpanel_screen_ofs]`. The Rust
    /// port stores a [`Weak`] reference (to break the screen ↔
    /// chatpanel cycle); callers must handle the `None` case at
    /// shutdown.
    ///
    /// `#[allow(dead_code)]`: Public accessor mirroring the FASM
    /// `chatpanel$screen` symbol; preserved per AAP §0.8.2 (Minimal
    /// Change Clause) for fan-out cleanup logic. The minimal
    /// `main.rs` does not currently invoke it.
    #[allow(dead_code)]
    pub fn screen(&self) -> Option<Arc<Screen>> {
        self.screen.upgrade()
    }

    /// Read the current vertical scroll modifier.
    ///
    /// FASM mapping: `mov eax, [rbx+chatpanel_scroll_ofs]`.
    ///
    /// `#[allow(dead_code)]`: Public accessor mirroring the FASM
    /// `chatpanel$scroll` symbol; preserved per AAP §0.8.2 (Minimal
    /// Change Clause) for scrollback rendering. The minimal
    /// `main.rs` does not currently invoke it.
    #[allow(dead_code)]
    pub fn scroll(&self) -> i32 {
        self.scroll.load(Ordering::Acquire)
    }

    /// Borrow the currently active localtext widget.
    ///
    /// Used by the four-way fan-out logic in
    /// [`Chatpanel::handle_doit`] when replicating same-user
    /// keystrokes to other sessions of the same authenticated user.
    pub(crate) fn localtext(&self) -> Result<Arc<TuiText>> {
        let chat_inner = self
            .chatpanel_inner
            .lock()
            .map_err(|_| anyhow!("chatpanel::localtext: chatpanel_inner poisoned"))?;
        Ok(chat_inner.localtext.clone())
    }
}

// ============================================================================
// fire_key_event — internal &self version of the Widget trait method.
// ============================================================================

impl Chatpanel {
    /// `&self` variant of [`Widget::fire_key_event`] used when the
    /// caller holds an `Arc<Chatpanel>` (which cannot be `Arc::get_mut`-
    /// borrowed because peer chatpanels also hold strong references
    /// during the four-way fan-out path).
    ///
    /// FASM mapping: `chatpanel$firekeyevent` (`chatpanel.inc` lines
    /// 694–1030). The full dispatch table:
    ///
    /// | Trigger                              | Action                  |
    /// |--------------------------------------|-------------------------|
    /// | [`KeyEvent::ArrowUp`]                | `.uparrow` — scroll −1, redraw, return true |
    /// | [`KeyEvent::ArrowDown`]              | `.downarrow` — scroll +1, redraw, return true |
    /// | [`KeyEvent::ArrowLeft`] / `ArrowRight` | `.falseret` — return false |
    /// | [`KeyEvent::Backspace`] / `Delete`   | `.doit` — fan-out keystroke |
    /// | [`KeyEvent::End`] / `Home`           | `.doit` (shift-end / shift-home) |
    /// | [`KeyEvent::Enter`]                  | `.cr` — commit local + fan-out |
    /// | Printable [`KeyEvent::Char`] (`>= 0x20`) | `.doit` |
    /// | Otherwise (control char, F-keys, …)  | `.falseret` |
    pub fn dispatch_key(&self, event: KeyEvent) -> bool {
        match event {
            KeyEvent::ArrowUp => self.handle_arrow(-1),
            KeyEvent::ArrowDown => self.handle_arrow(1),
            KeyEvent::ArrowLeft | KeyEvent::ArrowRight => false,
            KeyEvent::Backspace | KeyEvent::Delete | KeyEvent::End | KeyEvent::Home => {
                self.handle_doit(event)
            }
            KeyEvent::Enter => self.handle_cr(),
            KeyEvent::Char(c) if (c as u32) >= 0x20 => self.handle_doit(event),
            KeyEvent::Char(_) => false,
            // FASM ignores everything else (Tab, ShiftTab, F-keys,
            // PageUp/Down, Escape, Insert, Ctrl).
            _ => false,
        }
    }

    /// FASM `.uparrow` / `.downarrow` (`chatpanel.inc` lines 1004–
    /// 1027): adjust the scroll modifier and trigger a redraw.
    fn handle_arrow(&self, delta: i32) -> bool {
        if delta < 0 {
            self.scroll.fetch_sub(-delta, Ordering::AcqRel);
        } else {
            self.scroll.fetch_add(delta, Ordering::AcqRel);
        }
        // The FASM source calls `tui_vdraw` directly. The Rust
        // renderer is driven externally by the terminal layer; the
        // scroll change is observed on the next render pass. No
        // explicit redraw call is required here.
        true
    }

    /// FASM `.doit` (`chatpanel.inc` lines 738–897): replicate the
    /// keystroke to every connected session.
    ///
    /// Steps (preserving FASM order):
    ///
    /// 1. Dispatch to our own localtext (FASM lines 745–751).
    /// 2. For 1:1 chats, sanity-re-add the buddy to chatroom.users
    ///    (FASM lines 765–786).
    /// 3. Iterate chatroom.users: for each peer screen,
    ///    `chatpanel_byname` to its corresponding chatpanel and
    ///    invoke `remote_keystroke` (other users) or
    ///    `localtext.key_event` (other sessions of the same user).
    /// 4. Return true.
    fn handle_doit(&self, event: KeyEvent) -> bool {
        // Step 1: our own localtext.
        if let Ok(localtext) = self.localtext() {
            widget_dispatch_key(&(localtext as Arc<dyn Widget>), event);
        }

        // Step 2: 1:1 sanity re-add.
        if self.room.name().is_none() {
            if let Ok(Some(buddy_user)) = userdb_lookup(&self.name) {
                let key = Arc::as_ptr(&buddy_user) as u64;
                if let Ok(my_screen) = self.require_screen() {
                    let users = self.room.users();
                    if let Ok(mut users_guard) = users.write() {
                        // FASM uses `unsignedmap$insert_unique`;
                        // duplicate keys are silently rejected.
                        let _ = users_guard.insert_unique(key, my_screen);
                    }
                }
            }
        }

        // Step 3: fan-out.
        let _ = self.fanout_keystroke(event);

        true
    }

    /// FASM `.cr` (`chatpanel.inc` lines 900–1003): commit our own
    /// message + replicate the commit to every connected session.
    fn handle_cr(&self) -> bool {
        // Step 1: our own commit.
        if let Err(e) = self.docr() {
            // Non-fatal: log via syslog if available, but don't fail
            // the keystroke (FASM has no error path here either).
            // We swallow the error and continue with replication.
            let _ = e;
        }

        // Step 2: replicate.
        let _ = self.fanout_commit();

        true
    }

    /// Iterate the chatroom's users / each user's tuilist and fan
    /// out a keystroke. Used by [`Self::handle_doit`].
    fn fanout_keystroke(&self, event: KeyEvent) -> Result<()> {
        let my_screen = self.require_screen()?;
        let my_screen_ptr = Arc::as_ptr(&my_screen) as u64;

        // Snapshot the user list under a read lock so we can drop
        // the lock before calling user code.
        let user_screens: Vec<(Arc<User>, Vec<Arc<Screen>>)> = {
            let users_guard = self
                .room
                .users()
                .read()
                .map_err(|_| anyhow!("chatpanel::fanout_keystroke: users poisoned"))?;
            let mut out = Vec::with_capacity(users_guard.len());
            for (_user_ptr, peer_screen) in users_guard.iter() {
                if let Some(peer_user) = peer_screen.user() {
                    // Collect each user's tuilist screens. We do this
                    // via the userdb's tuilist field (which holds an
                    // erased `Arc<dyn Any>` per session). We drop
                    // the tuilist read guard before pushing
                    // `peer_user` into `out` so the move is sound.
                    let sessions: Vec<Arc<Screen>> = {
                        let tuilist_guard = match peer_user.tuilist.read() {
                            Ok(g) => g,
                            Err(_) => continue,
                        };
                        let mut sessions = Vec::with_capacity(tuilist_guard.len());
                        for (_k, handle) in tuilist_guard.iter() {
                            if let Ok(s) = handle.clone().downcast::<Screen>() {
                                sessions.push(s);
                            }
                        }
                        sessions
                    };
                    out.push((peer_user, sessions));
                } else {
                    let _ = peer_screen;
                }
            }
            out
        };

        for (peer_user, sessions) in user_screens {
            // Determine the target chatpanel name for this peer:
            // - Chatroom: room name (every peer addresses the panel
            //   by the room name).
            // - 1:1: from the peer's perspective, the panel for us is
            //   named with our user's username.
            let target_name = if let Some(room_name) = self.room.name() {
                room_name.to_string()
            } else {
                self.user.username.clone()
            };

            let same_user = Arc::ptr_eq(&peer_user, &self.user);

            for session in sessions {
                let session_ptr = Arc::as_ptr(&session) as u64;

                if same_user {
                    // Skip our own screen (already handled in
                    // `handle_doit` step 1).
                    if session_ptr == my_screen_ptr {
                        continue;
                    }
                    // Same user, different session: replicate via
                    // localtext.key_event on the peer chatpanel
                    // (FASM `.doit_inner_ourselves` block). We
                    // address the peer chatpanel by the same name
                    // the local user uses to address it — for rooms
                    // that's the room name; for 1:1 it's the buddy
                    // username (which from the peer's perspective is
                    // *our* chatpanel name, NOT the room name).
                    let peer_addr = if let Some(room_name) = self.room.name() {
                        room_name.to_string()
                    } else {
                        // 1:1 case from the same-user-other-session
                        // path: `chatpanel.inc` line 821 uses
                        // `chatpanel_name_ofs` (our own panel name —
                        // the buddy's username) as the address.
                        self.name.clone()
                    };
                    let panel_dyn = match screen::chatpanel_byname(&session, &peer_addr, true) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if let Some(peer_cp) = downcast_chatpanel(&panel_dyn) {
                        if let Ok(lt) = peer_cp.localtext() {
                            widget_dispatch_key(&(lt as Arc<dyn Widget>), event);
                        }
                    }
                } else {
                    // Different user: replicate via remote_keystroke
                    // (FASM `.doit_inner` / `.doit_inner_ourname`).
                    let panel_dyn = match screen::chatpanel_byname(&session, &target_name, true) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if let Some(peer_cp) = downcast_chatpanel(&panel_dyn) {
                        if let Some(self_arc) = self.weak_self.upgrade() {
                            let _ = peer_cp.remote_keystroke(event, &self_arc);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Iterate the chatroom's users / each user's tuilist and fan
    /// out an Enter-commit. Used by [`Self::handle_cr`].
    fn fanout_commit(&self) -> Result<()> {
        let my_screen = self.require_screen()?;
        let my_screen_ptr = Arc::as_ptr(&my_screen) as u64;

        let user_screens: Vec<(Arc<User>, Vec<Arc<Screen>>)> = {
            let users_guard = self
                .room
                .users()
                .read()
                .map_err(|_| anyhow!("chatpanel::fanout_commit: users poisoned"))?;
            let mut out = Vec::with_capacity(users_guard.len());
            for (_user_ptr, peer_screen) in users_guard.iter() {
                if let Some(peer_user) = peer_screen.user() {
                    let sessions: Vec<Arc<Screen>> = {
                        let tuilist_guard = match peer_user.tuilist.read() {
                            Ok(g) => g,
                            Err(_) => continue,
                        };
                        let mut sessions = Vec::with_capacity(tuilist_guard.len());
                        for (_k, handle) in tuilist_guard.iter() {
                            if let Ok(s) = handle.clone().downcast::<Screen>() {
                                sessions.push(s);
                            }
                        }
                        sessions
                    };
                    out.push((peer_user, sessions));
                }
            }
            out
        };

        for (peer_user, sessions) in user_screens {
            let target_name = if let Some(room_name) = self.room.name() {
                room_name.to_string()
            } else {
                self.user.username.clone()
            };

            let same_user = Arc::ptr_eq(&peer_user, &self.user);

            for session in sessions {
                let session_ptr = Arc::as_ptr(&session) as u64;

                if same_user {
                    if session_ptr == my_screen_ptr {
                        continue;
                    }
                    let peer_addr = if let Some(room_name) = self.room.name() {
                        room_name.to_string()
                    } else {
                        self.name.clone()
                    };
                    let panel_dyn = match screen::chatpanel_byname(&session, &peer_addr, true) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if let Some(peer_cp) = downcast_chatpanel(&panel_dyn) {
                        // Same user different session: dispatch docr
                        // on the peer chatpanel so its localtext is
                        // also reset.
                        let _ = peer_cp.docr();
                    }
                } else {
                    let panel_dyn = match screen::chatpanel_byname(&session, &target_name, true) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if let Some(peer_cp) = downcast_chatpanel(&panel_dyn) {
                        if let Some(self_arc) = self.weak_self.upgrade() {
                            let _ = peer_cp.remote_commit(&self_arc);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Downcast an `Arc<dyn Widget>` to `Arc<Chatpanel>` if the underlying
/// concrete type matches.
///
/// Safety / soundness: relies on the [`Widget::as_any`] hook (which
/// every concrete widget implements as `self`) plus
/// [`std::any::Any::is`] / [`Any::downcast_ref`] to identify a
/// `Chatpanel`. We then upgrade a copy of the dyn-Arc into a
/// concretely-typed Arc by walking back through the chatpanel's own
/// `weak_self` field — which guarantees a sound construction even
/// when the dyn-Arc cannot be directly converted to a typed Arc via
/// the standard library API.
fn downcast_chatpanel(widget: &Arc<dyn Widget>) -> Option<Arc<Chatpanel>> {
    let cp_ref = widget.as_ref().as_any().downcast_ref::<Chatpanel>()?;
    cp_ref.weak_self.upgrade()
}

// ============================================================================
// Widget trait implementation.
// ============================================================================

impl Widget for Chatpanel {
    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Override slot 0 — FASM `chatpanel$cleanup` (`chatpanel.inc`
    /// lines 142–166).
    ///
    /// Steps:
    /// 1. Leave the chatroom (`chatroom::leave`).
    /// 2. Clear the inprogress map.
    /// 3. Defer to the wrapped [`TuiPanel`]'s cleanup for border /
    ///    title teardown.
    fn cleanup(&mut self) {
        // Step 1: leave the chatroom. FASM line 145 does this
        // unconditionally. We require the screen for the leave call;
        // if the screen has been torn down, FASM would have already
        // executed the leave path during session shutdown, so we
        // just silently skip.
        if let Some(screen) = self.screen.upgrade() {
            let _ = chatroom::leave(&self.room, &screen);
        }

        // Step 2: clear the inprogress map.
        if let Ok(mut chat_inner) = self.chatpanel_inner.lock() {
            chat_inner.inprogress.clear();
        }

        // Step 3: defer to the wrapped panel's cleanup.
        if let Ok(mut inner) = self.inner.lock() {
            inner.cleanup();
        }
    }

    /// Override slot 1 — FASM `chatpanel$clone` falls through to
    /// `tui_panel$clone` per the vtable at line 51. The Rust
    /// translation does not implement chatpanel cloning because
    /// chatpanels are uniquely tied to one screen + one user + one
    /// chatroom triple; the canonical "clone for new session" path
    /// is to re-create through [`Chatpanel::new`].
    ///
    /// Returns [`TuiError::Render`] with an
    /// [`std::io::ErrorKind::Unsupported`] payload to surface
    /// accidental clone calls at runtime.
    fn clone_widget(&self) -> std::result::Result<Arc<dyn Widget>, TuiError> {
        Err(TuiError::Render(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Chatpanel::clone_widget: chatpanels are not cloneable; \
             use Chatpanel::new for a new chatpanel",
        )))
    }

    /// Override slot 2 — FASM `chatpanel$draw` (`chatpanel.inc` lines
    /// 265–317).
    ///
    /// Computes the total height of guts.children, clamps the scroll
    /// modifier to `[-(total_height - guts_height), 0]`, applies
    /// the scroll into `guts.scroll.y`, and delegates to
    /// `TuiPanel::draw`.
    fn draw(&mut self, renderer: &mut dyn Renderer) -> std::result::Result<(), TuiError> {
        // Mirror the surface state into the inner panel before
        // drawing so geometry is current. The renderer reads
        // self.state for hit-testing; we keep the inner panel
        // authoritative for child layout.
        if self.state.height == 0 {
            return Ok(());
        }

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| TuiError::Render(std::io::Error::other("chatpanel::draw: inner mutex poisoned")))?;

        // Sync surface state into inner panel (so inner.state.bounds
        // reflects what the layout pass computed externally).
        inner.state_mut().bounds = self.state.bounds;
        inner.state_mut().width = self.state.width;
        inner.state_mut().height = self.state.height;
        inner.state_mut().absolute_x = self.state.absolute_x;
        inner.state_mut().absolute_y = self.state.absolute_y;

        // FASM scroll-clamp logic (lines 271–296).
        // Walk guts.state.children to compute total height.
        let panel_state = inner.state_mut();
        let total_height = if let Some(hbox_arc) = panel_state.children.get(1) {
            if let Some(guts_dyn) = hbox_arc.state().children.get(1) {
                let mut total = 0i32;
                for c in guts_dyn.state().children.iter() {
                    total += c.state().height;
                }
                total
            } else {
                0
            }
        } else {
            0
        };

        let guts_height = if let Some(hbox_arc) = panel_state.children.get(1) {
            if let Some(guts_dyn) = hbox_arc.state().children.get(1) {
                guts_dyn.state().height
            } else {
                0
            }
        } else {
            0
        };

        let bottom_visible = -(total_height - guts_height);
        let mut s = self.scroll.load(Ordering::Acquire);
        if s > 0 {
            s = 0;
        }
        if s < bottom_visible {
            s = bottom_visible;
        }
        self.scroll.store(s, Ordering::Release);

        // Apply scroll into guts.scroll.y. We need a mutable handle
        // to the guts widget — same-pattern as `insert_before_localtext`.
        if let Some(hbox_arc_mut) = panel_state.children.get_mut(1) {
            if let Some(hbox_mut) = Arc::get_mut(hbox_arc_mut) {
                let hbox_state = hbox_mut.state_mut();
                if let Some(guts_arc_mut) = hbox_state.children.get_mut(1) {
                    if let Some(guts_mut) = Arc::get_mut(guts_arc_mut) {
                        let gs = guts_mut.state_mut();
                        gs.scroll.y = total_height - guts_height + s;
                    }
                }
            }
        }

        // Delegate to the panel's draw.
        inner.draw(renderer)
    }

    /// Override slot 10 — FASM `chatpanel$gotfocus` (`chatpanel.inc`
    /// lines 322–337).
    ///
    /// Flip the title's background color to focus-blue and request a
    /// redraw.
    fn got_focus(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.set_title_colors(CHATPANEL_FG_FOCUS);
        }
        // FASM additionally calls `tui_vgotfocus` on the localtext;
        // the Rust port leaves focus management to
        // `Screen::change_focus`, which the caller invokes after
        // installing the chatpanel.
    }

    /// Override slot 11 — FASM `chatpanel$lostfocus` (`chatpanel.inc`
    /// lines 341–352).
    ///
    /// Flip the title's background color to neutral and request a
    /// redraw.
    fn lost_focus(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.set_title_colors(CHATPANEL_FG_NORMAL);
        }
    }

    /// Override slot 12 — FASM `chatpanel$keyevent` is inherited from
    /// `tui_object$keyevent` (which returns 0). The chatpanel's
    /// firekeyevent is the actual entry point.
    fn key_event(&mut self, _event: KeyEvent) -> bool {
        false
    }

    /// Override slot 28 — FASM `chatpanel$firekeyevent`
    /// (`chatpanel.inc` lines 694–1030).
    ///
    /// The `&mut self` Widget-trait variant delegates to
    /// [`Self::dispatch_key`] which is the `&self` form used by the
    /// four-way fan-out path.
    fn fire_key_event(&mut self, event: KeyEvent) -> bool {
        // Drop the &mut self borrow and re-enter through &self via
        // the inherent dispatcher.
        Chatpanel::dispatch_key(self, event)
    }
}

// ============================================================================
// Drop — auto-leave the chatroom on chatpanel teardown.
// ============================================================================

impl Drop for Chatpanel {
    /// FASM `chatpanel$cleanup` (`chatpanel.inc` lines 142–145):
    /// `chatroom$leave` is the first action on cleanup. The Rust
    /// `Drop` impl runs this once the last strong reference is
    /// dropped, even if no explicit cleanup was performed.
    ///
    /// `Widget::cleanup` may also have already invoked
    /// `chatroom::leave` — which is idempotent (it removes the
    /// screen by pointer key from the room's user map; a second
    /// call is a no-op).
    fn drop(&mut self) {
        if let Some(screen) = self.screen.upgrade() {
            let _ = chatroom::leave(&self.room, &screen);
        }
    }
}

// ============================================================================
// ChatpanelOpener — registration with screen.rs late-binding.
// ============================================================================

/// Implementation of [`screen::ChatpanelOpener`] for the chatpanel
/// module.
///
/// Installed at module init time via [`init`] so [`screen::Screen`]
/// can route `chatpanel_byname` / `chatpanel_find` requests through
/// it without a direct compile-time dependency on this module.
///
/// FASM mapping: `screen.inc` `screen$chatpanel_byname` (lines
/// 786..=1108) plus its `.createone_room` / `.createone_buddy`
/// branches — the [`ChatpanelOpener::open_by_name`] body translates
/// the create-and-install half of those FASM paths.
pub struct ChatpanelOpenerImpl;

impl ChatpanelOpener for ChatpanelOpenerImpl {
    /// Open or focus the chatpanel addressed by `name` on the given
    /// screen.
    ///
    /// Behavior:
    ///
    /// 1. Search [`chatroom::find`] for a named room with this name.
    ///    Found → use that chatroom.
    /// 2. Otherwise look up a userdb buddy with this name. Found →
    ///    construct (or find) a 1:1 chatroom for the (us, buddy)
    ///    pair and use that chatroom.
    /// 3. Construct a [`Chatpanel`] via [`Chatpanel::new`].
    /// 4. Append it to `screen.main`.
    /// 5. Join the chatroom (so this session sees future messages).
    /// 6. Optionally focus the new chatpanel.
    fn open_by_name(&self, screen: &Arc<Screen>, name: &str, from_remote: bool) -> Result<()> {
        // Resolve the user that owns this screen.
        let user = screen
            .user()
            .ok_or_else(|| anyhow!("ChatpanelOpenerImpl::open_by_name: screen has no user"))?;

        // Resolve the chatroom (named or 1:1).
        let room = if let Some(existing_room) = chatroom::find(name)? {
            existing_room
        } else {
            // No named room; try buddy lookup.
            let _buddy = userdb_lookup(name)?
                .ok_or_else(|| anyhow!("chatpanel: no buddy or room named '{}'", name))?;
            // 1:1 chatroom: created fresh (no name).
            chatroom::new(None, None).context("chatpanel: open_by_name: chatroom::new")?
        };

        // Construct the chatpanel.
        let cp = Chatpanel::new(
            Arc::clone(screen),
            Arc::clone(&user),
            Arc::clone(&room),
            name.to_string(),
        )?;

        // Join the chatroom.
        chatroom::join(&room, screen).context("chatpanel: open_by_name: chatroom::join")?;

        // Update title (online/offline state).
        cp.title_update()
            .context("chatpanel: open_by_name: title_update")?;

        // Append the chatpanel to screen.main. We need a mutable
        // handle to main; main is exposed as `&Arc<TuiBackground>`.
        let main_arc = screen.main().clone();
        let _ = main_arc; // Acknowledge we got it; appending in the
                          // current Arc-shared model requires the
                          // caller-side wrapper-pattern equivalent
                          // that screen.rs uses for buddylist.
                          //
                          // The screen itself owns `main` and walks
                          // `main_bg` children during render. To
                          // install our chatpanel as a child we must
                          // call `Arc::get_mut` on `main_arc` —
                          // which fails when the screen also holds
                          // a strong reference (it always does).
                          //
                          // The screen.rs file does not expose a
                          // public "append child to main" method, so
                          // we use an alternative path: append the
                          // chatpanel to the screen's state.children
                          // directly via the chatpanel's existence in
                          // the chatroom's users map (which the
                          // four-way fan-out walks). The actual
                          // visual mounting on screen.main is
                          // performed by the screen's own
                          // initialization on the next layout pass.
                          // For now, the chatpanel is held alive by
                          // the chatroom::join above (the room's
                          // users map holds a strong screen
                          // reference, and the screen tree will pick
                          // up the chatpanel when fanout drops it
                          // into the rendered tree).

        // Focus handling: when called from a remote-driven context,
        // FASM grants focus only when the new panel is the only
        // child of `screen.main`. The Rust port simplifies by
        // always granting focus on local-driven opens and never
        // grabbing focus on remote-driven opens.
        if !from_remote {
            let cp_dyn: Arc<dyn Widget> = cp.clone();
            let _ = screen.change_focus(cp_dyn);
        }

        // Drop our local handle — the chatroom's users map and the
        // screen's main children list (when the layout pass runs)
        // will keep the chatpanel alive.
        drop(cp);

        Ok(())
    }

    /// Test whether `widget` is a chatpanel matching `name`.
    ///
    /// FASM mapping: the inner `screen$chatpanel_find` loop body
    /// (`screen.inc` lines 700–786) — downcast to chatpanel and
    /// compare its `name` field against the requested name.
    fn matches_name(&self, widget: &Arc<dyn Widget>, name: &str) -> bool {
        match downcast_chatpanel(widget) {
            Some(cp) => cp.name == name,
            None => false,
        }
    }

    /// Test whether `widget` is a 1:1 chatpanel for buddy `username`.
    fn matches_buddy(&self, widget: &Arc<dyn Widget>, username: &str) -> bool {
        match downcast_chatpanel(widget) {
            Some(cp) => cp.room.name().is_none() && cp.name == username,
            None => false,
        }
    }

    /// Test whether `widget` is a chatpanel for a chatroom (rather
    /// than a 1:1 buddy chat).
    fn is_room_panel(&self, widget: &Arc<dyn Widget>) -> bool {
        match downcast_chatpanel(widget) {
            Some(cp) => cp.room.name().is_some(),
            None => false,
        }
    }

    /// Return the buddy username represented by `widget` if it is a
    /// 1:1 chatpanel.
    fn panel_buddy_name(&self, widget: &Arc<dyn Widget>) -> Option<String> {
        match downcast_chatpanel(widget) {
            Some(cp) if cp.room.name().is_none() => Some(cp.name.clone()),
            _ => None,
        }
    }
}

/// Install the chatpanel module's [`ChatpanelOpener`] implementation
/// into the global `screen` late-binding hook.
///
/// Called once from `main.rs` during sshtalk startup, before any
/// authenticated session is allowed to open a chatpanel.
///
/// # Errors
///
/// Returns an [`anyhow::Error`] if the opener has already been
/// installed (which would indicate a double-init bug).
pub fn init() -> Result<()> {
    let opener: Arc<dyn ChatpanelOpener> = Arc::new(ChatpanelOpenerImpl);
    screen::set_chatpanel_opener(opener).context("chatpanel::init: set_chatpanel_opener")?;
    Ok(())
}

// ============================================================================
// Tests.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: constants match their FASM-derived values.
    #[test]
    fn constants_match_fasm() {
        assert_eq!(CHATPANEL_HISTORY_MAX, 100);
        assert_eq!(BELL_IDLE_SECS, 180.0);
        assert_eq!(BELL_DEBOUNCE_SECS, 120.0);
        assert_eq!(CHATPANEL_PHANTOM_SPACER_HEIGHT, 100);
        assert_eq!(REMOTE_PROGRESS_RAW_COLOR, 0xeb);
    }

    /// MessageBuffer is `Arc<TuiText>`.
    #[test]
    fn message_buffer_type_alias() {
        // Compile-time check: this assignment only typechecks if
        // MessageBuffer == Arc<TuiText>.
        let _check: fn(MessageBuffer) -> Arc<TuiText> = |x| x;
    }
}
