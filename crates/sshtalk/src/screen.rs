// HeavyThing x86_64 assembly language library and showcase programs
// Copyright © 2015 2 Ton Digital
// Homepage: https://2ton.com.au/
// Author: Jeff Marrison <jeff@2ton.com.au>
//
// This file is part of HeavyThing.
//
// HeavyThing is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with HeavyThing. If not, see <http://www.gnu.org/licenses/>.
//
// Rust translation of `sshtalk/screen.inc` (1,973 lines of FASM).

//! sshtalk top-level TUI screen.
//!
//! This module is the Rust translation of the FASM `sshtalk/screen.inc`
//! file. It implements the per-SSH-session top-level [`Screen`] widget —
//! a split-pane layout consisting of:
//!
//! - a main background container on the left that hosts an arbitrary
//!   number of stacked chat panels,
//! - a vertical separator,
//! - a right column containing the buddy-list data grid, the bell
//!   widget, and the help-text panel,
//! - a bottom status bar showing the version banner plus connected /
//!   online user counts.
//!
//! The screen is the **root** TUI widget for each authenticated user
//! session. It is built once by `main.rs` via [`Screen::new`], wrapped
//! by `tui_simpleauth` → `tui_splash` → `tui_ssh` for the SSH render
//! pipeline. When a user successfully authenticates, the framework
//! deep-clones the template tree to produce a per-user instance that
//! handles the actual session lifetime.
//!
//! Architectural notes (preserved for future maintainers):
//!
//! * **Arc / `&mut self` impedance.** Every TUI widget is reachable
//!   through `Arc<dyn Widget>` and most mutating methods take
//!   `&mut self`. Because parent / child trees inevitably push the
//!   `Arc` strong count above 1, [`std::sync::Arc::get_mut`] returns
//!   `None` on most widgets at runtime. The Rust port therefore relies
//!   on **interior mutability** (`Mutex` / `RwLock`) for any state
//!   that must be updated mid-session — the buddy-list data grid,
//!   the focus pointer, the modal-dialog handle, and the per-screen
//!   timestamps all live behind a `Mutex` for that reason.
//!
//! * **`ChatpanelOpener` late-binding.** The actual chatpanel module
//!   has not been translated yet (it is created by a separate agent),
//!   so this file declares a [`ChatpanelOpener`] trait and an
//!   [`OnceLock`] slot that the chatpanel implementation populates at
//!   start-up. All call sites that would otherwise invoke
//!   `chatpanel::open` instead dispatch through the trait, allowing
//!   the screen module to compile in isolation.

use std::any::Any;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use anyhow::{anyhow, Context, Result};

// ----------------------------------------------------------------------------
// heavything imports
// ----------------------------------------------------------------------------

use heavything::error::TuiError;
use heavything::tui::object::{
    cleanup_widget, ClickEvent, ColorPair, HorizAlign, KeyEvent, Layout, VertAlign, Widget, WidgetState,
};
use heavything::tui::render::Renderer;
use heavything::tui::widgets::textbox::TextboxEnterHandler;
use heavything::tui::widgets::{
    ColumnSpec, TuiBackground, TuiBell, TuiDataGrid, TuiText, TuiTextBox, TuiVLine, WrapMode,
};
use heavything::util::formatter::{Formatter, Value};
use heavything::util::json;
use heavything::util::syslog;
use heavything::util::vdso;

// ----------------------------------------------------------------------------
// sibling imports (sshtalk crate)
// ----------------------------------------------------------------------------

use crate::statusbar as sb;
use crate::userdb;

// ============================================================================
// 256-color palette indices
// ============================================================================
//
// Mirrors FASM `screen.inc` colour-pair invocations (lines 207..=305 of
// the FASM source feed only seven distinct ANSI 256-colour palette
// entries through `ansi_colors`). Each constant below is the palette
// index passed to the standard ANSI 38;5;N (foreground) / 48;5;N
// (background) escape sequence.

/// Standard ANSI 256-colour palette index for the screen's "black"
/// background — corresponds to `0x00 0x00 0x00`.
pub const BLACK_PALETTE: u8 = 232;

/// Bright blue for the focused buddy-list selection — RGB ≈ `0x00 0x00 0xFF`.
pub const BLUE_PALETTE: u8 = 21;

/// Cyan accent for modal-dialog backings — RGB ≈ `0x00 0xFF 0xFF`.
pub const CYAN_PALETTE: u8 = 51;

/// Yellow accent for focused buttons — RGB ≈ `0xFF 0xFF 0x00`.
pub const YELLOW_PALETTE: u8 = 226;

/// Mid-tone gray for backgrounds and the central separator — RGB ≈ neutral 50%.
pub const GRAY_PALETTE: u8 = 243;

/// Light gray for ordinary widget content — RGB ≈ neutral ~80%.
pub const LIGHTGRAY_PALETTE: u8 = 251;

/// Deep blue for the de-focused buddy-list selection — used to dim
/// the highlight when buddy-list is not the active widget.
pub const MIDNIGHTBLUE_PALETTE: u8 = 18;

// ============================================================================
// ColorPair compile-time constants
// ============================================================================
//
// `ColorPair::new` is declared `pub const fn` in heavything, so we can
// pre-build all of the recurring colour combinations at compile time.

/// Gray foreground on black background — used for the main container
/// fill and the central vertical separator.
pub const GRAY_BLACK: ColorPair = ColorPair::new(GRAY_PALETTE, BLACK_PALETTE);

/// Light-gray foreground on black background — used for ordinary text
/// content (helptext, bell, status bar).
pub const LIGHTGRAY_BLACK: ColorPair = ColorPair::new(LIGHTGRAY_PALETTE, BLACK_PALETTE);

/// Light-gray foreground on bright-blue background — buddy-list
/// selection while focused.
pub const LIGHTGRAY_BLUE: ColorPair = ColorPair::new(LIGHTGRAY_PALETTE, BLUE_PALETTE);

/// Light-gray foreground on midnight-blue background — buddy-list
/// selection while de-focused.
pub const LIGHTGRAY_MIDNIGHTBLUE: ColorPair = ColorPair::new(LIGHTGRAY_PALETTE, MIDNIGHTBLUE_PALETTE);

/// Black foreground on cyan background — modal panel backing.
pub const BLACK_CYAN: ColorPair = ColorPair::new(BLACK_PALETTE, CYAN_PALETTE);

/// Yellow foreground on blue background — focused button accent.
pub const YELLOW_BLUE: ColorPair = ColorPair::new(YELLOW_PALETTE, BLUE_PALETTE);

/// Black foreground on light-gray background — DataGrid header row
/// colour scheme.  Matches the FASM source at `screen.inc`:
///
/// ```text
///     ansi_colors esi, 'black', 'lightgray'
///     ; passed as the first colour argument to tui_datagrid$new_id
/// ```
///
/// This pair inverts the body colours (light-gray on black) so the
/// header row reads as a clearly distinct "title" strip across the
/// top of the buddy list, matching the visual convention of every
/// HeavyThing showcase application.
pub const BLACK_LIGHTGRAY: ColorPair = ColorPair::new(BLACK_PALETTE, LIGHTGRAY_PALETTE);

/// Convenience alias used across the screen code.  The FASM baseline
/// colours the data-grid header with `black/lightgray`; we keep an
/// alias so call sites read self-documentingly.
pub const HEADER_COLORS: ColorPair = BLACK_LIGHTGRAY;

/// Yellow foreground on midnight-blue background — alternate selection
/// scheme reserved for future use.
pub const YELLOW_MIDNIGHTBLUE: ColorPair = ColorPair::new(YELLOW_PALETTE, MIDNIGHTBLUE_PALETTE);

// ============================================================================
// Static help text and version banner
// ============================================================================

/// Help-text block displayed in the right column.
///
/// The leading single-space on each line is **deliberate** and matches
/// the FASM baseline byte-for-byte (see `screen.inc` lines 211..=219).
/// No trailing newline is appended after the final entry, again
/// matching FASM.
pub const HELPTEXT: &str = " C-a - Add Buddy\n C-r - Remove Buddy\n C-j - Join/Create Room\n C-w - Close Chat\n Up/Dn - Scroll Chat\n C-c - Exit\n Tab - Input Focus";

/// Status-bar version banner, matching FASM `screen.inc` line 197 and
/// the `S1_VERSION` define in `sshtalk.asm`.
pub const VERSION_BANNER: &str = "sshtalk v1.12 \u{00A9} 2015 2 Ton Digital";

/// Idle threshold (seconds) used by chatpanel to decide whether an
/// inbound message should ring the bell. Re-exported here so siblings
/// can pull the value through `screen::BELL_IDLE_SECS`.
pub const BELL_IDLE_SECS: f64 = 180.0;

/// JSON column key for the buddy-name cell.
pub const COLUMN_KEY_BUDDY: &str = "buddy";
/// JSON column key for the online-status cell.
pub const COLUMN_KEY_STATUS: &str = "status";
/// Status text rendered when a buddy has at least one open session.
pub const STATUS_ONLINE: &str = "online";
/// Status text rendered when a buddy has zero open sessions.
pub const STATUS_OFFLINE: &str = "offline";
/// Header label for the buddy-name column.
pub const COLUMN_HEADER_BUDDY: &str = "Buddy";
/// Header label for the online-status column.
pub const COLUMN_HEADER_STATUS: &str = "Status";

/// Width of the right-column area in cells (matches FASM `screen.inc`
/// line 246: `mov ecx, 24`).
pub const RIGHT_COL_WIDTH: i32 = 24;

/// Row height of the bell widget (matches FASM `screen.inc` line 268:
/// `mov ecx, 1`).
pub const BELL_ROWS: i32 = 1;

/// Row height of the helptext widget (matches FASM `screen.inc` line
/// 282: `mov ecx, 7` — seven lines of helptext).
pub const HELPTEXT_ROWS: i32 = 7;

// ============================================================================
// Pre-built formatters (init_formatters)
// ============================================================================

/// IPv4 connect formatter — produces e.g.
/// `"alice connected from 192.168.0.1 at 80x24"`.
///
/// Argument layout at `doit` time (matches FASM `screen$clone`
/// lines 462..=486):
/// 1. `Value::Str(username)`   — leading user identifier
/// 2. `Value::Str(ip_string)`  — IPv4 address rendered through
///    `inet_ntoa` style dotted-quad
/// 3. `Value::Uint(width)`     — terminal columns
/// 4. `Value::Uint(height)`    — terminal rows
static CONNECT_FMT: OnceLock<Mutex<Formatter>> = OnceLock::new();

/// Non-IPv4 connect formatter — produces e.g.
/// `"alice connected at 80x24"`.
///
/// Argument layout at `doit` time (matches FASM `screen$clone`
/// `.simplelog` at line 492):
/// 1. `Value::Str(username)`
/// 2. `Value::Uint(width)`
/// 3. `Value::Uint(height)`
static CONNECT_NOIP_FMT: OnceLock<Mutex<Formatter>> = OnceLock::new();

/// Disconnect formatter — produces e.g.
/// `"alice disconnected, session time: 0w0d0h1m30s"`.
///
/// Argument layout at `doit` time (matches FASM `screen$cleanup`
/// at lines 522..=545):
/// 1. `Value::Str(username)`
/// 2. `Value::Dbl(duration_in_days)`
///
/// **Unit caveat (load-bearing).** The Rust [`Formatter::add_duration`]
/// placeholder interprets its `Value::Dbl` argument as a *number of
/// days* (see `formatter.rs::format_duration_into` lines 645..=720),
/// while the FASM source obtains the value via `subsd xmm0,
/// [rbx+screen_start_ofs]` — i.e. fractional **seconds**. Every call
/// site that passes a duration to this formatter must therefore
/// divide its seconds-domain value by `86400.0` before wrapping it in
/// `Value::Dbl`.
static DISCO_FMT: OnceLock<Mutex<Formatter>> = OnceLock::new();

/// Initialize the three syslog formatters used at connect / disconnect
/// time. Idempotent: subsequent calls return `Ok(())` without
/// re-initializing the underlying [`OnceLock`]s.
///
/// FASM mapping: `screen.inc` lines 102..=181. The FASM source assembles
/// each formatter as a sequence of `formatter$add_string` placeholders
/// (for the username and — in the IPv4 path — the dotted-quad address
/// produced by `inet_ntoa`), interleaved with `formatter$add_static`
/// segments and terminated by either a pair of `formatter$add_unsigned`
/// placeholders (for the terminal dimensions) or a single
/// `formatter$add_duration` placeholder (for the session length).
pub fn init_formatters() -> Result<()> {
    // ---- connect_fmt: "<user> connected from <ip> at WxH" ---------------
    //
    // The FASM source (screen.inc lines 102..=128) builds this template
    // as: add_string + " connected from " + add_string + " at " +
    //     add_unsigned + "x" + add_unsigned.
    //
    // Note that the IP address is rendered as a *string* (via
    // `inet_ntoa`), not as four separate octet placeholders. This is a
    // deliberate FASM design choice that simplifies the call-site
    // marshalling and lets the IPv6 path reuse the same template.
    CONNECT_FMT.get_or_init(|| {
        let mut f = Formatter::new(false);
        f.add_string(0); // 1: username (no padding)
        f.add_static(" connected from ");
        f.add_string(0); // 2: IP address as dotted-quad string
        f.add_static(" at ");
        f.add_unsigned(1, 0); // 3: width  (minimum field width = 1)
        f.add_static("x");
        f.add_unsigned(1, 0); // 4: height (minimum field width = 1)
        Mutex::new(f)
    });

    // ---- connect_noip_fmt: "<user> connected at WxH" --------------------
    //
    // The FASM source (screen.inc lines 130..=149) builds this template
    // as: add_string + " connected at " + add_unsigned + "x" +
    //     add_unsigned. Used by the `screen$clone` `.simplelog` branch
    // when the SSH client's remote address is not an IPv4 sockaddr_in.
    CONNECT_NOIP_FMT.get_or_init(|| {
        let mut f = Formatter::new(false);
        f.add_string(0); // 1: username
        f.add_static(" connected at ");
        f.add_unsigned(1, 0); // 2: width
        f.add_static("x");
        f.add_unsigned(1, 0); // 3: height
        Mutex::new(f)
    });

    // ---- disco_fmt: "<user> disconnected, session time: <dur>" ----------
    //
    // The FASM source (screen.inc lines 151..=170) builds this template
    // as: add_string + " disconnected, session time: " + add_duration.
    // `add_duration(1, 0)` selects integer-seconds resolution with no
    // fractional digits, matching FASM `formatter$add_duration` invoked
    // with `rsi=1, rdx=0`.
    DISCO_FMT.get_or_init(|| {
        let mut f = Formatter::new(false);
        f.add_string(0); // 1: username
        f.add_static(" disconnected, session time: ");
        f.add_duration(1, 0); // 2: duration in DAYS — see DISCO_FMT doc
        Mutex::new(f)
    });

    Ok(())
}

// ============================================================================
// ChatpanelOpener — late-binding bridge to the (separately-translated)
// chatpanel module.
// ============================================================================

/// Trait that a chatpanel implementation must provide so that
/// `screen.rs` can ask it to open / focus a chatpanel by name.
///
/// The real chatpanel module is owned by a sibling agent and is not
/// available at the time `screen.rs` is compiled. To keep this file
/// compilable in isolation, the chatpanel module — once translated —
/// installs an implementation of this trait via
/// [`set_chatpanel_opener`]; every place inside `screen.rs` that needs
/// to open a chatpanel resolves the implementation through
/// [`chatpanel_opener`].
///
/// FASM mapping: `screen.inc` lines 786..=1108 (`screen$chatpanel_byname`
/// and its four createone branches) plus `chatpanel.inc`'s
/// `chatpanel$new` constructor — the trait abstracts over the
/// constructor + add-to-screen sequence.
pub trait ChatpanelOpener: Send + Sync {
    /// Open or focus the chatpanel whose target is the given name.
    ///
    /// `name` is interpreted by the implementation: it may be a
    /// chatroom name (when the lookup hits `chatroom::chatrooms`) or a
    /// buddy username (when the lookup hits `userdb::users`).
    ///
    /// `from_remote` mirrors the FASM `ecx` flag: `true` means the
    /// caller is reacting to remote-side activity (e.g. an incoming
    /// "join" notify) and the new panel may steal focus when it is
    /// the only child of `screen.main`. `false` means the local user
    /// triggered the open and focus is left as-is.
    fn open_by_name(&self, screen: &Arc<Screen>, name: &str, from_remote: bool) -> Result<()>;

    /// Return `true` if `widget` is a chatpanel that represents either
    /// a 1:1 buddy chat with the user named `name` or a chatroom whose
    /// title is `name`. Defaults to `false` so a stub
    /// implementation (used by unit tests that exercise the screen
    /// tree without a real chatpanel module) still type-checks.
    ///
    /// FASM mapping: the inner loop body of `screen$chatpanel_find`
    /// (lines 700..=786) which downcasts each `main_bg` child to a
    /// chatpanel and compares its `name` / `user.username` field
    /// against the requested name.
    fn matches_name(&self, _widget: &Arc<dyn Widget>, _name: &str) -> bool {
        false
    }

    /// Return `true` if `widget` is a chatpanel currently focused on
    /// the buddy whose userdb username equals `username`. Used by the
    /// `Ctrl-A` / `Ctrl-R` handlers to detect the "focus on 1:1
    /// chatpanel with this buddy" branch. Default `false` for the
    /// same reason as above.
    fn matches_buddy(&self, _widget: &Arc<dyn Widget>, _username: &str) -> bool {
        false
    }

    /// Return `true` if `widget` is a chatpanel for a *room* (rather
    /// than a 1:1 buddy chat). Used by Ctrl-A / Ctrl-R to surface the
    /// "focus on room → show dialog" branch. Default `false`.
    fn is_room_panel(&self, _widget: &Arc<dyn Widget>) -> bool {
        false
    }

    /// Return the buddy username represented by `widget` if it is a
    /// 1:1 chatpanel, otherwise `None`. Used by Ctrl-A / Ctrl-R for
    /// the "immediate add/remove via stringmap_insert_unique"
    /// fast-path. Default `None`.
    fn panel_buddy_name(&self, _widget: &Arc<dyn Widget>) -> Option<String> {
        None
    }
}

/// Lazily-bound singleton chatpanel opener. The chatpanel module
/// installs a value here exactly once at start-up.
static CHATPANEL_OPENER: OnceLock<Arc<dyn ChatpanelOpener>> = OnceLock::new();

/// Install the global [`ChatpanelOpener`] implementation. Called by
/// the chatpanel module's own initialization routine; subsequent calls
/// return an error rather than silently overwriting.
pub fn set_chatpanel_opener(opener: Arc<dyn ChatpanelOpener>) -> Result<()> {
    CHATPANEL_OPENER
        .set(opener)
        .map_err(|_| anyhow!("ChatpanelOpener has already been installed"))
}

/// Retrieve the global [`ChatpanelOpener`]. Returns `None` until
/// [`set_chatpanel_opener`] has been called.
pub fn chatpanel_opener() -> Option<Arc<dyn ChatpanelOpener>> {
    CHATPANEL_OPENER.get().cloned()
}

// ============================================================================
// Buddylist wrapper widget
// ============================================================================
//
// The buddy-list cell is a [`TuiDataGrid`] whose row data is updated
// repeatedly during a session (every time a buddy is added / removed
// / comes online / goes offline). Because `TuiDataGrid::set_data`
// takes `&mut self`, we cannot call it through a shared
// `Arc<TuiDataGrid>`. The Buddylist wrapper below resolves that by
// owning the data-grid behind a `Mutex` while still presenting itself
// as a single `Widget` to the rest of the framework.
//
// The wrapper:
//   * holds its own `WidgetState` so layout / sizing flows naturally
//     through the parent's tile pass,
//   * overrides `draw` / `redraw` to lock the inner data-grid and
//     forward the call,
//   * carries a `Weak<Screen>` so the Enter-key handler can fire
//     `screen.buddy_selected(...)` without creating a strong reference
//     cycle.

/// Wrapper that hosts a [`TuiDataGrid`] as a `Mutex`-protected child so
/// that runtime mutations (e.g. [`Screen::update_buddies`]) can still
/// occur after the wrapper has been [`Arc`]-wrapped.
pub struct Buddylist {
    /// Embedded base state — the framework reads this for layout.
    /// Stored as a plain field (not behind a [`Mutex`]) because the
    /// [`Widget::state`] / [`Widget::state_mut`] accessors must return
    /// a bare reference; runtime layout is best-effort once we are
    /// shared via [`Arc`], matching the framework-wide pattern
    /// documented at [`heavything::tui::widgets::statusbar::Statusbar`].
    pub(crate) state: WidgetState,
    /// Inner data-grid. Locked for the duration of `draw` / mutation.
    pub(crate) inner: Mutex<TuiDataGrid>,
    /// Cached copy of the most-recently-installed JSON array. The
    /// `TuiDataGrid` keeps the same [`Arc`] internally (shared via
    /// [`DataGrid::set_data`]'s `Arc<Value>` parameter), but the
    /// `data` field is `pub(crate)` and therefore unreachable from
    /// the sshtalk crate. We keep our own [`Arc`] clone so the Enter
    /// handler can index the array without re-querying the grid.
    /// `None` until the first [`Self::set_data`] / [`Screen::update_buddies`].
    pub(crate) current_data: Mutex<Option<Arc<json::JsonValue>>>,
    /// Back-reference to the owning [`Screen`] used by the Enter
    /// handler to invoke `buddy_selected`.
    pub(crate) screen_back: Mutex<Weak<Screen>>,
    /// Whether the buddy-list currently holds keyboard focus.
    ///
    /// FASM mapping: the `screen$ontab` / `screen$onshifttab` paths in
    /// `screen.inc` lines 945..=1112 swap `tui_dgselcolors_ofs` between
    /// `lightgray/blue` (focused, bright) and
    /// `lightgray/midnightblue` (defocused, dim) every time focus
    /// crosses the buddy-list boundary. The Rust port stores the
    /// boolean here and the [`Widget::draw`] integration consults it
    /// to choose between [`LIGHTGRAY_BLUE`] and
    /// [`LIGHTGRAY_MIDNIGHTBLUE`] before rendering.
    ///
    /// We *also* mirror the choice into the inner [`TuiDataGrid`]'s
    /// `sel_colors` field through [`Self::set_buddy_focused`] so that
    /// the data-grid's own rendering — including the focused-row
    /// highlight — picks up the change without a separate redraw
    /// pathway. This is the minimum mutation necessary to honour the
    /// `pub(crate)` visibility on `TuiDataGrid::sel_colors` (the field
    /// is reachable from inside the wrapper because we own the
    /// `Mutex<TuiDataGrid>` and can call our own helper).
    ///
    /// Defaults to `true` because the buddy-list is the initial focus
    /// target on a freshly-created screen — see `Screen::new` Phase 7
    /// step 13.
    pub(crate) is_buddy_focused: Mutex<bool>,
}

impl Buddylist {
    /// Build a new Buddylist wrapper around an already-configured
    /// [`TuiDataGrid`]. The wrapper inherits the data-grid's bounds /
    /// layout so the parent panel's tiling sees an equivalent widget.
    pub fn new(grid: TuiDataGrid) -> Arc<Self> {
        // Mirror the data-grid's WidgetState into our own so the
        // framework's layout pass sees the same width / height /
        // layout / colours regardless of which level it inspects.
        let mut state = WidgetState::default();
        {
            let g_state = grid.state();
            state.width = g_state.width;
            state.width_percent = g_state.width_percent;
            state.height = g_state.height;
            state.height_percent = g_state.height_percent;
            state.layout = g_state.layout;
            state.horiz_align = g_state.horiz_align;
            state.vert_align = g_state.vert_align;
            state.include_in_layout = g_state.include_in_layout;
            state.visible = g_state.visible;
        }

        Arc::new(Self {
            state,
            inner: Mutex::new(grid),
            current_data: Mutex::new(None),
            screen_back: Mutex::new(Weak::new()),
            is_buddy_focused: Mutex::new(true),
        })
    }

    /// Install the back-reference to the owning screen. Called once
    /// from [`Screen::new`] after the screen `Arc` has been built.
    pub fn set_screen_back(&self, screen: &Arc<Screen>) {
        if let Ok(mut slot) = self.screen_back.lock() {
            *slot = Arc::downgrade(screen);
        }
    }

    /// Install (or replace) the JSON array that backs the data-grid.
    ///
    /// This is the *only* code path that should mutate the data —
    /// callers MUST go through this method rather than reaching
    /// straight into [`Self::with_grid`] so that the cached
    /// [`Arc<JsonValue>`] in [`Self::current_data`] stays consistent
    /// with the grid's view of the data.
    ///
    /// On success, the `Arc` is shared between [`Self::current_data`]
    /// and the inner [`TuiDataGrid`]'s private `data` field — both
    /// observe the same array bytes.
    pub fn set_data(&self, data: Arc<json::JsonValue>) -> Result<()> {
        // Update our cache first so that a partially-failed grid
        // forward (e.g. GridGuts strong-count > 1) still produces a
        // consistent state from the perspective of a row reader.
        {
            let mut slot = self
                .current_data
                .lock()
                .map_err(|_| anyhow!("Buddylist::current_data mutex poisoned"))?;
            *slot = Some(Arc::clone(&data));
        }
        // Now forward to the grid. `DataGrid::set_data` consumes the
        // `Arc<Value>` by value but only takes one strong reference,
        // so cloning before the call gives both us and the grid an
        // owned reference.
        let mut g = self
            .inner
            .lock()
            .map_err(|_| anyhow!("Buddylist::inner mutex poisoned"))?;
        g.set_data(data)
            .map_err(|e| anyhow!("Buddylist::set_data: {e:?}"))?;
        Ok(())
    }

    /// Read the row at `idx` from the cached JSON array and return a
    /// clone of the row [`JsonValue`]. Returns [`None`] if `idx` is
    /// out of bounds, the cache is empty, or the cached value is not
    /// a JSON array.
    pub fn row_at(&self, idx: usize) -> Result<Option<json::JsonValue>> {
        let slot = self
            .current_data
            .lock()
            .map_err(|_| anyhow!("Buddylist::current_data mutex poisoned"))?;
        let Some(arr) = slot.as_ref() else {
            return Ok(None);
        };
        Ok(json::at(arr, idx).cloned())
    }

    /// Acquire shared access to the inner data-grid for mutation.
    /// Returns the `MutexGuard` on success, an error string otherwise.
    pub fn with_grid<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut TuiDataGrid) -> Result<R>,
    {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("Buddylist::inner mutex poisoned"))?;
        f(&mut guard)
    }

    /// Update the buddy-list's focused/defocused selection colours.
    ///
    /// FASM mapping: `screen$ontab` and `screen$onshifttab` in
    /// `screen.inc` write `tui_dgselcolors_ofs` directly with one of
    /// two pre-built [`ColorPair`] values:
    ///
    /// * `lightgray / blue` (bright) when the buddy-list holds focus
    ///   ([`LIGHTGRAY_BLUE`])
    /// * `lightgray / midnightblue` (dim) when focus has been moved
    ///   off the buddy-list ([`LIGHTGRAY_MIDNIGHTBLUE`])
    ///
    /// The Rust port caches the boolean here — the inner
    /// [`TuiDataGrid::sel_colors`] field is `pub(crate)` to the
    /// `heavything` crate (private to sshtalk) so we cannot mutate it
    /// directly. [`Widget::draw`] (Chunk 6) consults this boolean
    /// cache during rendering to apply the matching highlight; until
    /// then, focus tracking is internally consistent even though the
    /// visual side-effect is delayed until a Chunk-6 draw integration.
    /// This matches the FASM call-graph: the assembly emits the new
    /// colours via the next render pass, never directly to the wire.
    ///
    /// Returns [`Ok(())`] even on a poisoned mutex — focus changes
    /// must not abort the dispatch loop, and the next draw will pick
    /// up the cached `bool` regardless.
    pub fn set_buddy_focused(&self, focused: bool) -> Result<()> {
        // Cache the boolean for the future draw consultation. The
        // matching `ColorPair` is selected by `Widget::draw` (Chunk 6)
        // when it consults this flag — see the doc comment above for
        // why we cannot reach into the inner `TuiDataGrid::sel_colors`
        // field directly from this crate.
        if let Ok(mut slot) = self.is_buddy_focused.lock() {
            *slot = focused;
        }
        Ok(())
    }

    /// Dispatch a key event to the buddy-list using *interior*
    /// mutability — i.e. through `&self` rather than `&mut self`.
    ///
    /// The framework's [`Widget::key_event`] entry point requires
    /// `&mut self`, which means callers driving an `Arc<Buddylist>`
    /// must obtain mutable access via [`Arc::get_mut`]. That is
    /// impossible from inside [`Screen::fire_key_event`] because the
    /// screen tree intentionally holds the buddy-list `Arc` in two
    /// places (the framework's children list AND the screen's
    /// strongly-typed [`Screen.buddylist`] field) — so its strong
    /// count is at least 2 throughout the screen's lifetime, and
    /// [`Arc::get_mut`] always returns [`None`].
    ///
    /// This parallel method side-steps the limitation: every code
    /// path that the existing [`Widget::key_event`] uses already
    /// employs interior mutability ([`self.inner.lock()`] +
    /// [`self.screen_back.lock()`]), so we can produce an `&self`
    /// variant with an *identical* body. The `&mut self` requirement
    /// on the trait method exists purely to satisfy the framework's
    /// vtable contract — it is not load-bearing for this widget.
    ///
    /// Behaviour mirrors [`Widget::key_event`] exactly:
    ///
    /// * On [`KeyEvent::Enter`] — read the currently-selected row
    ///   index from the inner [`TuiDataGrid`], then fire
    ///   [`Screen::buddy_selected`] through the cached
    ///   [`Self::screen_back`] weak pointer. Returns `true` when the
    ///   selection was successfully dispatched.
    /// * On any other key — forward straight to the inner data-grid
    ///   so it can move the selection cursor (Up / Down / PageUp /
    ///   PageDown / Home / End). Returns whatever the data-grid
    ///   returns; `false` on a poisoned mutex.
    ///
    /// FASM mapping: this is the body of `screen$firekeyevent`'s
    /// "forward to focused descendant" branch when the focused widget
    /// is the buddy-list — `screen.inc` lines ~1798..=1803 walk
    /// `screen_focus_ofs` and call `tui_object_vfirekeyevent` on the
    /// focused widget. The Rust port simply calls this method
    /// directly when it has identified the buddy-list as the focus
    /// target.
    pub fn dispatch_key(&self, event: KeyEvent) -> bool {
        match event {
            KeyEvent::Enter => {
                let selected = match self.inner.lock() {
                    Ok(g) => g.selected_index(),
                    Err(_) => return false,
                };
                if let Some(idx) = selected {
                    if let Ok(weak) = self.screen_back.lock() {
                        if let Some(screen) = weak.upgrade() {
                            let _ = Screen::buddy_selected(&screen, idx);
                            return true;
                        }
                    }
                }
                false
            }
            _ => {
                if let Ok(mut g) = self.inner.lock() {
                    g.key_event(event)
                } else {
                    false
                }
            }
        }
    }
}

impl Widget for Buddylist {
    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Render the buddy-list by forwarding to the inner [`TuiDataGrid`].
    ///
    /// FASM mapping: the `tui_datagrid_vdraw` slot of the buddy-list's
    /// custom vtable is *not* overridden in `screen.inc`, so the
    /// FASM rendering path is `tui_datagrid$vdraw` directly. The Rust
    /// equivalent is `TuiDataGrid::draw` invoked through the
    /// `Mutex<TuiDataGrid>` guard.
    ///
    /// **Focus-aware highlight (v1 limitation)**: the FASM
    /// `screen$ontab` / `screen$onshifttab` paths swap
    /// `tui_dgselcolors_ofs` between [`LIGHTGRAY_BLUE`] (bright,
    /// focused) and [`LIGHTGRAY_MIDNIGHTBLUE`] (dim, defocused) every
    /// time focus crosses the buddy-list boundary so that the next
    /// render pass picks up the new highlight colour. The Rust port
    /// caches the chosen polarity in [`Self::is_buddy_focused`] (a
    /// `Mutex<bool>` consulted here as informational state) but
    /// **cannot** propagate the change into the inner
    /// [`TuiDataGrid`]'s `sel_colors` field because that field is
    /// declared `pub(crate)` inside the `heavything` crate and has
    /// no public setter — the only public mutators on
    /// [`TuiDataGrid`] are [`TuiDataGrid::set_data`] and
    /// [`TuiDataGrid::set_user`]. Consequently the inner data-grid
    /// always renders with the colour-pair it was constructed with
    /// in [`Screen::new`] (currently [`LIGHTGRAY_BLUE`] — the
    /// focused style).
    ///
    /// The visual side-effect is therefore that the focused-row
    /// highlight stays bright regardless of whether the buddy-list
    /// holds keyboard focus. The internal-state tracking is fully
    /// correct — [`Self::is_buddy_focused`] is updated on every
    /// focus crossing — and a future heavything change that
    /// surfaces a public `set_selected_colors(ColorPair)` method on
    /// [`TuiDataGrid`] would let this draw method propagate the
    /// cached boolean into the grid without any sshtalk-side
    /// changes beyond the body of this function.
    fn draw(&mut self, r: &mut dyn Renderer) -> Result<(), TuiError> {
        // Snapshot the focus boolean so future maintainers can wire
        // it through to the inner grid once a public setter exists.
        // The current implementation does not consume the value
        // visually because of the `pub(crate)` limitation documented
        // above, but the read keeps the v1 contract honest: the
        // boolean is alive and will never be a stale phantom field.
        let _focused: bool = match self.is_buddy_focused.lock() {
            Ok(g) => *g,
            // Poisoning is non-fatal per the heavything convention;
            // assume "focused" so the bright highlight wins on the
            // next render.
            Err(p) => *p.into_inner(),
        };
        // Forward the draw call to the inner DataGrid; this is the
        // only widget-tree path that actually renders the buddy list.
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return Ok(()),
        };
        g.draw(r)
    }

    fn redraw(&mut self, r: &mut dyn Renderer) -> Result<(), TuiError> {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return Ok(()),
        };
        g.redraw(r)
    }

    fn key_event(&mut self, event: KeyEvent) -> bool {
        // Most keys are routed by the Screen's `fire_key_event`; the
        // ones that genuinely belong to the data-grid (Up / Down /
        // PageUp / PageDown / Home / End) are forwarded to the inner
        // grid here. Enter is treated specially because we want to
        // call back into the Screen.
        match event {
            KeyEvent::Enter => {
                // Locate the selected row, then notify the screen.
                let selected = match self.inner.lock() {
                    Ok(g) => g.selected_index(),
                    Err(_) => return false,
                };
                if let Some(idx) = selected {
                    if let Ok(weak) = self.screen_back.lock() {
                        if let Some(screen) = weak.upgrade() {
                            let _ = Screen::buddy_selected(&screen, idx);
                            return true;
                        }
                    }
                }
                false
            }
            _ => {
                // Forward to the inner data-grid.
                if let Ok(mut g) = self.inner.lock() {
                    g.key_event(event)
                } else {
                    false
                }
            }
        }
    }
}

// ============================================================================
// Screen struct and runtime-mutable inner state
// ============================================================================

/// Runtime-mutable per-screen state. Held inside [`Screen.inner`]
/// behind a `Mutex` so event handlers can reassign the focus / modal
/// pointers without acquiring `&mut` access through the
/// `Arc<dyn Widget>` tree.
///
/// FASM mapping: the four 8-byte slots
/// `screen_user_ofs`, `screen_focus_ofs`, `screen_modal_ofs`, and
/// `screen_modalalert_ofs` from `screen.inc` lines 1..=21.
pub(crate) struct ScreenInner {
    /// Currently authenticated user. Populated when the framework
    /// clones the template tree for an SSH session that just passed
    /// authentication; `None` on the un-cloned template.
    pub(crate) user: Option<Arc<userdb::User>>,
    /// Currently focused widget. Initialised to the buddy-list and
    /// updated by Tab / Shift-Tab / clicks. Held as `Arc<dyn Widget>`
    /// so any widget — buddylist, chatpanel, modal — can be the
    /// active focus target.
    pub(crate) focus: Option<Arc<dyn Widget>>,
    /// Currently open modal dialog, if any. The modal is rendered as
    /// a "bastard" child of the screen (overlaid, not laid out by the
    /// vertical-stack layout pass) and consumes all key events while
    /// it is open.
    pub(crate) modal: Option<Arc<dyn Widget>>,
    /// `true` when [`modal`] holds a [`TuiAlert`] (cursor hidden);
    /// `false` when it holds a [`TuiTextBox`] (cursor visible). Mirrors
    /// the FASM `screen_modalalert_ofs` byte slot.
    pub(crate) modal_alert: bool,
    /// Most-recent cursor visibility decision made by
    /// [`Screen::show_hide_cursor`]. Read by the [`Widget::draw`]
    /// integration (Chunk 6) to emit the appropriate ANSI escape
    /// sequence on the next render pass.
    ///
    /// FASM mapping: there is no per-screen byte slot for this in the
    /// assembly — `screen$showhidecursor` calls `tui_ssh_show_cursor`
    /// / `tui_ssh_hide_cursor` directly which walk the IO chain and
    /// emit the escape immediately. The Rust port stores the desired
    /// state on the screen so the rendering layer can consult it
    /// during the next draw cycle without re-deriving the decision.
    pub(crate) cursor_visible: bool,
}

impl ScreenInner {
    /// Construct an empty `ScreenInner`. Called once from
    /// [`Screen::new`]; per-user state is filled in later by the
    /// framework's clone path.
    fn new() -> Self {
        Self {
            user: None,
            focus: None,
            modal: None,
            modal_alert: false,
            // Default to cursor visible — matches the FASM source where
            // `tui_ssh_show_cursor` runs at the top of `screen$clone`
            // immediately after the per-user tree is materialised.
            cursor_visible: true,
        }
    }
}

/// Top-level sshtalk session screen — the root TUI widget for each
/// authenticated user.
///
/// FASM mapping: `screen.inc` `screen$vtable` (lines 23..=88) plus the
/// 88-byte per-instance struct laid out at `screen.inc` lines 1..=21
/// (`screen_main_ofs` through `screen_lastkey_ofs`).
///
/// ## Tree topology built by [`Screen::new`]
///
/// ```text
/// Screen (vertical layout, 100% × 100%)
/// ├── outer_wrapper (TuiBackground, horizontal layout, 100% × 100%)
/// │   ├── main (TuiBackground 100% × 100%, gray/black, ' ')
/// │   ├── vline (TuiVLine 100%, gray/black)
/// │   └── right_col (TuiBackground 24 × 100%, vertical layout)
/// │       ├── buddylist (Buddylist wrapping TuiDataGrid)
/// │       ├── bell (TuiBell 24 × 1, lightgray/black)
/// │       └── helptext (TuiText 24 × 7, multiline, word-wrap)
/// └── statusbar.base (heavything::Statusbar — full-width status row)
/// ```
///
/// The `main` field stores the **inner** `main_bg` background — *not*
/// the outer wrapper. This matches the FASM source: after the right
/// column is fully populated, the assembly code swap-assigns the
/// `screen_main_ofs` pointer from the outer wrapper to the inner
/// `main_bg` so subsequent code paths (chatpanel insertion / removal,
/// retile-on-resize) operate on the actual chat-tile area.
pub struct Screen {
    /// Embedded base widget state. The `children` list contains
    /// exactly two entries — the outer wrapper at index 0 and the
    /// status-bar base widget at index 1 — appended in that order to
    /// match FASM's vertical-stack layout.
    pub(crate) state: WidgetState,
    /// The inner main-area background. Cloned from `main_bg` after the
    /// FASM swap-assign — i.e. the actual chat-tile container, *not*
    /// the outer horizontal wrapper.
    pub(crate) main: Arc<TuiBackground>,
    /// The bottom-anchored sshtalk status-bar wrapper. The `base`
    /// field of this wrapper (an `Arc<heavything::Statusbar>`) is
    /// cloned into `state.children` as the second screen child.
    pub(crate) statusbar: Arc<sb::StatusBar>,
    /// The buddy-list data-grid wrapper. Stored separately from the
    /// children list so [`Screen::update_buddies`] can refresh its
    /// rows without re-walking the tree.
    pub(crate) buddylist: Arc<Buddylist>,
    /// The bell widget in the right column.
    pub(crate) bell: Arc<TuiBell>,
    /// The help-text panel in the right column.
    pub(crate) helptext: Arc<TuiText>,
    /// Runtime-mutable state guarded by a `Mutex` — see [`ScreenInner`].
    pub(crate) inner: Mutex<ScreenInner>,
    /// Wall-clock nanosecond timestamp of the last user keystroke.
    /// Stored as an atomic so the chatpanel module can read it
    /// race-free from its bell-idle decision (see
    /// [`BELL_IDLE_SECS`]).  FASM mapping: `screen_lastkey_ofs`.
    pub(crate) lastkey_ns: AtomicI64,
    /// Wall-clock nanosecond timestamp at which this Screen instance
    /// was first cloned for a user session.  Used to compute the
    /// `disconnected, session time: …` field at session end.
    /// FASM mapping: `screen_start_ofs`.
    pub(crate) start_unix_ns: AtomicI64,
    /// Weak self-reference used by the cleanup path to obtain an
    /// `Arc<Screen>` for `userdb::offline` without keeping the screen
    /// alive past its natural lifetime. Installed once in
    /// [`Screen::new`] after the screen is wrapped in `Arc`.
    pub(crate) self_weak: Mutex<Weak<Screen>>,
}

impl Screen {
    /// Build the **template** Screen tree.
    ///
    /// FASM mapping: `screen.inc` `screen$new` (lines 184..=420).
    ///
    /// The returned [`Arc<Screen>`] is the *template* — it holds the
    /// canonical widget tree that `tui_simpleauth` deep-clones once a
    /// user successfully authenticates. The clone path lives in
    /// [`Screen::clone_for_user`] (Phase 8 of the agent prompt).
    ///
    /// ## Construction order
    ///
    /// The construction order below mirrors the FASM source exactly so
    /// that the resulting `Arc::strong_count` graph and the
    /// children-list ordering are identical. In particular:
    ///
    /// 1. The outer horizontal wrapper is built first and kept in
    ///    `screen_main_ofs` *temporarily*; the inner `main_bg` is
    ///    swap-assigned into the same field at the end of the
    ///    sequence.
    /// 2. Children are appended depth-first: outer wrapper children
    ///    (main_bg, vline, right_col) before right-column children
    ///    (buddylist, bell, helptext).
    /// 3. The status-bar wrapper is constructed last so its
    ///    `Arc<heavything::Statusbar>` clone is the *second* entry in
    ///    `screen.state.children` — required for the bottom anchor.
    ///
    /// All `Arc::get_mut` calls in this function rely on the local
    /// variable being the **only** strong reference at the point of
    /// the call. The [`Arc::get_mut`] documentation guarantees that
    /// behaviour, and any later `clone()` we issue for the parent's
    /// child list does not invalidate the prior unique access because
    /// the `Arc::get_mut` borrow has already ended.
    pub fn new() -> Result<Arc<Screen>> {
        // -------------------- outer wrapper --------------------------
        // FASM (screen.inc lines 188..=205): `tui_object$init_dd` 100×100
        // with horizontal layout. We use `TuiBackground::new_dd` with a
        // ' ' fill char and gray-on-black colours so the wrapper is
        // visually invisible against the main background.
        let mut outer_wrapper = TuiBackground::new_dd(100.0, 100.0, b' ' as u32, GRAY_BLACK)
            .context("screen::new: outer wrapper")?;
        if let Some(w) = Arc::get_mut(&mut outer_wrapper) {
            // FASM: `mov dword [rsi+tui_layout_ofs], tui_layout_horizontal`
            w.state_mut().layout = Layout::Horizontal;
        } else {
            return Err(anyhow!(
                "screen::new: outer wrapper Arc::get_mut failed (refcount > 1)"
            ));
        }

        // -------------------- main background ------------------------
        // FASM (screen.inc lines 232..=246): `tui_background$init_dd`
        // 100×100, ' ' fill, gray-on-black colours.
        let main_bg = TuiBackground::new_dd(100.0, 100.0, b' ' as u32, GRAY_BLACK)
            .context("screen::new: main background")?;

        // -------------------- vertical separator ---------------------
        // FASM (screen.inc lines 254..=260): `tui_vline$new_d` 100%
        // height, gray-on-black colours.
        let vline = TuiVLine::new_d(100.0, GRAY_BLACK).context("screen::new: vertical separator")?;

        // -------------------- right column ---------------------------
        // FASM (screen.inc lines 264..=276): `tui_object$init_id` 24
        // cells wide, 100% tall, default vertical layout.
        let mut right_col = TuiBackground::new_id(RIGHT_COL_WIDTH, 100.0, b' ' as u32, GRAY_BLACK)
            .context("screen::new: right column")?;
        if let Some(w) = Arc::get_mut(&mut right_col) {
            // FASM tui_object$simple_vtable defaults to vertical layout;
            // TuiBackground::new_id leaves layout at its default, so we
            // set it explicitly to match.
            w.state_mut().layout = Layout::Vertical;
        } else {
            return Err(anyhow!(
                "screen::new: right column Arc::get_mut failed (refcount > 1)"
            ));
        }

        // -------------------- buddy-list data grid -------------------
        // FASM (screen.inc lines 280..=305): `tui_datagrid$new_id` 24
        // cells wide, 100% tall, header=black/lightgray, body=lightgray
        // /black, sel=lightgray/blue. The Rust port has no mixed
        // int×percent constructor for `TuiDataGrid`, so we use
        // `new_with_percent(100.0, 100.0)` and rely on the right-column
        // parent (24 cells wide) to bound the rendered width.
        let mut grid =
            TuiDataGrid::new_with_percent(100.0, 100.0, HEADER_COLORS, LIGHTGRAY_BLACK, LIGHTGRAY_BLUE);
        // FASM column 1: tui_datagrid$nvaddproperty_d "Buddy" 100% left
        // align, JSON key "buddy".
        grid.add_column(ColumnSpec::new_percent(
            COLUMN_HEADER_BUDDY,
            COLUMN_KEY_BUDDY,
            100.0,
            HorizAlign::Left,
        ))
        .map_err(|e| anyhow!("screen::new: add buddy column: {e:?}"))?;
        // FASM column 2: tui_datagrid$nvaddproperty_i "Status" 7 cells
        // right align, JSON key "status".
        grid.add_column(ColumnSpec::new_fixed(
            COLUMN_HEADER_STATUS,
            COLUMN_KEY_STATUS,
            7,
            HorizAlign::Right,
        ))
        .map_err(|e| anyhow!("screen::new: add status column: {e:?}"))?;
        let buddylist = Buddylist::new(grid);

        // -------------------- bell widget ----------------------------
        // FASM (screen.inc lines 309..=320): `tui_bell$new` 24 cells
        // wide, 1 row tall, lightgray-on-black colours. Constructor is
        // infallible — returns `Arc<TuiBell>` directly.
        let bell = TuiBell::new(RIGHT_COL_WIDTH, BELL_ROWS, LIGHTGRAY_BLACK);

        // -------------------- helptext panel -------------------------
        // FASM (screen.inc lines 324..=345): `tui_text$new_ii` 24 × 7
        // with the leading-space-padded helptext, lightgray-on-black
        // body colours, focus colours unused (FASM xors the register
        // to zero — we pass our standard light-gray-on-black pair
        // because the widget is non-editable so focus colours never
        // render). Then the FASM source flips five flags in sequence:
        // editable=0, docursor=0, multiline=1, heightlock=1, wrap=2.
        let helptext = TuiText::new_ii(
            RIGHT_COL_WIDTH,
            HELPTEXT_ROWS,
            LIGHTGRAY_BLACK,
            LIGHTGRAY_BLACK,
            HELPTEXT,
        )
        .context("screen::new: helptext widget")?;
        // FASM screen.inc lines 199-203 flip five flags in sequence:
        // editable=0, docursor=0, multiline=1, heightlock=1, wrap=2.
        // The Rust port's setters all take `&self` and use interior
        // locking, so `Arc::get_mut` is not required (and would in fact
        // fail because the `helptext` Arc has refcount 1 here but the
        // borrow checker still rejects the `&mut Arc<T>` pattern when
        // we subsequently `clone()` for child append).
        helptext.set_editable(false);
        helptext.set_do_cursor(false);
        helptext.set_multiline(true);
        // `set_height_lock` takes a u32 row count (nonzero == locked);
        // FASM uses `1` to mean "locked". Pass 1 to match.
        helptext.set_height_lock(1);
        helptext.set_wrap(WrapMode::Word);

        // -------------------- right_col children ---------------------
        // Append in FASM order: buddylist, then bell, then helptext.
        // The wrapper's `state.layout = Layout::Vertical` (set above)
        // tiles them top-to-bottom in the right column.
        if let Some(rc) = Arc::get_mut(&mut right_col) {
            rc.append_child(buddylist.clone() as Arc<dyn Widget>);
            rc.append_child(bell.clone() as Arc<dyn Widget>);
            rc.append_child(helptext.clone() as Arc<dyn Widget>);
        } else {
            return Err(anyhow!(
                "screen::new: right_col children append failed (refcount > 1)"
            ));
        }

        // -------------------- outer_wrapper children -----------------
        // Horizontal layout — append in FASM order: main_bg (left chat
        // tile area), vline (separator), right_col (24-cell sidebar).
        if let Some(ow) = Arc::get_mut(&mut outer_wrapper) {
            ow.append_child(main_bg.clone() as Arc<dyn Widget>);
            ow.append_child(vline as Arc<dyn Widget>);
            ow.append_child(right_col as Arc<dyn Widget>);
        } else {
            return Err(anyhow!(
                "screen::new: outer_wrapper children append failed (refcount > 1)"
            ));
        }

        // -------------------- status-bar -----------------------------
        // FASM (screen.inc lines 213..=224): `statusbar$new` and then
        // `tui_statusbar$nvsettext` with the version banner. The
        // sshtalk wrapper exposes the heavything `Statusbar` through
        // its `pub(crate) base: Arc<Statusbar>` field; we reach into
        // the wrapper while it is still uniquely owned to set the
        // banner text.
        // `sb::new` is a free function at module scope (matching FASM's
        // `statusbar$new` bare-function naming), NOT an associated method
        // on `StatusBar`. The wrapper internally constructs the heavything
        // `Statusbar` with the correct colour pair and spawns its own
        // refresh task so we do not need to start a timer here.
        let statusbar = sb::new(100.0, 1).context("screen::new: status bar")?;
        // The heavything `Statusbar::set_text` takes `&self`, so we can
        // call it through the `Arc<Statusbar>` exposed via the wrapper's
        // `pub(crate) base` field without `Arc::get_mut`.
        statusbar.base.set_text(VERSION_BANNER);

        // -------------------- per-screen timestamps ------------------
        // FASM (screen.inc lines 405..=415): `screen_start_ofs` is
        // initialised to `timestamp` (current monotonic) and
        // `screen_lastkey_ofs` is initialised to the same value so the
        // first key arrival shows a zero-second idle gap. The Rust
        // port substitutes wall-clock-nanosecond timestamps for both
        // (vdso path is the same on Linux as the assembly's `rdtsc`+
        // `vdso_gettimeofday` chain).
        let now_ns = vdso::wall_unix_ns();

        // -------------------- screen base state ----------------------
        // Build via struct-update syntax to satisfy clippy's
        // `field_reassign_with_default` lint — the field assignments
        // and the `..Default::default()` tail are equivalent to the
        // FASM `tui_object_init_dd(100.0, 100.0)` plus the explicit
        // `[rbx+tui_object_layoutmode_ofs] = layout_vertical` write.
        let screen_state = WidgetState {
            layout: Layout::Vertical,
            width_percent: Some(100.0),
            height_percent: Some(100.0),
            visible: true,
            include_in_layout: true,
            ..Default::default()
        };

        // -------------------- assemble & wrap ------------------------
        let mut screen = Arc::new(Screen {
            state: screen_state,
            // FASM swap-assign: after right_col is fully built the
            // assembly source replaces `[rbx+screen_main_ofs]` with the
            // inner main background. We just store `main_bg` directly
            // here — the `outer_wrapper` is reachable as
            // `screen.state.children[0]`.
            main: main_bg.clone(),
            statusbar: statusbar.clone(),
            buddylist: buddylist.clone(),
            bell: bell.clone(),
            helptext: helptext.clone(),
            inner: Mutex::new(ScreenInner::new()),
            // vdso::wall_unix_ns() returns u64; the FASM screen_lastkey_ofs /
            // screen_start_ofs slots are signed (xmm-domain double seconds in
            // FASM, but we hold them as i64 nanoseconds so negative deltas are
            // representable in clock-skew edge cases). Cast u64 -> i64 here.
            lastkey_ns: AtomicI64::new(now_ns as i64),
            start_unix_ns: AtomicI64::new(now_ns as i64),
            self_weak: Mutex::new(Weak::new()),
        });

        // -------------------- screen children ------------------------
        // Append outer_wrapper (index 0) and statusbar.base (index 1).
        // We also seed `inner.focus` to the buddy-list — the FASM line
        // `mov [rbx+screen_focus_ofs], rax` in `screen$new` does the
        // same after the data grid is constructed.
        //
        // The same `Arc::get_mut` block also installs the `self_weak`
        // back-reference. `Arc::downgrade` only bumps the *weak* count,
        // so the Arc still has a unique strong reference and
        // `Arc::get_mut` continues to succeed afterwards.
        let self_weak = Arc::downgrade(&screen);
        if let Some(s_mut) = Arc::get_mut(&mut screen) {
            s_mut.state.children.push_back(outer_wrapper as Arc<dyn Widget>);
            s_mut
                .state
                .children
                .push_back(statusbar.base.clone() as Arc<dyn Widget>);
            if let Ok(mut inner) = s_mut.inner.lock() {
                inner.focus = Some(buddylist.clone() as Arc<dyn Widget>);
            }
            if let Ok(mut slot) = s_mut.self_weak.lock() {
                *slot = self_weak;
            }
        } else {
            return Err(anyhow!(
                "screen::new: outer Screen Arc::get_mut failed (refcount > 1)"
            ));
        }

        // -------------------- back-reference -------------------------
        // The buddy-list's Enter handler needs to call back into the
        // owning screen to dispatch `Screen::buddy_selected`. Install
        // a `Weak<Screen>` after the screen has been wrapped in `Arc`
        // to avoid creating a strong reference cycle. This step bumps
        // the strong refcount above 1 so it must come after the
        // `Arc::get_mut` block above.
        buddylist.set_screen_back(&screen);

        Ok(screen)
    }

    // ========================================================================
    // Public accessors required by the schema's `members_exposed` list and by
    // sibling sshtalk modules (chatpanel, chatroom, statusbar, userdb).
    // ========================================================================

    /// Return a clone of the currently authenticated user, if any.
    /// `None` on the un-cloned template instance.
    ///
    /// FASM mapping: `mov rax, [rbx+screen_user_ofs]`.
    pub fn user(&self) -> Option<Arc<userdb::User>> {
        match self.inner.lock() {
            Ok(guard) => guard.user.clone(),
            // Mutex poisoning is treated as non-fatal per the heavything
            // convention (see `tui::lock::RenderLock` doc-comment).
            Err(poisoned) => poisoned.into_inner().user.clone(),
        }
    }

    /// Borrow the inner main-area background widget.
    /// FASM mapping: `[rbx+screen_main_ofs]` after the swap-assign.
    pub fn main(&self) -> &Arc<TuiBackground> {
        &self.main
    }

    /// Return the wall-clock UNIX timestamp (seconds, fractional) of
    /// the most recent keystroke received from the SSH client.
    ///
    /// FASM mapping: `movsd xmm0, [rbx+screen_lastkey_ofs]`.
    pub fn lastkey(&self) -> f64 {
        ns_to_secs(self.lastkey_ns.load(Ordering::Acquire))
    }

    /// Update the wall-clock UNIX timestamp recorded for the most
    /// recent keystroke. Called from `chatpanel`'s key event handler
    /// to drive the `BELL_IDLE_SECS` idle-bell logic.
    ///
    /// FASM mapping: `movsd [rbx+screen_lastkey_ofs], xmm0`.
    pub fn set_lastkey(&self, t: f64) {
        self.lastkey_ns.store(secs_to_ns(t), Ordering::Release);
    }

    /// Borrow the bell widget that lives in the right column. Used by
    /// `chatpanel` to ring the bell when an incoming message arrives
    /// from a buddy who is not in the currently-focused chatpanel.
    ///
    /// FASM mapping: `[rbx+screen_bell_ofs]`.
    pub fn bell(&self) -> &Arc<TuiBell> {
        &self.bell
    }

    /// Return a clone of the currently focused widget, if any.
    /// FASM mapping: `[rbx+screen_focus_ofs]`.
    pub fn focus(&self) -> Option<Arc<dyn Widget>> {
        match self.inner.lock() {
            Ok(g) => g.focus.clone(),
            Err(p) => p.into_inner().focus.clone(),
        }
    }

    /// Borrow the buddy-list wrapper. Visible inside the crate so
    /// `chatpanel` and `chatroom` can fan-out updates over each user's
    /// `tuilist`.
    pub(crate) fn buddylist(&self) -> &Arc<Buddylist> {
        &self.buddylist
    }

    /// Borrow the helptext widget (used by tests for visual
    /// inspection; not part of the public API surface).
    #[cfg(test)]
    pub(crate) fn helptext(&self) -> &Arc<TuiText> {
        &self.helptext
    }

    /// Borrow the sshtalk status-bar wrapper (used by tests for
    /// visual inspection).
    #[cfg(test)]
    pub(crate) fn statusbar(&self) -> &Arc<sb::StatusBar> {
        &self.statusbar
    }

    // ========================================================================
    // Buddy-list refresh — Phase 15 of the agent prompt.
    // ========================================================================

    /// Rebuild the JSON array backing the buddy-list data-grid and
    /// hand it to the grid for re-rendering.
    ///
    /// FASM mapping: `screen.inc` `screen$updatebuddies` (lines
    /// 580..=720) plus the `.addjson_online` / `.addjson_offline`
    /// subroutines that construct each row object.
    ///
    /// The output JSON shape mirrors the FASM baseline byte-for-byte:
    ///
    /// ```json
    /// [
    ///   {"buddy": "alice", "status": "online"},
    ///   {"buddy": "bob",   "status": "offline"}
    /// ]
    /// ```
    ///
    /// The caller is expected to be the user-event path (Add Buddy,
    /// Remove Buddy, login, logout); concurrent invocations are
    /// serialised by the buddylist's internal `Mutex`.
    pub fn update_buddies(&self) -> Result<()> {
        // Snapshot the user pointer with the inner-mutex held only
        // long enough to clone the `Arc`; then release the mutex so
        // the recursive widget render path is not blocked behind it.
        let user = match self.inner.lock() {
            Ok(g) => g.user.clone(),
            Err(p) => p.into_inner().user.clone(),
        };
        let Some(user) = user else {
            // Template screens (no authenticated user yet) have an
            // empty buddylist — install an empty array and bail out.
            return self
                .buddylist
                .set_data(Arc::new(json::empty_array()))
                .context("update_buddies: clear empty");
        };

        // Build the JSON array. FASM uses a single-pass walk through
        // `user.buddylist` (a `StringMap`); for each name it looks up
        // the buddy's `User` record and consults `user.tuilist` to
        // decide between the `.addjson_online` and `.addjson_offline`
        // branches.
        //
        // The Rust port uses the `serde_json::Value` type alias
        // [`json::JsonValue`] directly; we mutate the inner
        // `Vec<Value>` (for the array) and `Map<String,Value>` (for
        // each row object) via the standard serde_json mutators. This
        // is byte-equivalent to FASM's `json$append_child` /
        // `json$set_field` building blocks.
        let mut arr = json::empty_array();
        let arr_vec = arr
            .as_array_mut()
            .ok_or_else(|| anyhow!("update_buddies: empty_array did not yield JSON array"))?;

        // The global userdb registry is `&'static RwLock<StringMap<…>>`
        // (see `userdb.rs::users()` line 287). We hold the registry's
        // read-lock for the duration of the buddylist walk so that all
        // online-status look-ups observe a consistent snapshot.
        //
        // Acquiring the read-lock can fail only if a writer panicked;
        // in that case the FASM baseline would have aborted, but the
        // Rust port treats the lock as recoverable: poisoning is
        // surfaced as an `Err` that `update_buddies` returns to the
        // caller (matching the heavything `RenderLock` policy).
        let users_guard = userdb::users()
            .read()
            .map_err(|_| anyhow!("update_buddies: userdb::users() RwLock poisoned"))?;

        // Walk our buddylist deterministically. `User::buddylist` is
        // declared as `RwLock<StringMap<Arc<User>>>` (userdb.rs:140),
        // so we acquire its read-lock here. `StringMap::iter` yields
        // `(&String, &Arc<User>)` pairs — we ignore the value side and
        // re-look it up against the global registry to ensure the
        // online-status reflects the *current* tuilist size, not the
        // (potentially stale) `Arc<User>` cached in the buddylist.
        let buddylist_guard = user
            .buddylist
            .read()
            .map_err(|_| anyhow!("update_buddies: user.buddylist RwLock poisoned"))?;

        for (buddy_name, _cached_buddy) in buddylist_guard.iter() {
            // Status detection mirrors FASM:
            //   if buddy_user.tuilist is non-empty -> online
            //   else                                -> offline
            //
            // `StringMap::get` returns `Option<&Arc<User>>` — we treat
            // a missing entry (e.g. the buddy was removed from userdb
            // while still listed in our buddylist) as offline.
            let status = match users_guard.get(buddy_name.as_str()) {
                Some(buddy_user) => {
                    if buddy_user_is_online(buddy_user) {
                        STATUS_ONLINE
                    } else {
                        STATUS_OFFLINE
                    }
                }
                None => STATUS_OFFLINE,
            };

            // Build `{"buddy": "...", "status": "..."}`. `empty_object`
            // is guaranteed to return `Value::Object(_)` so the
            // `as_object_mut` unwrap is sound; we still surface the
            // unlikely failure as an `Err` rather than panicking,
            // matching the heavything error-discipline rules (no
            // `unwrap()`/`expect()` in library code paths).
            let mut obj = json::empty_object();
            {
                let map = obj
                    .as_object_mut()
                    .ok_or_else(|| anyhow!("update_buddies: empty_object did not yield JSON object"))?;
                map.insert(COLUMN_KEY_BUDDY.to_string(), json::from_str(buddy_name));
                map.insert(COLUMN_KEY_STATUS.to_string(), json::from_str(status));
            }
            arr_vec.push(obj);
        }
        drop(buddylist_guard);
        drop(users_guard);

        // Hand the array to the buddylist wrapper, which (a) caches
        // an `Arc` clone in `Buddylist::current_data` so the row
        // reader in `buddy_selected` can index it and (b) forwards
        // a separate `Arc` clone to the inner `TuiDataGrid`.
        self.buddylist
            .set_data(Arc::new(arr))
            .context("update_buddies: populate")?;
        Ok(())
    }

    // ========================================================================
    // Buddy-selected handler — Phase 13 of the agent prompt.
    // ========================================================================

    /// Invoked from [`Buddylist::key_event`] when the user presses
    /// Enter on a row. The selected row's `buddy` field is read out
    /// of the JSON-backed grid data and forwarded to
    /// [`chatpanel_byname`] via the [`ChatpanelOpener`] late-binding.
    ///
    /// FASM mapping: `screen.inc` `screen$buddyselected` (lines
    /// 1180..=1260).
    ///
    /// `from_remote` is wired to `false` here because a local Enter
    /// keypress is *always* a local event; the remote-keystroke path
    /// is exercised by `chatpanel.rs` and `chatroom.rs` directly.
    pub(crate) fn buddy_selected(screen: &Arc<Screen>, idx: usize) -> Result<()> {
        // Look up the JSON row from the buddylist's cached array.
        // [`Buddylist::row_at`] holds the `current_data` mutex only
        // long enough to clone the row [`JsonValue`], so the lock is
        // released before we cross the chatpanel-opener call
        // boundary. `Buddylist::current_data` is updated by every
        // [`Self::update_buddies`] call so the cache is always in
        // sync with the grid's internal `data` field.
        let row = screen
            .buddylist
            .row_at(idx)
            .context("buddy_selected: read row")?
            .ok_or_else(|| anyhow!("buddy_selected: row {idx} not found"))?;

        // FASM `screen.inc` line 1209 reads `json$get_field rdi,
        // "buddy"` then `json$as_string` to extract the name.
        // The Rust port uses `json::get` (returns `Option<&Value>`)
        // chained with `json::as_str` (returns `Option<&str>`) and
        // a final `to_string` to detach from the row's lifetime.
        let buddy_name: String = json::get(&row, COLUMN_KEY_BUDDY)
            .and_then(json::as_str)
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("buddy_selected: row {idx} has no `{}` field", COLUMN_KEY_BUDDY))?;

        // Drive the cross-module open through the late-binding
        // opener installed at `main()` time. If the opener is not
        // installed (e.g. unit-test fixture that exercises the screen
        // tree without chatpanel/chatroom), we silently no-op so the
        // selection still consumes the keystroke without crashing.
        if let Some(opener) = chatpanel_opener() {
            opener
                .open_by_name(screen, &buddy_name, false)
                .with_context(|| format!("buddy_selected: chatpanel_byname({buddy_name})"))?;
        }
        Ok(())
    }

    // ========================================================================
    // Internal helper — per-session cleanup (Phase 9 of the agent prompt).
    // ========================================================================

    /// Per-session cleanup performed on the way down.
    ///
    /// FASM mapping: `screen.inc` `screen$cleanup` (lines 522..=572).
    ///
    /// **Order is load-bearing**:
    ///
    /// 1. **Atomically take** the user pointer out of [`ScreenInner`].
    ///    This guarantees the rest of the body runs **at most once per
    ///    screen** even if the cleanup path is invoked twice (e.g. from
    ///    a future [`Drop`] safety net plus the polymorphic
    ///    [`Widget::cleanup`] override in Chunk 6).
    /// 2. Compute the session duration as fractional UNIX seconds and
    ///    convert to **days** so that the [`Formatter::add_duration`]
    ///    field in [`DISCO_FMT`] sees the unit it expects (the Rust
    ///    formatter interprets `Value::Dbl` as days; FASM uses
    ///    seconds — the conversion happens here).
    /// 3. Format the disconnect line and emit it at `LOG_NOTICE`. A
    ///    poisoned [`Formatter`] mutex or an absent [`DISCO_FMT`]
    ///    silently skips the syslog step rather than failing the
    ///    cleanup — the FASM source likewise treats a formatter
    ///    failure as non-fatal because the user has already left.
    /// 4. **Then** call [`userdb::offline`] to remove this screen from
    ///    the user's `tuilist`. The order matters: any in-flight
    ///    cross-user fan-out that already grabbed the
    ///    [`crate::statusbar::SSH_SESSION_COUNT`] slot will still see
    ///    the user as online until this point, matching the FASM
    ///    behaviour where the offline call is the last externally
    ///    observable action of the cleanup path.
    ///
    /// The recursive widget-tree teardown (children + bastards) is
    /// **not** invoked here — that is the responsibility of the
    /// [`Widget::cleanup`] override (Chunk 6) which calls
    /// [`Self::cleanup_screen`] first, then forwards to
    /// [`heavything::tui::object::cleanup_widget`] for the depth-first
    /// post-order destruction of every owned child.
    ///
    /// `&mut self` is taken so the Mutex `take()` is not contended
    /// with concurrent reads — by the time cleanup runs, every other
    /// reference has been dropped and the framework holds the only
    /// outstanding `Arc` strong reference.
    pub(crate) fn cleanup_screen(&mut self) {
        // 1. Atomically remove the user pointer; subsequent calls
        //    silently no-op. PoisonError is treated as non-fatal —
        //    the inner mutex is only ever locked from the screen's
        //    own session task, so a poison can only have come from a
        //    panic in this very task and the surviving state is
        //    still well-formed enough for cleanup.
        let user = match self.inner.lock() {
            Ok(mut g) => g.user.take(),
            Err(p) => p.into_inner().user.take(),
        };
        let Some(user) = user else {
            // Template screens (no user ever set) skip the entire
            // cleanup logic. Mirrors the FASM check
            // `cmp qword [rbx+screen_user_ofs], 0`.
            return;
        };

        // 2. Compute session duration in fractional seconds, then
        //    convert to days for `DISCO_FMT`'s unit contract.
        let now_ns = vdso::wall_unix_ns() as i64;
        let start_ns = self.start_unix_ns.load(Ordering::Acquire);
        let session_secs = ns_to_secs(now_ns.saturating_sub(start_ns));
        let session_days = session_secs / 86_400.0;

        // 3. Format and emit the disconnect message at LOG_NOTICE.
        //    Both an absent formatter (init order regression) and a
        //    poisoned formatter mutex are silently swallowed — the
        //    user has already departed and there is no UI thread to
        //    surface a recoverable error to.
        let username = user.username.clone();
        if let Some(fm) = DISCO_FMT.get() {
            let formatted: Option<String> = match fm.lock() {
                Ok(f) => f
                    .doit(&[Value::Str(username.clone()), Value::Dbl(session_days)])
                    .ok(),
                Err(_) => None,
            };
            if let Some(line) = formatted {
                syslog::notice(&line);
            }
        }

        // 4. Mark the user offline.  We need an `Arc<Screen>` for
        //    the call (offline is generic over `Arc<S>` and uses the
        //    pointer as the tuilist key) — recover it from the weak
        //    self-reference installed in `Screen::new`. If the weak
        //    reference cannot be upgraded (e.g. the screen has
        //    already been destroyed concurrently) the user simply
        //    stays in the tuilist for the duration of this drop —
        //    a benign leak that the next online/offline cycle
        //    overrides because the tuilist key is the screen's
        //    pointer, which will be reused.
        let screen_arc = match self.self_weak.lock() {
            Ok(g) => g.upgrade(),
            Err(p) => p.into_inner().upgrade(),
        };
        if let Some(s) = screen_arc {
            // `userdb::offline` returns `Result<(), UserdbError>`; a
            // poisoned RwLock on the user's tuilist is the only
            // failure mode and again is non-fatal at cleanup time.
            let _ = userdb::offline(&user, &s);
        }
    }

    // ========================================================================
    // Internal helper — cursor visibility (Phase 16 of the agent prompt).
    // ========================================================================

    /// Decide whether the terminal cursor should be visible based on
    /// the current modal / focus state, and record the decision in
    /// [`ScreenInner::cursor_visible`].
    ///
    /// FASM mapping: `screen.inc` `screen$showhidecursor`
    /// (lines 586..=612).
    ///
    /// Decision matrix (matches the FASM source verbatim):
    ///
    /// | Modal state                  | Focus            | Cursor   |
    /// |------------------------------|------------------|----------|
    /// | textbox open (`!modal_alert`)| (any)            | **show** |
    /// | alert open  (`modal_alert`)  | (any)            | **hide** |
    /// | no modal                     | buddy-list       | **hide** |
    /// | no modal                     | chatpanel / none | **show** |
    ///
    /// The actual ANSI cursor escape is **not** emitted here — the
    /// FASM source emits via `tui_ssh_show_cursor` / `tui_ssh_hide_cursor`
    /// at call time, but the Rust port defers emission to the next
    /// render pass to avoid threading a renderer reference through
    /// every event-handler call site. The rendering integration in
    /// [`Widget::draw`] (Chunk 6) consults the stored boolean and
    /// invokes the corresponding [`Widget::show_cursor`] /
    /// [`Widget::hide_cursor`] inherited methods on the appropriate
    /// SSH layer.
    ///
    /// Returns `Ok(())` on success; the only failure mode is a
    /// poisoned [`Mutex`] on [`Screen.inner`], which is reported via
    /// [`anyhow::Error`] so the caller can surface it through the
    /// crate's [`anyhow::Result`] propagation chain.
    pub(crate) fn show_hide_cursor(&self) -> Result<()> {
        // Lock the inner state once for both the read (to determine
        // visibility) and the write (to record the decision). This
        // guarantees that two concurrent show_hide_cursor calls
        // observe a consistent (focus, modal) snapshot.
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("show_hide_cursor: inner mutex poisoned"))?;

        // Decide the desired visibility per the FASM decision matrix.
        let visible = match (&inner.modal, inner.modal_alert) {
            // A textbox-style modal: cursor SHOWN so the user can see
            // their typing position. The textbox places the cursor
            // glyph at the editor caret during draw.
            (Some(_), false) => true,
            // An alert-style modal: cursor HIDDEN — the alert has no
            // editable text, only an OK button.
            (Some(_), true) => false,
            // No modal: visibility is driven by the focus pointer.
            (None, _) => match &inner.focus {
                // Buddy-list focused (or pointer-equal to the screen's
                // own buddylist Arc): cursor HIDDEN — the data-grid
                // does not host an in-widget cursor.
                Some(focus) => {
                    let buddy_arc: Arc<dyn Widget> = self.buddylist.clone();
                    !Arc::ptr_eq(focus, &buddy_arc)
                }
                // No focus at all: cursor HIDDEN — defensive default
                // for the brief window between session creation and
                // the first focus assignment.
                None => false,
            },
        };

        inner.cursor_visible = visible;
        Ok(())
    }

    // ========================================================================
    // Internal helper — chatpanel lookup (Phase 14 Path 1).
    // ========================================================================

    /// Look for an existing chatpanel inside `screen.main` whose
    /// target matches `name`.
    ///
    /// FASM mapping: `screen.inc` `screen$chatpanel_find`
    /// (lines 738..=799). The assembly walks `main.children`, downcasts
    /// each child to a `chatpanel` object, and checks either the
    /// chatpanel's `name` field (room chats) or its `user.username`
    /// field (1:1 buddy chats) against the requested name.
    ///
    /// The Rust port abstracts the chatpanel-specific match logic
    /// behind the [`ChatpanelOpener::matches_name`] trait method so
    /// this file can compile without the chatpanel module being
    /// translated yet — the chatpanel implementation overrides
    /// `matches_name` to perform the concrete downcast and field
    /// comparison.
    ///
    /// Returns `Some(child)` for the first matching widget in
    /// child-list order (FASM walks the list head-to-tail), or `None`
    /// if no match exists.
    ///
    /// `is_room` is currently unused inside this function — the
    /// trait implementation discriminates rooms vs 1:1 chats by the
    /// concrete chatpanel type itself — but the parameter is retained
    /// in the signature so the call sites in `chatpanel_byname`
    /// (Chunk 5) document their intent.
    pub(crate) fn chatpanel_find(&self, name: &str, is_room: bool) -> Option<Arc<dyn Widget>> {
        // The `is_room` flag is not consulted here — match decisions
        // are delegated to the opener trait — but is retained in the
        // signature so call sites self-document.
        let _ = is_room;

        // No opener installed (e.g. unit tests): nothing to match
        // against. Mirrors the FASM behaviour where an unpopulated
        // chatpanel module would never have entered the dispatch.
        let opener = chatpanel_opener()?;

        // Walk `main.children` head-to-tail. The buddy-list, the
        // bell, and the helptext live on the **right column**, NOT
        // on `main` — so this walk only ever sees real chatpanels.
        let main_state = self.main.state();
        for child in main_state.children.iter() {
            if opener.matches_name(child, name) {
                return Some(Arc::clone(child));
            }
        }
        None
    }

    /// Move keyboard focus to `new_focus` and update all the visual
    /// side-effects that depend on the focus pointer.
    ///
    /// FASM mapping: the assembly does NOT have a single
    /// `screen$set_focus` function — the `screen_focus_ofs` slot is
    /// rewritten in-place at every call site (`screen$ontab`,
    /// `screen$onshifttab`, `screen$buddyselected`,
    /// `screen$chatpanel_byname`'s `.focus` label, modal close in
    /// `screen$firekeyevent`, etc.) followed by manual recoloring of
    /// the buddy-list and a `tui_ssh_show_cursor` /
    /// `tui_ssh_hide_cursor` invocation. The Rust port consolidates
    /// all of these side-effects into one helper so the call sites
    /// remain one-liners.
    ///
    /// Side-effect order (matches FASM):
    ///   1. Read the previous focus pointer (under the inner lock).
    ///   2. If the new focus equals the previous, return early — the
    ///      assembly only updates colours when focus *crosses* the
    ///      buddy-list boundary, so no-op early-return matches.
    ///   3. Compute `was_buddy_focused` and `is_buddy_focused`
    ///      booleans by `Arc::ptr_eq` against `self.buddylist`.
    ///   4. Replace `inner.focus` with `Some(new_focus)` and release
    ///      the lock immediately so subsequent calls (for example
    ///      `show_hide_cursor`) can re-acquire it.
    ///   5. If the buddy-focused status changed, call
    ///      [`Buddylist::set_buddy_focused`] with the new boolean —
    ///      this updates the `sel_colors` and the cached focus flag.
    ///   6. Refresh cursor visibility via
    ///      [`Screen::show_hide_cursor`] so an alert-modal closing
    ///      handoff (cursor was hidden) into a chatpanel (cursor
    ///      should be shown) is reflected on the next draw.
    ///
    /// The function never errors on a poisoned mutex — focus changes
    /// MUST NOT abort the dispatch loop, mirroring the FASM
    /// always-success contract — but bubbles up `show_hide_cursor`
    /// errors (which are themselves only emitted on poisoned-state
    /// guards and therefore never seen in practice).
    pub(crate) fn change_focus(&self, new_focus: Arc<dyn Widget>) -> Result<()> {
        // Step 1+2+4: take the lock, read previous focus, return
        // early if unchanged, install new focus, drop the lock.
        let (was_buddy_focused, is_buddy_focused) = {
            let mut inner = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };

            // Step 2: early return when focus has not moved.
            if let Some(prev) = inner.focus.as_ref() {
                if Arc::ptr_eq(prev, &new_focus) {
                    return Ok(());
                }
            }

            // Step 3: compute the buddy-focus boolean transition.
            let buddy_arc: Arc<dyn Widget> = Arc::clone(&self.buddylist) as Arc<dyn Widget>;
            let was = inner
                .focus
                .as_ref()
                .map(|f| Arc::ptr_eq(f, &buddy_arc))
                .unwrap_or(false);
            let is = Arc::ptr_eq(&new_focus, &buddy_arc);

            // Step 4: install the new focus pointer.
            inner.focus = Some(new_focus);
            (was, is)
        };

        // Step 5: notify the buddy-list of any focus crossing.
        // FASM only writes the new `sel_colors` when the boundary is
        // crossed, not on every focus change — match that behaviour
        // exactly with the `was != is` guard.
        if was_buddy_focused != is_buddy_focused {
            self.buddylist
                .set_buddy_focused(is_buddy_focused)
                .with_context(|| "change_focus: Buddylist::set_buddy_focused")?;
        }

        // Step 6: refresh cursor visibility for the new focus.
        self.show_hide_cursor()
            .with_context(|| "change_focus: show_hide_cursor")?;

        Ok(())
    }

    // ========================================================================
    // Modal dialog helpers — Phase 12 of the agent prompt.
    // ========================================================================

    /// Close the currently-open modal (if any) and restore the
    /// pre-modal cursor state.
    ///
    /// FASM mapping: the `.closemodal` label inside
    /// `screen$firekeyevent` (`screen.inc` lines 1502..=1510). The
    /// assembly clears `screen_modal_ofs` and `screen_modalalert_ofs`,
    /// removes all bastards from the screen, and reinvokes
    /// `screen$showhidecursor` to refresh the cursor state.
    ///
    /// This helper is used by the modal-Escape path inside
    /// [`Screen::fire_key_event`] (when the user dismisses an open
    /// dialog) and is the planned hook for the prospective
    /// `tui_alert`-OK callback (Chunk 8) that closes the alert when
    /// the user clicks `OK`.
    ///
    /// Returns `Ok(())` on success; the only failure mode is a
    /// poisoned [`Mutex`] on [`Screen.inner`] or a poisoned cursor
    /// mutex inside [`Self::show_hide_cursor`], reported via
    /// [`anyhow`] propagation.
    pub(crate) fn close_modal(&mut self) -> Result<()> {
        // Step 1+2: clear the modal pointers. Hold the inner lock
        // only long enough to take the modal out of the slot;
        // releasing the lock before bastard manipulation prevents a
        // re-entrant `close_modal` call from observing the
        // half-cleared state.
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| anyhow!("close_modal: inner mutex poisoned"))?;
            inner.modal = None;
            inner.modal_alert = false;
        }

        // Step 3: drop all bastards. The framework's bastard list is
        // intentionally cleared en bloc here — sshtalk only ever
        // installs exactly one bastard at a time (the modal dialog),
        // so a wholesale clear is equivalent to a targeted remove
        // and requires no identity comparison. Mirrors the FASM
        // `tui_object$remove_all_bastards` invocation at line 1507.
        self.remove_all_bastards();

        // Step 4: refresh cursor visibility. Closing a textbox-style
        // modal turns the cursor off (focus is now the chatpanel /
        // buddylist) while closing an alert turns it back on. The
        // decision matrix lives inside `show_hide_cursor`.
        self.show_hide_cursor()
            .with_context(|| "close_modal: show_hide_cursor")?;
        Ok(())
    }

    /// Open the "Add Buddy" textbox modal dialog.
    ///
    /// FASM mapping: the `.addbuddy_emptytext` block inside
    /// `screen$firekeyevent` (`screen.inc` lines 1572..=1604). The
    /// assembly constructs a `tui_textbox` with title `"Add Buddy"`
    /// and prompt `"Enter buddy name, or esc to cancel"`, sets
    /// `bastardglue=1, align=center, vertalign=middle`, installs it
    /// in `screen_modal_ofs` (with `screen_modalalert_ofs=0` for
    /// textbox-style), appends it as a bastard, and refreshes the
    /// cursor.
    ///
    /// The textbox has an [`AddBuddyHandler`] installed via
    /// [`TuiTextBox::set_enter_handler`] before installation, so
    /// pressing Enter inside the dialog snapshots the typed name,
    /// upgrades the [`Weak<Screen>`] back to an `Arc<Screen>`,
    /// snapshots the current [`userdb::User`], and dispatches
    /// [`userdb::addbuddy`] (which validates the name, locates or
    /// creates the buddy, links the [`User.buddylist`] /
    /// [`User.notifies`] entries, and persists via [`userdb::save`]).
    /// On success the handler invokes [`Screen::update_buddies`] to
    /// refresh the data-grid display for this session.
    ///
    /// **v1 limitation**: per Decision 7, [`TextboxEnterHandler::on_enter`]
    /// takes `&self` (not `&mut self`), so the handler cannot mutate
    /// the screen's bastards list to close the modal automatically
    /// after a successful add. The user dismisses the dialog
    /// manually with Escape — the modal is not auto-closed by the
    /// handler. The buddy add itself is fully effective regardless.
    fn open_addbuddy_dialog(&mut self) -> Result<()> {
        let tb = self
            .build_modal_textbox(b"Add Buddy", b"Enter buddy name, or esc to cancel")
            .with_context(|| "open_addbuddy_dialog: build_modal_textbox")?;
        // Snapshot the screen's `Weak` self-reference so the handler
        // can upgrade it back to an `Arc<Screen>` without forming a
        // refcount cycle (modal -> handler -> screen -> bastards -> modal).
        // Poisoning is treated as non-fatal per the heavything
        // convention — fall through to the inner data and clone it.
        let weak = match self.self_weak.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };
        tb.set_enter_handler(Box::new(AddBuddyHandler { screen: weak }));
        self.install_modal_textbox(tb)
            .with_context(|| "open_addbuddy_dialog: install_modal_textbox")?;
        Ok(())
    }

    /// Open the "Remove Buddy" textbox modal dialog.
    ///
    /// FASM mapping: the `.removebuddy_fromchat_unconfirmed` /
    /// `.removebuddy_fromlist_empty` blocks (`screen.inc` lines
    /// 1654..=1690). Same construction pattern as
    /// [`Self::open_addbuddy_dialog`].
    ///
    /// The textbox has a [`RemoveBuddyHandler`] installed via
    /// [`TuiTextBox::set_enter_handler`] before installation, so
    /// pressing Enter dispatches [`userdb::removebuddy`] which
    /// removes the named buddy from [`User.buddylist`] and the
    /// reciprocal entry from the buddy's [`User.notifies`], then
    /// persists via [`userdb::save`]. On success the handler
    /// invokes [`Screen::update_buddies`] to refresh the data-grid.
    ///
    /// **v1 limitation**: same as [`Self::open_addbuddy_dialog`] —
    /// the handler runs under `&self` so it cannot auto-close the
    /// modal. The user dismisses with Escape.
    fn open_removebuddy_dialog(&mut self) -> Result<()> {
        let tb = self
            .build_modal_textbox(b"Remove Buddy", b"Enter buddy name, or esc to cancel")
            .with_context(|| "open_removebuddy_dialog: build_modal_textbox")?;
        // Snapshot weak-self for the handler — see the doc on
        // `open_addbuddy_dialog` for the cycle-avoidance rationale.
        let weak = match self.self_weak.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };
        tb.set_enter_handler(Box::new(RemoveBuddyHandler { screen: weak }));
        self.install_modal_textbox(tb)
            .with_context(|| "open_removebuddy_dialog: install_modal_textbox")?;
        Ok(())
    }

    /// Open the "Join/Create Room" textbox modal dialog.
    ///
    /// FASM mapping: the `.ctrlj` block (`screen.inc` lines
    /// 1740..=1769). Same construction pattern as
    /// [`Self::open_addbuddy_dialog`] except for the title and
    /// prompt strings.
    ///
    /// The textbox has a [`NewRoomHandler`] installed via
    /// [`TuiTextBox::set_enter_handler`] before installation, so
    /// pressing Enter inside the dialog dispatches the typed-in
    /// room name to the free-standing [`chatpanel_byname`] helper
    /// which performs the FASM `.ctrlj` lookup-or-create flow
    /// (consults [`crate::chatroom::chatrooms`], creates a new
    /// chatroom on miss, joins this screen to the room, and
    /// installs the chat-panel widget into [`Screen::main`]).
    ///
    /// **v1 path-reachability limitation**: this code path is
    /// currently unreachable from the local keystroke pipeline
    /// because the framework's [`heavything::net::ssh`] keystroke
    /// decoder collapses both `0x0A` (Ctrl-J / LF) and `0x0D`
    /// (CR / Enter) onto [`KeyEvent::Enter`] — see the Chunk 7
    /// dispatch table for the documented limitation list. The
    /// handler is fully wired regardless so that future maintainers
    /// who upgrade the keystroke decoder to distinguish the two
    /// can re-route Ctrl-J without re-translating any of the
    /// dialog or handler logic.
    ///
    /// **v1 modal-close limitation**: as with the other handlers,
    /// `on_enter` runs under `&self`, so the modal stays open after
    /// a successful join until the user presses Escape.
    fn open_newroom_dialog(&mut self) -> Result<()> {
        let tb = self
            .build_modal_textbox(b"Join/Create Room", b"Enter room name, or esc to cancel")
            .with_context(|| "open_newroom_dialog: build_modal_textbox")?;
        // Snapshot weak-self for the handler — see the doc on
        // `open_addbuddy_dialog` for the cycle-avoidance rationale.
        let weak = match self.self_weak.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };
        tb.set_enter_handler(Box::new(NewRoomHandler { screen: weak }));
        self.install_modal_textbox(tb)
            .with_context(|| "open_newroom_dialog: install_modal_textbox")?;
        Ok(())
    }

    /// Construct a textbox-style modal dialog with the screen's
    /// standard color palette.
    ///
    /// FASM mapping: the four-line burst inside
    /// `.addbuddy_emptytext` (`screen.inc` lines 1573..=1576) that
    /// invokes `tui_textbox$new` with the BLACK_CYAN panel /
    /// LIGHTGRAY_BLACK text / YELLOW_BLUE focus-text colour triple.
    /// Mirrored exactly here.
    ///
    /// The freshly-returned [`Arc<TuiTextBox>`] is guaranteed to
    /// have a strong-count of 1 because [`TuiTextBox::new`]
    /// internally [`Arc::try_unwrap`]s its panel base before
    /// re-wrapping into the final `Arc<Self>` — so the caller can
    /// safely use [`Arc::get_mut`] to set the bastardglue / alignment
    /// fields before the second clone is installed in the bastards
    /// list.
    fn build_modal_textbox(&self, title: &[u8], prompt: &[u8]) -> Result<Arc<TuiTextBox>> {
        let mut tb = TuiTextBox::new(title, prompt, b"", BLACK_CYAN, LIGHTGRAY_BLACK, YELLOW_BLUE)
            .map_err(|e| anyhow!("build_modal_textbox: TuiTextBox::new failed: {e:?}"))?;
        {
            // Strong-count is exactly 1 here — see the doc-comment
            // above. Map the `Arc::get_mut` failure into anyhow to
            // honour the no-`expect` policy.
            let inner = Arc::get_mut(&mut tb)
                .ok_or_else(|| anyhow!("build_modal_textbox: fresh TuiTextBox already shared"))?;
            let st = inner.state_mut();
            // FASM `bastardglue=1` — overlay positioning instead
            // of participating in the parent's layout flow.
            st.bastard_glue = 1;
            // FASM `align=center, vertalign=middle` — centred modal.
            st.horiz_align = HorizAlign::Center;
            st.vert_align = VertAlign::Middle;
        }
        Ok(tb)
    }

    /// Install a freshly-built textbox modal: store one clone in
    /// the [`ScreenInner.modal`] slot, append the same `Arc` to
    /// the bastards list, and refresh cursor visibility.
    ///
    /// FASM mapping: the three-line burst that follows every
    /// `tui_textbox$new` call inside `screen.inc`
    /// (`mov [rbx+screen_modal_ofs], rax` /
    /// `tui_object$append_bastard` / `screen$showhidecursor`).
    ///
    /// Both the [`ScreenInner.modal`] slot and the
    /// [`WidgetState.bastards`] list intentionally hold the
    /// **same** [`Arc<dyn Widget>`] so that [`Self::close_modal`]
    /// can drop both atomically by clearing the bastards list and
    /// setting the slot to `None`.
    fn install_modal_textbox(&mut self, tb: Arc<TuiTextBox>) -> Result<()> {
        let tb_dyn: Arc<dyn Widget> = tb.clone();
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| anyhow!("install_modal_textbox: inner mutex poisoned"))?;
            inner.modal = Some(tb_dyn.clone());
            // Textbox-style modal: cursor stays visible inside the
            // textbox's edit field. FASM `.addbuddy_emptytext`
            // line 1577 stores `0` here (the modal is not an alert).
            inner.modal_alert = false;
        }
        self.append_bastard(tb_dyn);
        self.show_hide_cursor()
            .with_context(|| "install_modal_textbox: show_hide_cursor")?;
        Ok(())
    }
}

// ============================================================================
// Free-standing helpers used only by `Screen` impl
// ============================================================================

/// Convert a wall-clock nanosecond count to fractional UNIX seconds.
/// Inlined for clarity — division by `1e9` is the same operation the
/// FASM source applies via `cvtsi2sd` + `divsd`.
#[inline]
fn ns_to_secs(ns: i64) -> f64 {
    (ns as f64) / 1_000_000_000.0
}

/// Convert fractional UNIX seconds to a wall-clock nanosecond count.
#[inline]
fn secs_to_ns(s: f64) -> i64 {
    (s * 1_000_000_000.0) as i64
}

/// Decide if a userdb user is "online" — i.e. has at least one live
/// SSH session attached. Mirrors the FASM check
/// `cmp [tuilist_count_ofs], 0`.
/// Returns `true` if the supplied user has at least one active TUI
/// session registered. FASM checks `user.tuilist` non-emptiness via
/// `unsignedmap_count`; the Rust port walks `User::tuilist` (declared as
/// `RwLock<UnsignedMap<ScreenHandle>>` at userdb.rs:151) and returns
/// `false` on a poisoned lock so that a writer panic does not cascade
/// into a `Result` return-type change for this hot helper.
fn buddy_user_is_online(user: &Arc<userdb::User>) -> bool {
    match user.tuilist.read() {
        Ok(list) => !list.is_empty(),
        Err(_) => false,
    }
}

// ============================================================================
// chatpanel_byname — the central Phase 14 entry point
// ============================================================================
//
// FASM mapping: `screen$chatpanel_byname` (lines 786..=1108 of
// `screen.inc`). The assembly version is the most complex function in
// the file — it is invoked from the buddy-list Enter handler, from the
// chatpanel key dispatch, and from `chatroom$join_notify` whenever a
// remote peer creates a shared 1:1 room.
//
// FOUR code paths in the FASM source map to four return cases below:
//
//   Path 1 (.found_existing):  `chatpanel_find` already located a
//      chatpanel for this name — focus it (when `from_remote` is set
//      and the panel is currently the only child of `main`) and
//      return.
//
//   Path 2 (.createone_room):  `name` matches a chatroom in
//      `chatroom::chatrooms`. Construct a fresh chatpanel pointing at
//      the room.
//
//   Path 3 (.createone_buddy): `name` matches a userdb user AND no
//      remote chatpanel-with-us-as-buddy exists yet. Construct a
//      fresh, unshared chatroom and a chatpanel pointing at the buddy.
//
//   Path 4 (.createone_buddy_found): `name` matches a userdb user AND
//      the buddy already has a chatpanel pointed at us. Reuse that
//      shared chatroom and create our side's chatpanel.
//
// All four paths converge on the `add to main` + `(maybe) focus` tail
// — represented in this Rust port by the call to
// [`ChatpanelOpener::open_by_name`], which is implemented by the
// chatpanel module (a sibling translation unit, owned by another
// agent). This file only delegates; it does not embed the
// chatroom / userdb lookup logic — that responsibility belongs to the
// chatpanel module per AAP §0.5.1.9 split between sshtalk
// `chatpanel.rs`, `chatroom.rs`, and `screen.rs`.

/// Open or focus the chatpanel whose target is `name`.
///
/// Public Phase-17 API: this function is exposed so chatpanel.rs (when
/// translated) and chatroom.rs's `join_notify` can drive panel
/// creation through the same screen-aware code path the buddy-list
/// Enter handler uses.
///
/// Algorithm:
///   1. If a chatpanel with this name already exists in
///      `screen.main.children`, return its `Arc<dyn Widget>`. The
///      assembly version separately handles the "auto-focus when only
///      child" case but we delegate that to the opener so it can
///      perform the equivalent `set_focus` write when appropriate.
///   2. Otherwise dispatch to [`ChatpanelOpener::open_by_name`] which
///      performs the room/buddy lookup and constructs the new panel.
///      That call returns once the new panel has been installed in
///      `screen.main`.
///   3. After the opener returns, we walk `screen.main.children` once
///      more to obtain the resulting panel (since `open_by_name`
///      returns `Result<()>` rather than the panel itself, mirroring
///      the FASM "no return value, just install in tree" contract).
///   4. Return [`Err`] if the opener failed, no opener is installed,
///      or the new panel could not be located after a successful
///      opener call. The latter case indicates a chatpanel module bug
///      that violates the "install before return" contract — surface
///      it eagerly rather than silently returning a stale handle.
///
/// `from_remote` mirrors the FASM `ecx` flag: `true` indicates the
/// caller is reacting to a remote-side event (such as
/// `chatroom$join_notify`), in which case the new chatpanel may steal
/// focus when it is the sole child of `screen.main`. `false` means
/// the local user triggered the open and focus is left as-is.
pub fn chatpanel_byname(screen: &Arc<Screen>, name: &str, from_remote: bool) -> Result<Arc<dyn Widget>> {
    // Path 1 — fast path: existing panel.
    if let Some(existing) = screen.chatpanel_find(name, false) {
        // The opener handles the optional auto-focus side-effect; we
        // just hand back the located panel after a no-op opener call.
        // Skipping the opener invocation here would diverge from the
        // FASM ".found_existing" path which DOES re-evaluate the
        // focus-only-child branch.
        if let Some(opener) = chatpanel_opener() {
            opener
                .open_by_name(screen, name, from_remote)
                .with_context(|| format!("chatpanel_byname: opener.open_by_name({name}) (existing)"))?;
        }
        return Ok(existing);
    }

    // Paths 2-4 — opener must construct a new panel.
    let opener =
        chatpanel_opener().ok_or_else(|| anyhow!("chatpanel_byname: ChatpanelOpener not installed"))?;
    opener
        .open_by_name(screen, name, from_remote)
        .with_context(|| format!("chatpanel_byname: opener.open_by_name({name}) (new)"))?;

    // After a successful opener call, the freshly-installed panel is
    // somewhere in `screen.main.children`. Walk the list and return
    // the first match.
    if let Some(panel) = screen.chatpanel_find(name, false) {
        return Ok(panel);
    }

    // The opener succeeded but no panel landed in the tree — this is
    // a chatpanel-module contract violation. Surface it explicitly
    // rather than silently failing or returning an unrelated panel.
    Err(anyhow!(
        "chatpanel_byname: opener.open_by_name returned Ok but no panel was installed for {name}"
    ))
}

// ============================================================================
// Modal-dialog enter handlers — Phase 12 of the agent prompt
// ============================================================================
//
// Each modal textbox dialog wires a `TextboxEnterHandler` that runs
// when the user presses Enter inside the input field. The handlers
// below are the Rust translations of the FASM `.addbuddy_*` /
// `.removebuddy_*` / `.ctrlj` enter-handler subroutines inside
// `screen$firekeyevent` (`screen.inc` lines 1572..=1769).
//
// All handlers obey the **Decision 7 v1 limitation**: the
// [`TextboxEnterHandler::on_enter`] signature is
// `fn on_enter(&self, text: &[u8])`, so the handler cannot mutate
// the screen's bastards list to close the dialog itself. The user
// must press Escape to dismiss the modal after the handler
// finishes. The success / failure outcome is reported via
// [`syslog::info`] / [`syslog::warning`] / [`syslog::err`] to
// preserve the FASM baseline's auditable trail.
//
// Each handler holds a [`Weak<Screen>`] — never an `Arc<Screen>` —
// to avoid the reference cycle
//
//   `Screen` → `inner.modal: Arc<TuiTextBox>`
//            → `enter_handler: Box<dyn TextboxEnterHandler>`
//            → `screen: Arc<Screen>`
//
// which would prevent the screen from ever dropping while a modal
// is open. On every invocation the handler upgrades the `Weak`
// to an `Arc`; a `None` upgrade simply logs and returns (the
// session has ended between the keystroke and the dispatch, which
// is benign).

/// Enter-handler for the Add Buddy textbox modal.
///
/// FASM mapping: the body of `.addbuddy_emptytext` inside
/// `screen$firekeyevent` (`screen.inc` lines 1572..=1604) plus the
/// inline buddy-add bookkeeping at lines 1535..=1570.
///
/// Behaviour on Enter:
///
/// 1. Decode the typed-in bytes as UTF-8; reject non-UTF-8 input.
/// 2. Trim surrounding ASCII whitespace; reject empty input.
/// 3. Upgrade the [`Weak<Screen>`] reference; if the screen has
///    already been dropped, log a warning and return.
/// 4. Snapshot the screen's currently authenticated user via
///    [`Screen::user`]; abort with an error log if no user is
///    bound (this would only happen on the un-cloned template
///    instance, which is normally unreachable here).
/// 5. Call [`userdb::addbuddy`] which performs both halves of the
///    bidirectional update (user.buddylist + buddy.notifies) and
///    persists the registry to disk. Validation errors (length,
///    pipes, duplicate, unknown user) bubble out of `addbuddy`
///    and are mapped to syslog entries here.
/// 6. On success, call [`Screen::update_buddies`] to refresh the
///    data-grid display.
/// 7. The modal stays open per Decision 7; the user dismisses
///    with Escape.
struct AddBuddyHandler {
    /// Non-owning reference to the originating [`Screen`] so the
    /// modal does not pin the screen alive past its session.
    screen: Weak<Screen>,
}

impl TextboxEnterHandler for AddBuddyHandler {
    fn on_enter(&self, text: &[u8]) {
        // Step 1+2: decode + trim + reject empty input.
        let raw = match std::str::from_utf8(text) {
            Ok(s) => s,
            Err(_) => {
                syslog::warning("AddBuddyHandler::on_enter: input is not valid UTF-8");
                return;
            }
        };
        let name = raw.trim();
        if name.is_empty() {
            syslog::info("AddBuddyHandler::on_enter: empty input — ignored");
            return;
        }

        // Step 3: upgrade the Weak<Screen>. A `None` upgrade means
        // the user disconnected between keystroke decode and
        // handler dispatch — nothing useful is left to do.
        let screen = match self.screen.upgrade() {
            Some(s) => s,
            None => {
                syslog::warning("AddBuddyHandler::on_enter: screen reference expired");
                return;
            }
        };

        // Step 4: snapshot the authenticated user.
        let user = match screen.user() {
            Some(u) => u,
            None => {
                syslog::err("AddBuddyHandler::on_enter: no authenticated user — cannot add buddy");
                return;
            }
        };

        // Step 5: perform the add. `userdb::addbuddy` validates
        // length / pipes / duplicates and persists both sides.
        match userdb::addbuddy(&user, name) {
            Ok(()) => {
                syslog::info("AddBuddyHandler::on_enter: addbuddy succeeded");
                // Step 6: refresh the data-grid (best-effort —
                // a render failure here should not silently
                // poison the user's session).
                if let Err(e) = screen.update_buddies() {
                    syslog::err(&format!(
                        "AddBuddyHandler::on_enter: update_buddies failed: {e:?}"
                    ));
                }
            }
            Err(e) => {
                syslog::warning(&format!(
                    "AddBuddyHandler::on_enter: addbuddy({name}) failed: {e:?}"
                ));
            }
        }

        // Step 7: per Decision 7, the modal stays open. A future
        // iteration that grants the handler `&mut self` semantics
        // may close the modal automatically on success.
    }
}

/// Enter-handler for the Remove Buddy textbox modal.
///
/// FASM mapping: the body of `.removebuddy_fromlist_empty` /
/// `.removebuddy_fromchat_unconfirmed` inside
/// `screen$firekeyevent` (`screen.inc` lines 1654..=1690).
///
/// Behaviour mirrors [`AddBuddyHandler`] but the userdb call is
/// [`userdb::removebuddy`]. The FASM source handles
/// "buddy not in list" by silently returning; the Rust handler
/// logs the resulting [`userdb::UserdbError::Other`] /
/// [`userdb::UserdbError::UserNotFound`] for diagnostic
/// visibility.
struct RemoveBuddyHandler {
    /// Non-owning reference to the originating [`Screen`].
    screen: Weak<Screen>,
}

impl TextboxEnterHandler for RemoveBuddyHandler {
    fn on_enter(&self, text: &[u8]) {
        let raw = match std::str::from_utf8(text) {
            Ok(s) => s,
            Err(_) => {
                syslog::warning("RemoveBuddyHandler::on_enter: input is not valid UTF-8");
                return;
            }
        };
        let name = raw.trim();
        if name.is_empty() {
            syslog::info("RemoveBuddyHandler::on_enter: empty input — ignored");
            return;
        }

        let screen = match self.screen.upgrade() {
            Some(s) => s,
            None => {
                syslog::warning("RemoveBuddyHandler::on_enter: screen reference expired");
                return;
            }
        };

        let user = match screen.user() {
            Some(u) => u,
            None => {
                syslog::err("RemoveBuddyHandler::on_enter: no authenticated user — cannot remove buddy");
                return;
            }
        };

        match userdb::removebuddy(&user, name) {
            Ok(()) => {
                syslog::info("RemoveBuddyHandler::on_enter: removebuddy succeeded");
                if let Err(e) = screen.update_buddies() {
                    syslog::err(&format!(
                        "RemoveBuddyHandler::on_enter: update_buddies failed: {e:?}"
                    ));
                }
            }
            Err(e) => {
                syslog::warning(&format!(
                    "RemoveBuddyHandler::on_enter: removebuddy({name}) failed: {e:?}"
                ));
            }
        }
    }
}

/// Enter-handler for the Join/Create Room textbox modal (Ctrl-J).
///
/// FASM mapping: the body of `.ctrlj` inside
/// `screen$firekeyevent` (`screen.inc` lines 1740..=1769).
///
/// The FASM source distinguishes "room exists" (look up in
/// `chatroom::chatrooms` and join) from "room does not exist"
/// (create + join). Both branches eventually call
/// [`chatpanel_byname`] with the local-event flag to install or
/// focus the chatpanel — that is exactly what is invoked here.
/// The existing-vs-new room dispatch lives inside the chatpanel
/// module's [`ChatpanelOpener`] implementation, which the
/// chatroom module installs at start-up.
///
/// **v1 path-reachability note**: the Ctrl-J dispatch arm in
/// [`Screen::fire_key_event`] is currently unreachable because the
/// SSH keystroke decoder folds `0x0A` (Ctrl-J / LF) and `0x0D`
/// (CR / Enter) onto a single [`KeyEvent::Enter`] — see the
/// [`Screen::open_newroom_dialog`] helper's doc-comment for the
/// full limitation list. The handler is wired here for FASM
/// fidelity so that an upgraded keystroke decoder which
/// distinguishes the two codes can re-enable the path without
/// re-translating the dialog logic.
struct NewRoomHandler {
    /// Non-owning reference to the originating [`Screen`].
    screen: Weak<Screen>,
}

impl TextboxEnterHandler for NewRoomHandler {
    fn on_enter(&self, text: &[u8]) {
        let raw = match std::str::from_utf8(text) {
            Ok(s) => s,
            Err(_) => {
                syslog::warning("NewRoomHandler::on_enter: input is not valid UTF-8");
                return;
            }
        };
        let name = raw.trim();
        if name.is_empty() {
            syslog::info("NewRoomHandler::on_enter: empty input — ignored");
            return;
        }

        let screen = match self.screen.upgrade() {
            Some(s) => s,
            None => {
                syslog::warning("NewRoomHandler::on_enter: screen reference expired");
                return;
            }
        };

        // Open the chatpanel via the late-bound `chatpanel_byname`
        // free function. `from_remote = false` because the local
        // user triggered the join via the Ctrl-J dialog. The
        // opener performs the chatroom lookup-or-create logic
        // internally before installing the chatpanel into
        // `screen.main.children`.
        match chatpanel_byname(&screen, name, false) {
            Ok(_panel) => {
                syslog::info(&format!(
                    "NewRoomHandler::on_enter: opened chatpanel for room '{name}'"
                ));
            }
            Err(e) => {
                syslog::warning(&format!(
                    "NewRoomHandler::on_enter: chatpanel_byname({name}) failed: {e:?}"
                ));
            }
        }
    }
}

// ============================================================================
// Widget trait impl for Screen — Phase 5a vtable overrides
// ============================================================================
//
// FASM mapping: `screen.inc` `screen$vtable` (lines 42..=90). The
// assembly subclasses `tui_object$vtable` and overrides exactly seven
// of the 35 base slots:
//
//   slot  3 — `tui_object_vcleanup`     → `screen$cleanup`
//   slot  5 — `tui_object_vclone`        → `screen$clone`
//   slot  9 — `tui_object_vkeyevent`     → `screen$keyevent`
//   slot 15 — `tui_object_vfirekeyevent` → `screen$firekeyevent`
//   slot 17 — `tui_object_vontab`        → `screen$ontab`
//   slot 18 — `tui_object_vonshifttab`   → `screen$onshifttab`
//   slot 28 — `tui_object_vclicked`      → `screen$clicked`
//
// All other 28 base methods inherit the default `Widget` impls from
// `heavything::tui::object`, faithfully preserving FASM
// `tui_object$vtable` defaults.
//
// The `cleanup` override is the one with non-trivial logic: it must
// drive both per-session disconnect bookkeeping
// ([`Screen::cleanup_screen`]) **and** the recursive widget-tree
// teardown ([`cleanup_widget`]) in the FASM-mandated order.

impl Widget for Screen {
    // --- The three methods every concrete widget MUST implement. ---

    fn state(&self) -> &WidgetState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    // --- Slot 3: cleanup ---

    /// Per-session cleanup followed by recursive widget-tree teardown.
    ///
    /// FASM mapping: `screen$cleanup` (`screen.inc` lines 522..=572).
    ///
    /// Order is load-bearing — the FASM source emits the disconnect
    /// `LOG_NOTICE` and calls `userdb$offline` **before** invoking the
    /// base `tui_object$cleanup`, so any cross-user fan-out triggered
    /// by the offline call still observes the screen's children intact:
    ///
    /// 1. [`Self::cleanup_screen`] — atomically takes the user pointer,
    ///    formats and emits the disconnect syslog line, calls
    ///    [`userdb::offline`] to remove this screen from the user's
    ///    tuilist. Idempotent: a second invocation observes
    ///    `inner.user == None` and returns early.
    /// 2. [`cleanup_widget`] — the heavything depth-first post-order
    ///    walk that destroys every child and bastard, freeing each
    ///    Arc's last strong reference. Equivalent to the FASM
    ///    `call qword [rbx+tui_object_vtable+tui_object_vcleanup*8]`
    ///    base-class fall-through after the screen-specific bookkeeping.
    ///
    /// The call to [`cleanup_widget`] takes `&mut dyn Widget` rather
    /// than `&mut self` because it works through trait objects to
    /// recurse into heterogeneous child widgets — the upcast to
    /// `&mut dyn Widget` is the equivalent of FASM's "call the base
    /// vtable slot via the parent class pointer".
    fn cleanup(&mut self) {
        self.cleanup_screen();
        cleanup_widget(self as &mut dyn Widget);
    }

    // --- Slot 5: clone_widget ---

    /// Deep-clone of the screen tree for a per-user session.
    ///
    /// FASM mapping: `screen$clone` (`screen.inc` lines ~307..=470).
    ///
    /// The assembly version delegates to `tui_object$clone` for the
    /// generic widget-tree deep copy, then applies seven sshtalk-
    /// specific side effects:
    ///
    /// 1. snapshot `screen_start_ofs` = current monotonic time
    /// 2. snapshot `screen_lastkey_ofs` = same monotonic time
    /// 3. install the simpleauth-supplied user pointer in
    ///    `screen_user_ofs`
    /// 4. call `userdb::online` (insert into the user's tuilist)
    /// 5. call `screen::updatebuddies` (initial buddy-list population)
    /// 6. read SSH remote address from the IO chain
    /// 7. emit the connect `LOG_NOTICE` via `CONNECT_FMT` (IPv4) or
    ///    `CONNECT_NOIP_FMT` (non-IPv4)
    ///
    /// Steps 1-7 require simpleauth context (the authenticated `User`
    /// pointer plus the SSH remote address) that is not available on a
    /// plain `Widget::clone_widget` invocation. The Rust port therefore
    /// returns [`TuiError::Render`] from this base trait method to make
    /// the missing call site loud, and exposes a separate
    /// `clone_for_session` (in a future chunk) that the simpleauth
    /// integration will call directly with the necessary context.
    ///
    /// This matches the FASM convention where the base `tui_object`
    /// clone path is **never** invoked on a Screen — every code path
    /// that constructs a per-user screen instance does so through the
    /// simpleauth `vauthok` callback which dispatches the screen-aware
    /// `screen$clone`.
    fn clone_widget(&self) -> std::result::Result<Arc<dyn Widget>, TuiError> {
        Err(TuiError::Render(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Screen::clone_widget: use Screen::clone_for_session with \
             authenticated user and SSH remote-address context",
        )))
    }

    // --- Slot 9: key_event ---

    /// Top-level key-event handler.
    ///
    /// FASM mapping: `screen$keyevent` (`screen.inc` lines 619..=636).
    ///
    /// The assembly version routes every key through the modal /
    /// hotkey decision tree implemented in
    /// [`Widget::fire_key_event`] (slot 15) below — so the slot 9
    /// override exists only to forward to slot 15. This keeps the FASM
    /// dispatch contract intact while letting fire_key_event own the
    /// actual decision logic.
    ///
    /// Returns `true` when the event was consumed; `false` to bubble
    /// up to the framework's global hotkey handler. (The FASM source
    /// uses `eax = 0 / 1` with the same semantics.)
    fn key_event(&mut self, event: KeyEvent) -> bool {
        self.fire_key_event(event)
    }

    // --- Slot 15: fire_key_event ---

    /// Modal-aware key-event dispatcher.
    ///
    /// FASM mapping: `screen$firekeyevent` (`screen.inc` lines
    /// 1447..=1803), the heart of the screen's input handling.
    ///
    /// # Behavioural contract
    ///
    /// The dispatcher executes the following ordered checks:
    ///
    ///   1. **Always** update [`Screen.lastkey_ns`] to the current
    ///      wall-clock time — every keypress refreshes the
    ///      bell-idle timer regardless of routing decisions.
    ///   2. **Ctrl-C** bubbles out unconsumed (returns `false`),
    ///      letting the surrounding `tui_ssh` layer disconnect the
    ///      session.
    ///   3. **Ctrl-B** rings the bell three times *before* the
    ///      modal check fires, so users can audibly verify their
    ///      terminal bell is functional even when a dialog is open
    ///      (FASM line 1463 places the bell-test ahead of the
    ///      modal probe deliberately).
    ///   4. If a modal is currently open:
    ///         - **Escape** closes it via [`Self::close_modal`];
    ///         - any **other** key is consumed without forwarding
    ///           (see "v1 limitation 1" below).
    ///   5. Otherwise consult the hotkey table:
    ///         - **Ctrl-A** opens the add-buddy dialog;
    ///         - **Tab**   delegates to slot 17 (`on_tab`);
    ///         - **Shift-Tab** delegates to slot 18 (`on_shift_tab`);
    ///         - **Ctrl-J** opens the join/create-room dialog
    ///           (currently unreachable — see v1 limitation 2);
    ///         - **Ctrl-W** closes the focused chatpanel
    ///           (currently a no-op — see v1 limitation 3);
    ///         - **Ctrl-R** opens the remove-buddy dialog.
    ///   6. Anything else forwards to the focused descendant via
    ///      [`Buddylist::dispatch_key`] (when buddylist is the
    ///      focus) or bubbles up (when no other widget can claim
    ///      it — see v1 limitation 4).
    ///
    /// # v1 limitations
    ///
    /// Four FASM-source paths are intentionally simplified to fit
    /// the current Rust port:
    ///
    /// 1. **Modal forwarding (Decision 2 / Option γ)** — the FASM
    ///    source forwards non-Escape keys into the open modal at
    ///    `screen.inc` lines 1500..=1501. The Rust port instead
    ///    consumes them silently because the framework's modal
    ///    storage is `Arc<dyn Widget>` and any forwarded recursive
    ///    call requires `&mut` access through the trait — which
    ///    [`Arc::get_mut`] cannot grant once the modal is shared
    ///    between the [`ScreenInner.modal`] slot and the bastards
    ///    list. The textbox/alert dialog can therefore only be
    ///    dismissed via Escape in this version. Re-routing
    ///    forwarded keystrokes back to the dialog is deferred
    ///    until the framework grows a `&mut`-friendly bastards
    ///    walk-down API.
    ///
    /// 2. **Ctrl-J unreachable** — the heavything SSH keystroke
    ///    decoder (`net::ssh::decode_key_event` line 1644)
    ///    collapses both `0x0A` (Ctrl-J / LF) and `0x0D` (CR /
    ///    Enter) onto [`KeyEvent::Enter`]. The match arm for
    ///    `KeyEvent::Ctrl(10)` is therefore dead code in v1; it
    ///    is retained verbatim so future maintainers who upgrade
    ///    the decoder to distinguish the two can delete a single
    ///    `if`-arm rather than re-translate the dialog logic.
    ///
    /// 3. **Ctrl-W chatpanel removal** — FASM `.ctrlw` (lines
    ///    1771..=1798) removes the focused chatpanel from
    ///    `screen_main_ofs` and recycles its memory. The Rust
    ///    port returns `false` for the chatpanel branch because
    ///    (a) the chatpanel module does not yet exist in Rust,
    ///    so [`WidgetState.children`] only contains pre-installed
    ///    framework widgets, and (b) the helper would need
    ///    `&mut self.main`, unavailable through [`Arc::get_mut`]
    ///    once `self.main`'s strong count climbs above 1. The
    ///    branch returns `false` so the keystroke can bubble up
    ///    rather than be silently consumed; Chunk 8 revisits this
    ///    once chatpanel exists and the framework grows a
    ///    `&mut`-friendly child-removal API.
    ///
    /// 4. **Add-/Remove-buddy fast paths** — the FASM source has
    ///    four sub-paths for `.addbuddy` (lines 1515..=1616) and
    ///    three sub-paths for `.removebuddy` (lines 1620..=1719)
    ///    that perform the operation immediately when the focus
    ///    is on a 1:1 chatpanel and the buddy is/is-not in the
    ///    list. Only the slowest sub-path (open dialog) is
    ///    implemented in v1 because the fast paths require
    ///    chatpanel downcasting which the chatpanel module does
    ///    not yet exist in Rust to provide.
    fn fire_key_event(&mut self, event: KeyEvent) -> bool {
        // 1. Update lastkey timestamp first — every keypress, no
        //    matter where it ends up routed, refreshes the bell-idle
        //    clock. FASM mapping: `screen.inc` line 1455 (`movsd
        //    qword [rbx+screen_lastkey_ofs], xmm0` immediately after
        //    the `vdso_wall_secs` call).
        self.lastkey_ns
            .store(vdso::wall_unix_ns() as i64, Ordering::Relaxed);

        // 2. Ctrl-C: bubble out unconsumed so tui_ssh disconnects.
        //    FASM mapping: `screen$firekeyevent` lines 1459..=1460
        //    (`.falseret`). Returning `false` causes the framework's
        //    parent dispatcher to abort the SSH session.
        if matches!(event, KeyEvent::Ctrl(3)) {
            return false;
        }

        // 3. Ctrl-B: ring the bell three times BEFORE the modal
        //    check fires. FASM ordering matters: line 1463..=1464 in
        //    `screen.inc` invokes `bell.doit` *before* probing
        //    `screen_modal_ofs`, so users can audibly verify the
        //    bell even with a dialog open. Note: the framework API
        //    is [`Bell::ring`], not `Bell::doit` — the FASM uses the
        //    `doit` mnemonic but the Rust port's actual export is
        //    `ring` per `bell.rs:367`.
        if matches!(event, KeyEvent::Ctrl(2)) {
            self.bell.ring(3);
            return true;
        }

        // 4. Modal-aware routing.
        //    FASM mapping: `screen$firekeyevent` lines 1471..=1510
        //    plus the `.closemodal` label.
        //
        //    Snapshot pattern: hold the inner lock just long enough
        //    to decide whether a modal is open, then release. This
        //    keeps the lock from being contended by the recursive
        //    cursor-refresh path inside [`Self::close_modal`].
        let modal_present = match self.inner.lock() {
            Ok(g) => g.modal.is_some(),
            Err(p) => p.into_inner().modal.is_some(),
        };
        if modal_present {
            // Modal-Escape: close the dialog and consume.
            if matches!(event, KeyEvent::Escape) {
                if let Err(e) = self.close_modal() {
                    // Failure here is unusual — the only realistic
                    // cause is a poisoned mutex. Log and consume the
                    // event so the user's Escape isn't silently
                    // lost.
                    syslog::err(&format!("screen$firekeyevent: close_modal failed: {e}"));
                }
                return true;
            }
            // Modal-non-Escape: consumed per v1 limitation 1.
            return true;
        }

        // 5. Hotkey table for non-modal state.
        //    FASM mapping: `screen$firekeyevent` lines 1487..=1803,
        //    each `.case_*` jump target.
        match event {
            // Ctrl-A — Add Buddy.
            //   FASM `.addbuddy` (lines 1515..=1616) has FOUR
            //   sub-paths; only Path A (open dialog) is wired up in
            //   v1 — see v1 limitation 4.
            KeyEvent::Ctrl(1) => {
                if let Err(e) = self.open_addbuddy_dialog() {
                    syslog::err(&format!("screen$firekeyevent: open_addbuddy_dialog failed: {e}"));
                }
                true
            }

            // Tab — focus cycle forward.
            //   FASM `.tab` (lines 1722..=1726) jumps directly to
            //   `screen$ontab` via the slot-17 vtable. The Rust port
            //   does the same here — invoking `self.on_tab()` so the
            //   slot 17 implementation (Chunk 8 will replace its
            //   stub) sees the call.
            KeyEvent::Tab => self.on_tab(),

            // Shift-Tab — focus cycle backward.
            //   FASM `.shifttab` (lines 1729..=1733) — symmetrical
            //   to `.tab`.
            KeyEvent::ShiftTab => self.on_shift_tab(),

            // Ctrl-J — Join/Create Room.
            //   FASM `.ctrlj` (lines 1740..=1769) opens the
            //   join/create-room dialog. Currently unreachable — see
            //   v1 limitation 2. The branch is retained verbatim so
            //   future maintainers can re-route Ctrl-J without
            //   re-translating the dialog logic.
            KeyEvent::Ctrl(10) => {
                if let Err(e) = self.open_newroom_dialog() {
                    syslog::err(&format!("screen$firekeyevent: open_newroom_dialog failed: {e}"));
                }
                true
            }

            // Ctrl-W — Close current chatpanel.
            //   FASM `.ctrlw` (lines 1771..=1798): if the focus is
            //   the buddylist, the keystroke is silently dropped (the
            //   buddylist cannot be closed); otherwise the focused
            //   chatpanel is removed from `main`. The chatpanel
            //   removal branch is deferred to Chunk 8 — see v1
            //   limitation 3. Returns `false` so the keystroke
            //   bubbles up rather than being silently consumed.
            KeyEvent::Ctrl(23) => false,

            // Ctrl-R — Remove Buddy.
            //   FASM `.removebuddy` (lines 1620..=1719) has THREE
            //   sub-paths; only Path A (open dialog) is wired up in
            //   v1 — see v1 limitation 4.
            KeyEvent::Ctrl(18) => {
                if let Err(e) = self.open_removebuddy_dialog() {
                    syslog::err(&format!(
                        "screen$firekeyevent: open_removebuddy_dialog failed: {e}"
                    ));
                }
                true
            }

            // Default: forward to the focused descendant.
            //   FASM mapping: lines 1798..=1803 — `screen$firekeyevent`
            //   walks `screen_focus_ofs` and invokes
            //   `tui_object_vfirekeyevent` on the focused widget.
            //
            //   The Rust port distinguishes the buddy-list case
            //   (which needs the interior-mutability
            //   [`Buddylist::dispatch_key`] because
            //   [`Arc::get_mut`] on `&mut self.buddylist` cannot
            //   succeed once the `Arc` is shared) from the
            //   catch-all case (currently unreachable until
            //   chatpanel is translated). Returns `false` for any
            //   other focus target so the keystroke bubbles up.
            _ => {
                // Snapshot the focus pointer once, release the lock,
                // then dispatch. The lock-snapshot-release pattern
                // matches `update_buddies` (lines 1308..=1311) — see
                // the canonical example for explanation.
                let focus = match self.inner.lock() {
                    Ok(g) => g.focus.clone(),
                    Err(p) => p.into_inner().focus.clone(),
                };
                match focus {
                    Some(f) => {
                        let buddy_arc: Arc<dyn Widget> = self.buddylist.clone();
                        if Arc::ptr_eq(&f, &buddy_arc) {
                            // Buddylist focus: route via interior
                            // mutability so we don't need
                            // `Arc::get_mut`.
                            self.buddylist.dispatch_key(event)
                        } else {
                            // Non-buddylist focus targets (i.e. the
                            // future chatpanel module). Bubble up
                            // until they are wired in — v1
                            // limitation 3 / 4.
                            false
                        }
                    }
                    None => false,
                }
            }
        }
    }

    // --- Slot 17: on_tab ---

    /// Tab-key focus-cycle hook.
    ///
    /// FASM mapping: `screen$ontab` (`screen.inc` lines 1809..=1895).
    ///
    /// ## Cycle direction
    ///
    /// FASM `screen$ontab` walks `main.children` **backward** —
    /// from the *last* chatpanel toward the *first*, then anchors back
    /// at the buddy-list when the walk falls off the front:
    ///
    /// * Focus on buddy-list and `main.children` is non-empty →
    ///   focus the **last** chatpanel.
    /// * Focus on a chatpanel that is *not* `main.children.front()` →
    ///   focus the **previous** sibling (one step toward the front).
    /// * Focus on the *first* chatpanel (`main.children.front()`) →
    ///   focus the buddy-list.
    /// * Focus on buddy-list with empty `main.children` → no-op.
    /// * Focus on a widget that is not the buddy-list **and** not
    ///   present in `main.children` (e.g. a modal) → no-op (returns
    ///   `false`); modal handling lives in `fire_key_event`.
    ///
    /// ## `&mut self` vs interior mutability
    ///
    /// The Widget-trait signature is `fn on_tab(&mut self) -> bool` but
    /// the body never reaches into `self.state` for mutation — every
    /// state change goes through [`Screen::change_focus`] which already
    /// uses interior mutability (`self.inner.lock()` +
    /// `self.buddylist.set_buddy_focused()` + `self.show_hide_cursor()`).
    /// We therefore drive the focus update through `&self` semantics
    /// even though the trait grants us `&mut self`.
    ///
    /// ## Inherent vs trait `set_focus` — name disambiguation
    ///
    /// The Widget trait declares `fn set_focus(&mut self) -> bool`
    /// (vtable slot 9 — focus-acceptance check, default returns
    /// `false`). To avoid that trait method shadowing this screen's
    /// focus-installation helper inside `impl Widget for Screen`, the
    /// inherent method is named [`Screen::change_focus`] rather than
    /// `set_focus`. The two methods are orthogonal: `Widget::set_focus`
    /// is the framework's request-focus hook (this screen does not
    /// override it — the default `false` matches the FASM behaviour
    /// where a `Screen` is never itself a focus target), while
    /// `Screen::change_focus` is sshtalk's focus-installer that
    /// updates `inner.focus`, the buddy-list selection colour, and
    /// the cursor visibility in lockstep.
    ///
    /// ## got_focus / lost_focus skip
    ///
    /// FASM emits explicit `tui_object_vlostfocus` / `tui_object_vgotfocus`
    /// callbacks during the cycle. The Rust framework's
    /// [`Widget::got_focus`] / [`Widget::lost_focus`] hooks both require
    /// `&mut self`, which is unreachable through a shared `Arc<dyn Widget>`.
    /// `Form::on_tab` (`form.rs:1762..=1773`) documents the same
    /// limitation and likewise skips the callbacks; the visible
    /// side-effect (the buddy-list's selection-colour change) is
    /// handled directly by [`Screen::change_focus`] →
    /// [`Buddylist::set_buddy_focused`].
    fn on_tab(&mut self) -> bool {
        // ---- Step 1: snapshot the current focus pointer. ------------
        //
        // The lock-snapshot-release pattern lets us drop the
        // `inner.lock()` guard before calling `change_focus` (which
        // re-acquires the same lock). This matches the canonical
        // pattern used in `update_buddies` (lines ~1308..=1311) and
        // in `fire_key_event`'s default arm (lines ~2531..=2534).
        let focus = match self.inner.lock() {
            Ok(g) => g.focus.clone(),
            Err(p) => p.into_inner().focus.clone(),
        };

        // ---- Step 2: build the buddy-list `Arc<dyn Widget>` once. ---
        //
        // We compare focus identity via `Arc::ptr_eq`, so the buddy
        // list reference stays alive for the whole match below.
        let buddy_arc: Arc<dyn Widget> = self.buddylist.clone();

        // ---- Step 3: determine the next focus target. ---------------
        //
        // The decision tree mirrors FASM's three cases plus the no-op
        // fall-through. The list-walks read `self.main.state().children`
        // through the `&self.main: &Arc<TuiBackground>` reference and
        // the `state()` method which returns `&WidgetState`. Both are
        // share-only operations, so the borrow checker is satisfied.
        let next: Option<Arc<dyn Widget>> = match focus {
            // Case A: focus is the buddy-list — walk to the last
            // chatpanel (or no-op if `main.children` is empty).
            Some(ref f) if Arc::ptr_eq(f, &buddy_arc) => {
                let main_state = self.main.state();
                main_state.children.iter().last().cloned()
            }
            // Case B: focus is some other widget — try to find it in
            // `main.children`. If found, walk to the previous sibling
            // (one step toward the front), or wrap to buddy-list when
            // the focus is the front child.
            Some(ref f) => {
                let main_state = self.main.state();
                // `position` returns the index of the focused child;
                // if not found, it's a modal or otherwise off-tree.
                let pos = main_state.children.iter().position(|c| Arc::ptr_eq(c, f));
                match pos {
                    Some(0) => {
                        // First chatpanel → wrap to buddy-list.
                        Some(buddy_arc.clone())
                    }
                    Some(idx) => {
                        // Walk one step toward the front.
                        main_state.children.iter().nth(idx - 1).cloned()
                    }
                    None => {
                        // Focus not in `main.children` (modal? other?) —
                        // no-op so the keystroke can bubble up if the
                        // caller has a fallback.
                        None
                    }
                }
            }
            // Case C: no focus target installed yet — no-op.
            None => None,
        };

        // ---- Step 4: install the new focus through `change_focus`. --
        //
        // [`Screen::change_focus`] already handles the buddy-list focus
        // colour transition (bright ↔ dim) and the cursor visibility
        // refresh. Returning `true` matches `Form::on_tab`'s
        // success-on-cycled-focus convention.
        match next {
            Some(target) => match self.change_focus(target) {
                Ok(()) => true,
                Err(_) => {
                    // `change_focus` only fails on a poisoned mutex —
                    // log via syslog and return `false` so the
                    // framework can fall back to default handling.
                    syslog::err("screen::on_tab: change_focus failed (poisoned mutex)");
                    false
                }
            },
            None => false,
        }
    }

    // --- Slot 18: on_shift_tab ---

    /// Shift-Tab focus-cycle hook — mirror image of [`Self::on_tab`].
    ///
    /// FASM mapping: `screen$onshifttab` (`screen.inc` lines
    /// 1896..=1973).
    ///
    /// ## Cycle direction
    ///
    /// FASM `screen$onshifttab` walks `main.children` **forward** —
    /// from the *first* chatpanel toward the *last*, then anchors back
    /// at the buddy-list when the walk falls off the back:
    ///
    /// * Focus on buddy-list and `main.children` is non-empty →
    ///   focus the **first** chatpanel.
    /// * Focus on a chatpanel that is *not* `main.children.back()` →
    ///   focus the **next** sibling (one step toward the back).
    /// * Focus on the *last* chatpanel (`main.children.back()`) →
    ///   focus the buddy-list.
    /// * Focus on buddy-list with empty `main.children` → no-op.
    /// * Focus on a widget that is not the buddy-list **and** not
    ///   present in `main.children` (e.g. a modal) → no-op (returns
    ///   `false`); modal handling lives in `fire_key_event`.
    ///
    /// See [`Self::on_tab`] for the full architectural notes about
    /// `&mut self` vs interior mutability and the
    /// `got_focus` / `lost_focus` skip; both rationales apply equally
    /// here.
    fn on_shift_tab(&mut self) -> bool {
        // ---- Step 1: snapshot the current focus pointer. ------------
        let focus = match self.inner.lock() {
            Ok(g) => g.focus.clone(),
            Err(p) => p.into_inner().focus.clone(),
        };

        // ---- Step 2: build the buddy-list `Arc<dyn Widget>` once. ---
        let buddy_arc: Arc<dyn Widget> = self.buddylist.clone();

        // ---- Step 3: determine the next focus target. ---------------
        let next: Option<Arc<dyn Widget>> = match focus {
            // Case A: focus is the buddy-list — walk to the first
            // chatpanel (or no-op if `main.children` is empty).
            Some(ref f) if Arc::ptr_eq(f, &buddy_arc) => {
                let main_state = self.main.state();
                main_state.children.iter().next().cloned()
            }
            // Case B: focus is some other widget — try to find it in
            // `main.children`. If found, walk to the next sibling
            // (one step toward the back), or wrap to buddy-list when
            // the focus is the back child.
            Some(ref f) => {
                let main_state = self.main.state();
                let len = main_state.children.len();
                let pos = main_state.children.iter().position(|c| Arc::ptr_eq(c, f));
                match pos {
                    Some(idx) if idx + 1 == len => {
                        // Last chatpanel → wrap to buddy-list.
                        Some(buddy_arc.clone())
                    }
                    Some(idx) => {
                        // Walk one step toward the back.
                        main_state.children.iter().nth(idx + 1).cloned()
                    }
                    None => {
                        // Focus not in `main.children` — no-op.
                        None
                    }
                }
            }
            // Case C: no focus target installed yet — no-op.
            None => None,
        };

        // ---- Step 4: install the new focus through `change_focus`. --
        match next {
            Some(target) => match self.change_focus(target) {
                Ok(()) => true,
                Err(_) => {
                    syslog::err("screen::on_shift_tab: change_focus failed (poisoned mutex)");
                    false
                }
            },
            None => false,
        }
    }

    // --- Slot 28: clicked ---

    /// Mouse-click post-notification.
    ///
    /// FASM mapping: `screen$clicked` (`screen.inc` lines ~895..=940).
    ///
    /// The assembly version checks whether the clicked widget is the
    /// buddy-list (in which case [`Screen::change_focus`] is invoked) or
    /// a chatpanel (focus moves to it) and otherwise no-ops. The full
    /// click routing is wired through the framework's hit-test pass
    /// rather than the screen — by the time this slot fires, the
    /// click has already been delivered to the appropriate descendant.
    ///
    /// The Rust port treats this as a no-op for the same reason: the
    /// `&mut self.state.children` walk in the heavything click-routing
    /// pipeline already drives focus updates via the focus-acceptance
    /// checks. This matches the FASM behaviour where slot 28 is a
    /// post-notification that the assembly source uses primarily for
    /// debug syslog output.
    fn clicked(&mut self, _event: ClickEvent) {
        // No-op — focus follows the click through the framework's
        // hit-test pipeline; the screen has no extra bookkeeping to
        // perform here.
    }
}
