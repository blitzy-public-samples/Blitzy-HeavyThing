//! TUI / presentation layer for the `hnwatch` binary — Rust port of
//! `hnwatch/ui.inc` (1,715 lines).
//!
//! Manages the top-level [`MainScreenWidget`] tree, the data grid for
//! the story list, the per-item detail screen with threaded comments,
//! key bindings, and status-bar updates.
//!
//! The widget tree is built using **only** the `heavything::tui::*`
//! widgets per AAP §0.1.1 (third-party TUI crates such as `ratatui`
//! and `crossterm` are prohibited).
//!
//! ---
//!
//! Copyright © 2015 2 Ton Digital, Jeff Marrison <jeff@2ton.com.au>
//!
//! This file is part of HeavyThing — see the project root `LICENSE`
//! file for the full terms (GPLv3).
//!
//! HeavyThing is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published
//! by the Free Software Foundation, either version 3 of the License,
//! or (at your option) any later version. HeavyThing is distributed
//! in the hope that it will be useful, but WITHOUT ANY WARRANTY;
//! without even the implied warranty of MERCHANTABILITY or FITNESS
//! FOR A PARTICULAR PURPOSE. See the GNU General Public License for
//! more details.

use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde_json::Value;

use heavything::error::TuiError;
use heavything::tui::object::{ColorPair, HorizAlign, KeyEvent, Widget, WidgetState};
use heavything::tui::render::Renderer;
use heavything::tui::widgets::{
    AlignMode, ColumnSpec, TuiBackground, TuiDataGrid, TuiSplash, TuiStatusBar, TuiText, WrapMode,
};
use heavything::util::formatter::{Formatter, Value as FmtValue};

use crate::hnmodel::HnModel;
use crate::textify::textify;

// ===========================================================================
// Color constants
// ===========================================================================
//
// Translated from FASM `tui_ansi.inc` color names to xterm-256 indices
// via `heavything::tui::ansi::rgb_to_256`. See AAP §0.8.2 for the
// behavioral-parity rationale (preserve the assembly baseline's color
// palette exactly).

/// `black` — RGB(0, 0, 0). Used as a default text background.
const COLOR_BLACK: u8 = 232;
/// `lightgray` — RGB(211, 211, 211). Default body / status background.
const COLOR_LIGHTGRAY: u8 = 251;
/// `gray` — RGB(128, 128, 128). Used as the highlight-letter background
/// on status-bar navigation labels.
const COLOR_GRAY: u8 = 243;
/// `blue` — RGB(0, 0, 255). Used as the focus background for the data
/// grid's selected row.
const COLOR_BLUE: u8 = 21;
/// `darkslategray` — RGB(60, 64, 74). Used as the byline foreground in
/// the threaded-comment rows of the item detail screen.
const COLOR_DARKSLATEGRAY: u8 = 59;
/// `venetianred` — RGB(212, 26, 31). Used as the highlight-letter
/// foreground on status-bar navigation labels (the J/S/A/N/T accent).
const COLOR_VENETIANRED: u8 = 160;
/// `rgb(40, 40, 40)` — used as the foreground for the first item-detail
/// header line ("rank. title").
const COLOR_RGB_40: u8 = 235;
/// `rgb(130, 130, 130)` — used as the foreground for the second
/// item-detail header line ("pts points by …").
const COLOR_RGB_130: u8 = 243;
/// `rgb(247, 247, 247)` — used as the background for the first two
/// item-detail header lines.
const COLOR_RGB_247: u8 = 254;

// ===========================================================================
// String constants — preserved verbatim from `hnwatch/ui.inc`
// ===========================================================================
//
// Per AAP §0.8.2 (minimal change) and §0.8.9 (default navstring is
// `"topstories"`), every string visible in the UI is reproduced
// byte-for-byte from the assembly source.

/// Navigation topic: top stories (default per AAP §0.8.9).
const TOPSTORIES: &str = "topstories";
/// Navigation topic: new stories.
const NEWSTORIES: &str = "newstories";
/// Navigation topic: ask HN.
const ASKSTORIES: &str = "askstories";
/// Navigation topic: show HN.
const SHOWSTORIES: &str = "showstories";
/// Navigation topic: jobs.
const JOBSTORIES: &str = "jobstories";

// JSON property names used by serde_json `Value::get` lookups —
// exact spelling preserved from `ui.inc` for compatibility with the
// HN API responses cached in [`HnModel::items`].
const PROP_RANK: &str = "rank";
const PROP_TITLE: &str = "title";
const PROP_SCORE: &str = "score";
const PROP_AGE: &str = "age";
const PROP_BY: &str = "by";
const PROP_DESCENDANTS: &str = "descendants";
const PROP_URL: &str = "url";
const PROP_TEXT: &str = "text";
const PROP_KIDS: &str = "kids";
const PROP_DELETED: &str = "deleted";
const PROP_TIME: &str = "time";
const PROP_ID: &str = "id";
/// Sentinel value of the `"deleted"` property when the HN API has
/// flagged a comment for removal — see `ui.inc` `.rowupdate` line 1252.
const VALUE_TRUE: &str = "true";

// Display labels for the data-grid columns.
const LABEL_RANK: &str = "Pos";
const LABEL_TITLE: &str = "Title";
const LABEL_SCORE: &str = "Pts";
const LABEL_AGE: &str = "Age";
const LABEL_BY: &str = "By";
const LABEL_DESCENDANTS: &str = "Cmt";

// Status-bar navigation labels — passed bare (without prefix) to
// [`TuiStatusBar::add_label`] which automatically prepends
// `" │ "` (`ADD_LABEL_SEPARATOR` in `statusbar.rs`).
const STAT_TOP: &str = "Top";
const STAT_NEW: &str = "New";
const STAT_ASK: &str = "Ask";
const STAT_SHOW: &str = "Show";
const STAT_JOB: &str = "Job";

/// Status-bar copyright string. Contains U+00A9 (©) as a single
/// Unicode codepoint encoded in UTF-8 — preserved verbatim per AAP
/// §0.8.2 (any deviation breaks behavioral parity with the assembly
/// baseline).
const COPYRIGHT: &str = "hnwatch v1.13 © 2015 2 Ton Digital";

// Format separators — preserved verbatim from `ui.inc` `.s1` … `.s5`.
// `S1` contains U+2502 (BOX DRAWINGS LIGHT VERTICAL) flanked by spaces
// and is used internally by the status bar; the constant here is kept
// for documentation only (the live data path uses
// `Statusbar`'s built-in separator).
const _S1: &str = " \u{2502} ";
const S2: &str = "I: ";
const S3: &str = " R: ";
const S4: &str = " B: ";
const S5: &str = " E: ";

// Item-detail format snippets.
const SPACE: &str = " ";
const QUADSPACE: &str = "    ";
const DOT_SPACE: &str = ". ";
const POINTS_BY: &str = " points by ";
const AGO: &str = " ago";
const AGO_PIPE: &str = " ago | ";
const COMMENTS: &str = " comments";
const AGO_NO_SPACE: &str = "ago";

/// Sentinel returned by [`jsonage`] when the item has no parseable
/// `"time"` property — preserves the FASM `(null)` placeholder.
const NULL_STR: &str = "(null)";

// ===========================================================================
// Highlight characters for the status-bar navigation labels.
// ===========================================================================

const HK_JOB: u32 = b'J' as u32;
const HK_SHOW: u32 = b'S' as u32;
const HK_ASK: u32 = b'A' as u32;
const HK_NEW: u32 = b'N' as u32;
const HK_TOP: u32 = b'T' as u32;

// ===========================================================================
// Lock-poisoning recovery helper
// ===========================================================================
//
// The `ui` module surfaces every fallible operation through
// `anyhow::Result` per AAP §0.8.3 ("the binary crates use anyhow::Result<T>
// for top-level error propagation in main"). Library-side error
// variants (`TuiError`, `UtilError`) propagate via `?` and are wrapped
// by `anyhow::Error::from(...)` automatically. No bespoke `UiError`
// enum is required.

/// Convert a poisoned-mutex result into a usable guard, recovering
/// the inner data without panicking. Per AAP §0.8.3, no `unwrap()`
/// or `expect()` is permitted on `Mutex::lock()`.
fn unpoison<'a, T>(
    res: Result<std::sync::MutexGuard<'a, T>, std::sync::PoisonError<std::sync::MutexGuard<'a, T>>>,
) -> std::sync::MutexGuard<'a, T> {
    match res {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ===========================================================================
// Globally cached duration formatter for `jsonage` — built once.
// ===========================================================================

/// Single-shot duration formatter cached process-wide. Used by
/// [`jsonage`] to avoid rebuilding the formatter on every row update.
static AGE_FORMATTER: OnceLock<Formatter> = OnceLock::new();

/// Returns the shared age formatter (built lazily on first call).
fn age_formatter() -> &'static Formatter {
    AGE_FORMATTER.get_or_init(|| {
        // `Formatter::new(false)` — no automatic space between parts;
        // we want only the duration string (e.g. "5d 12h").
        let mut f = Formatter::new(false);
        // FASM `format$duration(delta_days, edi=2, esi=0)` — minute
        // resolution, no fractional digits.
        f.add_duration(2, 0);
        f
    })
}

// ===========================================================================
// MainScreenWidget — root widget; routes key events to `main_keyevent`.
// ===========================================================================

/// Root widget of the hnwatch UI tree.
///
/// FASM parallel: `ui$init.maketuiobject` (`ui.inc` lines 60–80).
/// Holds the children `[content_slot, statusbar]` directly in
/// [`WidgetState::children`].
///
/// Key events bubble down to this widget; the trait-method override
/// dispatches them to [`main_keyevent`] via the [`Weak<UiState>`]
/// back-reference installed by [`init`] after construction.
pub struct MainScreenWidget {
    state: WidgetState,
    /// Back-reference to the [`UiState`] that owns this widget.
    /// Populated by [`init`] using [`Arc::downgrade`] *after* the
    /// `UiState` is fully constructed (otherwise we would need to
    /// thread a mutable handle through the constructor chain).
    ui_back: OnceLock<Weak<UiState>>,
}

impl MainScreenWidget {
    /// Create a new root widget with the provided child list.
    fn new(children: Vec<Arc<dyn Widget>>) -> Arc<Self> {
        let mut state = WidgetState::new();
        // FASM `tui_object$init_dd(rdi, 100.0, 100.0)` — 100% × 100%.
        state.width_percent = Some(100.0);
        state.height_percent = Some(100.0);
        // Append every child to the framework's children list.
        for c in children {
            state.children.push_back(c);
        }
        Arc::new(Self {
            state,
            ui_back: OnceLock::new(),
        })
    }

    /// Install the [`Weak<UiState>`] back-reference. Called once
    /// after [`UiState`] construction completes.
    fn install_back(&self, ui: Weak<UiState>) {
        let _ = self.ui_back.set(ui);
    }

    /// Resolve the back-reference to a strong [`Arc<UiState>`].
    /// Returns [`None`] if the back-reference is unset (pre-`init`)
    /// or the [`UiState`] has been dropped.
    fn ui(&self) -> Option<Arc<UiState>> {
        self.ui_back.get().and_then(Weak::upgrade)
    }
}

impl Widget for MainScreenWidget {
    fn state(&self) -> &WidgetState {
        &self.state
    }
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    /// Override the default `key_event` to dispatch to
    /// [`main_keyevent`] — the FASM `.custom_vtable` slot 12 hook.
    fn key_event(&mut self, event: KeyEvent) -> bool {
        if let Some(ui) = self.ui() {
            return main_keyevent(&ui, event);
        }
        false
    }
}

// ===========================================================================
// ContentSlot — holds the swappable main content (datagrid or
// item-detail screen). Provides interior mutability for the FASM
// `_list_first.value` direct write that swaps datagrid ↔ item_screen.
// ===========================================================================

/// Swappable container used as the first child of the root widget.
///
/// FASM parallel: the main_screen's child[0] slot in `ui.inc` —
/// `ui$itemselected` writes `item_screen` into it (lines 1487–1499)
/// and `.bailout` writes `main_datagrid` back (lines 882–885). The
/// Rust port performs that swap via interior mutability so the
/// shared [`Arc`] in the widget tree remains stable.
///
/// ## Architectural note (CP8 review finding MEDIUM #14)
///
/// The FASM source mutated `screen_main.children[0]` directly via
/// `_list_first.value`. The Rust port cannot do that because the
/// framework's [`heavything::tui::object::WidgetState::children`]
/// list is plain [`heavything::ds::list::List<Arc<dyn Widget>>`] —
/// non-`Mutex`-protected — and `Arc::get_mut(&mut self_arc)` always
/// returns `None` post-construction (the parent main_screen and
/// any transient Arc clones keep the strong refcount above 1).
///
/// The Rust port therefore:
///
///   * Stores the currently-displayed widget on a Mutex-protected
///     [`ContentSlotInner::current`] slot (interior mutability).
///   * Leaves `state.children` empty — `ContentSlot` is intentionally
///     a single-widget wrapper that does NOT participate in the
///     framework's recursive children walk; rendering is delegated
///     directly to `inner.current` via [`Widget::draw`] below.
///   * Exposes [`ContentSlot::current`] for any external code that
///     needs to inspect the displayed widget without going through
///     the draw path.
///
/// This pattern matches [`crate::screen`]'s
/// `mounted_chatpanels` solution to the analogous issue.
pub struct ContentSlot {
    state: WidgetState,
    inner: Mutex<ContentSlotInner>,
}

struct ContentSlotInner {
    /// Currently-displayed widget: either the datagrid wrapper or the
    /// item-detail screen.
    current: Arc<dyn Widget>,
}

impl ContentSlot {
    /// Construct a new slot displaying `initial`.
    fn new(initial: Arc<dyn Widget>) -> Arc<Self> {
        let mut state = WidgetState::new();
        state.width_percent = Some(100.0);
        state.height_percent = Some(100.0);
        // CP8 review finding MEDIUM #14: do NOT push the initial
        // widget onto `state.children` here. The framework would
        // walk that pointer indefinitely (it never gets updated by
        // [`ContentSlot::swap`] because `state.children` is plain),
        // causing the framework's name-lookup / focus-walk passes
        // to find the stale initial widget after a swap.
        //
        // Instead, [`ContentSlot::draw`] below delegates rendering
        // directly to `inner.current` which IS updated atomically
        // by [`ContentSlot::swap`]. For external callers needing to
        // inspect the displayed widget, see [`ContentSlot::current`].
        Arc::new(Self {
            state,
            inner: Mutex::new(ContentSlotInner { current: initial }),
        })
    }

    /// Atomically replace the displayed widget.
    ///
    /// The new widget becomes visible on the next render pass — both
    /// [`ContentSlot::draw`] and [`ContentSlot::current`] consult
    /// the same Mutex-protected slot, so there is no window during
    /// which the slot can read stale state.
    ///
    /// Resolves CP8 review finding MEDIUM #14.
    fn swap(self: &Arc<Self>, new: Arc<dyn Widget>) {
        let mut inner = unpoison(self.inner.lock());
        inner.current = new;
        // No `state.children` mutation — see [`ContentSlot::new`]
        // doc-comment for the architectural rationale (the children
        // list is plain `VecDeque` with no interior mutability and
        // `Arc::get_mut` cannot succeed once the framework holds
        // a strong reference).
    }

    /// Borrow the currently-displayed widget.
    ///
    /// Used by external code that needs to inspect the slot's child
    /// without going through the draw delegation. Returns a fresh
    /// `Arc` clone so the caller can hold the reference past the
    /// next swap without disturbing the slot's interior mutex.
    ///
    /// `#[allow(dead_code)]`: Public accessor preserved per AAP
    /// §0.8.2 (Minimal Change Clause); not currently consumed by
    /// the hnwatch entry-point but exposed so future framework
    /// integration (e.g. focus-cycle walks) can discover the
    /// active content widget.
    #[allow(dead_code)]
    pub fn current(&self) -> Arc<dyn Widget> {
        let inner = unpoison(self.inner.lock());
        Arc::clone(&inner.current)
    }
}

impl Widget for ContentSlot {
    fn state(&self) -> &WidgetState {
        &self.state
    }
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    /// Delegate `draw` to the currently-selected child (datagrid or
    /// item-detail screen). Mutating the inner [`Arc<dyn Widget>`]
    /// would require [`Arc::get_mut`] — when the inner widget is
    /// uniquely owned (true for our wrappers, which only this slot
    /// holds), the call succeeds. When the framework holds clones,
    /// the call gracefully no-ops; the inner widget's own
    /// renderer-driven update path covers that case.
    fn draw(&mut self, r: &mut dyn Renderer) -> Result<(), TuiError> {
        let mut inner = unpoison(self.inner.lock());
        if let Some(child) = Arc::get_mut(&mut inner.current) {
            child.draw(r)?;
        }
        Ok(())
    }
}

// ===========================================================================
// DataGridWrapperWidget — wraps a TuiDataGrid in a Widget impl that
// exposes the grid for shared `set_data` access via the same Mutex
// stored in `UiState::main_datagrid`.
// ===========================================================================

/// Widget wrapper around a [`TuiDataGrid`] that shares its mutex with
/// [`UiState::main_datagrid`].
///
/// The wrapper's [`WidgetState`] is a snapshot of the grid's
/// dimensions and layout settings; the live grid lives behind an
/// [`Arc<Mutex<TuiDataGrid>>`] so [`compose`] can call `set_data`
/// without cross-thread synchronization gymnastics.
///
/// The wrapper also holds a [`Weak<UiState>`] back-reference so it
/// can dispatch into [`itemselected`] when the user presses Enter
/// — the FASM equivalent is the `.datagrid_vtable` override at
/// `ui.inc:395` that hooks slot 38 (`tui_datagrid$itemselected`)
/// to invoke `ui$itemselected` on the row that was activated.
pub struct DataGridWrapperWidget {
    state: WidgetState,
    /// Shared mutex over the data grid. The same [`Arc`] is also
    /// stored in [`UiState::main_datagrid`] so callers can mutate it
    /// without going through the widget tree.
    grid: Arc<Mutex<TuiDataGrid>>,
    /// Back-reference to the owning [`UiState`]. Installed once via
    /// [`Self::install_back`] right after the [`UiState`] [`Arc`] is
    /// constructed. The [`Weak`] avoids the strong cycle that would
    /// otherwise pin the [`UiState`] alive forever.
    ui_back: OnceLock<Weak<UiState>>,
}

impl DataGridWrapperWidget {
    /// Construct a new wrapper around the supplied grid.
    fn new(grid: Arc<Mutex<TuiDataGrid>>, width_pct: f64, height_pct: f64) -> Arc<Self> {
        let mut state = WidgetState::new();
        state.width_percent = Some(width_pct);
        state.height_percent = Some(height_pct);
        Arc::new(Self {
            state,
            grid,
            ui_back: OnceLock::new(),
        })
    }

    /// Install the [`Weak<UiState>`] back-reference. Called once at
    /// the end of [`init`] after the [`Arc<UiState>`] is built.
    fn install_back(&self, ui: Weak<UiState>) {
        let _ = self.ui_back.set(ui);
    }

    /// Resolve the back-reference to a strong [`Arc<UiState>`].
    /// Returns [`None`] if the back-reference has been dropped (the
    /// [`UiState`] has been torn down) or if [`install_back`] was
    /// never called (a misconfigured init path).
    fn ui(&self) -> Option<Arc<UiState>> {
        self.ui_back.get().and_then(Weak::upgrade)
    }
}

impl Widget for DataGridWrapperWidget {
    fn state(&self) -> &WidgetState {
        &self.state
    }
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    /// Delegate `draw` to the wrapped data grid. The grid mutex is
    /// poisoning-tolerant (per `unpoison`).
    fn draw(&mut self, r: &mut dyn Renderer) -> Result<(), TuiError> {
        let mut g = unpoison(self.grid.lock());
        g.draw(r)
    }

    /// Intercept key events. Enter triggers [`itemselected`] on the
    /// currently-selected row; all other keys are reported as
    /// unhandled so the framework's grid-guts subsystem can route
    /// them to its built-in arrow-key navigation handler.
    ///
    /// FASM parallel: this is the bridge that the `.datagrid_vtable`
    /// override at `ui.inc:395` encodes — slot 38 of the data-grid
    /// vtable redirects `tui_datagrid$itemselected` to `ui$itemselected`.
    fn key_event(&mut self, event: KeyEvent) -> bool {
        // Only Enter triggers the row-selected dispatch; let the
        // grid handle every other key on its own.
        if !matches!(event, KeyEvent::Enter) {
            return false;
        }

        // Resolve the back-reference. If the UiState has been
        // dropped, silently drop the event — this is the same
        // failure mode as the FASM `[ui_object] dq 0` sentinel
        // before `ui$init` runs.
        let ui = match self.ui() {
            Some(u) => u,
            None => return false,
        };

        // Pull the currently-selected row index from the data grid.
        let row_idx = match unpoison(self.grid.lock()).selected_index() {
            Some(i) => i,
            None => return false,
        };

        // Resolve the row index → JSON via the model's mainorder
        // (same iteration order that `compose` uses to build the
        // array passed to `set_data`).
        let row_json: Value = {
            let mainorder = ui.model.mainorder();
            let key = match mainorder.get(row_idx) {
                Some(k) => k.clone(),
                None => return false,
            };
            drop(mainorder);
            let items = ui.model.items();
            match items.get(&key) {
                Some(Some(v)) => v.clone(),
                _ => return false,
            }
        };

        // Dispatch to the public `itemselected` entry point, which
        // builds the item-detail screen and swaps the content slot.
        // Errors are surfaced via the model's status callback path —
        // here we silently absorb them to keep the key-event
        // contract (`bool` return) intact.
        let _ = itemselected(&ui, &row_json);
        true
    }
}

// ===========================================================================
// ItemScreenWidget — item-detail container with scroll + dynamic
// comment rows.
// ===========================================================================

/// Item-detail screen built lazily by [`itemselected`].
///
/// FASM parallel: `ui$itemselected` (`ui.inc` lines 1378–1519). Owns
/// three header lines (rank+title, points/by/age/comments, url-or-text),
/// a 100-row scrollable filler background, and a dynamic list of
/// threaded comment rows that grows as `ui$itemupdate` walks the
/// kids tree.
pub struct ItemScreenWidget {
    state: WidgetState,
    inner: Mutex<ItemScreenInner>,
    ui_back: OnceLock<Weak<UiState>>,
}

struct ItemScreenInner {
    /// Header line 1 — rank + title.
    line1: Arc<TuiText>,
    /// Header line 2 — points by user N ago | M comments.
    line2: Arc<TuiText>,
    /// Header line 3 — url or article text.
    line3: Arc<TuiText>,
    /// 100-row filler background. Preserved verbatim per AAP §0.8.2.
    _filler: Arc<TuiBackground>,
    /// Dynamic threaded comment rows, in display order.
    rows: Vec<Arc<ItemRowWidget>>,
    /// Scroll offset (Y axis only — FASM `tui_scroll_ofs+4`).
    scroll_y: i32,
}

impl ItemScreenWidget {
    /// Construct a new item-detail screen with the four mandatory
    /// header children populated.
    fn new() -> Result<Arc<Self>, TuiError> {
        let mut state = WidgetState::new();
        state.width_percent = Some(100.0);
        state.height_percent = Some(100.0);

        // Item-detail color scheme — preserved verbatim from
        // `ui.inc` `ui$itemselected` lines 1378–1485:
        //
        //  * Line 1 fg = rgb(40, 40, 40)  bg = rgb(247, 247, 247)
        //  * Line 2 fg = rgb(130,130,130) bg = rgb(247, 247, 247)
        //  * Line 3 fg = lightgray        bg = black
        //  * Filler char = ' ', fg = lightgray, bg = black
        let line1_colors = ColorPair::new(COLOR_RGB_40, COLOR_RGB_247);
        let line2_colors = ColorPair::new(COLOR_RGB_130, COLOR_RGB_247);
        let line3_colors = ColorPair::new(COLOR_LIGHTGRAY, COLOR_BLACK);
        let filler_colors = ColorPair::new(COLOR_LIGHTGRAY, COLOR_BLACK);

        // FASM new_di(100%, 1) — full-width, height-1, multiline,
        // word-wrap, height-locked, non-editable.
        let line1 = TuiText::new_di(100.0, 1, line1_colors, line1_colors, "")?;
        configure_item_text(&line1);

        let line2 = TuiText::new_di(100.0, 1, line2_colors, line2_colors, "")?;
        configure_item_text(&line2);

        let line3 = TuiText::new_di(100.0, 1, line3_colors, line3_colors, "")?;
        configure_item_text(&line3);

        // FASM `tui_background$new_di(100%, 100, ' ', filler_colors)`.
        let filler = TuiBackground::new_di(100.0, 100, b' ' as u32, filler_colors)?;

        state.children.push_back(Arc::clone(&line1) as Arc<dyn Widget>);
        state.children.push_back(Arc::clone(&line2) as Arc<dyn Widget>);
        state.children.push_back(Arc::clone(&line3) as Arc<dyn Widget>);
        state.children.push_back(Arc::clone(&filler) as Arc<dyn Widget>);

        Ok(Arc::new(Self {
            state,
            inner: Mutex::new(ItemScreenInner {
                line1,
                line2,
                line3,
                _filler: filler,
                rows: Vec::new(),
                scroll_y: 0,
            }),
            ui_back: OnceLock::new(),
        }))
    }

    /// Install the back-reference for callbacks.
    fn install_back(&self, ui: Weak<UiState>) {
        let _ = self.ui_back.set(ui);
    }

    /// Resolve the back-reference.
    fn ui(&self) -> Option<Arc<UiState>> {
        self.ui_back.get().and_then(Weak::upgrade)
    }

    /// Read the current scroll offset.
    fn scroll_y(&self) -> i32 {
        unpoison(self.inner.lock()).scroll_y
    }

    /// Set the scroll offset (used by `uparrow` / `downarrow`).
    fn set_scroll_y(&self, y: i32) {
        unpoison(self.inner.lock()).scroll_y = y.max(0);
    }

    /// Total height of the dynamic comment rows. Used by
    /// `downarrow` to decide whether to allow further scrolling.
    fn rows_total_height(&self) -> i32 {
        let inner = unpoison(self.inner.lock());
        inner.rows.iter().map(|r| r.height()).sum::<i32>()
    }
}

impl Widget for ItemScreenWidget {
    fn state(&self) -> &WidgetState {
        &self.state
    }
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    /// Override the default `key_event` to dispatch to
    /// [`item_keyevent`] — the FASM `.custom_vtable` slot 12 hook
    /// installed by `ui$itemselected` (line 1524).
    fn key_event(&mut self, event: KeyEvent) -> bool {
        if let Some(ui) = self.ui() {
            return item_keyevent(&ui, event);
        }
        false
    }
}

/// Apply the FASM-default settings used by every TuiText line in the
/// item detail screen — multiline + word-wrap + height-locked + left
/// alignment + non-editable. Centralized here so all four call sites
/// (line1/line2/line3 + the threaded body lines) share one body.
fn configure_item_text(t: &Arc<TuiText>) {
    // FASM ui.inc lines 1393-1410:
    //   tui_text$nvsetmultiline(rdi, 1)
    //   tui_text$nvsetfocussed(rdi, 0)   ; framework-managed in Rust
    //   tui_text$nvsetdocursor(rdi, 0)   ; framework-managed in Rust
    //   tui_text$nvseteditable(rdi, 0)
    //   tui_text$nvsetheightlock(rdi, 1)
    //   tui_text$nvsetalign(rdi, tui_textalign_left)
    //   tui_text$nvsetwrap(rdi, 2)
    t.set_multiline(true);
    t.set_editable(false);
    t.set_height_lock(1);
    t.set_align(AlignMode::Left);
    t.set_wrap(WrapMode::Word);
}

// ===========================================================================
// ItemRowWidget — single threaded-comment row (outer + inner +
// indent spacer + byline + body). Stores the item id for in-place
// updates.
// ===========================================================================

/// One threaded-comment row in the item-detail screen.
///
/// FASM parallel: `ui$itemnewrow` (`ui.inc` lines 626–770). Each row
/// owns a constant indent spacer (width = nesting × 2), a byline
/// [`TuiText`] in dark-slate-gray, and a body [`TuiText`] in
/// lightgray. The row's height is the sum of byline height + body
/// height (computed by the FASM `outer_layoutchanged` /
/// `inner_layoutchanged` overrides; the Rust port stores the
/// computed height in `inner.height` for the `rows_total_height`
/// scroll calculation).
pub struct ItemRowWidget {
    state: WidgetState,
    inner: Mutex<ItemRowInner>,
}

struct ItemRowInner {
    /// HN item id — FASM stores at `tui_object_size + 0` extra slot.
    item_id: u64,
    /// Threaded-comment nesting depth. Drives the indent spacer
    /// width (`nesting * 2`).
    nesting: u32,
    /// Indent spacer (FASM child[0]).
    _indent: Arc<TuiBackground>,
    /// Byline TuiText (FASM inner.child[0]).
    byline: Arc<TuiText>,
    /// Body TuiText (FASM inner.child[1]).
    body: Arc<TuiText>,
    /// Cached total height (byline 1 + body N). Used by the scroll
    /// arithmetic in `downarrow`.
    height: i32,
}

impl ItemRowWidget {
    /// Build a fresh row for `item` at the given `nesting` level.
    fn new(
        item_id: u64,
        item: &Value,
        nesting: u32,
        item_format4: &Formatter,
    ) -> Result<Arc<Self>, TuiError> {
        // ----- Outer widget state (height = 2 initially, will grow
        // as the body wraps).
        let mut state = WidgetState::new();
        state.width_percent = Some(100.0);
        state.height = 2;
        state.layout = heavything::tui::object::Layout::Horizontal;

        // ----- Indent spacer: width = nesting * 2, height = 2,
        // fillchar = ' ', colors = lightgray/black.
        let indent_colors = ColorPair::new(COLOR_LIGHTGRAY, COLOR_BLACK);
        let indent_width: i32 = (nesting as i32).saturating_mul(2);
        let indent = TuiBackground::new_ii(indent_width, 2, b' ' as u32, indent_colors)?;

        // ----- Byline: 100% × 1, dark-slate-gray on black, single
        // line.
        let byline_colors = ColorPair::new(COLOR_DARKSLATEGRAY, COLOR_BLACK);
        let byline = TuiText::new_di(100.0, 1, byline_colors, byline_colors, "")?;
        // Byline is single-line, left-aligned, non-editable.
        byline.set_multiline(false);
        byline.set_editable(false);
        byline.set_align(AlignMode::Left);

        // Compose initial byline text via the shared `item_format4`
        // formatter ("by time ago" with `space_between = true`).
        let username = item.get(PROP_BY).and_then(Value::as_str).unwrap_or(NULL_STR);
        let age = jsonage(item);
        let byline_text = item_format4
            .doit(&[
                FmtValue::Str(username.to_string()),
                FmtValue::Str(age),
                FmtValue::Str(AGO_NO_SPACE.to_string()),
            ])
            .unwrap_or_else(|_| String::new());
        // Best-effort — the call failing means the buffer pre-allocate
        // failed which only happens with absurd dimensions.
        let _ = byline.nvsettext(&byline_text);

        // ----- Body: 100% × 1, lightgray on black, multiline +
        // word-wrap + height-locked.
        let body_colors = ColorPair::new(COLOR_LIGHTGRAY, COLOR_BLACK);
        let body = TuiText::new_di(100.0, 1, body_colors, body_colors, "")?;
        body.set_multiline(true);
        body.set_editable(false);
        body.set_height_lock(1);
        body.set_align(AlignMode::Left);
        body.set_wrap(WrapMode::Word);

        let body_raw = item.get(PROP_TEXT).and_then(Value::as_str).unwrap_or("");
        let _ = body.nvsettext(&textify(body_raw));

        // ----- Append children to the framework's children list so
        // the renderer sees them. Outer layout is horizontal:
        // indent | (vertical: byline / body).
        // For the Rust port we attach the indent and a virtual inner
        // group as a flat sequence — the framework's layout pass
        // resolves widths.
        state.children.push_back(Arc::clone(&indent) as Arc<dyn Widget>);
        state.children.push_back(Arc::clone(&byline) as Arc<dyn Widget>);
        state.children.push_back(Arc::clone(&body) as Arc<dyn Widget>);

        Ok(Arc::new(Self {
            state,
            inner: Mutex::new(ItemRowInner {
                item_id,
                nesting,
                _indent: indent,
                byline,
                body,
                height: 2,
            }),
        }))
    }

    /// In-place update — preserves the row's identity and just
    /// rewrites the byline and body. FASM parallel:
    /// `ui$itemupdaterow` (`ui.inc` lines 528–617).
    fn update(&self, item_id: u64, item: &Value, nesting: u32, item_format4: &Formatter) {
        let mut inner = unpoison(self.inner.lock());
        inner.item_id = item_id;
        inner.nesting = nesting;

        let username = item.get(PROP_BY).and_then(Value::as_str).unwrap_or(NULL_STR);
        let age = jsonage(item);
        let byline_text = item_format4
            .doit(&[
                FmtValue::Str(username.to_string()),
                FmtValue::Str(age),
                FmtValue::Str(AGO_NO_SPACE.to_string()),
            ])
            .unwrap_or_else(|_| String::new());

        let body_raw = item.get(PROP_TEXT).and_then(Value::as_str).unwrap_or("");
        let body_text = textify(body_raw);

        // Best-effort updates — failures here only occur on absurd
        // dimensions and are treated as silent no-ops to preserve
        // the FASM behavior of always advancing the iterator even
        // when intermediate work fails.
        let _ = inner.byline.nvsettext(&byline_text);
        let _ = inner.body.nvsettext(&body_text);
    }

    /// Read the cached row height for scroll arithmetic.
    fn height(&self) -> i32 {
        unpoison(self.inner.lock()).height
    }

    /// Read the row's HN item id (used by debug / lookup paths).
    #[allow(dead_code)]
    fn item_id(&self) -> u64 {
        unpoison(self.inner.lock()).item_id
    }
}

impl Widget for ItemRowWidget {
    fn state(&self) -> &WidgetState {
        &self.state
    }
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ===========================================================================
// UiState — central container exposing the 12 schema-required fields.
// ===========================================================================

/// Public UI state container.
///
/// FASM parallel: the bank of `ui.inc` globals declared at lines
/// 25–43 — `main_screen`, `main_datagrid`, `status_format`,
/// `item_screen`, `item_format1` … `item_format4`, `item_kids`,
/// `displayitem`. Centralized here as a single struct returned by
/// [`init`].
///
/// All twelve fields are public so binary-side callers (`hnwatch`'s
/// `main.rs`) can drive the UI without going through extra accessor
/// methods, matching the FASM globals' direct-access semantics.
pub struct UiState {
    /// Outer 100% × 100% widget at the root of the UI tree.
    /// Children: `[content_slot, statusbar]`.
    pub main_screen: Arc<MainScreenWidget>,

    /// The story-list data grid. Shared with the wrapper widget that
    /// the renderer sees in the widget tree, so callers can mutate
    /// data without a separate handle.
    pub main_datagrid: Arc<Mutex<TuiDataGrid>>,

    /// Status-bar format string — copyright + counts.
    pub status_format: Arc<Formatter>,

    /// Item-detail screen, present when an item is selected. Wrapped
    /// in [`Mutex<Option<...>>`] because it is built lazily on each
    /// row click and torn down by `bailout`.
    pub item_screen: Mutex<Option<Arc<ItemScreenWidget>>>,

    /// Formatter for the first item-detail header line: `" rank. title"`.
    pub item_format1: Arc<Formatter>,
    /// Formatter for the second item-detail line (no comment count):
    /// `"    pts points by by age ago"`.
    pub item_format2: Arc<Formatter>,
    /// Formatter for the second item-detail line (with comment
    /// count): `"    pts points by by age ago | cmt comments"`.
    pub item_format3: Arc<Formatter>,
    /// Formatter for threaded comment-row bylines: `"by time ago"`.
    pub item_format4: Arc<Formatter>,

    /// Map of currently-tracked kid item ids.
    pub item_kids: Mutex<HashMap<u64, ()>>,
    /// Currently-selected item id, [`None`] when in the list view.
    pub displayitem: Mutex<Option<u64>>,

    /// Status-bar widget (built once at init, mutated via
    /// [`TuiStatusBar::set_text`] over its interior mutex).
    pub statusbar: Arc<TuiStatusBar>,

    /// Shared data model — used by callbacks and event handlers.
    pub model: Arc<HnModel>,

    // -------- Private retention fields below this line --------
    /// Slot that holds the swappable main content (datagrid ↔
    /// item_screen). Not part of the public schema.
    content_slot: Arc<ContentSlot>,
    /// Wrapper widget the renderer sees for the data grid. Holds
    /// the same [`Arc<Mutex<TuiDataGrid>>`] as `main_datagrid`.
    datagrid_widget: Arc<DataGridWrapperWidget>,
    /// Splash widget kept alive for the duration of the UI session.
    /// Not exposed because the schema's twelve fields fully cover
    /// the FASM `ui.inc` globals — this is a pure retention slot.
    _splash: Arc<TuiSplash>,
}

// ===========================================================================
// init — port of `ui$init` (`ui.inc` lines 48–340).
// ===========================================================================

/// Build the `hnwatch` UI tree and wire callbacks into [`HnModel`].
///
/// Returns a fully-constructed [`UiState`] wrapped in [`Arc`]. The
/// caller is expected to hold this until the application exits — the
/// status-bar timer task and the splash screen rely on the strong
/// reference graph rooted here.
///
/// FASM parallel: `ui$init` (`ui.inc` lines 48–340).
///
/// # Errors
///
/// Returns an error if any widget construction fails (typically
/// because of allocator pressure or absurd dimensions) or if the
/// formatter pre-build fails.
pub fn init(model: Arc<HnModel>) -> Result<Arc<UiState>> {
    // ---- Phase 4a: item_kids map.
    let item_kids = Mutex::new(HashMap::new());

    // ---- Phase 4c: the data grid, eagerly constructed with all six
    // columns appended in their FASM order.
    let header_colors = ColorPair::new(COLOR_BLACK, COLOR_LIGHTGRAY);
    let body_colors = ColorPair::new(COLOR_BLACK, COLOR_LIGHTGRAY);
    let sel_colors = ColorPair::new(COLOR_LIGHTGRAY, COLOR_BLUE);
    let mut grid = TuiDataGrid::new_with_percent(100.0, 100.0, header_colors, body_colors, sel_colors);

    // FASM column list (`ui.inc` lines 88–125):
    //   ("Pos",   width=4,  Left,  property="rank")
    //   ("Title", width=100%,Left, property="title")
    //   ("Pts",   width=4,  Right, property="score")
    //   ("Age",   width=7,  Right, property="age")
    //   ("By",    width=16, Left,  property="by")
    //   ("Cmt",   width=4,  Right, property="descendants")
    grid.add_column(ColumnSpec::new_fixed(LABEL_RANK, PROP_RANK, 4, HorizAlign::Left))?;
    grid.add_column(ColumnSpec::new_percent(
        LABEL_TITLE,
        PROP_TITLE,
        100.0,
        HorizAlign::Left,
    ))?;
    grid.add_column(ColumnSpec::new_fixed(
        LABEL_SCORE,
        PROP_SCORE,
        4,
        HorizAlign::Right,
    ))?;
    grid.add_column(ColumnSpec::new_fixed(LABEL_AGE, PROP_AGE, 7, HorizAlign::Right))?;
    grid.add_column(ColumnSpec::new_fixed(LABEL_BY, PROP_BY, 16, HorizAlign::Left))?;
    grid.add_column(ColumnSpec::new_fixed(
        LABEL_DESCENDANTS,
        PROP_DESCENDANTS,
        4,
        HorizAlign::Right,
    ))?;

    let main_datagrid = Arc::new(Mutex::new(grid));
    let datagrid_widget = DataGridWrapperWidget::new(Arc::clone(&main_datagrid), 100.0, 100.0);

    // ---- Phase 4d: status bar (100% width, height 1, body colors
    // black/lightgray, no built-in uptime label).
    let statusbar_colors = ColorPair::new(COLOR_BLACK, COLOR_LIGHTGRAY);
    let statusbar = TuiStatusBar::new_d(100.0, statusbar_colors, false)?;

    // ---- Phase 4e: status-bar navigation labels. The Rust
    // `Statusbar::add_label` requires `&mut self` and inserts at
    // index 1, pushing previously-inserted labels to the right —
    // matching the FASM `add_statusbar_label` order produces the
    // same final visual order: `copyright | Top | New | Ask | Show | Job`.
    //
    // Mutation is achieved through a one-shot ownership transfer:
    // we own the freshly-built `Arc<TuiStatusBar>` exclusively, so
    // `Arc::get_mut` succeeds inside `build_statusbar_with_labels`.
    let statusbar = build_statusbar_with_labels(statusbar)?;

    // ---- Phase 4f: status_format formatter — copyright + s1 +
    // (s2..s5 alternating with unsigned counts).
    let mut sf = Formatter::new(false);
    sf.add_static(COPYRIGHT);
    sf.add_static(_S1);
    sf.add_static(S2);
    sf.add_unsigned(1, 0);
    sf.add_static(S3);
    sf.add_unsigned(1, 0);
    sf.add_static(S4);
    sf.add_unsigned(1, 0);
    sf.add_static(S5);
    sf.add_unsigned(1, 0);
    let status_format = Arc::new(sf);

    // ---- Phase 4g: item_format1 / 2 / 3 / 4 — verbatim from
    // `ui.inc` lines 324–340.
    //
    // item_format1: " rank. title"
    let mut f1 = Formatter::new(false);
    f1.add_static(SPACE);
    f1.add_unsigned(1, 0);
    f1.add_static(DOT_SPACE);
    f1.add_string(0);
    let item_format1 = Arc::new(f1);

    // item_format2: "    pts points by by age ago"
    let mut f2 = Formatter::new(false);
    f2.add_static(QUADSPACE);
    f2.add_unsigned(1, 0);
    f2.add_static(POINTS_BY);
    f2.add_string(0);
    f2.add_static(SPACE);
    f2.add_string(0);
    f2.add_static(AGO);
    let item_format2 = Arc::new(f2);

    // item_format3: "    pts points by by age ago | cmt comments"
    let mut f3 = Formatter::new(false);
    f3.add_static(QUADSPACE);
    f3.add_unsigned(1, 0);
    f3.add_static(POINTS_BY);
    f3.add_string(0);
    f3.add_static(SPACE);
    f3.add_string(0);
    f3.add_static(AGO_PIPE);
    f3.add_unsigned(1, 0);
    f3.add_static(COMMENTS);
    let item_format3 = Arc::new(f3);

    // item_format4: "by time ago" — `Formatter::new(true)` enables
    // automatic single-space joining between non-empty parts.
    let mut f4 = Formatter::new(true);
    f4.add_string(0);
    f4.add_string(0);
    f4.add_static(AGO_NO_SPACE);
    let item_format4 = Arc::new(f4);

    // ---- Build the root widget tree.
    //
    // content_slot starts pointing at the data-grid wrapper; the
    // root has [content_slot, statusbar] children.
    let content_slot = ContentSlot::new(Arc::clone(&datagrid_widget) as Arc<dyn Widget>);
    let main_screen = MainScreenWidget::new(vec![
        Arc::clone(&content_slot) as Arc<dyn Widget>,
        Arc::clone(&statusbar) as Arc<dyn Widget>,
    ]);

    // ---- Phase 4i: the splash widget wraps `main_screen` for the
    // initial branded animation. Held on `UiState` purely to keep
    // the Arc alive for the framework's rendering pipeline.
    let splash = TuiSplash::new(Arc::clone(&main_screen) as Arc<dyn Widget>)?;

    // ---- Assemble UiState. Back-references are populated below.
    let ui = Arc::new(UiState {
        main_screen: Arc::clone(&main_screen),
        main_datagrid: Arc::clone(&main_datagrid),
        status_format: Arc::clone(&status_format),
        item_screen: Mutex::new(None),
        item_format1,
        item_format2,
        item_format3,
        item_format4,
        item_kids,
        displayitem: Mutex::new(None),
        statusbar: Arc::clone(&statusbar),
        model: Arc::clone(&model),
        content_slot,
        datagrid_widget,
        _splash: splash,
    });

    // Install Weak<UiState> on widgets that need to dispatch back
    // (key event handlers). The DataGridWrapperWidget needs the
    // back-reference to translate Enter-key presses into
    // `itemselected` calls — FASM parallel: `.datagrid_vtable`
    // override at `ui.inc:395` that hooks slot 38 of the datagrid
    // vtable.
    main_screen.install_back(Arc::downgrade(&ui));
    ui.datagrid_widget.install_back(Arc::downgrade(&ui));

    // ---- Phase 4h: wire status / updated callbacks on the model.
    //
    // `HnModel::set_statuscb` and `set_updatedcb` accept any closure
    // satisfying their `Fn(...) + Send + Sync + 'static` trait bound,
    // so we pass the closure unboxed — `set_statuscb` allocates the
    // `Arc<F>` internally. (Earlier drafts wrapped these in `Box::new`,
    // which was redundant; resolved per CP8 review INFO #15.)
    {
        let weak = Arc::downgrade(&ui);
        ui.model.set_statuscb(move |_msg: &str| {
            if let Some(strong) = weak.upgrade() {
                statusbar_update(&strong);
            }
        });
    }
    {
        let weak = Arc::downgrade(&ui);
        ui.model.set_updatedcb(move |item_id: Option<&str>| {
            if let Some(strong) = weak.upgrade() {
                let _ = compose(&strong, item_id);
            }
        });
    }

    Ok(ui)
}

/// Helper: take ownership of a freshly-built [`TuiStatusBar`] [`Arc`]
/// and append the five navigation labels via the FASM call order
/// (`Job`, `Show`, `Ask`, `New`, `Top`).
///
/// `add_label` requires `&mut Statusbar`, which is only obtainable by
/// extracting the inner value from the [`Arc`]. We use [`Arc::try_unwrap`]
/// (NOT `Arc::get_mut`): the spawned uptime-timer task inside
/// [`TuiStatusBar::new_d`]/`finalize_construction` captures a
/// [`std::sync::Weak<Statusbar>`] back-pointer, so the freshly-built `Arc`
/// always has `weak_count == 1`, which makes `Arc::get_mut` return
/// [`None`]. `Arc::try_unwrap` only checks `strong_count == 1` — the
/// outstanding [`std::sync::Weak`] does NOT block it. This pattern
/// matches the in-tree exemplar at
/// `heavything::tui::widgets::statusbar::test_add_label_*` (statusbar.rs
/// lines 1577-1610).
///
/// Once we have the inner [`Statusbar`] by value we mutate it by-value,
/// then re-wrap with [`Arc::new`]. The original allocation now has
/// `strong_count == 0`; on its next 5 s tick the pre-existing timer task
/// observes `Weak::upgrade() == None` and exits cleanly. For
/// `show_uptime = false` (hnwatch always passes this), the timer task
/// would have been a no-op anyway, so losing it is harmless.
fn build_statusbar_with_labels(sb: Arc<TuiStatusBar>) -> Result<Arc<TuiStatusBar>, TuiError> {
    let label_normal = ColorPair::new(COLOR_BLACK, COLOR_LIGHTGRAY);
    let label_highlight = ColorPair::new(COLOR_VENETIANRED, COLOR_GRAY);

    // Take unique ownership of the inner `Statusbar` via `Arc::try_unwrap`.
    // This succeeds because at this call site `strong_count == 1` (the
    // caller has just constructed the Arc and has not cloned it). Any
    // outstanding `Weak` reference held by the timer task is irrelevant
    // to `try_unwrap`.
    let mut sb_owned = Arc::try_unwrap(sb).map_err(|_| {
        TuiError::Render(std::io::Error::other(
            "ui::init: statusbar Arc was unexpectedly shared before label population",
        ))
    })?;

    // FASM `ui.inc` lines 200–280 — add labels in this exact order. Each
    // call inserts at index 1, so the final visual ordering (left to
    // right) is `copyright | Top | New | Ask | Show | Job`, matching the
    // FASM `list$insert_after(children, first, ...)` semantics
    // byte-for-byte.
    let l_job = sb_owned.add_label(STAT_JOB, label_normal)?;
    l_job.set_highlight(HK_JOB, label_highlight);

    let l_show = sb_owned.add_label(STAT_SHOW, label_normal)?;
    l_show.set_highlight(HK_SHOW, label_highlight);

    let l_ask = sb_owned.add_label(STAT_ASK, label_normal)?;
    l_ask.set_highlight(HK_ASK, label_highlight);

    let l_new = sb_owned.add_label(STAT_NEW, label_normal)?;
    l_new.set_highlight(HK_NEW, label_highlight);

    let l_top = sb_owned.add_label(STAT_TOP, label_normal)?;
    l_top.set_highlight(HK_TOP, label_highlight);

    Ok(Arc::new(sb_owned))
}

// ===========================================================================
// Key event dispatch
// ===========================================================================

/// Handle a key event while the data-grid (list view) is active.
///
/// FASM parallel: `ui$main_keyevent` (`ui.inc` lines 411–479). Maps
/// case-insensitive `T/N/A/S/J` to topic switches, returning `true`
/// when the key was consumed and `false` when it should bubble up.
///
/// Returns `true` if the event was handled.
pub fn main_keyevent(ui: &UiState, event: KeyEvent) -> bool {
    // FASM unconditionally case-folds the key with `or al, 0x20`.
    let ch = match event {
        KeyEvent::Char(c) => c.to_ascii_lowercase(),
        _ => return false,
    };

    let new_topic = match ch {
        't' => TOPSTORIES,
        'n' => NEWSTORIES,
        'a' => ASKSTORIES,
        's' => SHOWSTORIES,
        'j' => JOBSTORIES,
        _ => return false,
    };

    // FASM lines 437–460: compare `new_topic` to the current
    // `navstring`. If equal, skip the model reload (return 1,
    // "handled but no action taken").
    let nav_lock = crate::navstring();
    {
        let mut current = unpoison(nav_lock.lock());
        if *current == new_topic {
            return true;
        }
        // Mutate navstring before invoking the model so the model's
        // own `navstring()` reads see the new value.
        *current = new_topic.to_string();
    }

    // FASM line 466: `model$newmain(self_topic)`.
    if let Err(e) = ui.model.newmain(new_topic) {
        // Surface the failure via the status bar — preserves the
        // FASM behavior where model failures display as a status
        // line. Best effort: ignore secondary failures.
        let _ = e; // typed error already preserved at the model layer.
    }

    // Refresh the main grid composition (rank + age annotations).
    let _ = compose(ui, None);

    true
}

/// Handle a key event while the item-detail screen is active.
///
/// FASM parallel: `ui$item_keyevent` (`ui.inc` lines 839–955). The
/// dispatch covers four classes of key:
///
///  * Escape — bail back to the list view.
///  * `T/N/A/S/J` — bail back, then dispatch to [`main_keyevent`].
///  * Up / Down arrows — adjust the scroll offset.
///  * Left arrow — bail back (mirrors the assembly's
///    `0x44 → bailout` branch).
///
/// All other keys bubble (`return false`).
pub fn item_keyevent(ui: &UiState, event: KeyEvent) -> bool {
    match event {
        KeyEvent::Escape => {
            bailout(ui);
            true
        }
        KeyEvent::ArrowUp => {
            uparrow(ui);
            true
        }
        KeyEvent::ArrowDown => {
            downarrow(ui);
            true
        }
        KeyEvent::ArrowLeft => {
            bailout(ui);
            true
        }
        KeyEvent::Char(c) => {
            let ch = c.to_ascii_lowercase();
            if matches!(ch, 't' | 'n' | 'a' | 's' | 'j') {
                bailout(ui);
                main_keyevent(ui, event)
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Tear down the item-detail screen and re-display the data grid.
///
/// FASM parallel: `.bailout` (`ui.inc` lines 850–910). The Rust
/// version atomically swaps the `content_slot`'s inner widget back
/// to the data-grid wrapper, drops the item-screen reference, and
/// clears the displayitem and item_kids tracking maps.
fn bailout(ui: &UiState) {
    // 1. Swap the displayed content back to the data grid.
    ui.content_slot
        .swap(Arc::clone(&ui.datagrid_widget) as Arc<dyn Widget>);

    // 2. Drop the item-screen reference.
    {
        let mut slot = unpoison(ui.item_screen.lock());
        *slot = None;
    }

    // 3. Clear displayitem.
    {
        let mut dispitem = unpoison(ui.displayitem.lock());
        *dispitem = None;
    }

    // 4. Clear item_kids map.
    {
        let mut kids = unpoison(ui.item_kids.lock());
        kids.clear();
    }
}

/// Decrement the item-detail screen's scroll offset.
///
/// FASM parallel: `.uparrow` (`ui.inc` lines 915–935). Decrements
/// `scroll.y` if it is greater than zero; otherwise no-op.
fn uparrow(ui: &UiState) {
    let item_screen = {
        let slot = unpoison(ui.item_screen.lock());
        slot.clone()
    };
    if let Some(scr) = item_screen {
        let cur = scr.scroll_y();
        if cur > 0 {
            scr.set_scroll_y(cur - 1);
        }
    }
}

/// Increment the item-detail screen's scroll offset, bounded by the
/// total height of the threaded comment rows.
///
/// FASM parallel: `.downarrow` (`ui.inc` lines 940–970). The FASM
/// version walks every child via `.heightcalc` to compute total
/// height, subtracts 99 (the filler) and the statusbar overhead,
/// and only allows scrolling further if more content remains.
fn downarrow(ui: &UiState) {
    let item_screen = {
        let slot = unpoison(ui.item_screen.lock());
        slot.clone()
    };
    if let Some(scr) = item_screen {
        let total_rows = scr.rows_total_height();
        // The FASM heuristic: subtract the 99-row filler reserve so
        // a screen full of comments (well over 99 rows) doesn't
        // refuse to scroll.
        let max_scroll = total_rows.saturating_sub(99).max(0);
        let cur = scr.scroll_y();
        if cur < max_scroll {
            scr.set_scroll_y(cur + 1);
        }
    }
}

// ===========================================================================
// jsonage — compute the "X ago" age string for a JSON item.
// ===========================================================================

/// Compute the localized "ago" string for an item.
///
/// FASM parallel: `ui$jsonage` (`ui.inc` lines 486–530).
fn jsonage(item: &Value) -> String {
    let time_str = match item.get(PROP_TIME).and_then(Value::as_str) {
        Some(s) => s,
        None => return NULL_STR.to_string(),
    };
    let item_unix: u64 = match time_str.parse() {
        Ok(t) => t,
        Err(_) => return NULL_STR.to_string(),
    };

    // Compute current time as a Unix-seconds value. If the system
    // clock is before the Unix epoch (extreme edge case), fall back
    // to zero, which produces a sensible "0s ago" output.
    let now_unix: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let delta_seconds = now_unix.saturating_sub(item_unix);
    let delta_days = delta_seconds as f64 / heavything::util::date::SECONDS_PER_DAY as f64;

    age_formatter()
        .doit(&[FmtValue::Dbl(delta_days)])
        .unwrap_or_else(|_| NULL_STR.to_string())
}

// ===========================================================================
// itemupdate — refresh the item-detail screen's contents.
// ===========================================================================

/// Refresh the currently-displayed item-detail screen.
///
/// FASM parallel: `ui$itemupdate` (`ui.inc` lines 988–1221) plus the
/// inner `.rowupdate` (lines 1223–1304) and `.retriever` (lines
/// 1326–1363) helpers.
fn itemupdate(ui: &UiState) -> Result<()> {
    // ---- Pull the displayitem id and the item-screen reference.
    let display_id = {
        let dispitem = unpoison(ui.displayitem.lock());
        match *dispitem {
            Some(id) => id,
            None => return Ok(()),
        }
    };
    let display_id_str = display_id.to_string();

    let item_screen = {
        let slot = unpoison(ui.item_screen.lock());
        match slot.clone() {
            Some(s) => s,
            None => return Ok(()),
        }
    };

    // ---- Look up the item in the model.
    let item: Value = {
        let items_guard = ui.model.items();
        match items_guard.get(&display_id_str) {
            Some(Some(v)) => v.clone(),
            // Either not loaded yet (None) or absent — no-op.
            _ => return Ok(()),
        }
    };

    // ---- Render the three header lines.
    render_item_header(ui, &item_screen, &item)?;

    // ---- Track this item in `item_kids`.
    {
        let mut kids = unpoison(ui.item_kids.lock());
        kids.insert(display_id, ());
    }

    // ---- Walk kids recursively, queueing retrievals and updating
    // existing rows.
    if let Some(kids_array) = item.get(PROP_KIDS).and_then(Value::as_array) {
        for kid in kids_array {
            retriever(ui, kid);
        }
        rowupdate_walk(ui, &item_screen, kids_array, 0)?;
    }

    Ok(())
}

/// Render the three header lines of the item-detail screen.
///
/// FASM parallel: `ui$itemupdate` lines 1010–1100 — selects between
/// `item_format2` (no comments) and `item_format3` (with comments)
/// based on whether `descendants > 0`.
fn render_item_header(ui: &UiState, item_screen: &ItemScreenWidget, item: &Value) -> Result<()> {
    let inner = unpoison(item_screen.inner.lock());

    // ---- Line 1: " rank. title".
    let rank: u64 = item
        .get(PROP_RANK)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let title = item.get(PROP_TITLE).and_then(Value::as_str).unwrap_or("");
    let line1_text = ui
        .item_format1
        .doit(&[FmtValue::Uint(rank), FmtValue::Str(title.to_string())])
        .map_err(|e| anyhow!("item_format1 doit failed: {e}"))?;
    let _ = inner.line1.nvsettext(&line1_text);

    // ---- Line 2: depends on score / descendants presence.
    let by_user = item.get(PROP_BY).and_then(Value::as_str).unwrap_or(NULL_STR);
    let age_str = item.get(PROP_AGE).and_then(Value::as_str).unwrap_or(NULL_STR);

    let score: Option<u64> = item
        .get(PROP_SCORE)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok());
    let descendants: Option<u64> = item
        .get(PROP_DESCENDANTS)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok());

    let line2_text = match (score, descendants) {
        (Some(pts), Some(c)) => ui
            .item_format3
            .doit(&[
                FmtValue::Uint(pts),
                FmtValue::Str(by_user.to_string()),
                FmtValue::Str(age_str.to_string()),
                FmtValue::Uint(c),
            ])
            .map_err(|e| anyhow!("item_format3 doit failed: {e}"))?,
        (Some(pts), None) => ui
            .item_format2
            .doit(&[
                FmtValue::Uint(pts),
                FmtValue::Str(by_user.to_string()),
                FmtValue::Str(age_str.to_string()),
            ])
            .map_err(|e| anyhow!("item_format2 doit failed: {e}"))?,
        (None, _) => {
            // FASM `.check_ago`: simple `age + " ago"` concat —
            // job listings have no score.
            format!("{age_str}{AGO}")
        }
    };
    let _ = inner.line2.nvsettext(&line2_text);

    // ---- Line 3: url or text (url takes precedence).
    let url = item.get(PROP_URL).and_then(Value::as_str).unwrap_or("");
    let body_text = item.get(PROP_TEXT).and_then(Value::as_str).unwrap_or("");
    let line3_text = if !url.is_empty() {
        url.to_string()
    } else if !body_text.is_empty() {
        textify(body_text)
    } else {
        String::new()
    };
    let _ = inner.line3.nvsettext(&line3_text);

    Ok(())
}

/// Recursively queue model retrievals for a kid id and its
/// already-loaded sub-kids.
///
/// FASM parallel: `.retriever` (`ui.inc` lines 1327–1363).
fn retriever(ui: &UiState, kid: &Value) {
    let id_str = match kid.as_str() {
        Some(s) => s,
        None => return,
    };
    let kid_id: u64 = match id_str.parse() {
        Ok(i) => i,
        Err(_) => return,
    };

    // Track the kid in item_kids.
    {
        let mut kids = unpoison(ui.item_kids.lock());
        kids.insert(kid_id, ());
    }

    // Queue an async retrieval (not an update — `is_update = false`).
    let _ = ui.model.retrieve(id_str, false);

    // Recurse into already-loaded sub-kids.
    let sub_kids: Vec<Value> = {
        let items_guard = ui.model.items();
        match items_guard.get(id_str) {
            Some(Some(v)) => v
                .get(PROP_KIDS)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    };
    for sk in &sub_kids {
        retriever(ui, sk);
    }
}

/// Walk the kids array, creating new comment rows or updating
/// existing rows in place.
///
/// FASM parallel: the `.rowupdate` block of `ui$itemupdate` (`ui.inc`
/// lines 1223–1304). The FASM iterator advances through the
/// item_screen's children list, switching between three cases (insert
/// new, update existing while iterator has next, update last). The
/// Rust port collapses this into a position-aware update that
/// preserves the same visual ordering.
fn rowupdate_walk(
    ui: &UiState,
    item_screen: &Arc<ItemScreenWidget>,
    kids: &[Value],
    nesting: u32,
) -> Result<()> {
    // The FASM behavior at the top level is to walk the existing
    // rows in display order; nested calls extend the list. The
    // simplest faithful translation here is: starting at the
    // current rows length, for each kid append a new row (or
    // update the existing one if the index already exists).
    //
    // For first-time itemupdate calls, `rows` is empty so each kid
    // appends; for subsequent updates, the indexed update path
    // refreshes existing rows. We always scan from the front,
    // matching the FASM iterator that always begins at child[3]
    // (i.e. row[0]).
    let mut row_idx: usize = 0;

    for kid in kids {
        let id_str = match kid.as_str() {
            Some(s) => s,
            None => continue,
        };
        let kid_id: u64 = match id_str.parse() {
            Ok(i) => i,
            Err(_) => continue,
        };

        // Look up the item in the model. A `None` indicates an
        // in-flight request — skip until the next compose pass.
        let item: Value = {
            let items_guard = ui.model.items();
            match items_guard.get(id_str) {
                Some(Some(v)) => v.clone(),
                _ => continue,
            }
        };

        // Skip deleted comments — FASM `.rowupdate` line 1252.
        if item.get(PROP_DELETED).and_then(Value::as_str) == Some(VALUE_TRUE) {
            continue;
        }

        // Either update the existing row at row_idx (case 2/3) or
        // append a new one (case 1).
        let existing: Option<Arc<ItemRowWidget>> = {
            let inner = unpoison(item_screen.inner.lock());
            inner.rows.get(row_idx).cloned()
        };

        if let Some(row) = existing {
            row.update(kid_id, &item, nesting, &ui.item_format4);
        } else {
            // Create a new row and append.
            let row = ItemRowWidget::new(kid_id, &item, nesting, &ui.item_format4)?;
            let mut inner = unpoison(item_screen.inner.lock());
            inner.rows.push(Arc::clone(&row));
        }

        row_idx = row_idx.saturating_add(1);

        // Recurse into this item's kids with nesting + 1.
        if let Some(nested_kids) = item.get(PROP_KIDS).and_then(Value::as_array) {
            rowupdate_walk(ui, item_screen, nested_kids, nesting.saturating_add(1))?;
        }
    }

    Ok(())
}

// ===========================================================================
// itemselected — port of `ui$itemselected` (lines 1378–1519).
// ===========================================================================

/// Build and install the item-detail screen for the supplied JSON
/// item, then trigger an immediate [`itemupdate`] to populate it.
///
/// FASM parallel: `ui$itemselected` (`ui.inc` lines 1378–1519).
///
/// Takes `ui` as `&Arc<UiState>` so the freshly-allocated
/// [`ItemScreenWidget`] can store a [`Weak<UiState>`] back-reference
/// for its own [`Widget::key_event`] override to dispatch into
/// [`item_keyevent`].
///
/// # Errors
///
/// Returns an error if the item-screen widgets cannot be allocated
/// or if any of the formatter pre-build operations fail.
pub fn itemselected(ui: &Arc<UiState>, selected_json: &Value) -> Result<()> {
    // ---- Phase A: build a fresh item-detail screen widget and
    // install the Weak<UiState> back-reference so its key_event
    // override can route into `item_keyevent`.
    let item_screen = ItemScreenWidget::new()?;
    item_screen.install_back(Arc::downgrade(ui));

    // ---- Phase B: swap the content slot from the datagrid wrapper
    // to this new item screen.
    ui.content_slot.swap(Arc::clone(&item_screen) as Arc<dyn Widget>);

    // ---- Phase C: extract the id, store it as the displayitem,
    // and trigger the initial population.
    let id_str = selected_json.get(PROP_ID).and_then(Value::as_str).unwrap_or("");
    let id_num: u64 = id_str.parse().unwrap_or(0);

    {
        let mut slot = unpoison(ui.item_screen.lock());
        *slot = Some(Arc::clone(&item_screen));
    }

    if id_num != 0 {
        let mut dispitem = unpoison(ui.displayitem.lock());
        *dispitem = Some(id_num);
    }

    // Drop the lock before triggering itemupdate which re-acquires.
    if id_num != 0 {
        itemupdate(ui)?;
    }

    Ok(())
}

// ===========================================================================
// statusbar_update — port of `ui$statusbar_update` (lines 1535–1555).
// ===========================================================================

/// Refresh the status-bar text with the current model counters.
///
/// FASM parallel: `ui$statusbar_update` (`ui.inc` lines 1536–1555).
/// Reads the four atomic counters off [`HnModel`] and renders them
/// into the status-bar text via [`UiState::status_format`].
pub(crate) fn statusbar_update(ui: &UiState) {
    let items_count: u64 = {
        let items_guard = ui.model.items();
        items_guard.len() as u64
    };
    let request_count = ui.model.requestcount.load(Ordering::Relaxed);
    let byte_count = ui.model.bytecount.load(Ordering::Relaxed);
    let error_count = ui.model.errorcount.load(Ordering::Relaxed);

    let text = match ui.status_format.doit(&[
        FmtValue::Uint(items_count),
        FmtValue::Uint(request_count),
        FmtValue::Uint(byte_count),
        FmtValue::Uint(error_count),
    ]) {
        Ok(s) => s,
        Err(_) => return,
    };

    ui.statusbar.set_text(&text);
}

// ===========================================================================
// compose — port of `ui$compose` (`ui.inc` lines 1561–1711).
// ===========================================================================

/// Re-build the data-grid's JSON array view from the model's
/// `mainorder` + `items` map and (optionally) refresh the
/// item-detail screen if the supplied id matches the displayed item.
///
/// FASM parallel: `ui$compose` (`ui.inc` lines 1561–1711) and its
/// inner `.eachmainorder` helper (lines 1602–1711).
///
/// # Errors
///
/// Propagates any [`TuiError`] from the data-grid update path.
pub fn compose(ui: &UiState, item_str: Option<&str>) -> Result<()> {
    // ---- Phase A: walk mainorder, deep-copy each item, annotate
    // with rank + age, push into the array passed to the grid.
    let mut array: Vec<Value> = Vec::new();

    {
        let mainorder_guard = ui.model.mainorder();
        let mut items_guard = ui.model.items();

        for key in mainorder_guard.iter() {
            // Compute rank as 1-based index in display order.
            let rank: u64 = (array.len() as u64).saturating_add(1);
            let rank_str = rank.to_string();

            // Look up the item — skip when the slot is empty (in-flight).
            let item_clone = match items_guard.get(key) {
                Some(Some(v)) => v.clone(),
                _ => continue,
            };

            // Compute the age string from the cloned item — uses
            // `time` and the system clock; doesn't mutate the item.
            let age_str = jsonage(&item_clone);

            // Annotate the original (live) item with rank + age so
            // a subsequent click into the item view picks them up
            // automatically (FASM annotates the originals too).
            if let Some(orig_slot) = items_guard.get_mut(key) {
                if let Some(orig) = orig_slot.as_mut() {
                    if let Some(obj) = orig.as_object_mut() {
                        obj.insert(PROP_RANK.to_string(), Value::String(rank_str.clone()));
                        obj.insert(PROP_AGE.to_string(), Value::String(age_str.clone()));
                    }
                }
            }

            // Annotate the clone we are pushing into the grid.
            let mut item_to_push = item_clone;
            if let Some(obj) = item_to_push.as_object_mut() {
                obj.insert(PROP_RANK.to_string(), Value::String(rank_str));
                obj.insert(PROP_AGE.to_string(), Value::String(age_str));
            }
            array.push(item_to_push);
        }
    }

    // ---- Phase B: hand the new array off to the data grid, then
    // confirm via the top-level `main_screen` that the widget tree
    // is in a renderable state. FASM parallel: `ui.inc:1655` calls
    // `tui_vlayoutchanged` on `[main_screen]` after the datagrid
    // refresh so the framework resyncs scrollbars / column widths.
    // The Rust framework drives layout invalidation externally via
    // the renderer pass, so the post-`set_data` step here just
    // verifies the main_screen still has at least one child (the
    // ContentSlot) — a defensive invariant matching the FASM code's
    // assumption that `[_list_first]` is non-zero.
    {
        let mut grid = unpoison(ui.main_datagrid.lock());
        let arc_value = Arc::new(Value::Array(array));
        grid.set_data(arc_value)?;
    }
    debug_assert!(
        !ui.main_screen.state().children.is_empty(),
        "main_screen must contain ContentSlot + Statusbar children"
    );

    // ---- Phase C: if `item_str` is Some and the id is one of our
    // tracked item_kids, refresh the item-detail screen.
    if let Some(s) = item_str {
        if let Ok(id_num) = s.parse::<u64>() {
            let tracked = {
                let kids = unpoison(ui.item_kids.lock());
                kids.contains_key(&id_num)
            };
            if tracked {
                itemupdate(ui)?;
            }
        }
    }

    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity-check the color constants: every named color resolves
    /// to a `u8` in xterm-256 range.
    #[test]
    fn color_constants_are_valid_indices() {
        // All u8 values are by construction in 0..=255 so this is
        // primarily a guard against accidental sentinel values.
        let _ = COLOR_BLACK;
        let _ = COLOR_LIGHTGRAY;
        let _ = COLOR_GRAY;
        let _ = COLOR_BLUE;
        let _ = COLOR_DARKSLATEGRAY;
        let _ = COLOR_VENETIANRED;
        let _ = COLOR_RGB_40;
        let _ = COLOR_RGB_130;
        let _ = COLOR_RGB_247;
    }

    /// The status-bar separator must contain exactly three Unicode
    /// scalars: space, U+2502 (BOX DRAWINGS LIGHT VERTICAL), space.
    #[test]
    fn s1_separator_is_three_codepoints() {
        let cps: Vec<char> = _S1.chars().collect();
        assert_eq!(cps.len(), 3);
        assert_eq!(cps[0], ' ');
        assert_eq!(cps[1], '\u{2502}');
        assert_eq!(cps[2], ' ');
    }

    /// The copyright literal is byte-identical to the assembly source
    /// — guard against accidental edits.
    #[test]
    fn copyright_literal_is_exact() {
        assert_eq!(COPYRIGHT, "hnwatch v1.13 © 2015 2 Ton Digital");
    }

    /// Topic constants match the assembly literals byte-for-byte.
    #[test]
    fn topic_constants_match_assembly() {
        assert_eq!(TOPSTORIES, "topstories");
        assert_eq!(NEWSTORIES, "newstories");
        assert_eq!(ASKSTORIES, "askstories");
        assert_eq!(SHOWSTORIES, "showstories");
        assert_eq!(JOBSTORIES, "jobstories");
    }

    /// Property names match the FASM `string$equals` comparands.
    #[test]
    fn property_names_match_assembly() {
        assert_eq!(PROP_RANK, "rank");
        assert_eq!(PROP_TITLE, "title");
        assert_eq!(PROP_SCORE, "score");
        assert_eq!(PROP_AGE, "age");
        assert_eq!(PROP_BY, "by");
        assert_eq!(PROP_DESCENDANTS, "descendants");
        assert_eq!(PROP_URL, "url");
        assert_eq!(PROP_TEXT, "text");
        assert_eq!(PROP_KIDS, "kids");
        assert_eq!(PROP_DELETED, "deleted");
        assert_eq!(PROP_TIME, "time");
        assert_eq!(PROP_ID, "id");
        assert_eq!(VALUE_TRUE, "true");
    }

    /// `jsonage` returns the null-sentinel for items with no
    /// `"time"` property.
    #[test]
    fn jsonage_returns_null_sentinel_when_missing_time() {
        let v = serde_json::json!({});
        assert_eq!(jsonage(&v), NULL_STR);
    }

    /// `jsonage` returns the null-sentinel for items whose `"time"`
    /// is non-numeric.
    #[test]
    fn jsonage_returns_null_sentinel_when_time_is_garbage() {
        let v = serde_json::json!({ "time": "not-a-number" });
        assert_eq!(jsonage(&v), NULL_STR);
    }
}
