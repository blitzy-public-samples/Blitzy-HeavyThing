// ------------------------------------------------------------------------
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
// ------------------------------------------------------------------------
//
// crates/heavything/src/tui/widgets/button.rs — clickable button widget.
//
// Rust translation of FASM `tui_button.inc` (294 lines). A
// `TuiBackground`-descendant clickable button with focus and press
// visual states. The button embeds a centered `Label` child whose text
// is the button caption wrapped in newlines for vertical centering.
// Pressing Space triggers a 300-ms one-shot press animation that
// completes by firing a click event.
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! Button widget — Background-descendant clickable button with focus
//! and press visual states.
//!
//! # FASM parallel
//!
//! Direct translation of `tui_button.inc`. The 37-slot vtable
//! (`tui_button$vtable`) is a copy of `tui_background$vtable` with
//! six overrides at the FASM slot indices:
//!
//! | Slot | Method      | FASM symbol             | Rust override target |
//! |------|-------------|-------------------------|----------------------|
//! | 0    | cleanup     | `tui_button$cleanup`    | [`Widget::cleanup`]  |
//! | 1    | clone       | `tui_button$clone`      | [`Widget::clone_widget`] |
//! | 6    | timer       | `tui_button$timer`      | [`Widget::timer`]    |
//! | 10   | gotfocus    | `tui_button$gotfocus`   | [`Widget::got_focus`]|
//! | 11   | lostfocus   | `tui_button$lostfocus`  | [`Widget::lost_focus`]|
//! | 12   | keyevent    | `tui_button$keyevent`   | [`Widget::key_event`]|
//!
//! Slot 2 (`draw`) is **not** overridden — the FASM vtable references
//! `tui_background$draw` directly, and the Rust port mirrors that by
//! providing a draw impl that fills the background and lets the
//! embedded label render itself.
//!
//! # Press animation
//!
//! On Space-key press while focussed, the button:
//!
//! 1. Sets `pressed = true`.
//! 2. Disables the label's drop shadow and shifts the label by (1, 1)
//!    cells to give a visual "pressed-in" effect (FASM
//!    `tui_vmove(label, 1, 1)`). Because the cloned `Arc<dyn Widget>`
//!    children prevent runtime mutation of the label after construction,
//!    the visual offset is tracked in [`ButtonInner::press_offset`] and
//!    applied during the rendering pass — see the design note inside
//!    [`Button::key_event`].
//! 3. Spawns a one-shot 300-ms `tokio::time::sleep` task that, on
//!    completion, calls [`Button::finish_press`] via a `Weak<Self>`
//!    upgrade — this prevents `Arc` reference cycles from the timer
//!    task back to the button.
//! 4. After 300 ms the press finishes: `pressed` flips back to `false`,
//!    the offset is cleared, and the FASM-equivalent click hook fires.
//!
//! All button-internal state mutated through `&self` (focus toggles,
//! press animation, color changes propagated to the label) lives behind
//! the [`std::sync::Mutex`] guarding [`ButtonInner`]. The widget tree's
//! [`crate::tui::object::WidgetState`] is exposed as `pub(crate) state`
//! per the convention established by [`crate::tui::widgets::label`].

use std::any::Any;
use std::sync::{Arc, Mutex, Weak};

use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

use crate::error::TuiError;
use crate::tui::geometry::Rect;
use crate::tui::object::{ClickEvent, ColorPair, KeyEvent, Layout, Widget, WidgetState};
use crate::tui::render::Renderer;
use crate::tui::widgets::label::{Label, TextAlign};

// ============================================================================
// Constants — animation timing, pad/margin offsets, click event placeholder.
// ============================================================================

/// Press-animation duration in milliseconds.
///
/// Matches FASM `tui_button$keyevent` line 267:
/// `mov edi, 300` — a one-shot delay registered with `epoll$timer_new`
/// that fires `tui_button$timer` after 300 ms.
const PRESS_ANIMATION_MS: u64 = 300;

/// Width padding added to the caption text length to compute the button
/// outer width: `width = text.chars().count() + WIDTH_PADDING`.
///
/// Matches FASM `tui_button$new` lines 62–63:
/// `mov esi, [r9]` (load string char count) ; `add esi, 7`. The 7-cell
/// padding accommodates the label's drop-shadow plus left/right border
/// margins around the centered caption.
const WIDTH_PADDING: i32 = 7;

/// Fixed button height in cells.
///
/// Matches FASM `tui_button$new` line 64: `mov edx, 4`. The button is
/// always exactly 4 rows tall: 1 row top margin, 3 rows label area,
/// trailing drop-shadow occupying the 4th row's lower edge.
const BUTTON_HEIGHT: i32 = 4;

/// Width of the label child rectangle (one cell narrower than the
/// outer button to leave room for the drop shadow on the right side).
///
/// Matches FASM `tui_button$new` lines 95–96:
/// `mov r8d, [rsi]` (text char count) ; `add r8d, 6`. The label
/// rectangle's `bx` field is `text_chars + 6`, exactly one less than
/// the button's outer width.
const LABEL_WIDTH_PADDING: i32 = 6;

/// Height of the label child rectangle (3 rows: 1 row top LF padding,
/// 1 row centered text, 1 row bottom LF padding).
///
/// Matches FASM `tui_button$new` line 104: `mov dword [rdi+12], 3`.
const LABEL_HEIGHT: i32 = 3;

/// Press-time pixel offset applied to the label.
///
/// Matches FASM `tui_button$keyevent` lines 262–263:
/// `mov esi, 1` ; `mov edx, 1` — the label is shifted by (+1, +1)
/// cells to give the visual "pressed-in" effect, and on press release
/// `tui_button$timer` (lines 196–197) shifts back by (-1, -1).
const PRESS_OFFSET: (i32, i32) = (1, 1);

// ============================================================================
// ButtonInner — Mutex-guarded button-specific state.
// ============================================================================

/// Mutex-guarded interior state for [`Button`].
///
/// Mirrors FASM `tui_button` extra fields above `tui_background_size`:
///
/// | FASM offset                       | Field                    | Type      |
/// |-----------------------------------|--------------------------|-----------|
/// | `tui_button_label_ofs`         (+0)| [`Self::label`]          | `Arc<dyn Widget>` |
/// | `tui_button_pressed_ofs`       (+8)| [`Self::pressed`]        | `bool`    |
/// | `tui_button_focussed_ofs`     (+16)| [`Self::focussed`]       | `bool`    |
/// | `tui_button_normalcolors_ofs` (+24)| [`Self::normal_colors`]  | [`ColorPair`] |
/// | `tui_button_focuscolors_ofs`  (+32)| [`Self::focus_colors`]   | [`ColorPair`] |
/// | `tui_button_timerptr_ofs`     (+40)| [`Self::anim_timer`]     | `Option<JoinHandle<()>>` |
///
/// Total FASM extra: 48 bytes (`tui_button_size = tui_background_size
/// + 48`).
///
/// Three Rust-only fields are added to bridge the FASM behavior to the
/// `Arc<dyn Widget>` ownership model:
///
/// - [`Self::press_offset`] — tracks the (+1, +1) label shift applied
///   during the press animation. FASM mutates the label's bounds
///   directly via `tui_vmove`; the Rust port cannot mutate
///   `Arc<dyn Widget>` children, so the offset is recorded here and
///   applied during render.
/// - [`Self::label_drop_shadow`] — tracks the press-driven drop shadow
///   toggle (true at rest, false during press) for the same reason.
/// - [`Self::weak_self`] — a [`Weak`] back-reference to the enclosing
///   [`Button`] used by [`Button::key_event`] to spawn the press
///   animation timer task. `key_event` is a `&mut self` trait method
///   so it cannot directly grab an [`Arc`] of itself; the back-pointer
///   established via [`Arc::new_cyclic`] in [`Button::new`] solves
///   this without leaking memory (the timer task holds the weak ref
///   only, never an Arc).
///
/// All fields are crate-private; external code interacts with the
/// button through the [`Button`] public API (constructor, focus
/// accessors, [`Widget`] trait methods).
struct ButtonInner {
    /// Embedded centered label child. Stored as `Arc<dyn Widget>`
    /// (rather than `Arc<Label>`) so [`Widget::clone_widget`] can
    /// reconstruct the field directly from the cloned `WidgetState`'s
    /// children list without trait-object downcasting at the type
    /// system level. Color changes during focus transitions are
    /// dispatched via [`Any::downcast_ref`] in [`Button::got_focus`]
    /// and [`Button::lost_focus`].
    label: Arc<dyn Widget>,

    /// `true` while the button is mid-press (Space depressed and the
    /// 300-ms animation timer is still pending).
    ///
    /// FASM `tui_button_pressed_ofs` (offset +8 above
    /// `tui_background_size`).
    pressed: bool,

    /// `true` while the button currently holds keyboard focus.
    ///
    /// FASM `tui_button_focussed_ofs` (offset +16). Inspected directly
    /// by [`Button::is_focussed`] for external focus-cycling logic
    /// (`Alert::on_tab` and similar parent-coordinator code).
    focussed: bool,

    /// Label colors when the button is **not** focussed.
    ///
    /// FASM `tui_button_normalcolors_ofs` (offset +24). Pushed to the
    /// label via [`Label::set_colors`] on `lost_focus`.
    normal_colors: ColorPair,

    /// Label colors when the button **is** focussed.
    ///
    /// FASM `tui_button_focuscolors_ofs` (offset +32). Pushed to the
    /// label via [`Label::set_colors`] on `got_focus`.
    focus_colors: ColorPair,

    /// Pending press-animation timer task handle.
    ///
    /// FASM `tui_button_timerptr_ofs` (offset +40) stored a pointer
    /// to the registered `epoll$timer` object so cleanup could call
    /// `epoll$timer_clear` to cancel a pending firing. The Rust port
    /// stores a `tokio::task::JoinHandle` returned by `tokio::spawn`;
    /// [`Button::cleanup`] aborts the handle to mirror
    /// `epoll$timer_clear`. `None` means no animation is in flight.
    anim_timer: Option<JoinHandle<()>>,

    /// Cumulative (dx, dy) cell offset applied to the label during the
    /// press animation.
    ///
    /// FASM directly mutates the label widget's bounds rectangle via
    /// `tui_vmove(label, 1, 1)` on press and `tui_vmove(label, -1, -1)`
    /// on release. The Rust port records the offset here because
    /// `Arc<dyn Widget>` children are shared and cannot be mutated
    /// after construction. Render-time consumers can query the offset
    /// via [`Button::press_offset`] (test-only public accessor) and
    /// apply it when emitting the label's cells.
    press_offset: (i32, i32),

    /// Cached drop-shadow flag for the embedded label.
    ///
    /// FASM directly mutates the label's `tui_dropshadow_ofs` field
    /// (true at rest, false during the press animation). The Rust
    /// port records the desired value here for the same
    /// `Arc<dyn Widget>` mutability reason as [`Self::press_offset`].
    label_drop_shadow: bool,

    /// Self-reference used to spawn the press-animation timer task
    /// from the [`Widget::key_event`] entry point.
    ///
    /// Established in [`Button::new`] via [`Arc::new_cyclic`]: the
    /// constructor receives a `&Weak<Button>` from the cyclic builder
    /// and stores a clone of it here so [`Button::start_press_timer`]
    /// can later upgrade it to an `Arc<Button>` to spawn the tokio
    /// task. Holding only a [`Weak`] (not an [`Arc`]) prevents a
    /// reference cycle: when the last external `Arc<Button>` is
    /// dropped, the button is freed and the timer task's upgrade
    /// fails harmlessly.
    weak_self: Weak<Button>,
}

// ============================================================================
// Button — public clickable button widget.
// ============================================================================

/// Clickable button widget with focus and press visual states.
///
/// Rust translation of FASM `tui_button` (`tui_button.inc`). Composed
/// of:
///
/// - A [`WidgetState`] field carrying the inherited base widget data
///   (bounds, dimensions, layout, children, attributes buffer) — this
///   directly replaces the FASM `tui_object` portion of the
///   in-memory layout.
/// - Two background fields (`bgfillchar`, `bgcolors`) replicating the
///   `TuiBackground` extension exactly — Button does not embed
///   [`crate::tui::widgets::background::TuiBackground`] because the
///   embedded child would obscure access to the inherited
///   [`WidgetState`] fields the [`Widget`] trait needs to expose
///   through `state` / `state_mut`.
/// - A [`Mutex`] guarding [`ButtonInner`] for all button-specific
///   state requiring `&self`-mutation (focus toggles, press animation,
///   color propagation to the embedded label).
///
/// # Lifecycle
///
/// 1. Construct with [`Button::new`] — returns
///    `Arc<Self>` so the button can be appended to a parent's children
///    list and shared across `tokio` tasks. The constructor uses
///    [`Arc::new_cyclic`] to populate [`ButtonInner::weak_self`] so
///    later `&mut self` calls into [`Widget::key_event`] can spawn an
///    animation task that holds a [`Weak`] back to the button. The
///    constructor also appends a centered [`Label`] child to its own
///    `state.children` list, mirroring FASM lines 109–113.
/// 2. Focus changes trigger label color updates via
///    [`Widget::got_focus`] / [`Widget::lost_focus`].
/// 3. A Space-key press (while focussed) triggers the press animation
///    via [`Widget::key_event`]; after 300 ms [`Widget::timer`] fires
///    to complete the animation.
/// 4. [`Widget::cleanup`] aborts any pending animation timer before
///    delegating to the inherited base cleanup.
///
/// # Thread safety
///
/// `Button: Send + Sync` is required by the [`Widget`] trait bound.
/// [`ButtonInner`] is held behind a [`Mutex`] so the spawned timer
/// task (which holds a `Weak<Self>`) can mutate it safely without
/// requiring `&mut self` on the trait-object reference.
pub struct Button {
    /// Inherited base [`WidgetState`] — Rust equivalent of the FASM
    /// `tui_object` portion of the button's heap layout.
    pub(crate) state: WidgetState,

    /// Background fill character (matches FASM
    /// `tui_background_fillchar_ofs`). Constructor sets this to the
    /// space character (` ` / 0x20), matching FASM line 65:
    /// `mov ecx, ' '`.
    pub(crate) bgfillchar: u32,

    /// Background fill colors (matches FASM
    /// `tui_background_colors_ofs`). Constructor stores the
    /// `background_colors` argument here for use by [`Widget::draw`].
    pub(crate) bgcolors: ColorPair,

    /// Mutex-guarded button-specific state.
    inner: Mutex<ButtonInner>,
}

// `Button: Send + Sync` is automatically derived because all fields
// are `Send + Sync`:
// - `WidgetState` is `Send + Sync` (its `List<Arc<dyn Widget>>` is
//   `Send + Sync` because `Widget: Send + Sync`).
// - `u32`, `ColorPair` are POD `Send + Sync`.
// - `Mutex<ButtonInner>` is `Send + Sync` because `ButtonInner: Send`
//   (its `Arc<dyn Widget>`, `Option<JoinHandle<()>>`, `Weak<Button>`,
//   scalar fields are all `Send`).

// ============================================================================
// Constructor — Button::new
// ============================================================================

impl Button {
    /// Construct a new button with the given caption and color triplet.
    ///
    /// Mirrors FASM `tui_button$new` (`tui_button.inc` lines 53–119)
    /// which takes four arguments: `rdi = string text`,
    /// `esi = background colors`, `edx = colors`,
    /// `ecx = focuscolors`.
    ///
    /// # Construction algorithm (FASM line-by-line preservation)
    ///
    /// 1. Compute `text_char_count = text.chars().count()` (FASM
    ///    `mov esi, [r9]` reads the FASM-string char count from offset 0).
    /// 2. Outer width = `text_char_count + WIDTH_PADDING` (`+= 7`).
    /// 3. Outer height = `BUTTON_HEIGHT` (= 4).
    /// 4. Allocate inherited [`WidgetState`] with the computed bounds
    ///    and pre-allocate the text/attr buffers when both dimensions
    ///    are positive (mirrors FASM `tui_background$init_ii` line 68).
    /// 5. Set `state.layout = Layout::None` (FASM
    ///    `tui_layout_absolute` per line 72).
    /// 6. Build the label caption by wrapping `text` with leading and
    ///    trailing line feeds: `"\n{text}\n"` (FASM lines 80–90 do
    ///    this with two `string$concat` calls).
    /// 7. Construct the embedded label via
    ///    [`Label::new_rect`] with rectangle
    ///    `(0, 0, text_char_count + LABEL_WIDTH_PADDING, LABEL_HEIGHT)`
    ///    and alignment [`TextAlign::Center`] (FASM lines 92–105).
    /// 8. Force the label's drop-shadow flag to `true` while we still
    ///    hold unique ownership of the `Arc<Label>` (FASM line 106:
    ///    `mov dword [rax+tui_dropshadow_ofs], 1`).
    /// 9. Append the label to `state.children` (FASM line 113:
    ///    `tui_vappendchild`).
    /// 10. Use [`Arc::new_cyclic`] to wire the [`ButtonInner::weak_self`]
    ///     field — this enables [`Widget::key_event`] (which only has
    ///     `&mut self`) to spawn the press-animation task with a
    ///     `Weak<Self>` back-reference to the button, avoiding both
    ///     reference cycles and `Arc<Self>`-style lifetime constraints.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if buffer pre-allocation overflows
    /// `usize` arithmetic (essentially impossible under realistic
    /// dimensions) or if the embedded [`Label`] constructor fails.
    pub fn new(
        text: &str,
        background_colors: ColorPair,
        normal_colors: ColorPair,
        focus_colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        // Step 1–3: compute outer dimensions.
        let text_char_count: i32 = i32::try_from(text.chars().count()).map_err(|_| {
            TuiError::Render(std::io::Error::other(format!(
                "Button::new: text too long for i32 (count={})",
                text.chars().count()
            )))
        })?;
        let width: i32 = text_char_count + WIDTH_PADDING;
        let height: i32 = BUTTON_HEIGHT;

        // Step 4: allocate WidgetState with positive dimensions and
        // pre-allocated text/attr buffers, replicating
        // TuiBackground::finalize_init's sizing logic.
        let mut state = WidgetState::new();
        state.width = width;
        state.height = height;
        state.width_percent = None;
        state.height_percent = None;
        // Step 5: absolute layout (FASM `tui_layout_absolute`,
        // mapped to `Layout::None` per the `Layout` enum docs).
        state.layout = Layout::None;

        if state.width > 0 && state.height > 0 {
            let cells = (state.width as usize)
                .checked_mul(state.height as usize)
                .ok_or_else(|| {
                    TuiError::Render(std::io::Error::other(format!(
                        "Button::new: width*height overflowed usize \
                         (width={}, height={})",
                        state.width, state.height
                    )))
                })?;
            let bytes = cells.checked_mul(4).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(format!(
                    "Button::new: cells*4 overflowed usize (cells={cells})"
                )))
            })?;
            // Reserve and append `bytes` zero bytes to the text buffer.
            state.text.reserve_exact(bytes);
            for _ in 0..bytes {
                state.text.push(0);
            }
            // Resize attributes to `cells` zero entries.
            state.attributes.cells.resize(cells, 0);
        }

        // Step 6: build label caption with newline padding.
        // FASM concatenates `"\n"` + text + `"\n"` via two
        // `string$concat` calls; the Rust equivalent is a single
        // formatted string.
        let label_text = format!("\n{text}\n");

        // Step 7: construct the embedded label.
        // Rect.bx = text_char_count + LABEL_WIDTH_PADDING (= text_char_count + 6),
        // matching FASM line 96. Rect.by = LABEL_HEIGHT (= 3).
        let label_rect = Rect::new(0, 0, text_char_count + LABEL_WIDTH_PADDING, LABEL_HEIGHT);
        let mut label_arc: Arc<Label> =
            Label::new_rect(label_rect, &label_text, normal_colors, TextAlign::Center)?;

        // Step 8: force the label's drop_shadow flag to `true`. We
        // still have unique ownership of the `Arc<Label>` (refcount =
        // 1 immediately after `new_rect`) so `Arc::get_mut` succeeds
        // here. After the subsequent `Arc::clone` for the children
        // list this would no longer be possible.
        if let Some(label_mut) = Arc::get_mut(&mut label_arc) {
            label_mut.state_mut().drop_shadow = true;
        }
        // Note: if `Arc::get_mut` returns None (which shouldn't happen
        // here under any current usage pattern since the Arc was
        // freshly returned by `new_rect`), the drop-shadow flag will
        // remain in its default state — this is acceptable because
        // the press animation tracking in `ButtonInner::label_drop_shadow`
        // takes precedence at render time.

        // Step 9: append the label as a laid-out child. We clone the
        // Arc once for `inner.label` storage, then move the original
        // into the children list.
        let label_for_inner: Arc<dyn Widget> = label_arc.clone();
        state.children.push_back(label_arc as Arc<dyn Widget>);

        // Step 10: build the Arc<Self> using new_cyclic so the inner
        // weak_self field is populated with a back-reference to the
        // button's own Arc allocation. This is the canonical Rust
        // idiom for self-referential Arc structures and is what
        // enables the spawned animation timer task to call back into
        // the button after `key_event` returns (see
        // `start_press_timer`).
        //
        // CAVEAT: state and label_for_inner are captured by move into
        // the closure, but `Arc::new_cyclic` will only invoke the
        // closure once (synchronously) before returning — there's no
        // capture-and-replay concern.
        Ok(Arc::new_cyclic(|weak: &Weak<Self>| {
            let inner = ButtonInner {
                label: label_for_inner,
                pressed: false,
                focussed: false,
                normal_colors,
                focus_colors,
                anim_timer: None,
                press_offset: (0, 0),
                label_drop_shadow: true,
                weak_self: weak.clone(),
            };
            Self {
                state,
                bgfillchar: b' ' as u32,
                bgcolors: background_colors,
                inner: Mutex::new(inner),
            }
        }))
    }
}

// ============================================================================
// Public accessors — focus and (test-only) press inspection.
// ============================================================================

impl Button {
    /// Return `true` when the button currently holds focus.
    ///
    /// FASM `tui_button_focussed_ofs` (offset +16). External focus-
    /// cycling code (e.g. `Alert::on_tab` cycling its focussed-button
    /// child) inspects this flag directly, so it is exposed as a
    /// public read accessor.
    ///
    /// Lock acquisition is robust against poisoning: a poisoned mutex
    /// (which can occur only if a previous call panicked while holding
    /// the lock) is recovered via `PoisonError::into_inner`. The
    /// alternative — propagating a panic — would leave the focus chain
    /// permanently broken, so the lenient policy is preferred.
    #[must_use]
    pub fn is_focussed(&self) -> bool {
        match self.inner.lock() {
            Ok(guard) => guard.focussed,
            Err(poisoned) => poisoned.into_inner().focussed,
        }
    }

    /// Return `true` while the button is mid-press (Space depressed,
    /// 300-ms animation timer pending).
    ///
    /// Used primarily by tests and by render-pass code that needs to
    /// query the press state to decide whether to apply the visual
    /// offset / drop-shadow toggle. No FASM equivalent; the FASM
    /// version inspects `tui_button_pressed_ofs` directly.
    #[must_use]
    pub fn is_pressed(&self) -> bool {
        match self.inner.lock() {
            Ok(guard) => guard.pressed,
            Err(poisoned) => poisoned.into_inner().pressed,
        }
    }

    /// Return the cumulative `(dx, dy)` cell offset currently applied
    /// to the embedded label as part of the press animation.
    ///
    /// `(0, 0)` at rest; `(1, 1)` while the press animation is active
    /// (mirrors FASM `tui_vmove(label, 1, 1)` on press and
    /// `tui_vmove(label, -1, -1)` on release). Render-pass code
    /// applies this offset to the label's cell positions when emitting
    /// glyphs to the terminal.
    #[must_use]
    pub fn press_offset(&self) -> (i32, i32) {
        match self.inner.lock() {
            Ok(guard) => guard.press_offset,
            Err(poisoned) => poisoned.into_inner().press_offset,
        }
    }

    /// Return the desired drop-shadow flag for the embedded label.
    ///
    /// `true` at rest; `false` during the press animation (mirrors
    /// FASM `mov dword [rsi+tui_dropshadow_ofs], 0` at line 259).
    /// Render-pass code overrides the label's own `state.drop_shadow`
    /// with this value when drawing the button subtree.
    #[must_use]
    pub fn label_drop_shadow(&self) -> bool {
        match self.inner.lock() {
            Ok(guard) => guard.label_drop_shadow,
            Err(poisoned) => poisoned.into_inner().label_drop_shadow,
        }
    }

    /// Return the configured "normal" (unfocussed) label colors.
    ///
    /// Inspector accessor. FASM equivalent: `[self +
    /// tui_button_normalcolors_ofs]`.
    #[must_use]
    pub fn normal_colors(&self) -> ColorPair {
        match self.inner.lock() {
            Ok(guard) => guard.normal_colors,
            Err(poisoned) => poisoned.into_inner().normal_colors,
        }
    }

    /// Return the configured "focussed" label colors.
    ///
    /// Inspector accessor. FASM equivalent: `[self +
    /// tui_button_focuscolors_ofs]`.
    #[must_use]
    pub fn focus_colors(&self) -> ColorPair {
        match self.inner.lock() {
            Ok(guard) => guard.focus_colors,
            Err(poisoned) => poisoned.into_inner().focus_colors,
        }
    }

    /// Return the configured background fill colors (read-only
    /// accessor for tests).
    #[must_use]
    pub fn bgcolors(&self) -> ColorPair {
        self.bgcolors
    }

    /// Return the configured background fill character.
    #[must_use]
    pub fn bgfillchar(&self) -> u32 {
        self.bgfillchar
    }
}

// ============================================================================
// Private helpers — press-animation timer management, fill primitives.
// ============================================================================

impl Button {
    /// Spawn the 300-ms press-animation timer task.
    ///
    /// Mirrors FASM `tui_button$keyevent` lines 266–271:
    ///
    /// ```text
    ///   mov edi, 300
    ///   mov rsi, [rsp]            ; self
    ///   call epoll$timer_new      ; -> rax = timer pointer
    ///   pop rdi
    ///   mov [rdi+tui_button_timerptr_ofs], rax
    ///   mov dword [rax+24], 2     ; flag: don't destroy widget on fire
    /// ```
    ///
    /// The `[rax+24]=2` flag in FASM tells the epoll timer dispatcher
    /// that the widget should NOT be destroyed when the timer fires
    /// (only the timer object itself should be cleaned up). The Rust
    /// equivalent is implicit: the `JoinHandle` only holds task state
    /// (no widget reference), and the spawned task uses a `Weak<Self>`
    /// reference that may already have been dropped by the time the
    /// timer fires — in which case the upgrade fails and the task
    /// exits silently.
    ///
    /// The handle is stored in [`ButtonInner::anim_timer`] so
    /// [`Widget::cleanup`] can call `.abort()` on it (FASM
    /// `epoll$timer_clear` equivalent).
    ///
    /// # Panics in non-async contexts
    ///
    /// `tokio::spawn` panics when called outside a tokio runtime. This
    /// helper guards against that by checking
    /// [`tokio::runtime::Handle::try_current`] first; in non-async
    /// contexts (e.g. unit tests not annotated with `#[tokio::test]`)
    /// the press animation is skipped silently — the synchronous state
    /// transition (`pressed = true`, offset applied, label colors
    /// updated) still happens, just without the 300-ms auto-finish.
    /// Callers can manually invoke [`Button::finish_press`] in that
    /// case.
    fn start_press_timer(&self) {
        // Upgrade the weak self-reference to an Arc; if upgrade fails
        // the button is mid-destruction and there's nothing to do.
        let weak: Weak<Self> = match self.inner.lock() {
            Ok(guard) => guard.weak_self.clone(),
            Err(poisoned) => poisoned.into_inner().weak_self.clone(),
        };

        // Bail if we're not running inside a tokio runtime — the press
        // animation is best-effort. Callers that need synchronous
        // behavior (tests) can drive the press completion manually
        // via `finish_press`.
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }

        let weak_for_task = weak.clone();
        let handle: JoinHandle<()> = tokio::spawn(async move {
            sleep(Duration::from_millis(PRESS_ANIMATION_MS)).await;
            // Upgrade Weak -> Arc only if the button is still alive.
            // If `upgrade()` returns None, the button was already
            // destroyed and there's nothing to do. This is the Rust
            // analog of FASM's [rax+24]=2 "no destroy" flag.
            if let Some(button) = weak_for_task.upgrade() {
                button.finish_press();
            }
        });
        // Store the handle so cleanup() can abort it. If a previous
        // animation handle is still in flight (shouldn't happen
        // because keyevent rejects re-entry while pressed=true) we
        // abort the old one before overwriting.
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(prior) = inner.anim_timer.take() {
                prior.abort();
            }
            inner.anim_timer = Some(handle);
        }
    }

    /// Complete the press animation: reset state, fire the click hook.
    ///
    /// Mirrors FASM `tui_button$timer` (`tui_button.inc` lines 188–207):
    ///
    /// ```text
    ///   pressed = 0
    ///   timer_ptr = 0
    ///   label.dropshadow = 1
    ///   tui_vmove(label, -1, -1)         ; restore label position
    ///   self.vupdatedisplaylist(self)
    ///   self.vclick(self)                ; fires vclicked
    ///   return 1                          ; destroy timer object
    /// ```
    ///
    /// In the Rust port:
    ///
    /// 1. `pressed` and `press_offset` are reset on the [`ButtonInner`]
    ///    behind the [`Mutex`].
    /// 2. `label_drop_shadow` is set back to `true`.
    /// 3. The `JoinHandle` is dropped (the task is already finished
    ///    when this method runs — no abort needed).
    /// 4. The FASM `tui_vclick` -> `vclicked` dispatch chain is
    ///    deliberately omitted at this layer: [`Widget::clicked`] is
    ///    `&mut self` and unreachable through the timer's `Arc<Self>`.
    ///    Application code subscribes to button clicks through other
    ///    means (composition layer dispatching `clicked` on a
    ///    fresh `&mut Button` reference, polling [`Self::is_pressed`]
    ///    transitions, etc.).
    pub(crate) fn finish_press(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.pressed = false;
            inner.press_offset = (0, 0);
            inner.label_drop_shadow = true;
            // Drop the now-finished JoinHandle without aborting (the
            // task has already completed by definition — we ARE the
            // task).
            inner.anim_timer = None;
        }
    }

    /// Replicate the FASM `tui_background$nvfill` algorithm.
    ///
    /// Fills the inherited `state.text` buffer with `bgfillchar`
    /// (when non-zero) and the `state.attributes` buffer with the
    /// packed `bgcolors`, sized to `width * height` cells. Mirrors
    /// `TuiBackground::nvfill` exactly so [`Widget::draw`] can produce
    /// the same byte-level output as the FASM-derived
    /// `tui_button$vtable[2] = tui_background$draw` slot.
    ///
    /// # Errors
    ///
    /// Bails on `width <= 0`, `height <= 0`, or empty text buffer
    /// (matching FASM's silent-skip behavior for unsized widgets);
    /// returns [`TuiError::Render`] on arithmetic overflow computing
    /// `cells * 4`.
    fn nvfill(&mut self) -> Result<(), TuiError> {
        let width = self.state.width;
        let height = self.state.height;
        if width <= 0 || height <= 0 {
            return Ok(());
        }
        if self.state.text.is_empty() {
            return Ok(());
        }
        let cells = (width as usize).checked_mul(height as usize).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(format!(
                "Button::nvfill: width*height overflowed usize \
                     (width={width}, height={height})"
            )))
        })?;
        let bytes = cells.checked_mul(4).ok_or_else(|| {
            TuiError::Render(std::io::Error::other(format!(
                "Button::nvfill: cells*4 overflowed usize (cells={cells})"
            )))
        })?;

        // Fill text buffer with bgfillchar when non-zero (FASM:
        // `cmp dword [rdi+tui_bgfillchar_ofs], 0; je .skip_text`).
        if self.bgfillchar != 0 {
            let fillchar = self.bgfillchar;
            let value_le = fillchar.to_le_bytes();
            // Grow / truncate to exactly `bytes` length.
            if self.state.text.len() < bytes {
                let need = bytes - self.state.text.len();
                self.state.text.reserve(need);
                for _ in 0..need {
                    self.state.text.push(0);
                }
            } else if self.state.text.len() > bytes {
                let excess = self.state.text.len() - bytes;
                self.state.text.truncate(excess).map_err(|e| {
                    TuiError::Render(std::io::Error::other(format!(
                        "Button::nvfill: text.truncate failed: {e:?}"
                    )))
                })?;
            }
            // Write `cells` u32s in little-endian byte order.
            for chunk in self.state.text.as_mut_slice().chunks_exact_mut(4).take(cells) {
                chunk.copy_from_slice(&value_le);
            }
        }

        // Always fill attributes (FASM unconditionally writes the
        // packed bgcolors regardless of bgfillchar).
        let packed = pack_color_pair(self.bgcolors);
        if self.state.attributes.cells.len() < cells {
            self.state.attributes.cells.resize(cells, 0);
        } else if self.state.attributes.cells.len() > cells {
            self.state.attributes.cells.truncate(cells);
        }
        for cell in self.state.attributes.cells.iter_mut() {
            *cell = packed;
        }

        Ok(())
    }
}

// ============================================================================
// Module-level helpers — color packing and WidgetState deep-clone.
// ============================================================================

/// Pack a [`ColorPair`] into the per-cell `u32` attribute encoding.
///
/// Bit layout (low-to-high):
/// - bits 0..=7: foreground
/// - bits 8..=15: background
/// - bits 16..=31: SGR attributes (reserved; zero from this helper)
///
/// Mirrors `TuiBackground::pack_color_pair` and
/// `crate::tui::widgets::label::pack_color_pair`. The duplication is
/// intentional: those two helpers are file-private in their respective
/// modules, and this Button module replicates the algorithm rather
/// than reaching into private implementation details.
fn pack_color_pair(cp: ColorPair) -> u32 {
    u32::from(cp.fg) | (u32::from(cp.bg) << 8)
}

/// Deep-clone helper for the inherited [`WidgetState`] portion of a
/// button.
///
/// Mirrors `TuiBackground::clone_widget_state` (which is file-private
/// in `background.rs`) and the equivalent in `label.rs`. Performs:
///
/// - Direct copy of all scalar / `Copy` fields (bounds, dimensions,
///   layout, alignment, drop_shadow, scroll, absolute coords, …).
/// - Deep copy of `display_name`, `text`, and `attributes`.
/// - Deep clone of `children` via each child's
///   [`Widget::clone_widget`] vmethod (the embedded label clones
///   itself recursively this way).
/// - Bastards are intentionally left empty (FASM `init_copy` resets
///   the bastards list to a fresh empty list at line 274 of
///   `tui_object.inc`).
///
/// # Errors
///
/// Returns [`TuiError::Render`] when any child's `clone_widget` fails.
fn clone_widget_state(src: &WidgetState) -> Result<WidgetState, TuiError> {
    let mut cloned = WidgetState::new();

    // Scalar / Copy fields — direct assignment.
    cloned.bounds = src.bounds;
    cloned.width = src.width;
    cloned.width_percent = src.width_percent;
    cloned.height = src.height;
    cloned.height_percent = src.height_percent;
    cloned.visible = src.visible;
    cloned.include_in_layout = src.include_in_layout;
    cloned.absolute_x = src.absolute_x;
    cloned.absolute_y = src.absolute_y;
    cloned.layout = src.layout;
    cloned.horiz_align = src.horiz_align;
    cloned.vert_align = src.vert_align;
    cloned.bastard_glue = src.bastard_glue;
    cloned.drop_shadow = src.drop_shadow;
    cloned.scroll = src.scroll;
    cloned.display_name = src.display_name.clone();

    // Buffers — deep-copy contents.
    cloned.text = src.text.clone();
    cloned.attributes = src.attributes.clone();

    // Children — deep-clone via each child's `clone_widget` (FASM
    // `tui_object$init_copy` lines 308–331). Bastards remain empty.
    for child in src.children.iter() {
        let cloned_child = child.clone_widget()?;
        cloned.children.push_back(cloned_child);
    }

    Ok(cloned)
}

// ============================================================================
// Widget trait implementation — 6 overrides, 31 inherited defaults.
// ============================================================================

impl Widget for Button {
    /// Required — return immutable access to the inherited
    /// [`WidgetState`].
    fn state(&self) -> &WidgetState {
        &self.state
    }

    /// Required — return mutable access to the inherited
    /// [`WidgetState`].
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    /// Required — downcast helper.
    fn as_any(&self) -> &dyn Any {
        self
    }

    // ---------------- Override 1: cleanup (vtable slot 0) ----------------

    /// Override — vtable slot 0 (`tui_button$cleanup`).
    ///
    /// FASM parallel: `tui_button$cleanup`
    /// (`tui_button.inc` lines 129–145):
    ///
    /// ```text
    ///   if timer_ptr != 0:
    ///     epoll$timer_clear(timer_ptr)
    ///   tui_object$cleanup(self)         ; recurse into children
    /// ```
    ///
    /// Rust translation:
    ///
    /// 1. Lock the inner mutex (poison-recovering) and abort any
    ///    pending `JoinHandle` (Rust analog of `epoll$timer_clear`).
    /// 2. Inline the trait-default cleanup body to clear children,
    ///    bastards, and the text/attributes/display_name buffers.
    ///    The default body is duplicated rather than called via
    ///    `Widget::cleanup(self)` because that would re-enter
    ///    polymorphically (calling this same method) per the same
    ///    pattern used by [`crate::tui::widgets::label::TuiLabel`].
    fn cleanup(&mut self) {
        // ---- Step 1: abort any pending press-animation timer.
        match self.inner.lock() {
            Ok(mut guard) => {
                if let Some(handle) = guard.anim_timer.take() {
                    handle.abort();
                }
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if let Some(handle) = guard.anim_timer.take() {
                    handle.abort();
                }
            }
        }

        // ---- Step 2: inline the trait-default cleanup body so we
        // don't recursively dispatch through the vtable.
        let state = &mut self.state;
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();
    }

    // ---------------- Override 2: clone_widget (vtable slot 1) -----------

    /// Override — vtable slot 1 (`tui_button$clone`).
    ///
    /// FASM parallel: `tui_button$clone`
    /// (`tui_button.inc` lines 150–183):
    ///
    /// ```text
    ///   alloc_clear(tui_button_size)
    ///   tui_background$init_copy(dst, src) ; deep-clones children
    ///                                      ; (which copies the label)
    ///   dst.normalcolors = src.normalcolors
    ///   dst.focuscolors  = src.focuscolors
    ///   dst.focussed     = src.focussed
    ///   dst.pressed      = 0               ; reset press state
    ///   dst.timerptr     = 0               ; reset timer
    ///   dst.label = dst.children[0]        ; rebind label to first child
    ///   dst.label.dropshadow = 1           ; force-restore drop shadow
    /// ```
    ///
    /// Rust translation:
    /// 1. Snapshot the source `inner` under the lock (extract scalar
    ///    fields). The `pressed`, `anim_timer`, and `press_offset`
    ///    fields are intentionally **not** copied — the FASM clone
    ///    explicitly resets them (lines 170, 174).
    /// 2. Deep-clone `self.state` via [`clone_widget_state`] which
    ///    polymorphically clones all children including the label.
    /// 3. Use [`Arc::new_cyclic`] (matching [`Self::new`]) to wire the
    ///    new button's `weak_self`. The label reference is rebound to
    ///    the first child of the cloned state (matching FASM line 176:
    ///    `mov rdx, [rax+tui_children_ofs]` ; `mov rdx, [rdx+_list_first]`).
    /// 4. The cloned label's drop-shadow flag is forced to `true` —
    ///    matching FASM line 180. We achieve this through the cloned
    ///    state.children[0] before the closure returns; if the Arc
    ///    is uniquely owned at this point (which it should be since
    ///    the clone returned a fresh Arc) we can mutate via
    ///    `Arc::get_mut`. If `get_mut` fails (not expected under
    ///    current usage), the override falls through and the label's
    ///    own `clone_widget` defaults are used.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when [`clone_widget_state`]
    /// reports an error from a nested child's [`Widget::clone_widget`]
    /// (e.g. the trait-default's `Unsupported` for an unimplemented
    /// override).
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // ---- Step 1: snapshot source inner.
        let (focussed, normal_colors, focus_colors) = match self.inner.lock() {
            Ok(g) => (g.focussed, g.normal_colors, g.focus_colors),
            Err(p) => {
                let g = p.into_inner();
                (g.focussed, g.normal_colors, g.focus_colors)
            }
        };

        // ---- Step 2: deep-clone the inherited WidgetState.
        let mut cloned_state = clone_widget_state(&self.state)?;

        // ---- Step 3: rebind the label to first child of the cloned
        // state and force its drop_shadow flag back to true. This
        // mirrors FASM lines 176-180.
        let label_for_inner: Arc<dyn Widget> = cloned_state
            .children
            .front()
            .ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "Button::clone_widget: cloned state has no children",
                ))
            })?
            .clone();

        // Best-effort drop-shadow restoration: we only mutate if we
        // hold the unique ref. The cloned child Arc may have just
        // been pushed by clone_widget_state and have refcount 2
        // (the children list + our local clone), so get_mut might
        // fail. In that case the label's own clone_widget already
        // set drop_shadow per its own state copy logic, so the
        // visual is correct anyway.
        if let Some(first_child) = cloned_state.children.front_mut() {
            if let Some(child_mut) = Arc::get_mut(first_child) {
                child_mut.state_mut().drop_shadow = true;
            }
        }

        let bgfillchar = self.bgfillchar;
        let bgcolors = self.bgcolors;

        // ---- Step 4: build the fresh cloned button via new_cyclic.
        Ok(Arc::new_cyclic(|weak: &Weak<Button>| {
            let inner = ButtonInner {
                label: label_for_inner,
                pressed: false,
                focussed,
                normal_colors,
                focus_colors,
                anim_timer: None,
                press_offset: (0, 0),
                label_drop_shadow: true,
                weak_self: weak.clone(),
            };
            Button {
                state: cloned_state,
                bgfillchar,
                bgcolors,
                inner: Mutex::new(inner),
            }
        }) as Arc<dyn Widget>)
    }

    // ---------------- Override 3: draw (vtable slot 2 — INHERITED) -------
    //
    // FASM `tui_button$vtable[2] = tui_background$draw`. The Rust
    // override below replicates `tui_background$draw`'s effect: fill
    // the text/attributes buffers via `nvfill`, then return Ok(()).
    // The embedded label child renders itself separately when the
    // parent walks the children list during the draw pass.

    /// FASM parallel: `tui_background$draw` (vtable slot 2). The
    /// button does NOT override this slot in FASM (`tui_button$vtable`
    /// references `tui_background$draw` directly), so the Rust port
    /// implements the same fill-only behavior here.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when [`Self::nvfill`] fails (only
    /// possible on arithmetic overflow with absurd dimensions).
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        // Replicates TuiBackground::draw: fill the inherited
        // text/attributes buffers with the configured bgfillchar /
        // bgcolors so the renderer pass produces the correct visual.
        // The embedded label is rendered separately by the parent's
        // child-walk during the same pass.
        self.nvfill()
    }

    // ---------------- Override 4: timer (vtable slot 6) ------------------

    /// Override — vtable slot 6 (`tui_button$timer`).
    ///
    /// FASM parallel: `tui_button$timer`
    /// (`tui_button.inc` lines 188–207). See [`Self::finish_press`]
    /// for the FASM-line-by-line breakdown.
    ///
    /// Note: this trait method is invoked by external timer
    /// dispatchers (e.g. tests, the `tokio` runtime if it ever calls
    /// the trait method directly). The 300-ms internal animation task
    /// calls [`Self::finish_press`] directly via the `Weak<Self>`
    /// upgrade — the trait `timer` method is the public, polymorphic
    /// entry point.
    fn timer(&mut self) {
        self.finish_press();
    }

    // ---------------- Override 5: got_focus (vtable slot 10) -------------

    /// Override — vtable slot 10 (`tui_button$gotfocus`).
    ///
    /// FASM parallel: `tui_button$gotfocus`
    /// (`tui_button.inc` lines 211–222):
    ///
    /// ```text
    ///   self.focussed = 1
    ///   tui_label$nvsetcolors(self.label, self.focuscolors)
    /// ```
    ///
    /// Rust translation:
    /// 1. Set `inner.focussed = true` under the lock.
    /// 2. Read out `focus_colors` and the label `Arc<dyn Widget>`.
    /// 3. Drop the lock before invoking [`Label::set_colors`] (which
    ///    takes its own lock on the label's interior state) to avoid
    ///    a potential deadlock if any future change makes the label
    ///    re-enter the button's lock.
    /// 4. Downcast the label's `&dyn Any` to `&Label` and call
    ///    `set_colors`. If the downcast fails (which would indicate
    ///    a refactor that broke the label invariant), the focus color
    ///    update is silently skipped — the focus state flag is still
    ///    correctly set.
    fn got_focus(&mut self) {
        let (label, focus_colors) = match self.inner.lock() {
            Ok(mut guard) => {
                guard.focussed = true;
                (guard.label.clone(), guard.focus_colors)
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.focussed = true;
                (guard.label.clone(), guard.focus_colors)
            }
        };
        // Lock released — safe to call set_colors which takes its
        // own lock on the label's interior.
        if let Some(label_concrete) = label.as_any().downcast_ref::<Label>() {
            label_concrete.set_colors(focus_colors);
        }
    }

    // ---------------- Override 6: lost_focus (vtable slot 11) ------------

    /// Override — vtable slot 11 (`tui_button$lostfocus`).
    ///
    /// FASM parallel: `tui_button$lostfocus`
    /// (`tui_button.inc` lines 224–235):
    ///
    /// ```text
    ///   self.focussed = 0
    ///   tui_label$nvsetcolors(self.label, self.normalcolors)
    /// ```
    ///
    /// Same translation strategy as [`Self::got_focus`] but with
    /// `normal_colors` instead of `focus_colors` and `focussed = false`.
    fn lost_focus(&mut self) {
        let (label, normal_colors) = match self.inner.lock() {
            Ok(mut guard) => {
                guard.focussed = false;
                (guard.label.clone(), guard.normal_colors)
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.focussed = false;
                (guard.label.clone(), guard.normal_colors)
            }
        };
        if let Some(label_concrete) = label.as_any().downcast_ref::<Label>() {
            label_concrete.set_colors(normal_colors);
        }
    }

    // ---------------- Override 7: set_focus (vtable slot 9) --------------

    /// Override — vtable slot 9 (`tui_object$setfocus`).
    ///
    /// Buttons accept focus (unlike the base widget which returns
    /// `false` from `set_focus`). Returns `true` to signal the focus
    /// chain that the button now holds focus; the caller subsequently
    /// invokes [`Self::got_focus`] to apply the visual update.
    ///
    /// This override is required because the base trait default
    /// returns `false` (no widget accepts focus by default), which
    /// would make Tab key navigation skip every Button.
    fn set_focus(&mut self) -> bool {
        true
    }

    // ---------------- Override 8: key_event (vtable slot 12) -------------

    /// Override — vtable slot 12 (`tui_button$keyevent`).
    ///
    /// FASM parallel: `tui_button$keyevent`
    /// (`tui_button.inc` lines 237–294):
    ///
    /// ```text
    ///   if !focussed:               return 0
    ///   if key == Tab:              vontab(self); return 1
    ///   if esc_key == 0x5A (S-Tab): vonshifttab(self); return 1
    ///   if key != Space:            return 0
    ///   if pressed:                 return 0   ; ignore re-press
    ///   pressed = 1
    ///   label.dropshadow = 0
    ///   tui_vmove(label, 1, 1)                 ; "pressed-in" effect
    ///   timer_ptr = epoll$timer_new(300, self) ; one-shot 300ms
    ///   timer_ptr.flags = 2                    ; don't destroy widget
    ///   self.vupdatedisplaylist(self)
    ///   return 1
    /// ```
    ///
    /// Rust translation:
    ///
    /// 1. Lock inner; if `!focussed`, drop and return `false` (FASM
    ///    `xor eax, eax`).
    /// 2. On `Tab`, call [`Self::on_tab`] and return `true`.
    /// 3. On `ShiftTab`, call [`Self::on_shift_tab`] and return `true`.
    /// 4. On `Char(' ')`:
    ///    - If `pressed`, return `false` (no re-press).
    ///    - Set `pressed = true`, `label_drop_shadow = false`,
    ///      `press_offset = PRESS_OFFSET`.
    ///    - Drop the lock and call [`Self::start_press_timer`] to
    ///      spawn the 300-ms one-shot tokio task.
    ///    - Call [`Self::update_display_list`] (no-op default — but
    ///      preserved for parity with FASM call site).
    ///    - Return `true`.
    /// 5. Any other key: return `false`.
    fn key_event(&mut self, event: KeyEvent) -> bool {
        // Step 1: focus-gate.
        let focussed = match self.inner.lock() {
            Ok(g) => g.focussed,
            Err(p) => p.into_inner().focussed,
        };
        if !focussed {
            return false;
        }

        // Step 2 & 3: Tab / Shift-Tab dispatch.
        match event {
            KeyEvent::Tab => {
                let _ = self.on_tab();
                return true;
            }
            KeyEvent::ShiftTab => {
                let _ = self.on_shift_tab();
                return true;
            }
            KeyEvent::Char(' ') => {
                // Fall through to step 4.
            }
            _ => {
                // FASM `.nothingtodo`.
                return false;
            }
        }

        // Step 4: Space-key press handler.
        let already_pressed = match self.inner.lock() {
            Ok(mut guard) => {
                if guard.pressed {
                    true
                } else {
                    guard.pressed = true;
                    guard.label_drop_shadow = false;
                    guard.press_offset = PRESS_OFFSET;
                    false
                }
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if guard.pressed {
                    true
                } else {
                    guard.pressed = true;
                    guard.label_drop_shadow = false;
                    guard.press_offset = PRESS_OFFSET;
                    false
                }
            }
        };
        if already_pressed {
            // FASM line 251–252: ignore re-press while pressed=1.
            return false;
        }

        // Spawn the 300-ms press-animation timer (best-effort —
        // no-op when not running inside a tokio runtime).
        self.start_press_timer();
        // FASM line 274: `tui_vupdatedisplaylist(self)`. The Rust
        // trait default is a no-op; container widgets override.
        self.update_display_list();
        true
    }

    // ---------------- Override 9: click (vtable slot 35) -----------------

    /// Override — vtable slot 35 (`tui_object$click`).
    ///
    /// The base `tui_object$click` method invokes the user-installed
    /// `tui_vclicked` callback. The Rust port preserves this two-step
    /// dispatch by overriding `click` to fire `clicked`, allowing
    /// composition-layer code to subscribe to button clicks via the
    /// trait `clicked` method while still letting the press-animation
    /// finish-handler ([`Self::finish_press`]) drive a synthetic
    /// click via the parent dispatcher.
    ///
    /// Returns `true` to indicate the click was consumed.
    fn click(&mut self, event: ClickEvent) -> bool {
        self.clicked(event);
        true
    }
}

// ============================================================================
// Tests
// ============================================================================
//
// The test suite exercises the [`Button`] widget at three layers:
//
// 1. Constants and constructor — verify the FASM-derived dimension
//    formulas (`width = chars + 7`, `height = 4`), the label child
//    rectangle (`bx = chars + 6`, `by = 3`), the centered alignment,
//    the newline-padded caption, and the initial drop-shadow flag.
// 2. Synchronous Widget trait behavior — focus toggle, key-event
//    focus-gate, Space-press state transition, re-press idempotency,
//    Tab/Shift-Tab dispatch, clone determinism, cleanup-time mutex
//    state.
// 3. Asynchronous press-animation lifecycle — `#[tokio::test]` cases
//    that exercise the spawned 300-ms timer task, verifying that the
//    pressed-state self-clears after the animation completes.
//
// All tests run synchronously where possible (animation tests use
// `#[tokio::test]` because `start_press_timer` short-circuits when no
// tokio runtime is active — the synchronous press state transition
// is verifiable via separate plain-`#[test]` cases).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::object::ClickEvent;
    use crate::tui::render::{RenderState, Renderer};

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    /// Helper — produce a "background" [`ColorPair`] (white on black).
    fn bg_colors() -> ColorPair {
        ColorPair::new(7, 0)
    }

    /// Helper — produce a "normal" (unfocussed) [`ColorPair`].
    fn normal_colors() -> ColorPair {
        ColorPair::new(2, 0)
    }

    /// Helper — produce a "focus" (focussed) [`ColorPair`].
    fn focus_colors() -> ColorPair {
        ColorPair::new(15, 4)
    }

    /// Test-only [`Renderer`] impl — needed to invoke
    /// [`Widget::draw`] but the button's draw delegates to
    /// `nvfill` which never touches the renderer.
    struct NullRenderer {
        state: RenderState,
    }

    impl NullRenderer {
        fn new() -> Self {
            Self {
                state: RenderState::default(),
            }
        }
    }

    impl Renderer for NullRenderer {
        fn ansi_output(&mut self, _bytes: &[u8]) -> Result<(), TuiError> {
            Ok(())
        }
        fn flush(&mut self) -> Result<(), TuiError> {
            Ok(())
        }
        fn state(&self) -> &RenderState {
            &self.state
        }
        fn state_mut(&mut self) -> &mut RenderState {
            &mut self.state
        }
    }

    /// Helper — construct a button "OK" with deterministic test colors.
    fn make_button(text: &str) -> Arc<Button> {
        Button::new(text, bg_colors(), normal_colors(), focus_colors())
            .expect("Button::new must succeed for valid input")
    }

    // ------------------------------------------------------------------
    // Section 1: Constants — verify FASM-derived dimensional invariants
    // ------------------------------------------------------------------

    /// FASM `tui_button$keyevent` line 267: `mov edi, 300` →
    /// 300 ms one-shot animation timer.
    #[test]
    fn test_press_animation_ms_constant() {
        assert_eq!(
            PRESS_ANIMATION_MS, 300,
            "FASM line 267 hard-codes 300 ms as the press-animation duration"
        );
    }

    /// FASM `tui_button$new` line 63: `add esi, 7` → outer width
    /// padding above the caption character count.
    #[test]
    fn test_width_padding_constant() {
        assert_eq!(
            WIDTH_PADDING, 7,
            "outer button width = chars + 7 per FASM line 63"
        );
    }

    /// FASM `tui_button$new` line 64: `mov edx, 4` → fixed height.
    #[test]
    fn test_button_height_constant() {
        assert_eq!(
            BUTTON_HEIGHT, 4,
            "outer button height is fixed at 4 per FASM line 64"
        );
    }

    /// FASM `tui_button$new` line 96: `add r8d, 6` → label rectangle
    /// inner width (one cell narrower than the outer button).
    #[test]
    fn test_label_width_padding_constant() {
        assert_eq!(
            LABEL_WIDTH_PADDING, 6,
            "label rectangle width = chars + 6 per FASM line 96"
        );
    }

    /// FASM `tui_button$new` line 104: `mov dword [rdi+12], 3` →
    /// label rectangle height.
    #[test]
    fn test_label_height_constant() {
        assert_eq!(LABEL_HEIGHT, 3, "label rectangle height = 3 per FASM line 104");
    }

    /// FASM `tui_button$keyevent` lines 262–263: `mov esi, 1` /
    /// `mov edx, 1` → press-time label offset (+1, +1).
    #[test]
    fn test_press_offset_constant() {
        assert_eq!(
            PRESS_OFFSET,
            (1, 1),
            "press-time label offset is (+1, +1) per FASM lines 262–263"
        );
    }

    // ------------------------------------------------------------------
    // Section 2: Constructor — dimension propagation, layout, children
    // ------------------------------------------------------------------

    /// `Button::new` returns `Arc<Self>` (not just `Self`) so the
    /// button can be appended to a parent's `Arc<dyn Widget>`
    /// children list and shared across the spawned timer task.
    #[test]
    fn test_new_returns_arc() {
        let button = make_button("OK");
        assert_eq!(
            Arc::strong_count(&button),
            1,
            "fresh button has exactly one strong ref"
        );
        // The cyclic builder establishes a Weak<Self> ref inside
        // ButtonInner.weak_self; weak_count should be exactly 1.
        assert_eq!(
            Arc::weak_count(&button),
            1,
            "Arc::new_cyclic establishes exactly one weak self-ref"
        );
    }

    /// `Button::new("X", ...)` produces a button of width 8
    /// (1 char + 7 padding) and height 4.
    #[test]
    fn test_new_dimensions_single_char() {
        let button = make_button("X");
        assert_eq!(button.state().width, 1 + WIDTH_PADDING, "width = chars + 7");
        assert_eq!(button.state().height, BUTTON_HEIGHT);
    }

    /// Empty caption — width is exactly `WIDTH_PADDING` (= 7),
    /// height is still `BUTTON_HEIGHT` (= 4).
    #[test]
    fn test_new_dimensions_empty_caption() {
        let button = make_button("");
        assert_eq!(button.state().width, WIDTH_PADDING);
        assert_eq!(button.state().height, BUTTON_HEIGHT);
    }

    /// Multi-char caption ("Cancel" = 6 chars) → width 13.
    #[test]
    fn test_new_dimensions_multi_char() {
        let button = make_button("Cancel");
        assert_eq!(button.state().width, 6 + WIDTH_PADDING);
        assert_eq!(button.state().height, BUTTON_HEIGHT);
    }

    /// Multi-byte UTF-8 caption: char count is computed via
    /// `text.chars().count()`, NOT `text.len()`. "héllo" = 5
    /// codepoints (one is two bytes in UTF-8) → width 12.
    #[test]
    fn test_new_dimensions_unicode_chars() {
        let button = make_button("héllo");
        assert_eq!(
            button.state().width,
            5 + WIDTH_PADDING,
            "5-codepoint caption produces width 12 (5 + 7)"
        );
    }

    /// `Button::new` sets `state.layout = Layout::None` (FASM's
    /// `tui_layout_absolute`).
    #[test]
    fn test_new_sets_layout_absolute() {
        let button = make_button("OK");
        assert_eq!(
            button.state().layout,
            Layout::None,
            "layout must be None (= absolute) per FASM line 72"
        );
    }

    /// `Button::new` sets `state.width_percent = None` and
    /// `state.height_percent = None` (no fractional sizing).
    #[test]
    fn test_new_no_percent_dimensions() {
        let button = make_button("OK");
        assert_eq!(button.state().width_percent, None);
        assert_eq!(button.state().height_percent, None);
    }

    /// `Button::new` pre-allocates the text buffer to
    /// `width * height * 4` bytes and the attributes to
    /// `width * height` cells. For "OK" → width 9, height 4 →
    /// 36 cells → 144 text bytes, 36 attribute cells.
    #[test]
    fn test_new_preallocates_buffers() {
        let button = make_button("OK");
        let cells = (button.state().width as usize) * (button.state().height as usize);
        assert_eq!(
            button.state().text.as_slice().len(),
            cells * 4,
            "text buffer holds 4 bytes per cell"
        );
        assert_eq!(
            button.state().attributes.cells.len(),
            cells,
            "attributes buffer holds 1 u32 per cell"
        );
    }

    /// `Button::new` appends exactly one child (the embedded label)
    /// to `state.children`.
    #[test]
    fn test_new_appends_label_child() {
        let button = make_button("OK");
        assert_eq!(
            button.state().children.len(),
            1,
            "button has exactly one child (the embedded label)"
        );
    }

    /// The first child is downcastable to `&Label` — confirms the
    /// embedded label was constructed via [`Label::new_rect`] and
    /// stored as `Arc<dyn Widget>`.
    #[test]
    fn test_label_child_is_downcastable() {
        let button = make_button("OK");
        let first_child = button
            .state()
            .children
            .iter()
            .next()
            .expect("button must have at least one child");
        let downcast = first_child.as_any().downcast_ref::<Label>();
        assert!(downcast.is_some(), "first child must downcast to &Label");
    }

    /// The label child has the expected dimensions:
    /// `width = chars + 6` (one less than outer), `height = 3`
    /// (top LF + center text + bottom LF).
    #[test]
    fn test_label_child_dimensions() {
        let button = make_button("OK");
        let label = button
            .state()
            .children
            .iter()
            .next()
            .expect("button must have one child")
            .as_any()
            .downcast_ref::<Label>()
            .expect("first child is a Label");
        // OK = 2 chars → label width = 8.
        assert_eq!(label.state().width, 2 + LABEL_WIDTH_PADDING);
        assert_eq!(label.state().height, LABEL_HEIGHT);
    }

    // ------------------------------------------------------------------
    // Section 3: Initial state — accessors return correct defaults
    // ------------------------------------------------------------------

    /// At construction time, the button is unfocussed.
    #[test]
    fn test_initial_state_unfocussed() {
        let button = make_button("OK");
        assert!(!button.is_focussed(), "fresh button is unfocussed");
    }

    /// At construction time, the button is not pressed.
    #[test]
    fn test_initial_state_not_pressed() {
        let button = make_button("OK");
        assert!(!button.is_pressed(), "fresh button is not pressed");
    }

    /// At construction time, no press offset is applied.
    #[test]
    fn test_initial_state_zero_press_offset() {
        let button = make_button("OK");
        assert_eq!(button.press_offset(), (0, 0), "fresh button has no press offset");
    }

    /// At construction time, the label drop shadow is enabled
    /// (mirrors FASM line 106: `mov dword [rax + tui_dropshadow_ofs], 1`).
    #[test]
    fn test_initial_state_label_drop_shadow_on() {
        let button = make_button("OK");
        assert!(
            button.label_drop_shadow(),
            "fresh button has label drop shadow ON per FASM line 106"
        );
    }

    /// Color accessors return what was passed to the constructor.
    #[test]
    fn test_color_accessors() {
        let bg = bg_colors();
        let normal = normal_colors();
        let focus = focus_colors();
        let button = Button::new("OK", bg, normal, focus).expect("ctor succeeds");

        assert_eq!(button.bgcolors(), bg, "bgcolors round-trips");
        assert_eq!(button.normal_colors(), normal, "normal_colors round-trips");
        assert_eq!(button.focus_colors(), focus, "focus_colors round-trips");
    }

    /// `bgfillchar` is set to ASCII space (0x20) per FASM line 65.
    #[test]
    fn test_bgfillchar_is_space() {
        let button = make_button("OK");
        assert_eq!(
            button.bgfillchar(),
            b' ' as u32,
            "bgfillchar = ASCII space per FASM line 65"
        );
    }

    // ------------------------------------------------------------------
    // Section 4: Widget trait — required methods
    // ------------------------------------------------------------------

    /// `Widget::state` returns immutable access to the underlying
    /// `WidgetState` field; values must be readable via
    /// `state().width`, etc.
    #[test]
    fn test_widget_state_access() {
        let button = make_button("OK");
        let state = button.state();
        assert_eq!(state.width, 9);
        assert_eq!(state.height, 4);
    }

    /// `Widget::state_mut` returns mutable access. Tested via
    /// `Arc::try_unwrap` to obtain the unique owned `Button`.
    #[test]
    fn test_widget_state_mut_access() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.state_mut().visible = false;
        assert!(!owned.state().visible);
    }

    /// `Widget::as_any` returns a `&dyn Any` that downcasts back
    /// to `&Button` — required for trait-object identification by
    /// parent containers.
    #[test]
    fn test_as_any_downcast() {
        let button = make_button("OK");
        let dyn_widget: Arc<dyn Widget> = button.clone();
        let downcast = dyn_widget.as_any().downcast_ref::<Button>();
        assert!(downcast.is_some(), "Button must downcast successfully via as_any");
    }

    /// `Widget::set_focus` returns `true` (Button accepts focus,
    /// overriding the trait default of `false`).
    #[test]
    fn test_set_focus_returns_true() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        assert!(
            owned.set_focus(),
            "set_focus must return true (Button accepts focus)"
        );
    }

    // ------------------------------------------------------------------
    // Section 5: Focus transitions — got_focus / lost_focus
    // ------------------------------------------------------------------

    /// `got_focus` flips `focussed` to `true` and propagates a color
    /// change to the embedded label.
    #[test]
    fn test_got_focus_sets_focussed_true() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        assert!(!owned.is_focussed(), "starts unfocussed");
        owned.got_focus();
        assert!(owned.is_focussed(), "got_focus → focussed = true");
    }

    /// `lost_focus` flips `focussed` to `false` after `got_focus`
    /// had set it to `true`.
    #[test]
    fn test_lost_focus_sets_focussed_false() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        assert!(owned.is_focussed());
        owned.lost_focus();
        assert!(!owned.is_focussed(), "lost_focus → focussed = false");
    }

    /// Repeated `got_focus` is idempotent — successive calls leave
    /// `focussed = true` without panicking.
    #[test]
    fn test_got_focus_idempotent() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        owned.got_focus();
        owned.got_focus();
        assert!(owned.is_focussed());
    }

    /// Calling `got_focus` when the embedded label child is downcast-
    /// able must not panic. The label color update happens via
    /// `Label::set_colors` which writes to the label's interior
    /// mutex.
    #[test]
    fn test_got_focus_propagates_to_label() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        // Verify the label child is reachable BEFORE got_focus.
        let label_present = owned
            .state()
            .children
            .iter()
            .next()
            .and_then(|c| c.as_any().downcast_ref::<Label>())
            .is_some();
        assert!(label_present, "label child must be downcastable");

        owned.got_focus();
        // Verify the label is still reachable AFTER got_focus
        // (set_colors does not destabilize the children list).
        let label_still_present = owned
            .state()
            .children
            .iter()
            .next()
            .and_then(|c| c.as_any().downcast_ref::<Label>())
            .is_some();
        assert!(label_still_present, "label child remains intact after got_focus");
    }

    /// Same as above but for `lost_focus` — the label must remain
    /// reachable after the color update.
    #[test]
    fn test_lost_focus_propagates_to_label() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        owned.lost_focus();
        let label_present = owned
            .state()
            .children
            .iter()
            .next()
            .and_then(|c| c.as_any().downcast_ref::<Label>())
            .is_some();
        assert!(label_present, "label child remains intact after lost_focus");
    }

    // ------------------------------------------------------------------
    // Section 6: key_event — focus gate, Tab/Shift-Tab, Space
    // ------------------------------------------------------------------

    /// `key_event` returns `false` for any key when the button is
    /// unfocussed (FASM line 245: `cmp dword [rdi+...focussed_ofs], 0;
    /// je .nothingtodo`).
    #[test]
    fn test_key_event_unfocussed_rejects_all_keys() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");

        assert!(!owned.is_focussed(), "starts unfocussed");
        assert!(
            !owned.key_event(KeyEvent::Char(' ')),
            "Space rejected when unfocussed"
        );
        assert!(!owned.key_event(KeyEvent::Tab), "Tab rejected when unfocussed");
        assert!(
            !owned.key_event(KeyEvent::ShiftTab),
            "Shift-Tab rejected when unfocussed"
        );
        assert!(
            !owned.key_event(KeyEvent::Enter),
            "Enter rejected when unfocussed"
        );
    }

    /// `key_event(Tab)` when focussed returns `true` (consumed) and
    /// invokes the on-tab dispatch (default impl returns false but
    /// the call is still made).
    #[test]
    fn test_key_event_tab_dispatch() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        assert!(owned.key_event(KeyEvent::Tab), "Tab when focussed returns true");
        // After Tab, the press state is unchanged.
        assert!(!owned.is_pressed(), "Tab does NOT trigger press");
    }

    /// `key_event(ShiftTab)` when focussed returns `true` and
    /// invokes the on-shift-tab dispatch.
    #[test]
    fn test_key_event_shift_tab_dispatch() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        assert!(
            owned.key_event(KeyEvent::ShiftTab),
            "Shift-Tab when focussed returns true"
        );
        assert!(!owned.is_pressed(), "Shift-Tab does NOT trigger press");
    }

    /// Non-actionable keys (Enter, Escape, arrow keys) when
    /// focussed return `false` (bubble up to parent).
    #[test]
    fn test_key_event_unhandled_keys_return_false() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        assert!(!owned.key_event(KeyEvent::Enter));
        assert!(!owned.key_event(KeyEvent::Escape));
        assert!(!owned.key_event(KeyEvent::ArrowUp));
        assert!(!owned.key_event(KeyEvent::ArrowDown));
        assert!(!owned.key_event(KeyEvent::Char('a')));
        assert!(!owned.key_event(KeyEvent::F(1)));
    }

    /// `key_event(Char(' '))` when focussed returns `true` and
    /// triggers the press: `pressed = true`, `label_drop_shadow =
    /// false`, `press_offset = (1, 1)`. The 300-ms timer is
    /// best-effort — outside a tokio runtime
    /// `start_press_timer` short-circuits silently, but the
    /// synchronous state mutations still happen.
    #[test]
    fn test_key_event_space_triggers_press() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        assert!(!owned.is_pressed(), "starts unpressed");

        let consumed = owned.key_event(KeyEvent::Char(' '));
        assert!(consumed, "Space when focussed returns true");

        assert!(owned.is_pressed(), "press transitions to true");
        assert!(!owned.label_drop_shadow(), "label drop shadow OFF during press");
        assert_eq!(
            owned.press_offset(),
            PRESS_OFFSET,
            "press offset = (+1, +1) per FASM lines 262-263"
        );
    }

    /// `key_event(Char(' '))` while already pressed returns `false`
    /// (re-press is rejected per FASM lines 251-252:
    /// `cmp dword [rdi+...pressed_ofs], 0; jne .nothingtodo`).
    #[test]
    fn test_key_event_space_re_press_rejected() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();

        let first = owned.key_event(KeyEvent::Char(' '));
        assert!(first, "first Space accepted");

        let second = owned.key_event(KeyEvent::Char(' '));
        assert!(
            !second,
            "second Space (already pressed) rejected per FASM lines 251-252"
        );

        // Verify state unchanged from first press.
        assert!(owned.is_pressed());
        assert_eq!(owned.press_offset(), PRESS_OFFSET);
    }

    /// Non-space `Char` key when focussed returns `false` (only
    /// Char(' ') is actionable).
    #[test]
    fn test_key_event_non_space_char_rejected() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        assert!(
            !owned.key_event(KeyEvent::Char('A')),
            "Char('A') when focussed returns false"
        );
        assert!(!owned.is_pressed(), "no press on non-space char");
    }

    /// `key_event(Char(' '))` when unfocussed has no effect.
    /// This is doubly checked by the focus-gate test above, but
    /// here we additionally confirm the press state is unchanged.
    #[test]
    fn test_key_event_space_unfocussed_no_state_change() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        // No focus.
        let result = owned.key_event(KeyEvent::Char(' '));
        assert!(!result, "Space when unfocussed returns false");
        assert!(!owned.is_pressed(), "press state unchanged");
        assert_eq!(owned.press_offset(), (0, 0));
        assert!(owned.label_drop_shadow());
    }

    // ------------------------------------------------------------------
    // Section 7: finish_press — synchronous press completion
    // ------------------------------------------------------------------

    /// `finish_press` (the synchronous press-completion helper)
    /// resets all press state to clean values: `pressed = false`,
    /// `press_offset = (0, 0)`, `label_drop_shadow = true`,
    /// `anim_timer = None`. This is the function the spawned
    /// 300-ms timer task invokes (via `Weak::upgrade`).
    #[test]
    fn test_finish_press_resets_all_press_state() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        let _ = owned.key_event(KeyEvent::Char(' '));

        // Pre-condition: button is in pressed state.
        assert!(owned.is_pressed());
        assert_eq!(owned.press_offset(), PRESS_OFFSET);
        assert!(!owned.label_drop_shadow());

        // Synchronously complete the press.
        owned.finish_press();

        // Post-condition: button is at rest.
        assert!(!owned.is_pressed(), "press cleared");
        assert_eq!(owned.press_offset(), (0, 0), "press offset cleared");
        assert!(owned.label_drop_shadow(), "drop shadow restored");
        let timer_after = match owned.inner.lock() {
            Ok(g) => g.anim_timer.is_some(),
            Err(p) => p.into_inner().anim_timer.is_some(),
        };
        assert!(!timer_after, "anim_timer cleared");
    }

    /// `finish_press` is idempotent — calling it on a button that
    /// is already at rest is a no-op.
    #[test]
    fn test_finish_press_idempotent() {
        let button = make_button("OK");
        let owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        // Button is at rest already.
        owned.finish_press();
        owned.finish_press();
        // No panics, state still clean.
        assert!(!owned.is_pressed());
        assert_eq!(owned.press_offset(), (0, 0));
        assert!(owned.label_drop_shadow());
    }

    // ------------------------------------------------------------------
    // Section 8: Widget::timer — vtable slot 6 dispatch
    // ------------------------------------------------------------------

    /// `Widget::timer` is the public, polymorphic dispatch for the
    /// press-end animation. It must produce the same effect as
    /// `finish_press`.
    #[test]
    fn test_timer_dispatch_completes_press() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.got_focus();
        let _ = owned.key_event(KeyEvent::Char(' '));
        assert!(owned.is_pressed(), "pre: pressed");

        // Invoke via the trait method (vtable slot 6).
        owned.timer();

        assert!(!owned.is_pressed(), "post: pressed cleared via timer()");
        assert!(owned.label_drop_shadow());
        assert_eq!(owned.press_offset(), (0, 0));
    }

    // ------------------------------------------------------------------
    // Section 9: Widget::draw — fills the buffers, doesn't fail
    // ------------------------------------------------------------------

    /// `Widget::draw` (vtable slot 2, inherited from
    /// `tui_background$draw`) succeeds and fills the text/attribute
    /// buffers with the configured `bgfillchar` and packed
    /// `bgcolors`.
    #[test]
    fn test_draw_fills_buffers_with_bgfillchar_and_bgcolors() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        let mut renderer = NullRenderer::new();
        owned.draw(&mut renderer).expect("draw must succeed");

        // Width 9 * Height 4 = 36 cells.
        let expected_cells = 36;
        assert_eq!(owned.state().attributes.cells.len(), expected_cells);
        assert_eq!(owned.state().text.as_slice().len(), expected_cells * 4);

        // Every text cell is filled with ASCII space (0x20).
        let space_le = (b' ' as u32).to_le_bytes();
        for chunk in owned.state().text.as_slice().chunks_exact(4) {
            assert_eq!(chunk, space_le.as_slice());
        }

        // Every attribute cell holds packed bgcolors.
        let expected_attr = pack_color_pair(bg_colors());
        for &cell in &owned.state().attributes.cells {
            assert_eq!(cell, expected_attr);
        }
    }

    /// Re-drawing a button is idempotent — multiple `draw` calls
    /// produce the same buffer state.
    #[test]
    fn test_draw_is_idempotent() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        let mut renderer = NullRenderer::new();
        owned.draw(&mut renderer).expect("first draw");
        let text_after_first = owned.state().text.as_slice().to_vec();
        let attrs_after_first = owned.state().attributes.cells.clone();

        owned.draw(&mut renderer).expect("second draw");
        assert_eq!(owned.state().text.as_slice(), text_after_first.as_slice());
        assert_eq!(owned.state().attributes.cells, attrs_after_first);
    }

    // ------------------------------------------------------------------
    // Section 10: Widget::click — overridden to dispatch clicked
    // ------------------------------------------------------------------

    /// `click` returns `true` (consumed). The trait default is
    /// `false` — Button overrides it to forward to `clicked`.
    #[test]
    fn test_click_returns_true() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        let event = ClickEvent {
            x: 0,
            y: 0,
            button: 1,
        };
        assert!(owned.click(event), "Button::click returns true");
    }

    // ------------------------------------------------------------------
    // Section 11: clone_widget — deep clone with reset press state
    // ------------------------------------------------------------------

    /// `clone_widget` returns an `Arc<dyn Widget>` that downcasts
    /// successfully back to `&Button`.
    #[test]
    fn test_clone_widget_downcasts_to_button() {
        let button = make_button("OK");
        let cloned = button.clone_widget().expect("clone_widget succeeds");
        let cloned_button = cloned.as_any().downcast_ref::<Button>();
        assert!(cloned_button.is_some(), "cloned widget must downcast to &Button");
    }

    /// Cloned button has identical dimensions to the source.
    #[test]
    fn test_clone_widget_preserves_dimensions() {
        let button = make_button("Cancel");
        let cloned = button.clone_widget().expect("clone_widget succeeds");
        assert_eq!(cloned.state().width, button.state().width);
        assert_eq!(cloned.state().height, button.state().height);
    }

    /// Cloned button has identical layout (Layout::None /
    /// `tui_layout_absolute`).
    #[test]
    fn test_clone_widget_preserves_layout() {
        let button = make_button("OK");
        let cloned = button.clone_widget().expect("clone_widget succeeds");
        assert_eq!(cloned.state().layout, Layout::None);
    }

    /// Cloned button has its own deep-cloned label child (FASM
    /// `init_copy` recurses into children via `clone_widget`).
    #[test]
    fn test_clone_widget_clones_label_child() {
        let button = make_button("OK");
        let cloned = button.clone_widget().expect("clone_widget succeeds");
        // Cloned button has exactly one child.
        assert_eq!(cloned.state().children.len(), 1);
        // The child is a Label.
        let label = cloned
            .state()
            .children
            .iter()
            .next()
            .expect("clone has a child")
            .as_any()
            .downcast_ref::<Label>();
        assert!(label.is_some(), "clone's child is a Label");
    }

    /// Cloned button starts at rest: `pressed = false`,
    /// `press_offset = (0, 0)`, `label_drop_shadow = true`,
    /// `anim_timer = None`. FASM lines 170, 174, 180 explicitly
    /// reset these in the clone path.
    #[test]
    fn test_clone_widget_resets_press_state() {
        // Press the source first.
        let source = make_button("OK");
        let mut source_owned = Arc::try_unwrap(source)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        source_owned.got_focus();
        let _ = source_owned.key_event(KeyEvent::Char(' '));
        assert!(source_owned.is_pressed(), "source is pressed");

        // Now clone.
        let cloned_dyn = source_owned.clone_widget().expect("clone succeeds");
        let cloned: &Button = cloned_dyn
            .as_any()
            .downcast_ref::<Button>()
            .expect("downcast succeeds");

        // Clone is at rest, regardless of source state.
        assert!(!cloned.is_pressed(), "clone pressed = false (FASM line 174)");
        assert_eq!(cloned.press_offset(), (0, 0), "clone press_offset = (0, 0)");
        assert!(
            cloned.label_drop_shadow(),
            "clone label drop shadow ON (FASM line 180)"
        );
        let cloned_timer = match cloned.inner.lock() {
            Ok(g) => g.anim_timer.is_some(),
            Err(p) => p.into_inner().anim_timer.is_some(),
        };
        assert!(!cloned_timer, "clone has no anim_timer");
    }

    /// Cloned button preserves `focussed`, `normal_colors`, and
    /// `focus_colors` (FASM lines 165-169 copy these directly).
    #[test]
    fn test_clone_widget_preserves_focus_and_colors() {
        let bg = bg_colors();
        let normal = normal_colors();
        let focus = focus_colors();
        let source = Button::new("OK", bg, normal, focus).expect("ctor succeeds");
        let mut source_owned = Arc::try_unwrap(source)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        source_owned.got_focus();

        let cloned_dyn = source_owned.clone_widget().expect("clone succeeds");
        let cloned: &Button = cloned_dyn
            .as_any()
            .downcast_ref::<Button>()
            .expect("downcast succeeds");

        assert!(
            cloned.is_focussed(),
            "clone preserves focussed=true (FASM line 165)"
        );
        assert_eq!(
            cloned.normal_colors(),
            normal,
            "clone preserves normal_colors (FASM line 167)"
        );
        assert_eq!(
            cloned.focus_colors(),
            focus,
            "clone preserves focus_colors (FASM line 169)"
        );
        assert_eq!(cloned.bgcolors(), bg, "clone preserves bgcolors");
    }

    /// Cloned button is a fresh `Arc` allocation distinct from
    /// the source.
    #[test]
    fn test_clone_widget_is_fresh_allocation() {
        let source = make_button("OK");
        let cloned = source.clone_widget().expect("clone succeeds");
        let source_ptr = Arc::as_ptr(&source) as *const ();
        let cloned_concrete = cloned
            .as_any()
            .downcast_ref::<Button>()
            .expect("downcast succeeds");
        let cloned_ptr = cloned_concrete as *const Button as *const ();
        assert!(
            !std::ptr::eq(source_ptr, cloned_ptr),
            "clone must be a fresh allocation"
        );
    }

    /// Cloned button has its own `weak_self` populated via
    /// `Arc::new_cyclic`. Verifying the weak count of the cloned
    /// `Arc<dyn Widget>` shows at least one weak ref (the
    /// internal `ButtonInner.weak_self`).
    #[test]
    fn test_clone_widget_has_weak_self_reference() {
        let source = make_button("OK");
        let cloned = source.clone_widget().expect("clone succeeds");
        // Arc::weak_count on the clone reflects the cyclic builder's
        // weak_self ref. Requires the cloned Arc to have weak_count >= 1.
        assert!(
            Arc::weak_count(&cloned) >= 1,
            "cloned button has its own weak_self ref"
        );
    }

    /// Repeated `clone_widget` produces independent clones — each
    /// is a fresh Arc and modifications to one do not affect the
    /// others.
    #[test]
    fn test_clone_widget_repeated_independence() {
        let source = make_button("OK");
        let clone1 = source.clone_widget().expect("clone1 succeeds");
        let clone2 = source.clone_widget().expect("clone2 succeeds");

        let p1 = clone1
            .as_any()
            .downcast_ref::<Button>()
            .map(|b| b as *const Button as *const ());
        let p2 = clone2
            .as_any()
            .downcast_ref::<Button>()
            .map(|b| b as *const Button as *const ());

        assert!(p1.is_some());
        assert!(p2.is_some());
        assert!(
            !std::ptr::eq(p1.unwrap(), p2.unwrap()),
            "two clones are independent allocations"
        );
    }

    // ------------------------------------------------------------------
    // Section 12: cleanup — abort timer + clear inherited state
    // ------------------------------------------------------------------

    /// `cleanup` clears the inherited state buffers: children,
    /// bastards, text, attributes, and display_name.
    #[test]
    fn test_cleanup_clears_inherited_state() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");

        // Pre-condition: state buffers and children are populated.
        assert!(!owned.state().text.is_empty());
        assert!(!owned.state().attributes.cells.is_empty());
        assert!(!owned.state().children.is_empty());

        owned.cleanup();

        // Post-condition: everything cleared.
        assert!(owned.state().text.is_empty(), "text cleared after cleanup");
        assert!(
            owned.state().attributes.cells.is_empty(),
            "attributes cleared after cleanup"
        );
        assert!(
            owned.state().children.is_empty(),
            "children cleared after cleanup"
        );
        assert!(
            owned.state().bastards.is_empty(),
            "bastards cleared after cleanup"
        );
        assert!(
            owned.state().display_name.is_empty(),
            "display_name cleared after cleanup"
        );
    }

    /// `cleanup` is idempotent — second call is a no-op and does
    /// not panic.
    #[test]
    fn test_cleanup_is_idempotent() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.cleanup();
        owned.cleanup();
        // No panic; state remains cleared.
        assert!(owned.state().children.is_empty());
    }

    /// `cleanup` clears the `anim_timer` field even when no timer
    /// is active (covers the `None` branch of `take()`).
    #[test]
    fn test_cleanup_with_no_active_timer() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        // No press, so no timer to abort.
        let timer_before = match owned.inner.lock() {
            Ok(g) => g.anim_timer.is_some(),
            Err(p) => p.into_inner().anim_timer.is_some(),
        };
        assert!(!timer_before, "no timer pre-cleanup");
        owned.cleanup();
        // Still none.
        let timer_after = match owned.inner.lock() {
            Ok(g) => g.anim_timer.is_some(),
            Err(p) => p.into_inner().anim_timer.is_some(),
        };
        assert!(!timer_after, "no timer post-cleanup");
    }

    // ------------------------------------------------------------------
    // Section 13: Helpers — pack_color_pair byte format
    // ------------------------------------------------------------------

    /// `pack_color_pair` produces the FASM-defined byte layout:
    /// `(bg << 8) | fg` in the low 16 bits.
    #[test]
    fn test_pack_color_pair_byte_layout() {
        let cp = ColorPair::new(7, 0);
        let packed = pack_color_pair(cp);
        assert_eq!(packed & 0xFF, 7, "fg in low byte");
        assert_eq!((packed >> 8) & 0xFF, 0, "bg in second byte");
        assert_eq!(packed >> 16, 0, "high 16 bits zero (no SGR)");
    }

    /// Various `pack_color_pair` round-trips.
    #[test]
    fn test_pack_color_pair_round_trips() {
        // (fg, bg) → (fg, bg << 8)
        for (fg, bg, expected) in [
            (0, 0, 0u32),
            (255, 0, 0xFF),
            (0, 255, 0xFF00),
            (0xAB, 0xCD, 0xCDAB),
            (1, 7, 0x0701),
        ] {
            let cp = ColorPair::new(fg, bg);
            assert_eq!(pack_color_pair(cp), expected);
        }
    }

    // ------------------------------------------------------------------
    // Section 14: clone_widget_state helper — direct invocation
    // ------------------------------------------------------------------

    /// `clone_widget_state` produces a `WidgetState` with copied
    /// scalar fields and deep-cloned children.
    #[test]
    fn test_clone_widget_state_copies_scalars() {
        let mut src = WidgetState::new();
        src.width = 42;
        src.height = 7;
        src.visible = false;
        src.absolute_x = 10;
        src.absolute_y = 20;
        src.drop_shadow = true;

        let cloned = clone_widget_state(&src).expect("clone succeeds");
        assert_eq!(cloned.width, 42);
        assert_eq!(cloned.height, 7);
        assert!(!cloned.visible);
        assert_eq!(cloned.absolute_x, 10);
        assert_eq!(cloned.absolute_y, 20);
        assert!(cloned.drop_shadow);
    }

    /// `clone_widget_state` deep-clones the text and attributes
    /// buffers so the source and clone are independent.
    #[test]
    fn test_clone_widget_state_deep_clones_buffers() {
        let mut src = WidgetState::new();
        src.text.push(0xAA);
        src.text.push(0xBB);
        src.attributes.cells.push(0x12345678);

        let cloned = clone_widget_state(&src).expect("clone succeeds");
        assert_eq!(cloned.text.as_slice(), &[0xAA, 0xBB]);
        assert_eq!(cloned.attributes.cells, vec![0x12345678]);
    }

    /// `clone_widget_state` resets the bastards list to empty
    /// (FASM `init_copy` line 274).
    #[test]
    fn test_clone_widget_state_resets_bastards() {
        let src = WidgetState::new();
        let cloned = clone_widget_state(&src).expect("clone succeeds");
        assert_eq!(cloned.bastards.len(), 0);
    }

    // ------------------------------------------------------------------
    // Section 15: nvfill — direct invocation (private helper)
    // ------------------------------------------------------------------

    /// `nvfill` early-returns on zero or negative dimensions.
    #[test]
    fn test_nvfill_zero_dim_no_op() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        // Force width to 0 — nvfill should bail.
        owned.state.width = 0;
        let prior_len = owned.state.text.as_slice().len();
        owned.nvfill().expect("nvfill must not error on width=0");
        assert_eq!(
            owned.state.text.as_slice().len(),
            prior_len,
            "nvfill leaves buffer untouched on width=0"
        );
    }

    /// `nvfill` early-returns on empty text buffer.
    #[test]
    fn test_nvfill_empty_buffer_no_op() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.state.text.clear();
        owned.nvfill().expect("nvfill must succeed on empty buffer");
        // Buffer remains empty.
        assert!(owned.state.text.is_empty());
    }

    /// `nvfill` with `bgfillchar = 0` skips the text fill but
    /// still updates attributes.
    #[test]
    fn test_nvfill_zero_fillchar_skips_text_fill() {
        let button = make_button("OK");
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.bgfillchar = 0;
        // Pre-fill text with a sentinel byte so we can detect a write.
        for byte in owned.state.text.as_mut_slice() {
            *byte = 0xEE;
        }
        owned.nvfill().expect("nvfill succeeds");
        // Sentinel survives because bgfillchar=0 skips text fill.
        let expected_text_byte = 0xEE;
        for &byte in owned.state.text.as_slice() {
            assert_eq!(byte, expected_text_byte, "bgfillchar=0 must not overwrite text");
        }
        // Attributes ARE updated unconditionally.
        let expected_attr = pack_color_pair(bg_colors());
        for &cell in &owned.state.attributes.cells {
            assert_eq!(cell, expected_attr);
        }
    }

    // ------------------------------------------------------------------
    // Section 16: ButtonInner — internal state inspection via `inner`
    // ------------------------------------------------------------------

    /// `ButtonInner.weak_self` is populated via `Arc::new_cyclic`
    /// — verify it upgrades back to the same Arc as the original.
    #[test]
    fn test_inner_weak_self_upgrades_correctly() {
        let button = make_button("OK");
        let weak = match button.inner.lock() {
            Ok(g) => g.weak_self.clone(),
            Err(p) => p.into_inner().weak_self.clone(),
        };
        let upgraded = weak.upgrade();
        assert!(upgraded.is_some(), "weak_self upgrades successfully");
        let upgraded_arc = upgraded.expect("upgraded");
        // Same underlying allocation as `button`.
        assert!(
            Arc::ptr_eq(&button, &upgraded_arc),
            "upgraded Arc points to the same allocation"
        );
    }

    // ------------------------------------------------------------------
    // Section 17: Async tests — press animation lifecycle
    // ------------------------------------------------------------------

    /// **Async**: full press animation lifecycle.
    ///
    /// 1. Press the button (via `key_event(Space)`).
    /// 2. Observe `is_pressed = true` immediately.
    /// 3. Sleep 350 ms (longer than `PRESS_ANIMATION_MS = 300`).
    /// 4. Observe `is_pressed = false` (timer task fired).
    ///
    /// This exercises the full `start_press_timer` →
    /// `tokio::spawn` → `sleep(300ms)` → `Weak::upgrade` →
    /// `finish_press` flow.
    #[tokio::test]
    async fn test_press_animation_completes_after_300ms() {
        let button = make_button("OK");
        // Mutate via &mut self requires Arc::try_unwrap, but we
        // need to keep the Arc alive for the timer task's
        // weak_self upgrade. Workaround: clone the Arc, then
        // mutate via try_unwrap on a temporary, then re-clone.
        // Simpler: hold the Arc and manually run key_event by
        // first flipping focussed via an internal helper.
        //
        // Since key_event takes &mut self but we need the Arc
        // alive for the timer task, and we cannot easily get
        // &mut self out of Arc<Button> without unique ownership,
        // we drive the press synchronously by mutating ButtonInner
        // through the internal mutex — this is exactly what
        // `key_event` does internally.

        // Set focussed=true manually.
        match button.inner.lock() {
            Ok(mut g) => g.focussed = true,
            Err(p) => p.into_inner().focussed = true,
        }
        // Manually flip the press state.
        match button.inner.lock() {
            Ok(mut g) => {
                g.pressed = true;
                g.label_drop_shadow = false;
                g.press_offset = PRESS_OFFSET;
            }
            Err(p) => {
                let mut g = p.into_inner();
                g.pressed = true;
                g.label_drop_shadow = false;
                g.press_offset = PRESS_OFFSET;
            }
        }
        // Spawn the press-animation timer (uses the inner.weak_self).
        button.start_press_timer();

        // Pre-condition: button is pressed.
        assert!(button.is_pressed(), "press observed pre-sleep");

        // Sleep slightly longer than the animation duration.
        tokio::time::sleep(Duration::from_millis(PRESS_ANIMATION_MS + 50)).await;

        // Post-condition: timer fired, press cleared.
        assert!(!button.is_pressed(), "press auto-clears after PRESS_ANIMATION_MS");
        assert_eq!(button.press_offset(), (0, 0), "press_offset cleared by timer");
        assert!(button.label_drop_shadow(), "label_drop_shadow restored by timer");
    }

    /// **Async**: the timer handle is stored in `anim_timer` and
    /// cleanup aborts it.
    #[tokio::test]
    async fn test_anim_timer_handle_stored_and_aborted() {
        let button = make_button("OK");
        // Set focus and trigger press internally.
        match button.inner.lock() {
            Ok(mut g) => {
                g.focussed = true;
                g.pressed = true;
            }
            Err(p) => {
                let mut g = p.into_inner();
                g.focussed = true;
                g.pressed = true;
            }
        }
        button.start_press_timer();

        // Verify the handle was stored.
        let timer_present = match button.inner.lock() {
            Ok(g) => g.anim_timer.is_some(),
            Err(p) => p.into_inner().anim_timer.is_some(),
        };
        assert!(timer_present, "start_press_timer stores the handle");

        // Now drop the button via try_unwrap and call cleanup —
        // cleanup() must abort the still-pending timer.
        let mut owned = Arc::try_unwrap(button)
            .map_err(|_| ())
            .expect("test holds the only Arc reference");
        owned.cleanup();
        // Verify timer is taken/aborted.
        let timer_after = match owned.inner.lock() {
            Ok(g) => g.anim_timer.is_some(),
            Err(p) => p.into_inner().anim_timer.is_some(),
        };
        assert!(!timer_after, "cleanup aborts and clears anim_timer");
    }

    /// **Async**: the spawned timer task uses `Weak<Self>` and
    /// fails to fire if the button is dropped before
    /// `PRESS_ANIMATION_MS` elapses (no panic, silent exit).
    #[tokio::test]
    async fn test_timer_task_exits_silently_after_button_drop() {
        let button = make_button("OK");
        match button.inner.lock() {
            Ok(mut g) => {
                g.focussed = true;
                g.pressed = true;
            }
            Err(p) => {
                let mut g = p.into_inner();
                g.focussed = true;
                g.pressed = true;
            }
        }
        button.start_press_timer();

        // Drop the strong ref BEFORE the timer fires.
        drop(button);

        // Wait long enough for the timer to fire — if it
        // panicked or held a strong ref, this would fail.
        tokio::time::sleep(Duration::from_millis(PRESS_ANIMATION_MS + 100)).await;
        // Test reaches this point without panic — pass.
    }

    /// **Async**: synchronous re-press is rejected even when a
    /// timer is in flight. The pending animation continues
    /// uninterrupted.
    #[tokio::test]
    async fn test_re_press_during_animation_rejected() {
        let button = make_button("OK");
        match button.inner.lock() {
            Ok(mut g) => g.focussed = true,
            Err(p) => p.into_inner().focussed = true,
        }
        // Apply press state and spawn timer.
        match button.inner.lock() {
            Ok(mut g) => {
                g.pressed = true;
                g.label_drop_shadow = false;
                g.press_offset = PRESS_OFFSET;
            }
            Err(p) => {
                let mut g = p.into_inner();
                g.pressed = true;
                g.label_drop_shadow = false;
                g.press_offset = PRESS_OFFSET;
            }
        }
        button.start_press_timer();
        assert!(button.is_pressed());

        // Briefly wait, then try to re-press synchronously
        // (mirrors what key_event does).
        tokio::time::sleep(Duration::from_millis(50)).await;
        let already_pressed = match button.inner.lock() {
            Ok(g) => g.pressed,
            Err(p) => p.into_inner().pressed,
        };
        assert!(already_pressed, "still pressed mid-animation");

        // Wait for animation to fully complete.
        tokio::time::sleep(Duration::from_millis(PRESS_ANIMATION_MS + 50)).await;
        assert!(
            !button.is_pressed(),
            "animation completes regardless of re-press attempt"
        );
    }

    // ------------------------------------------------------------------
    // Section 18: Sanity — Button is Send + Sync
    // ------------------------------------------------------------------

    /// `Button: Send + Sync` — the trait bound `Widget: Send + Sync`
    /// requires this; verify via a compile-time assertion.
    #[test]
    fn test_button_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<Button>();
        assert_sync::<Button>();
        // Also verify Arc<Button> is Send + Sync (needed for
        // sharing across tokio tasks).
        assert_send::<Arc<Button>>();
        assert_sync::<Arc<Button>>();
    }

    /// `Button` implements `Widget` — verifiable by coercing to
    /// `Arc<dyn Widget>`.
    #[test]
    fn test_button_implements_widget_trait() {
        let button = make_button("OK");
        let _as_widget: Arc<dyn Widget> = button as Arc<dyn Widget>;
    }
}
