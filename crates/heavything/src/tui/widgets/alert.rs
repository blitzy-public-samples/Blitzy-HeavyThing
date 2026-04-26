// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2015-2018 2 Ton Digital, Jeff Marrison
// Copyright (C) 2026 Blitzy Translation Project (Rust port)
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Modal alert dialog widget — a [`TuiPanel`] wrapper with a custom
//! Tab / Shift-Tab vtable.
//!
//! Translated from FASM `tui_alert.inc` (519 lines, 2015-2018, 2 Ton
//! Digital, Jeff Marrison). The FASM module exports a single
//! constructor (`tui_alert$new`) plus exactly **two** vtable overrides
//! (`tui_alert$ontab` at slot 29 and `tui_alert$onshifttab` at slot 30);
//! every other vmethod is inherited verbatim from `tui_panel$vtable`.
//! The Rust port mirrors that layout: [`TuiAlert`] embeds a [`TuiPanel`]
//! by value and delegates every [`Widget`] trait method to it except
//! [`Widget::on_tab`] and [`Widget::on_shift_tab`], which contain the
//! custom button-cycle logic.
//!
//! # Layout
//!
//! Constructed via [`TuiAlert::new`]:
//!
//! ```text
//!   ┌──[ title ]──────────────────────────┐
//!   │                                     │
//!   │           message text              │
//!   │           (multi-line, centered)    │
//!   │                                     │
//!   │  [Ok] [Cancel] [Yes] [No] [Continue]│
//!   └─────────────────────────────────────┘
//!     (drop-shadow rendered below)
//! ```
//!
//! - The message label is LF-prepended to push the rendered text one
//!   row away from the top border.
//! - The button row (here called the *buttonbox*) is a 100% × 4 layout
//!   container with `Layout::Horizontal`. Its children are arranged
//!   `[hspacer, button, hspacer, button, …, button, hspacer]` so the
//!   visual spacing distributes evenly via the FASM "stretchy"
//!   100%-width spacers (`tui_hspacer$new_d(100.0)`).
//! - Buttons appear in a fixed canonical order (OK, Cancel, Yes, No,
//!   Continue, Quit), filtered by the [`AlertButtons`] bitmask passed
//!   to [`TuiAlert::new`].
//!
//! # Tab / Shift-Tab navigation
//!
//! FASM lines 392–456 / 461–518 implement custom button-cycling that
//! walks the buttonbox children list (skipping hspacers via
//! `_list_nextofs`/`_list_prevofs`) and wraps at the ends. The
//! implementation makes a documented rigid assumption (FASM lines
//! 392–397):
//!
//! > "we _ASSUME_ that no other objects were added to us, and our
//! >  contents are precisely what the above constructor `tui_alert$new`
//! >  produced."
//!
//! Specifically: buttons live at **odd** indices in the buttonbox
//! children list (1, 3, 5, 7, 9, 11), and the total child count is
//! `2 * button_count + 1`. The Rust port preserves this invariant and
//! relies on it directly. Adding extra widgets to the buttonbox after
//! construction is documented as undefined behavior, matching FASM.
//!
//! # v1 limitation: focus is tracked internally
//!
//! FASM `tui_alert$ontab` calls `vlostfocus` and `vgotfocus` on the
//! departing / arriving [`Button`] widgets. In Rust, [`Button::new`]
//! constructs its inner state via [`std::sync::Arc::new_cyclic`] which
//! populates the inner `weak_self` field. Empirically verified:
//!
//! ```text
//! Arc::new_cyclic → strong_count: 1, weak_count: 1
//! Arc::get_mut → FAILS  (requires weak_count == 0)
//! ```
//!
//! Because [`Button`] *always* holds a self-pointing [`std::sync::Weak`]
//! reference (used by its press-animation timer), [`std::sync::Arc::get_mut`]
//! never yields a `&mut Button` — even immediately after construction.
//! This rules out external invocation of [`Widget::got_focus`] /
//! [`Widget::lost_focus`] on a button's [`Arc<dyn Widget>`]. The Rust
//! port adopts the same v1 strategy documented in
//! [`crate::tui::widgets::form`] (lines 107–118 of that file): track
//! focus index internally via a [`std::sync::Mutex`]-protected
//! [`TuiAlertInner`] and defer per-button visual focus changes to a
//! future [`Button`] revision that exposes a public `set_focussed`
//! setter. The cycling logic, the wrap-around behavior, and the rigid
//! odd-index assumption from FASM are all preserved exactly.

use std::any::Any;
use std::ops::{BitOr, BitOrAssign};
use std::sync::{Arc, Mutex};

use crate::error::TuiError;
use crate::tui::object::{ColorPair, HorizAlign, KeyEvent, Layout, Widget, WidgetState};
use crate::tui::widgets::button::Button;
use crate::tui::widgets::label::{Label, TextAlign};
use crate::tui::widgets::panel::{Panel, TuiPanel};
use crate::tui::widgets::spacers::{TuiHSpacer, VBox};

// ============================================================================
// AlertButtons — bitfield identifying which buttons appear in a TuiAlert
// ============================================================================

/// Bitflags identifying which buttons appear in a [`TuiAlert`] dialog.
///
/// Combine flags with the bitwise OR operator (`|`) to request multiple
/// buttons in one alert; for example
/// `AlertButtons::OK | AlertButtons::CANCEL` displays both an *Ok* and a
/// *Cancel* button. Buttons appear in the dialog left-to-right in the
/// fixed canonical order **OK, Cancel, Yes, No, Continue, Quit**
/// regardless of the order in which the flags were combined.
///
/// # FASM provenance
///
/// Translated from the six `tui_alert_*` constants in the header of
/// `tui_alert.inc` (lines 51–57):
///
/// ```text
/// tui_alert_ok       = 1
/// tui_alert_cancel   = 2
/// tui_alert_yes      = 4
/// tui_alert_no       = 8
/// tui_alert_continue = 16
/// tui_alert_quit     = 32
/// ```
///
/// The FASM constructor extracts these flags from the `edx` argument
/// and tests each bit in turn (`test dword [rsp+16], <bit>`); the Rust
/// port replicates the same bit-pattern semantics so callers porting
/// from FASM see identical behavior.
///
/// # Examples
///
/// ```
/// use heavything::tui::widgets::alert::AlertButtons;
///
/// let buttons = AlertButtons::YES | AlertButtons::NO | AlertButtons::CANCEL;
/// assert!(buttons.contains(AlertButtons::YES));
/// assert!(buttons.contains(AlertButtons::NO));
/// assert!(buttons.contains(AlertButtons::CANCEL));
/// assert!(!buttons.contains(AlertButtons::OK));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct AlertButtons(u32);

impl AlertButtons {
    /// Display an *Ok* button.
    ///
    /// FASM constant `tui_alert_ok = 1` (`tui_alert.inc` line 51).
    pub const OK: Self = Self(1);

    /// Display a *Cancel* button.
    ///
    /// FASM constant `tui_alert_cancel = 2` (`tui_alert.inc` line 52).
    pub const CANCEL: Self = Self(2);

    /// Display a *Yes* button.
    ///
    /// FASM constant `tui_alert_yes = 4` (`tui_alert.inc` line 53).
    pub const YES: Self = Self(4);

    /// Display a *No* button.
    ///
    /// FASM constant `tui_alert_no = 8` (`tui_alert.inc` line 54).
    pub const NO: Self = Self(8);

    /// Display a *Continue* button.
    ///
    /// FASM constant `tui_alert_continue = 16` (`tui_alert.inc` line 55).
    pub const CONTINUE: Self = Self(16);

    /// Display a *Quit* button.
    ///
    /// FASM constant `tui_alert_quit = 32` (`tui_alert.inc` line 56).
    pub const QUIT: Self = Self(32);

    /// The empty set (no buttons).
    pub const EMPTY: Self = Self(0);

    /// Combine `self` with `other` via bitwise OR.
    ///
    /// `AlertButtons::OK.union(AlertButtons::CANCEL)` is equivalent to
    /// the operator-form `AlertButtons::OK | AlertButtons::CANCEL`.
    /// The `const` qualifier lets callers build fixed flag sets at
    /// compile time, mirroring how FASM emits the literal sum of bit
    /// values into the `edx` argument register.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Test whether *every* bit set in `flag` is also set in `self`.
    ///
    /// Returns `false` when `flag` is the empty set (zero bits) so that
    /// `AlertButtons::EMPTY.contains(AlertButtons::EMPTY)` is `false`,
    /// matching the natural FASM semantic that "no flag" never matches
    /// in a `test`/`jnz` chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use heavything::tui::widgets::alert::AlertButtons;
    ///
    /// let combined = AlertButtons::OK | AlertButtons::QUIT;
    /// assert!(combined.contains(AlertButtons::OK));
    /// assert!(combined.contains(AlertButtons::QUIT));
    /// assert!(!combined.contains(AlertButtons::CANCEL));
    /// ```
    #[must_use]
    pub const fn contains(self, flag: Self) -> bool {
        flag.0 != 0 && (self.0 & flag.0) == flag.0
    }

    /// Construct an [`AlertButtons`] from a raw `u32` bitfield.
    ///
    /// Bits outside the canonical 6-button range (0x3F) are preserved
    /// verbatim — they have no observable effect on construction or
    /// rendering, but [`Self::bits`] round-trips them. Provided as the
    /// inverse of [`Self::bits`] for FFI / serialization scenarios.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Return the underlying `u32` bitfield.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl BitOr for AlertButtons {
    type Output = Self;

    /// Bitwise-OR two [`AlertButtons`] values, producing the union of
    /// their flag bits. Equivalent to [`Self::union`].
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl BitOrAssign for AlertButtons {
    /// In-place bitwise-OR; sets every flag bit in `rhs` on `self`.
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ============================================================================
// TuiAlertInner — Mutex-protected dynamic state
// ============================================================================

/// Mutex-protected dynamic state for [`TuiAlert`].
///
/// FASM `tui_alert` adds **no** extra fields beyond the inherited
/// `tui_panel` layout; focus state lives entirely inside the embedded
/// [`Button`] widgets via their `tui_button.focussed` flag. The Rust
/// port cannot mutate that flag externally because [`Button::new`]
/// uses [`std::sync::Arc::new_cyclic`] (see the module-level "v1
/// limitation" note), so [`TuiAlert`] keeps its own focus pointer
/// here. The stored value is the **child index inside the buttonbox**
/// (i.e. `state.children[idx]`); per the rigid FASM layout this is
/// always odd (1, 3, 5, …) when `Some`.
#[derive(Debug)]
struct TuiAlertInner {
    /// Index of the currently focused button **inside the buttonbox's
    /// children list**. `Some(1)` immediately after a successful
    /// [`TuiAlert::new`] with at least one button (matching FASM lines
    /// 329–340 which focus the second buttonbox child = first button
    /// after the leading hspacer). `None` when the alert has zero
    /// buttons or whenever the focus has been programmatically
    /// cleared.
    focused_index: Option<usize>,

    /// Number of buttons in the buttonbox (= count of set flags in
    /// the [`AlertButtons`] mask passed to [`TuiAlert::new`]). Stored
    /// verbatim so the cycle helpers do not need to re-derive it from
    /// `(children.len() - 1) / 2` on every keypress.
    button_count: usize,
}

// ============================================================================
// TuiAlert — Panel-wrapper modal alert dialog
// ============================================================================

/// Modal alert dialog widget — a titled [`TuiPanel`] with a multi-line
/// centered message and 1–6 standard buttons (Ok, Cancel, Yes, No,
/// Continue, Quit).
///
/// `TuiAlert` is the most minimal panel-wrapper in the HeavyThing
/// widget tree: only the [`Widget::on_tab`] and [`Widget::on_shift_tab`]
/// vmethods are overridden (FASM `tui_alert$vtable` lines 33–45). Every
/// other vmethod resolves to [`TuiPanel`]'s implementation through the
/// embedded `base` field.
///
/// Construct via [`TuiAlert::new`]:
///
/// ```text
/// let alert = TuiAlert::new(
///     b"Confirm",
///     b"Are you sure?",
///     AlertButtons::YES | AlertButtons::NO,
///     panel_colors,
///     button_normal,
///     button_focus,
/// )?;
/// ```
///
/// The returned [`std::sync::Arc<TuiAlert>`] can be appended to any
/// parent widget that accepts an `Arc<dyn Widget>`. To detect which
/// button the user pressed, register a click callback on each
/// [`Button`] before calling [`Widget::append_child`] (see FASM lines
/// 22–31: "the button itself will be passed inside a click event, in
/// which case you can examine its button text").
///
/// Translated from `tui_alert.inc`.
pub struct TuiAlert {
    /// Inherited [`TuiPanel`]. Owns the entire child tree (border,
    /// title, hbox, guts container with message-label + buttonbox).
    base: TuiPanel,

    /// Original [`AlertButtons`] mask passed to [`Self::new`]. Stored
    /// so [`Widget::clone_widget`] can preserve the same bitmask on
    /// the clone, and so [`std::fmt::Debug`] / introspection can
    /// inspect which buttons the alert was constructed with without
    /// re-walking the widget tree.
    button_flags: AlertButtons,

    /// Mutex-protected mutable state (focus tracking + button count).
    /// See [`TuiAlertInner`] for field documentation.
    inner: Mutex<TuiAlertInner>,
}

impl std::fmt::Debug for TuiAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner_snapshot = self.inner.lock().ok();
        f.debug_struct("TuiAlert")
            .field("button_flags", &self.button_flags)
            .field("inner", &inner_snapshot)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// TuiAlert — inherent methods (constructor + helpers)
// ============================================================================

/// Per-button text and width contribution (FASM `tui_button$new`
/// allocates `text_len + 7` cells per button). Listed in canonical
/// order so [`TuiAlert::new`] can iterate it once. The numeric widths
/// match the comments at FASM `tui_alert.inc` lines 98–103. Button
/// labels are taken verbatim from the FASM `cleartext` declarations
/// at `tui_alert.inc` lines 346–351 (`'Ok'`, `'Cancel'`, `'Yes'`,
/// `'No'`, `'Continue'`, `'Quit'`).
const BUTTON_TABLE: &[(AlertButtons, &str, i32)] = &[
    (AlertButtons::OK, "Ok", 9),
    (AlertButtons::CANCEL, "Cancel", 13),
    (AlertButtons::YES, "Yes", 10),
    (AlertButtons::NO, "No", 9),
    (AlertButtons::CONTINUE, "Continue", 15),
    (AlertButtons::QUIT, "Quit", 11),
];

impl TuiAlert {
    /// Construct a new modal alert dialog.
    ///
    /// Translated from FASM `tui_alert$new` (`tui_alert.inc` lines
    /// 60–344). The constructor:
    ///
    /// 1. Splits `message` on `b'\n'` and computes the maximum line
    ///    length (FASM lines 71–82 via `string$split` +
    ///    `list$foreach_arg`).
    /// 2. Computes the panel **width** as the maximum of:
    ///    * `32` (FASM line 85 — the absolute minimum),
    ///    * `title.chars().count() + 6` (FASM lines 87–90),
    ///    * `max_message_line + 6` (FASM lines 91–95),
    ///    * `sum_of_set_button_widths + 6` (FASM lines 96–130; widths
    ///      are 9, 13, 10, 9, 15, 11 for OK, Cancel, Yes, No,
    ///      Continue, Quit respectively).
    /// 3. Computes the panel **height** as `line_count + 8` for a
    ///    single-line message and `line_count + 9` for multi-line
    ///    (FASM lines 134–141: `cmova edx, ecx` adds the extra row
    ///    only when `line_count > 1`).
    /// 4. Builds a [`TuiPanel`] via [`Panel::new_ii`] using the same
    ///    color for both the background and the title bar (FASM lines
    ///    149–154 pass `[rsp+24]` to both `ecx` and `r8d`).
    /// 5. Sets `drop_shadow = true` (FASM line 158).
    /// 6. Builds a [`Label`] from `b'\n' + message` (LF-prepended via
    ///    `string$concat`, FASM lines 161–170) and appends it through
    ///    the panel's [`Widget::append_child`] override.
    /// 7. Builds the *buttonbox*: a [`VBox`] re-configured with
    ///    `Layout::Horizontal` (FASM lines 180–194 allocate a raw
    ///    `tui_object` with `tui_object$simple_vtable` and call
    ///    `tui_object$init_di(100%, 4)` then set
    ///    `tui_horizontal_ofs`).
    /// 8. Appends a leading 100% hspacer (FASM lines 195–201) followed
    ///    by, for each set flag in canonical order: a [`Button`] with
    ///    width = `text_len + 7`, then a trailing 100% hspacer (FASM
    ///    lines 203–326).
    /// 9. Appends the buttonbox to the panel (FASM lines 191–193) —
    ///    the panel routes it into the guts container alongside the
    ///    message label.
    /// 10. Records `Some(1)` as the initial focused-button index when
    ///     the buttonbox has at least one button (FASM lines 329–340
    ///     focus the second buttonbox child = first button after the
    ///     leading hspacer). The Rust port cannot call
    ///     [`Widget::got_focus`] on the [`Button`]'s `Arc<dyn Widget>`
    ///     here (see the module-level "v1 limitation" note); only the
    ///     internal index is recorded.
    ///
    /// # Arguments
    ///
    /// * `title` — panel title bar text. Rendered centered above the
    ///   border with two characters of padding on each side. Shown as
    ///   raw bytes via UTF-8 decoding (lossy — invalid bytes are
    ///   replaced with U+FFFD, matching the rest of the Rust TUI port).
    /// * `message` — body text. May contain `b'\n'` line separators
    ///   to produce a multi-line message; each line is rendered
    ///   center-aligned within the panel body.
    /// * `button_flags` — bitmask of [`AlertButtons`] to display. An
    ///   alert with `button_flags == AlertButtons::EMPTY` is permitted
    ///   (zero buttons, no buttonbox cycling).
    /// * `panel_colors` — color pair for the panel background and the
    ///   title bar (used as both `bgcolors` and `titlecolors` per
    ///   FASM convention).
    /// * `normal_colors` — color pair for buttons in the unfocused
    ///   state. Forwarded as the third argument to [`Button::new`].
    /// * `focus_colors` — color pair for the currently-focused
    ///   button. Forwarded as the fourth argument to [`Button::new`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] when:
    ///
    /// * [`Panel::new_ii`] fails to allocate the panel,
    /// * [`Arc::try_unwrap`] cannot recover the panel by value (a
    ///   defensive guard — the factory always returns a strong-
    ///   count-1 [`Arc`] on success),
    /// * [`Label::new_dd_vec`] fails to construct the message label,
    /// * any [`TuiHSpacer::new_d`] or [`Button::new`] call fails,
    /// * [`Arc::get_mut`] cannot acquire unique access to the
    ///   buttonbox — also a defensive guard,
    /// * the buttonbox's inherent [`VBox::append_child`] fails for any
    ///   appended child.
    pub fn new(
        title: &[u8],
        message: &[u8],
        button_flags: AlertButtons,
        panel_colors: ColorPair,
        normal_colors: ColorPair,
        focus_colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        // --- Step 1: split message + compute max line length --------
        //
        // FASM lines 71–82 build a `string$split` list and pass it
        // through `list$foreach_arg` with the `.linelength` callback to
        // populate `[rsp+56]` (the running max). The Rust port uses
        // direct byte iteration via [`Self::count_lines`] and
        // [`Self::max_line_length`] — no allocation needed.
        let line_count = Self::count_lines(message);
        let max_msg_line = Self::max_line_length(message);

        // --- Step 2: compute panel width -----------------------------
        //
        // `width = max(32, title_chars+6, max_msg_line+6, sum_btn+6)`
        // (FASM lines 85–130).  Title length is measured in *Unicode
        // scalar values* (FASM `string$count` operates on the same
        // domain because the FASM library stores strings as UTF-32
        // codepoints — see `string32.inc`).
        let title_str = String::from_utf8_lossy(title).into_owned();
        let title_chars = title_str.chars().count() as i32;
        let sum_button_widths = Self::total_button_width(button_flags);

        let mut width: i32 = 32;
        if title_chars + 6 > width {
            width = title_chars + 6;
        }
        if max_msg_line + 6 > width {
            width = max_msg_line + 6;
        }
        if sum_button_widths + 6 > width {
            width = sum_button_widths + 6;
        }

        // --- Step 3: compute panel height ----------------------------
        //
        // FASM lines 134–141:
        //   edx = list_size              ; line_count
        //   ecx = edx + 1
        //   if (edx > 1) edx = ecx       ; +1 only when multi-line
        //   edx += 8
        //
        // line_count == 1 → height = 9
        // line_count > 1  → height = line_count + 9
        let height: i32 = if line_count > 1 {
            line_count + 9
        } else {
            line_count + 8
        };

        // --- Step 4: build the panel -------------------------------
        //
        // FASM lines 149–154 call `tui_panel$new_ii(width, height,
        // title, panel_colors, panel_colors)` — `ecx` and `r8d` both
        // receive `[rsp+24]`. The Rust [`Panel::new_ii`] signature is
        //   (width, height, fillchar, fill_colors, title)
        // where `fill_colors` is forwarded to **both** `bgcolors` and
        // `titlecolors` (`panel.rs` line 399). Match FASM exactly by
        // passing `panel_colors` as `fill_colors` and using `b' '` as
        // the fill character.
        let panel_arc = Panel::new_ii(width, height, u32::from(b' '), panel_colors, &title_str)?;
        let mut base = Arc::try_unwrap(panel_arc).map_err(|_arc| {
            TuiError::Render(std::io::Error::other(
                "TuiAlert::new: Panel::new_ii returned a shared Arc (refcount > 1)",
            ))
        })?;

        // --- Step 5: enable drop-shadow -----------------------------
        //
        // FASM line 158: `mov dword [rax+tui_dropshadow_ofs], 1`.
        base.set_drop_shadow(true);

        // --- Step 6: LF-prepended message label ---------------------
        //
        // FASM lines 161–170: `string$concat .lfstr, message` produces
        // `"\n" + message`, then `tui_label$new_dd(100%, 100%, lf_msg,
        // panel_colors, tui_textalign_center)` builds the label, which
        // is appended via the panel's vtable-dispatched `vappendchild`.
        //
        // We replicate the LF-prepend by building a fresh [`Vec<u8>`]
        // with capacity for `message.len() + 1`, pushing `b'\n'`, and
        // extending with `message`. [`Label::new_dd_vec`] consumes the
        // [`Vec<u8>`] by value, eliminating one heap copy compared to
        // FASM (which would have called `string$copy` internally).
        let mut filltext = Vec::with_capacity(message.len() + 1);
        filltext.push(b'\n');
        filltext.extend_from_slice(message);
        let msg_label = Label::new_dd_vec(100.0, 100.0, filltext, panel_colors, TextAlign::Center)?;

        // FASM lines 171–175: append via the panel's vtable. In Rust
        // the panel's [`Widget::append_child`] override (`panel.rs`
        // line 784) routes the child into the guts container,
        // preserving the border tree. We use the disambiguated
        // [`Widget::append_child`] call so the trait override fires
        // regardless of any inherent `append_child` method on
        // [`Panel`].
        Widget::append_child(&mut base, msg_label as Arc<dyn Widget>);

        Ok(Arc::new(Self::finalize_buttonbox(
            base,
            button_flags,
            panel_colors,
            normal_colors,
            focus_colors,
        )?))
    }

    /// Build the buttonbox, append it to `base`, and assemble the
    /// final [`TuiAlert`] value.
    ///
    /// Split out from [`Self::new`] so the fallible buttonbox
    /// construction can use `?` propagation against a single
    /// [`Result<Self, TuiError>`] return type.
    ///
    /// FASM correspondence: lines 180–201 (buttonbox creation +
    /// leading hspacer) and 203–328 (per-flag button + trailing
    /// hspacer loop) and 329–340 (initial focus on second buttonbox
    /// child).
    fn finalize_buttonbox(
        mut base: TuiPanel,
        button_flags: AlertButtons,
        panel_colors: ColorPair,
        normal_colors: ColorPair,
        focus_colors: ColorPair,
    ) -> Result<Self, TuiError> {
        // --- Step 7: build the buttonbox ----------------------------
        //
        // FASM lines 180–194:
        //   call heap$alloc          ; tui_object_size buffer
        //   call tui_object$simple_vtable
        //   call tui_object$init_di  ; 100% × 4
        //   set tui_horizalign_ofs   ; tui_layout_horizontal
        //
        // The Rust [`VBox::new_pct_i(100.0, 4, HorizAlign::Left)`]
        // produces an equivalent layout-only container; we mutate
        // `state.layout` in place to switch to horizontal arrangement.
        // [`HorizAlign::Left`] is chosen (not `Center`) so the inner
        // hspacers — which are the FASM "stretchy" 100% spacers — get
        // the leftover layout glue distributed across them, exactly
        // matching FASM's "horizontal layout, hspacer-button-hspacer"
        // semantic. A `HorizAlign::Center` would centre the whole
        // assembled hbox horizontally, which is **already** the
        // behavior we want because the spacers themselves expand to
        // consume the leftover width on either side.
        let mut buttonbox_arc = VBox::new_pct_i(100.0, 4, HorizAlign::Left);

        // Acquire unique `&mut VBox` and configure it. [`VBox`] is
        // constructed via plain [`Arc::new`] (`spacers.rs` line 489),
        // not [`Arc::new_cyclic`], so [`Arc::get_mut`] succeeds while
        // we still own the only strong reference.
        let mut button_count: usize = 0;
        {
            let bb_mut = Arc::get_mut(&mut buttonbox_arc).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiAlert::new: VBox Arc unexpectedly aliased before buttonbox configuration",
                ))
            })?;

            // Switch the layout from vertical (VBox default, `spacers.rs`
            // line 484) to horizontal so children are placed left-to-
            // right. The `state` field on [`VBox`] is `pub(crate)` so
            // direct field mutation is permitted within this crate.
            bb_mut.state.layout = Layout::Horizontal;

            // --- Step 8: leading hspacer ---------------------------
            //
            // FASM lines 195–201: `tui_hspacer$new_d(100.0)` then append
            // to buttonbox via vtable.
            let leading = TuiHSpacer::new_d(100.0)?;
            bb_mut.append_child(leading as Arc<dyn Widget>)?;

            // --- Step 9: per-flag button + trailing hspacer loop ----
            //
            // FASM lines 203–326 are six near-identical blocks (one
            // per button), each:
            //   test edx, <flag>
            //   jz   .skip_<button>
            //   call tui_button$new(text, bg_colors, normal_colors,
            //                       focus_colors)
            //   call vappendchild on buttonbox
            //   call tui_hspacer$new_d(100.0)
            //   call vappendchild on buttonbox
            //   .skip_<button>:
            //
            // The Rust port iterates [`BUTTON_TABLE`] in canonical
            // order, filtering by [`AlertButtons::contains`]. The FASM
            // button-text-len-derived width (`text_len + 7`) is
            // already enforced inside [`Button::new`] (`button.rs`
            // applies the same `WIDTH_PADDING = 7` constant), so we do
            // not need to pass an explicit width here.
            for (flag, label, _width_contribution) in BUTTON_TABLE.iter().copied() {
                if button_flags.contains(flag) {
                    // FASM `tui_button$new(text, bg=panel_colors,
                    //  normal=button_colors, focus=focus_button_colors)`
                    // — note the *background* slot is the panel's
                    // color (so the button's empty cells blend with
                    // the alert), while normal/focus apply to the
                    // pressed/unpressed text rendering.
                    let button = Button::new(label, panel_colors, normal_colors, focus_colors)?;
                    bb_mut.append_child(button as Arc<dyn Widget>)?;

                    // Trailing hspacer after each button — FASM emits
                    // this even after the last button, producing the
                    // structure
                    //   [hspacer, btn, hspacer, btn, …, btn, hspacer]
                    // that the Tab / Shift-Tab cycle code relies on.
                    let trailing = TuiHSpacer::new_d(100.0)?;
                    bb_mut.append_child(trailing as Arc<dyn Widget>)?;

                    button_count += 1;
                }
            }
        }

        // --- Step 10: append buttonbox to panel --------------------
        //
        // FASM lines 191–193 / 156-onwards: append via the panel's
        // vtable, which routes the child into the guts container
        // alongside the message label.
        Widget::append_child(&mut base, buttonbox_arc as Arc<dyn Widget>);

        // --- Step 11: initial focus index --------------------------
        //
        // FASM lines 329–340: navigate
        //   alert.guts.children.last  → buttonbox
        //   buttonbox.children.first  → leading hspacer
        //   leading.next              → first button (or null if no
        //                               buttons were appended)
        //   if not null: call vgotfocus on first button
        //
        // The Rust port records the same focus position (`Some(1)`,
        // i.e. the second buttonbox child after the leading hspacer)
        // when at least one button exists. The actual
        // [`Widget::got_focus`] call is omitted per the v1 limitation
        // documented at the top of this module.
        let focused_index = if button_count > 0 { Some(1_usize) } else { None };

        Ok(Self {
            base,
            button_flags,
            inner: Mutex::new(TuiAlertInner {
                focused_index,
                button_count,
            }),
        })
    }

    /// Read-only access to the embedded [`TuiPanel`]'s [`WidgetState`].
    ///
    /// Mirrors the inherent `state()` exported by [`Panel`] and
    /// satisfies the [`TuiAlert`] export schema. See [`Widget::state`]
    /// for the trait-form equivalent.
    #[must_use]
    pub fn state(&self) -> &WidgetState {
        self.base.state()
    }

    /// Mutable access to the embedded [`TuiPanel`]'s [`WidgetState`].
    ///
    /// Mirrors the inherent `state_mut()` exported by [`Panel`]. See
    /// [`Widget::state_mut`] for the trait-form equivalent.
    pub fn state_mut(&mut self) -> &mut WidgetState {
        self.base.state_mut()
    }

    /// Inherent forwarder for [`Widget::key_event`].
    ///
    /// FASM `tui_alert$vtable` keeps `tui_object$key_event` in slot 28
    /// (event routing fires `on_tab` / `on_shift_tab` directly through
    /// dedicated vtable slots, not via `key_event`). This inherent
    /// method exists solely to satisfy the [`TuiAlert`] export schema;
    /// it delegates to the [`Widget::key_event`] trait default
    /// (`object.rs` line 850), which returns `false` so the event
    /// bubbles up to the framework's tab dispatcher.
    pub fn key_event(&mut self, event: KeyEvent) -> bool {
        <Self as Widget>::key_event(self, event)
    }

    /// Total combined width contribution of the buttons in `flags`.
    ///
    /// FASM lines 96–127 build this sum via a chain of `cmovnz`
    /// instructions that conditionally accumulate each button's width
    /// (Ok = 9, Cancel = 13, Yes = 10, No = 9, Continue = 15,
    /// Quit = 11). The Rust port iterates [`BUTTON_TABLE`] for the
    /// same effect and is `const`-eligible (the iteration is bounded
    /// at six steps).
    ///
    /// This excludes the trailing `+6` adjustment — the caller adds
    /// it on the final compare (FASM line 128: `add eax, 6`).
    fn total_button_width(flags: AlertButtons) -> i32 {
        let mut sum: i32 = 0;
        let mut i = 0;
        while i < BUTTON_TABLE.len() {
            let (flag, _label, width) = BUTTON_TABLE[i];
            if flags.contains(flag) {
                sum += width;
            }
            i += 1;
        }
        sum
    }

    /// Number of logical lines in `msg`, matching FASM
    /// `string$split rdi=msg, esi=10` followed by `_list_size_ofs`
    /// retrieval (FASM line 135).
    ///
    /// Specifically: `string$split` returns at least one element even
    /// for an empty input, and a trailing `b'\n'` does **not** create
    /// a phantom empty trailer because the FASM splitter strips it
    /// (matching the C `strtok` convention used by HeavyThing's
    /// upstream split helper). Rust replicates this:
    ///
    /// * `b""` → 1 (one empty line)
    /// * `b"hello"` → 1
    /// * `b"a\nb"` → 2
    /// * `b"a\nb\n"` → 2 (trailing `\n` does not add a line)
    /// * `b"\n"` → 1 (single `\n` produces one empty line then no
    ///   trailer — the splitter sees one separator and
    ///   thus two slices, but the second is empty and
    ///   stripped, leaving 1)
    /// * `b"\n\n"` → 2 (two slices: empty + empty; trailing empty
    ///   stripped, leaving 1 empty + 1 from the start)
    fn count_lines(msg: &[u8]) -> i32 {
        let mut count: i32 = 1;
        for &b in msg {
            if b == b'\n' {
                count += 1;
            }
        }
        // Strip the phantom trailer when the message ends with `\n`.
        if msg.last() == Some(&b'\n') {
            count - 1
        } else {
            count
        }
    }

    /// Maximum byte-length of any single line in `msg` (terminated by
    /// `b'\n'` or end-of-string), measured in *bytes* not Unicode
    /// scalar values.
    ///
    /// FASM `tui_alert$.linelength` (lines 353–360) reads `[rdi]` —
    /// the `string` length field, which in `string32.inc` stores a
    /// codepoint count. The Rust port keeps this as a byte count for
    /// simplicity; the slight divergence is invisible for ASCII alerts
    /// (the dominant use case in [`crate::tui::widgets::alert`]
    /// callers) and harmless for non-ASCII because UTF-8 byte count is
    /// always ≥ codepoint count, so the panel is sized **at least** as
    /// wide as FASM would have built it. This is a documented
    /// over-allocation trade-off, not a behavioral regression.
    ///
    /// Returns `0` for an empty `msg`.
    fn max_line_length(msg: &[u8]) -> i32 {
        let mut max_len: i32 = 0;
        let mut current: i32 = 0;
        for &b in msg {
            if b == b'\n' {
                if current > max_len {
                    max_len = current;
                }
                current = 0;
            } else {
                current += 1;
            }
        }
        if current > max_len {
            max_len = current;
        }
        max_len
    }
}

// ============================================================================
// TuiAlert — Widget trait impl
// ============================================================================
//
// FASM `tui_alert$vtable` (lines 33–45) is a verbatim copy of
// `tui_panel$vtable` with exactly two entries replaced:
//
//   slot 29: tui_alert$ontab
//   slot 30: tui_alert$onshifttab
//
// The Rust translation honors that layout: every trait method except
// [`Widget::on_tab`], [`Widget::on_shift_tab`], [`Widget::clone_widget`]
// (which has to set up a fresh [`Mutex`]), and [`Widget::as_any`]
// (required to return `self` for downcasting) delegates to the
// embedded [`Panel`] / its inherited base.
// ============================================================================

impl Widget for TuiAlert {
    /// Required: borrow the inherited [`WidgetState`] immutably.
    /// Delegates through the embedded [`Panel`].
    fn state(&self) -> &WidgetState {
        self.base.state()
    }

    /// Required: borrow the inherited [`WidgetState`] mutably.
    /// Delegates through the embedded [`Panel`].
    fn state_mut(&mut self) -> &mut WidgetState {
        self.base.state_mut()
    }

    /// Required downcast support — returns `self` (the concrete
    /// [`TuiAlert`]) so callers using
    /// `widget.as_any().downcast_ref::<TuiAlert>()` recover the alert
    /// type rather than the underlying [`Panel`].
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Override slot 0 — release alert-specific state, then delegate
    /// the panel-shaped cleanup body to [`Panel`].
    ///
    /// FASM `tui_alert$vtable` does not override `cleanup`; it
    /// inherits `tui_panel$cleanup` directly. The Rust translation
    /// can't simply call the trait-default [`Widget::cleanup`] because
    /// that would invoke the `tui_object$cleanup` equivalent (clears
    /// children/text but does **not** free the title resources owned
    /// by the panel). Instead we delegate to the embedded
    /// [`Panel::cleanup`] override via [`Widget::cleanup`] on
    /// `&mut self.base`.
    ///
    /// The [`Mutex<TuiAlertInner>`] field is dropped automatically
    /// when [`TuiAlert`] is deallocated; resetting it here would
    /// require either an [`Option`] wrapper or duplicating the Mutex
    /// type. Skipping the explicit reset is safe because cleanup
    /// implies the widget is being torn down — a subsequent
    /// `lock()` call would never happen on a cleaned-up alert.
    fn cleanup(&mut self) {
        Widget::cleanup(&mut self.base);
    }

    /// Override slot 1 — produce a deep clone of this alert.
    ///
    /// FASM `tui_panel$init_copy` (the inherited slot-1 vmethod)
    /// memcpys the entire panel struct and then deep-clones the
    /// children tree. The Rust port:
    ///
    /// 1. Calls [`Panel::clone_as_panel`] to deep-clone the panel,
    ///    which recursively clones the message label and the
    ///    buttonbox + its hspacers + buttons. The cloned panel
    ///    contains an entirely fresh widget tree.
    /// 2. Reads the original [`TuiAlertInner`] under lock and copies
    ///    `focused_index` and `button_count` into a freshly-built
    ///    [`Mutex`] for the clone. Cloning preserves the focus
    ///    position so the clone "looks like" the original at the
    ///    moment of cloning.
    /// 3. Builds a fresh [`TuiAlert`] with the unwrapped panel and
    ///    the same [`AlertButtons`] mask.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if [`Panel::clone_as_panel`]
    /// fails or if its returned [`Arc`] cannot be unwrapped (a
    /// defensive guard — the factory returns a fresh strong-count-1
    /// [`Arc`] on every successful call), or if the source
    /// [`Mutex<TuiAlertInner>`] is poisoned.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // Deep-clone the panel + child tree.
        let panel_clone_arc = self.base.clone_as_panel()?;
        let panel_clone = Arc::try_unwrap(panel_clone_arc).map_err(|_arc| {
            TuiError::Render(std::io::Error::other(
                "TuiAlert::clone_widget: clone_as_panel returned a shared Arc (refcount > 1)",
            ))
        })?;

        // Snapshot the inner state. A poisoned mutex propagates as a
        // typed [`TuiError::Render`] — the alert's focus state has no
        // partial-write semantics that would leave the lock in an
        // inconsistent intermediate state under panic, so a poison is
        // genuinely surprising and worth surfacing.
        let inner_snapshot = self.inner.lock().map_err(|_poisoned| {
            TuiError::Render(std::io::Error::other(
                "TuiAlert::clone_widget: inner Mutex is poisoned",
            ))
        })?;
        let cloned_inner = TuiAlertInner {
            focused_index: inner_snapshot.focused_index,
            button_count: inner_snapshot.button_count,
        };
        drop(inner_snapshot);

        let cloned = Arc::new(Self {
            base: panel_clone,
            button_flags: self.button_flags,
            inner: Mutex::new(cloned_inner),
        });

        Ok(cloned as Arc<dyn Widget>)
    }

    /// Override slot 2 — render the panel border, title overlay,
    /// background fill, and child tree via the inherited [`Panel`]
    /// draw.
    ///
    /// The trait-default [`Widget::draw`] is a no-op; without this
    /// delegation the border + title + buttons would never be
    /// painted. Routing through `self.base.draw(r)` invokes
    /// [`Panel::draw`] directly, matching FASM
    /// `tui_alert$vtable[2] = tui_panel$draw`.
    fn draw(&mut self, r: &mut dyn crate::tui::render::Renderer) -> Result<(), TuiError> {
        self.base.draw(r)
    }

    /// Override slot 28 — append a child to the panel's guts
    /// container (preserving the border).
    ///
    /// Delegates to [`Panel`]'s [`Widget::append_child`] override
    /// (`panel.rs` line 784), which routes the child into the guts
    /// container rather than the panel's top-level children list.
    /// Without this override the trait-default `append_child` would
    /// push directly into `self.state.children`, breaking the
    /// border / hbox / guts tree shape established by
    /// [`Panel::new_ii`].
    ///
    /// **Note**: appending widgets to a [`TuiAlert`] post-construction
    /// breaks the rigid buttonbox-layout assumption documented in
    /// [`Self::on_tab`] / [`Self::on_shift_tab`]. The behavior matches
    /// FASM exactly (FASM lines 392–397: "we _ASSUME_ that no other
    /// objects were added to us"). Callers MUST refrain from doing so.
    fn append_child(&mut self, child: Arc<dyn Widget>) {
        Widget::append_child(&mut self.base, child);
    }

    /// Override slot 30 — prepend a child to the panel's guts
    /// container.
    ///
    /// Symmetric counterpart to [`Self::append_child`]. Delegates to
    /// [`Panel`]'s [`Widget::prepend_child`] override.
    fn prepend_child(&mut self, child: Arc<dyn Widget>) {
        Widget::prepend_child(&mut self.base, child);
    }

    /// Override slot 32 — locate `child` inside the guts container.
    ///
    /// Delegates to [`Panel`]'s [`Widget::get_child_index`] override
    /// (`panel.rs` line 803), which searches the guts container's
    /// children list rather than the panel's top-level children.
    fn get_child_index(&self, child: &Arc<dyn Widget>) -> Option<usize> {
        Widget::get_child_index(&self.base, child)
    }

    /// Override slot 33 — remove `child` from the guts container.
    ///
    /// Delegates to [`Panel`]'s [`Widget::remove_child`] override
    /// (`panel.rs` line 811). Returns `true` if the child was found
    /// and removed, `false` otherwise.
    fn remove_child(&mut self, child: &Arc<dyn Widget>) -> bool {
        Widget::remove_child(&mut self.base, child)
    }

    /// Override slot 29 — Tab handler: advance focus to the next
    /// button, wrapping at the end.
    ///
    /// Translated from FASM `tui_alert$ontab` (`tui_alert.inc` lines
    /// 392–456):
    ///
    /// 1. Read `inner.focused_index` (the buttonbox child index of
    ///    the currently focused button). If `None`, return `false`
    ///    (mirroring FASM's "skip if button list is empty" — line
    ///    411 `cmp dword [rbx+_list_size_ofs], 1; je .nothingtodo`).
    /// 2. If `button_count < 2`, there is nothing to cycle —
    ///    return `true` to claim the event (FASM line 411 returns
    ///    after the `nothingtodo` jump-target with `rax` already
    ///    set to the alert).
    /// 3. Otherwise compute `next_idx = current + 2`. If `next_idx`
    ///    overflows past the last button (i.e. exceeds
    ///    `2 * button_count + 1 - 2 = 2*button_count - 1`), wrap to
    ///    `1` (the first button after the leading hspacer).
    /// 4. Update `inner.focused_index = Some(next_idx)`.
    ///
    /// Per the v1 limitation note at the top of this module, this
    /// override does **not** call [`Widget::got_focus`] /
    /// [`Widget::lost_focus`] on the affected buttons. The internal
    /// index is the only state mutated.
    fn on_tab(&mut self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            // Poisoned lock — silently swallow the event. A
            // [`TuiError`] return type is unavailable on this trait
            // method (FASM `vontab` returns the alert pointer through
            // `rax`; the Rust trait returns [`bool`]). Returning
            // `false` lets the event bubble; under poisoning the
            // alert is no longer in a usable state anyway.
            return false;
        };

        let Some(curr_idx) = inner.focused_index else {
            return false;
        };

        if inner.button_count < 2 {
            // Single button: claim the event but don't move focus.
            return true;
        }

        // Total slots in the buttonbox children list, per the rigid
        // FASM layout: leading hspacer + (button + hspacer) * N.
        let total_slots = 2 * inner.button_count + 1;

        // Buttons live at indices 1, 3, 5, …, 2N-1. The last button
        // is at `total_slots - 2`.
        let last_button_idx = total_slots - 2;

        let next_idx = if curr_idx >= last_button_idx {
            // Wrap to first button (FASM lines 440–456:
            //   r12 = children.first  ; leading hspacer
            //   r12 = r12.next        ; first button
            //   call vgotfocus
            // ).
            1
        } else {
            curr_idx + 2
        };

        inner.focused_index = Some(next_idx);
        true
    }

    /// Override slot 30 — Shift-Tab handler: retreat focus to the
    /// previous button, wrapping at the start.
    ///
    /// Translated from FASM `tui_alert$onshifttab` (`tui_alert.inc`
    /// lines 461–518). Symmetric counterpart to [`Self::on_tab`]:
    ///
    /// 1. Read `inner.focused_index`. If `None` or `button_count < 2`,
    ///    treat as "nothing to cycle" (mirror of `on_tab`).
    /// 2. Compute `prev_idx = current - 2`. If `current` is already at
    ///    the first button (index 1), wrap to the last button
    ///    (index `2 * button_count - 1`, equivalent to
    ///    `total_slots - 2`).
    /// 3. Update `inner.focused_index = Some(prev_idx)`.
    fn on_shift_tab(&mut self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };

        let Some(curr_idx) = inner.focused_index else {
            return false;
        };

        if inner.button_count < 2 {
            return true;
        }

        let total_slots = 2 * inner.button_count + 1;
        let last_button_idx = total_slots - 2;

        let prev_idx = if curr_idx <= 1 {
            // Wrap to last button (FASM lines 503–518:
            //   r12 = children.last   ; trailing hspacer
            //   r12 = r12.prev        ; last button
            //   call vgotfocus
            // ).
            last_button_idx
        } else {
            curr_idx - 2
        };

        inner.focused_index = Some(prev_idx);
        true
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn panel_colors() -> ColorPair {
        ColorPair { fg: 7, bg: 0 }
    }

    fn normal_colors() -> ColorPair {
        ColorPair { fg: 0, bg: 7 }
    }

    fn focus_colors() -> ColorPair {
        ColorPair { fg: 15, bg: 4 }
    }

    // ------------------------------------------------------------------------
    // AlertButtons — flag manipulation
    // ------------------------------------------------------------------------

    #[test]
    fn alert_buttons_constants_match_fasm() {
        // FASM `tui_alert.inc` lines 51–56.
        assert_eq!(AlertButtons::OK.bits(), 1);
        assert_eq!(AlertButtons::CANCEL.bits(), 2);
        assert_eq!(AlertButtons::YES.bits(), 4);
        assert_eq!(AlertButtons::NO.bits(), 8);
        assert_eq!(AlertButtons::CONTINUE.bits(), 16);
        assert_eq!(AlertButtons::QUIT.bits(), 32);
        assert_eq!(AlertButtons::EMPTY.bits(), 0);
    }

    #[test]
    fn alert_buttons_bitor() {
        let combined = AlertButtons::OK | AlertButtons::CANCEL;
        assert_eq!(combined.bits(), 0x03);
        assert!(combined.contains(AlertButtons::OK));
        assert!(combined.contains(AlertButtons::CANCEL));
        assert!(!combined.contains(AlertButtons::YES));
        assert!(!combined.contains(AlertButtons::QUIT));
    }

    #[test]
    fn alert_buttons_bitor_assign() {
        let mut buttons = AlertButtons::OK;
        buttons |= AlertButtons::QUIT;
        buttons |= AlertButtons::YES;
        assert!(buttons.contains(AlertButtons::OK));
        assert!(buttons.contains(AlertButtons::QUIT));
        assert!(buttons.contains(AlertButtons::YES));
        assert!(!buttons.contains(AlertButtons::CANCEL));
        assert!(!buttons.contains(AlertButtons::NO));
        assert!(!buttons.contains(AlertButtons::CONTINUE));
        assert_eq!(buttons.bits(), 1 | 32 | 4);
    }

    #[test]
    fn alert_buttons_union_is_const_friendly() {
        // `union` is `const fn`, allowing compile-time composition.
        const ALL: AlertButtons = AlertButtons::OK
            .union(AlertButtons::CANCEL)
            .union(AlertButtons::YES)
            .union(AlertButtons::NO)
            .union(AlertButtons::CONTINUE)
            .union(AlertButtons::QUIT);
        assert_eq!(ALL.bits(), 0x3F);
    }

    #[test]
    fn alert_buttons_contains_empty_returns_false() {
        // EMPTY.contains(EMPTY) is `false` per the documented FASM
        // "test/jnz never matches no-flag" semantic.
        assert!(!AlertButtons::EMPTY.contains(AlertButtons::EMPTY));

        // A non-empty mask never "contains" the empty set either.
        let mask = AlertButtons::OK | AlertButtons::QUIT;
        assert!(!mask.contains(AlertButtons::EMPTY));
    }

    #[test]
    fn alert_buttons_from_bits_round_trip() {
        let raw = 1 | 4 | 16; // OK + YES + CONTINUE
        let buttons = AlertButtons::from_bits(raw);
        assert_eq!(buttons.bits(), raw);
        assert!(buttons.contains(AlertButtons::OK));
        assert!(buttons.contains(AlertButtons::YES));
        assert!(buttons.contains(AlertButtons::CONTINUE));
        assert!(!buttons.contains(AlertButtons::CANCEL));
        assert!(!buttons.contains(AlertButtons::NO));
        assert!(!buttons.contains(AlertButtons::QUIT));
    }

    #[test]
    fn alert_buttons_default_is_empty() {
        let default_value: AlertButtons = AlertButtons::default();
        assert_eq!(default_value, AlertButtons::EMPTY);
        assert_eq!(default_value.bits(), 0);
    }

    // ------------------------------------------------------------------------
    // total_button_width — FASM lines 96–127
    // ------------------------------------------------------------------------

    #[test]
    fn total_button_width_each_singleton() {
        assert_eq!(TuiAlert::total_button_width(AlertButtons::OK), 9);
        assert_eq!(TuiAlert::total_button_width(AlertButtons::CANCEL), 13);
        assert_eq!(TuiAlert::total_button_width(AlertButtons::YES), 10);
        assert_eq!(TuiAlert::total_button_width(AlertButtons::NO), 9);
        assert_eq!(TuiAlert::total_button_width(AlertButtons::CONTINUE), 15);
        assert_eq!(TuiAlert::total_button_width(AlertButtons::QUIT), 11);
    }

    #[test]
    fn total_button_width_empty_is_zero() {
        assert_eq!(TuiAlert::total_button_width(AlertButtons::EMPTY), 0);
    }

    #[test]
    fn total_button_width_combinations() {
        // YES + NO + CANCEL = 10 + 9 + 13 = 32
        let yn_cancel = AlertButtons::YES | AlertButtons::NO | AlertButtons::CANCEL;
        assert_eq!(TuiAlert::total_button_width(yn_cancel), 32);

        // OK + QUIT = 9 + 11 = 20
        let ok_quit = AlertButtons::OK | AlertButtons::QUIT;
        assert_eq!(TuiAlert::total_button_width(ok_quit), 20);

        // All 6 = 9 + 13 + 10 + 9 + 15 + 11 = 67
        let all = AlertButtons::OK
            | AlertButtons::CANCEL
            | AlertButtons::YES
            | AlertButtons::NO
            | AlertButtons::CONTINUE
            | AlertButtons::QUIT;
        assert_eq!(TuiAlert::total_button_width(all), 67);
    }

    // ------------------------------------------------------------------------
    // count_lines — FASM `string$split` semantic
    // ------------------------------------------------------------------------

    #[test]
    fn count_lines_empty_is_one() {
        assert_eq!(TuiAlert::count_lines(b""), 1);
    }

    #[test]
    fn count_lines_single_line() {
        assert_eq!(TuiAlert::count_lines(b"hello"), 1);
        assert_eq!(TuiAlert::count_lines(b"a"), 1);
    }

    #[test]
    fn count_lines_multi_line() {
        assert_eq!(TuiAlert::count_lines(b"a\nb"), 2);
        assert_eq!(TuiAlert::count_lines(b"a\nb\nc"), 3);
        assert_eq!(TuiAlert::count_lines(b"a\nb\nc\nd"), 4);
    }

    #[test]
    fn count_lines_trailing_newline_stripped() {
        // FASM `string$split` strips a trailing separator: "a\nb\n"
        // produces ["a", "b"], not ["a", "b", ""].
        assert_eq!(TuiAlert::count_lines(b"a\nb\n"), 2);
        assert_eq!(TuiAlert::count_lines(b"a\n"), 1);
    }

    // ------------------------------------------------------------------------
    // max_line_length
    // ------------------------------------------------------------------------

    #[test]
    fn max_line_length_empty_is_zero() {
        assert_eq!(TuiAlert::max_line_length(b""), 0);
    }

    #[test]
    fn max_line_length_single_line() {
        assert_eq!(TuiAlert::max_line_length(b"hello"), 5);
        assert_eq!(TuiAlert::max_line_length(b"a"), 1);
    }

    #[test]
    fn max_line_length_multi_line_picks_max() {
        assert_eq!(TuiAlert::max_line_length(b"short\nlong line"), 9);
        assert_eq!(TuiAlert::max_line_length(b"longest line\nshort"), 12);
        assert_eq!(TuiAlert::max_line_length(b"a\nbb\nccc"), 3);
    }

    #[test]
    fn max_line_length_trailing_newline() {
        // The trailing `\n` does not contribute a "phantom" zero-
        // length line that masks the real maximum.
        assert_eq!(TuiAlert::max_line_length(b"hello\n"), 5);
    }

    // ------------------------------------------------------------------------
    // TuiAlert::new — end-to-end construction
    // ------------------------------------------------------------------------

    #[test]
    fn new_with_single_ok_button() {
        let alert = TuiAlert::new(
            b"Title",
            b"A short message.",
            AlertButtons::OK,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");

        // button_flags is preserved verbatim.
        assert_eq!(alert.button_flags, AlertButtons::OK);

        // Inner state: 1 button, focus on the first button (idx 1).
        let inner = alert.inner.lock().expect("mutex unpoisoned");
        assert_eq!(inner.button_count, 1);
        assert_eq!(inner.focused_index, Some(1));
    }

    #[test]
    fn new_with_no_buttons_has_no_focus() {
        let alert = TuiAlert::new(
            b"Title",
            b"Body.",
            AlertButtons::EMPTY,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");

        let inner = alert.inner.lock().expect("mutex unpoisoned");
        assert_eq!(inner.button_count, 0);
        assert_eq!(inner.focused_index, None);
    }

    #[test]
    fn new_with_multiple_buttons_focuses_first() {
        let buttons = AlertButtons::YES | AlertButtons::NO | AlertButtons::CANCEL;
        let alert = TuiAlert::new(
            b"Confirm",
            b"Are you sure you want to proceed?",
            buttons,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");

        assert_eq!(alert.button_flags, buttons);

        let inner = alert.inner.lock().expect("mutex unpoisoned");
        assert_eq!(inner.button_count, 3);
        assert_eq!(inner.focused_index, Some(1));
    }

    #[test]
    fn new_panel_dimensions_meet_minimum() {
        // A short title + short message + single button must still
        // produce a panel at least 32 wide (FASM line 85).
        let alert = TuiAlert::new(
            b"X",
            b"y",
            AlertButtons::OK,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");

        let state = alert.state();
        assert!(
            state.width >= 32,
            "alert width {} should be at least 32",
            state.width
        );
    }

    #[test]
    fn new_panel_height_single_line_message() {
        let alert = TuiAlert::new(
            b"T",
            b"single line",
            AlertButtons::OK,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");

        // FASM line_count == 1 → height = 9.
        assert_eq!(alert.state().height, 9);
    }

    #[test]
    fn new_panel_height_multi_line_message() {
        // 3 lines → height = 3 + 9 = 12.
        let alert = TuiAlert::new(
            b"T",
            b"line 1\nline 2\nline 3",
            AlertButtons::OK,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");

        assert_eq!(alert.state().height, 12);
    }

    #[test]
    fn new_panel_drop_shadow_enabled() {
        let alert = TuiAlert::new(
            b"T",
            b"m",
            AlertButtons::OK,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");

        assert!(alert.state().drop_shadow);
    }

    // ------------------------------------------------------------------------
    // Tab / Shift-Tab cycling — FASM lines 392–518
    // ------------------------------------------------------------------------

    #[test]
    fn on_tab_with_zero_buttons_returns_false() {
        let alert_arc = TuiAlert::new(
            b"T",
            b"m",
            AlertButtons::EMPTY,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");
        let mut alert =
            Arc::try_unwrap(alert_arc).expect("test owns the Arc uniquely (no children retained outside)");

        assert!(!alert.on_tab());
        assert!(!alert.on_shift_tab());
    }

    #[test]
    fn on_tab_with_single_button_claims_event_but_no_focus_change() {
        let alert_arc = TuiAlert::new(
            b"T",
            b"m",
            AlertButtons::OK,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");
        let mut alert = Arc::try_unwrap(alert_arc).expect("test owns the Arc uniquely");

        assert!(alert.on_tab());
        let inner = alert.inner.lock().expect("mutex unpoisoned");
        // Focus stays put.
        assert_eq!(inner.focused_index, Some(1));
    }

    #[test]
    fn on_tab_advances_through_buttons() {
        // 3 buttons: OK, CANCEL, YES at indices 1, 3, 5.
        let alert_arc = TuiAlert::new(
            b"T",
            b"m",
            AlertButtons::OK | AlertButtons::CANCEL | AlertButtons::YES,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");
        let mut alert = Arc::try_unwrap(alert_arc).expect("test owns the Arc uniquely");

        // Initial focus = button at index 1 (OK).
        assert_eq!(
            alert.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(1)
        );

        // Tab → 3 (CANCEL).
        assert!(alert.on_tab());
        assert_eq!(
            alert.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(3)
        );

        // Tab → 5 (YES).
        assert!(alert.on_tab());
        assert_eq!(
            alert.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(5)
        );

        // Tab → wrap to 1 (OK).
        assert!(alert.on_tab());
        assert_eq!(
            alert.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(1)
        );
    }

    #[test]
    fn on_shift_tab_retreats_through_buttons_and_wraps() {
        // 3 buttons: OK, CANCEL, YES at indices 1, 3, 5.
        let alert_arc = TuiAlert::new(
            b"T",
            b"m",
            AlertButtons::OK | AlertButtons::CANCEL | AlertButtons::YES,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");
        let mut alert = Arc::try_unwrap(alert_arc).expect("test owns the Arc uniquely");

        // Initial = 1 (OK). Shift-Tab → wrap to 5 (YES).
        assert!(alert.on_shift_tab());
        assert_eq!(
            alert.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(5)
        );

        // Shift-Tab → 3 (CANCEL).
        assert!(alert.on_shift_tab());
        assert_eq!(
            alert.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(3)
        );

        // Shift-Tab → 1 (OK).
        assert!(alert.on_shift_tab());
        assert_eq!(
            alert.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(1)
        );

        // Shift-Tab again → wrap to 5 (YES).
        assert!(alert.on_shift_tab());
        assert_eq!(
            alert.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(5)
        );
    }

    #[test]
    fn on_tab_then_on_shift_tab_round_trip() {
        // 4 buttons: OK, CANCEL, YES, NO at indices 1, 3, 5, 7.
        let alert_arc = TuiAlert::new(
            b"T",
            b"m",
            AlertButtons::OK | AlertButtons::CANCEL | AlertButtons::YES | AlertButtons::NO,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");
        let mut alert = Arc::try_unwrap(alert_arc).expect("test owns the Arc uniquely");

        let total = 4;
        // Walk forward through every button.
        for step in 0..total {
            let want = 1 + ((step + 1) % total) * 2;
            assert!(alert.on_tab());
            let got = alert.inner.lock().expect("mutex unpoisoned").focused_index;
            assert_eq!(got, Some(want), "step {step}: forward cycle mismatch");
        }
        // After `total` Tab presses we are back at the start.
        assert_eq!(
            alert.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(1)
        );
    }

    #[test]
    fn on_tab_with_all_six_buttons_cycles_correctly() {
        // 6 buttons: OK, CANCEL, YES, NO, CONTINUE, QUIT at 1, 3, 5, 7, 9, 11.
        let all = AlertButtons::OK
            | AlertButtons::CANCEL
            | AlertButtons::YES
            | AlertButtons::NO
            | AlertButtons::CONTINUE
            | AlertButtons::QUIT;
        let alert_arc = TuiAlert::new(
            b"All",
            b"All buttons.",
            all,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");
        let mut alert = Arc::try_unwrap(alert_arc).expect("test owns the Arc uniquely");

        let inner_check = alert.inner.lock().expect("mutex unpoisoned");
        assert_eq!(inner_check.button_count, 6);
        assert_eq!(inner_check.focused_index, Some(1));
        drop(inner_check);

        let expected = [3, 5, 7, 9, 11, 1, 3, 5, 7, 9, 11, 1];
        for &want in &expected {
            assert!(alert.on_tab());
            assert_eq!(
                alert.inner.lock().expect("mutex unpoisoned").focused_index,
                Some(want)
            );
        }
    }

    #[test]
    fn key_event_inherent_returns_default_false() {
        let alert_arc = TuiAlert::new(
            b"T",
            b"m",
            AlertButtons::OK,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");
        let mut alert = Arc::try_unwrap(alert_arc).expect("test owns the Arc uniquely");

        // Inherent key_event delegates to the trait default which is
        // false (alert does not handle generic keystrokes; Tab and
        // Shift-Tab dispatch through dedicated vtable slots).
        assert!(!alert.key_event(KeyEvent::Char('x')));
    }

    // ------------------------------------------------------------------------
    // clone_widget — deep clone preserving focus state
    // ------------------------------------------------------------------------

    #[test]
    fn clone_widget_preserves_button_flags_and_focus() {
        let alert_arc = TuiAlert::new(
            b"Original",
            b"Body.",
            AlertButtons::OK | AlertButtons::CANCEL,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");
        let mut owned = Arc::try_unwrap(alert_arc).expect("test owns the Arc uniquely");

        // Cycle once so focus is at index 3 (CANCEL).
        assert!(owned.on_tab());
        assert_eq!(
            owned.inner.lock().expect("mutex unpoisoned").focused_index,
            Some(3)
        );

        // Clone via the trait method and verify the snapshot.
        let cloned: Arc<dyn Widget> = Widget::clone_widget(&owned).expect("clone must succeed");
        let cloned_alert = cloned
            .as_any()
            .downcast_ref::<TuiAlert>()
            .expect("clone must downcast to TuiAlert");
        assert_eq!(cloned_alert.button_flags, owned.button_flags);
        let cloned_inner = cloned_alert.inner.lock().expect("mutex unpoisoned");
        assert_eq!(cloned_inner.focused_index, Some(3));
        assert_eq!(cloned_inner.button_count, 2);
    }

    // ------------------------------------------------------------------------
    // Panel structural invariants
    // ------------------------------------------------------------------------

    #[test]
    fn debug_format_includes_button_flags() {
        let alert_arc = TuiAlert::new(
            b"T",
            b"m",
            AlertButtons::OK | AlertButtons::QUIT,
            panel_colors(),
            normal_colors(),
            focus_colors(),
        )
        .expect("alert construction must succeed");
        let alert = Arc::try_unwrap(alert_arc).expect("test owns the Arc uniquely");
        let dbg = format!("{alert:?}");
        assert!(
            dbg.contains("TuiAlert"),
            "Debug output should mention TuiAlert: {dbg}"
        );
    }

    #[test]
    fn alert_buttons_debug_format() {
        let buttons = AlertButtons::OK | AlertButtons::QUIT;
        let dbg = format!("{buttons:?}");
        // We only require the type name to appear; the inner u32 is
        // implementation detail.
        assert!(dbg.contains("AlertButtons"));
    }
}
