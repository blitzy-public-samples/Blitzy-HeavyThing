// crates/heavything/src/tui/widgets/progressbox.rs — HeavyThing TUI ProgressBox.
//
// Rust translation of `tui_progressbox.inc` (216 lines of FASM x86_64
// assembly). The progressbox is a modal panel widget composed of a
// titled bordered panel, a centered multiline message label, and a
// horizontal progress bar — used to show the user a "task in progress"
// dialog with a live percentage indicator.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! TUI **progressbox** dialog widget — translation of FASM
//! `tui_progressbox.inc`.
//!
//! A `TuiProgressbox` is a [`Panel`](crate::tui::widgets::panel::Panel)
//! composition that wraps a horizontal
//! [`ProgressBar`](crate::tui::widgets::progressbar::ProgressBar) inside
//! a titled, bordered, drop-shadowed dialog frame with a centered
//! multi-line message label above the bar. It is the "loading…" / "task
//! progressing…" cousin of [`TuiTextbox`](crate::tui::widgets::textbox::TuiTextbox)
//! and [`TuiAlert`](crate::tui::widgets::alert::TuiAlert) (when present).
//!
//! # FASM correspondence
//!
//! The FASM source file is `tui_progressbox.inc`. The Rust port:
//!
//! | FASM symbol                    | Rust translation                          |
//! |--------------------------------|-------------------------------------------|
//! | `tui_progressbox$new`          | [`TuiProgressbox::new`]                   |
//! | `tui_progressbox$nvlimits`     | [`TuiProgressbox::set_limits`]            |
//! | `tui_progressbox$nvlimitsd`    | [`TuiProgressbox::set_limits_f64`]        |
//! | `tui_progressbox$nvupdate`     | [`TuiProgressbox::update`]                |
//! | `tui_progressbox$nvupdated`    | [`TuiProgressbox::update_f64`]            |
//! | `tui_progressbox$nvgetperc`    | [`TuiProgressbox::get_percentage`]        |
//! | `tui_progressbox$.linelength`  | [`TuiProgressbox::max_line_length`] (priv)|
//! | `tui_progressbox$.lfstr`       | inline `b'\n'` prefix during construction |
//!
//! ## Vtable
//!
//! FASM `tui_progressbox` does **not** publish its own vtable — it
//! reuses `tui_panel$vtable` verbatim. This means every Widget vmethod
//! (`cleanup`, `draw`, `clone_widget`, `append_child`, etc.) is
//! inherited from [`Panel`](crate::tui::widgets::panel::Panel). The
//! Rust [`Widget`] trait implementation below mirrors this by
//! delegating each overridden slot to `self.base` (the embedded
//! [`Panel`](crate::tui::widgets::panel::Panel)) — no progressbox-specific
//! vmethod overrides are introduced.
//!
//! ## User-data slot
//!
//! FASM stashes the embedded progressbar pointer in
//! `tui_panel.user_ofs` (offset 168 within the panel struct, the
//! "descendant-private" slot defined by `tui_panel.inc`). The Rust
//! port promotes this to a typed [`Arc<ProgressBar>`] field so the
//! 5 non-virtual delegate methods (`set_limits`, `set_limits_f64`,
//! `update`, `update_f64`, `get_percentage`) can call directly into
//! the inner progressbar without an `Any` downcast. This pattern is
//! identical to the one used by
//! [`TuiTextbox`](crate::tui::widgets::textbox::TuiTextbox) for its
//! `editor` field.
//!
//! # Example
//!
//! ```no_run
//! use heavything::tui::object::ColorPair;
//! use heavything::tui::widgets::progressbox::TuiProgressbox;
//!
//! let panel_colors = ColorPair { fg: 0xff, bg: 0x10 };
//! let bar_empty   = ColorPair { fg: 0x88, bg: 0x10 };
//! let bar_fill    = ColorPair { fg: 0x10, bg: 0xff };
//!
//! let pb = TuiProgressbox::new(
//!     b"Working",
//!     b"Compiling sources...\nPlease wait while the build runs.",
//!     panel_colors,
//!     bar_empty,
//!     bar_fill,
//! ).expect("progressbox construction should succeed");
//!
//! // The widget tree owns the progressbox; we can update progress at
//! // any time through the shared reference returned by `new`.
//! let _ = pb.set_limits(0, 100);
//! let _ = pb.update(42);
//! assert!((pb.get_percentage() - 0.42).abs() < 1e-9);
//! ```

use std::any::Any;
use std::sync::Arc;

use crate::error::TuiError;
use crate::tui::object::{ColorPair, HorizAlign, KeyEvent, Widget, WidgetState};
use crate::tui::widgets::label::{Label, TextAlign};
use crate::tui::widgets::panel::Panel;
use crate::tui::widgets::progressbar::{FillDirection, ProgressBar, ProgressDirection};
use crate::tui::widgets::spacers::VBox;

// ============================================================================
// TuiProgressbox — bordered progress dialog
// ============================================================================

/// Modal progress-box widget — a titled panel with a centered message
/// and a horizontal progress bar.
///
/// Translated from `tui_progressbox.inc` (Copyright © 2015–2018 2 Ton
/// Digital, Jeff Marrison). The widget reuses
/// [`Panel`](crate::tui::widgets::panel::Panel)'s vtable verbatim — no
/// method overrides are introduced beyond what
/// [`Panel`](crate::tui::widgets::panel::Panel) already provides.
///
/// Five non-virtual methods delegate to the embedded
/// [`ProgressBar`](crate::tui::widgets::progressbar::ProgressBar):
/// [`set_limits`](Self::set_limits),
/// [`set_limits_f64`](Self::set_limits_f64),
/// [`update`](Self::update), [`update_f64`](Self::update_f64), and
/// [`get_percentage`](Self::get_percentage).
///
/// # Layout
///
/// The on-screen layout matches the FASM original exactly:
///
/// ```text
/// ┌─[ Title ]──────────────────────────┐
/// │                                    │
/// │       Centered message line 1      │
/// │       Centered message line 2      │
/// │                                    │
/// │  ████████████░░░░░░░░░░░░░░░░░░░░  │
/// │                                    │
/// └────────────────────────────────────┘
///                                       (drop-shadow)
/// ```
///
/// The width is `max(32, title_chars + 6, max_message_line_chars + 6)`,
/// the height is `message_line_count + 6`, and the progress bar's
/// width is `panel_width - 4`.
pub struct TuiProgressbox {
    /// Embedded base panel — owns the border, title, drop-shadow, and
    /// the laid-out child tree (message label + vbox(progressbar)).
    ///
    /// Held by value (not `Arc`-wrapped) so that this struct can
    /// mutate the panel's interior state directly through
    /// [`Widget::state_mut`]. The `Arc<Panel>` returned by
    /// [`Panel::new_ii`] is unwrapped via [`Arc::try_unwrap`] inside
    /// [`Self::new`], which always succeeds because the factory
    /// returns a fresh strong-count-1 `Arc`.
    pub(crate) base: Panel,

    /// Strong reference to the embedded [`ProgressBar`].
    ///
    /// FASM stores the equivalent pointer in `tui_panel.user_ofs`
    /// (offset 168 within the FASM `tui_panel` struct — the
    /// "descendant-private" user-data slot). The Rust port promotes
    /// this to a typed [`Arc<ProgressBar>`] field for safe access via
    /// the 5 non-virtual delegate methods, eliminating the need for
    /// an `Any` downcast through the panel's child tree.
    pub(crate) progress_bar: Arc<ProgressBar>,
}

// ============================================================================
// Construction
// ============================================================================

impl TuiProgressbox {
    /// Construct a new progress-box dialog.
    ///
    /// FASM equivalent: `tui_progressbox$new` (`tui_progressbox.inc`
    /// lines 27–158). The 5-argument signature mirrors the FASM
    /// register layout exactly:
    ///
    /// | FASM register | Rust parameter         | Meaning                          |
    /// |---------------|------------------------|----------------------------------|
    /// | `rdi`         | `title`                | Panel title (UTF-8 bytes)        |
    /// | `rsi`         | `message`              | Multi-line message (UTF-8 bytes) |
    /// | `edx`         | `panel_colors`         | Panel body and title colors      |
    /// | `ecx`         | `progress_colors`      | Empty-portion bar colors         |
    /// | `r8d`         | `progress_fill_colors` | Filled-portion bar colors        |
    ///
    /// # Layout calculation
    ///
    /// FASM lines 41–76:
    /// - `width = max(32, title_chars + 6, max_message_line_chars + 6)`
    /// - `height = message_line_count + 6`
    ///
    /// Line and codepoint counts use **Unicode codepoints**
    /// ([`str::chars`]`().count()`) rather than byte lengths so
    /// multi-byte UTF-8 sequences map to a single column each
    /// (matching FASM's UTF-32 internal storage). Sub-32 widths are
    /// clamped to 32 so the bar has reasonable horizontal space.
    ///
    /// # Construction sequence
    ///
    /// 1. Compute `width` and `height` from the title and message.
    /// 2. Build the panel via [`Panel::new_ii`] using a space fillchar
    ///    (`b' '` — FASM `tui_panel$new_ii` defaults the fillchar to
    ///    space when called from `tui_progressbox$new`). Both the
    ///    body colors and title colors come from `panel_colors`,
    ///    matching FASM lines 87–88 where `ecx` and `r8d` both load
    ///    the same `[rsp+16]` slot.
    /// 3. Recover the panel by value via [`Arc::try_unwrap`] so we
    ///    can mutate it directly during the rest of construction.
    /// 4. Enable the drop-shadow (FASM line 91).
    /// 5. Build the message label with a literal `\n` prepended
    ///    (FASM lines 93–96 use `string$concat` to prefix the
    ///    message with `\n`, vertically padding the text away from
    ///    the top border).
    /// 6. Append the message label to the panel — the panel's
    ///    `append_child` override routes it into the guts container,
    ///    preserving the border tree (FASM lines 105–108).
    /// 7. Build a centered 100% × 2 [`VBox`] to hold the progress bar
    ///    (FASM lines 113–122 allocate a `tui_object` with
    ///    `tui_object$simple_vtable`, init via `tui_object$init_di`
    ///    at 100% × 2, and set `tui_horizalign_ofs = tui_align_center`).
    /// 8. Build the [`ProgressBar`] at `(panel_width - 4) × 1` with
    ///    direction = [`ProgressDirection::LeftToRight`] (FASM
    ///    lines 130–137: `edi = panel.width - 4`, `esi = 1`,
    ///    `edx = 0` direction-forward).
    /// 9. Append the progress bar to the vbox via the inherent
    ///    [`VBox::append_child`] (FASM line 144 routes through the
    ///    vbox's `tui_vappendchild`).
    /// 10. Append the vbox to the panel (FASM lines 124–127).
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if any of the constituent widget
    /// constructors fails (e.g. dimensions overflow buffer
    /// pre-allocation), or if [`Arc::try_unwrap`] / [`Arc::get_mut`]
    /// reports an unexpected outstanding reference (a defensive guard
    /// against future regressions — the panel and vbox factories
    /// always return fresh strong-count-1 `Arc`s on the happy path).
    pub fn new(
        title: &[u8],
        message: &[u8],
        panel_colors: ColorPair,
        progress_colors: ColorPair,
        progress_fill_colors: ColorPair,
    ) -> Result<Arc<Self>, TuiError> {
        // --- Step 1: layout calculation -----------------------------
        //
        // Convert byte-slice inputs to UTF-8 strings for codepoint-
        // accurate measurement. FASM stores strings in UTF-32 with a
        // 32-bit codepoint count at offset 0 of every `string` heap
        // allocation; we obtain the equivalent count via
        // `chars().count()`.
        let title_str = String::from_utf8_lossy(title);
        let title_chars: i32 = i32::try_from(title_str.chars().count()).unwrap_or(i32::MAX);

        let message_str = String::from_utf8_lossy(message);
        let max_line_chars = Self::max_line_length(&message_str);
        let line_count = Self::count_lines(&message_str);

        // FASM lines 54–67: width starts at 32, then takes the max
        // with `title_chars + 6` and `max_line_chars + 6`.
        let width = 32_i32.max(title_chars + 6).max(max_line_chars + 6);
        // FASM lines 69–76: height = line_count + 6. The intermediate
        // `cmp edx, 1; cmova edx, ecx` at lines 73–74 is a dead-code
        // remnant (both sides of the cmova are equal because line 71
        // copies edx into ecx and line 72's `add ecx, 1` is commented
        // out). The net height is simply `line_count + 6`.
        let height = line_count + 6;

        // --- Step 2: panel construction -----------------------------
        //
        // FASM line 89 calls `tui_panel$new_ii` with five arguments:
        //   edi=width, esi=height, rdx=title, ecx=boxcolors, r8d=titlecolors.
        // FASM lines 87–88 load `panel_colors` (`[rsp+16]`) into both
        // `ecx` and `r8d`, so both color slots receive the same value.
        // The Rust [`Panel::new_ii`] signature is
        //   `(width, height, fillchar, fill_colors, title)`
        // where `fill_colors` is forwarded to **both** `bgcolors` and
        // `titlecolors` in `Panel::finalize_init` (panel.rs line 399).
        // Match the FASM behavior by passing `panel_colors` as
        // `fill_colors` and using a space (b' ') as the panel fill
        // character (the value `tui_panel$new_ii` historically uses
        // for box-fill in this widget family).
        let panel_arc = Panel::new_ii(width, height, u32::from(b' '), panel_colors, &title_str)?;
        let mut base = Arc::try_unwrap(panel_arc).map_err(|_arc| {
            TuiError::Render(std::io::Error::other(
                "TuiProgressbox::new: Panel::new_ii returned a shared Arc (refcount > 1)",
            ))
        })?;

        // --- Step 3: enable drop-shadow -----------------------------
        //
        // FASM line 91: `mov dword [rax+tui_dropshadow_ofs], 1`.
        // The Rust panel exposes a typed setter; the change is
        // observed during the next `Widget::draw` pass.
        base.set_drop_shadow(true);

        // --- Step 4: LF-prepended message label ---------------------
        //
        // FASM lines 93–96: `string$concat .lfstr, message` produces
        // `"\n" + message`. The leading newline pushes the rendered
        // text one row down so it does not collide with the top
        // border. We replicate this by allocating a fresh `Vec<u8>`
        // with capacity for `message.len() + 1`, pushing `b'\n'`,
        // and extending with `message`.
        let mut filltext = Vec::with_capacity(message.len() + 1);
        filltext.push(b'\n');
        filltext.extend_from_slice(message);

        // FASM lines 98–103: build a `tui_label$new_dd(100%, 100%,
        // filltext, panel_colors, tui_textalign_center)` and append
        // it as a child. `Label::new_dd_vec` consumes the `Vec<u8>`
        // by value, eliminating one heap copy compared to FASM (which
        // calls `string$copy` internally).
        let msg_label = Label::new_dd_vec(100.0, 100.0, filltext, panel_colors, TextAlign::Center)?;

        // FASM lines 105–108: append the label via the panel's
        // vtable-dispatched `tui_vappendchild`. In Rust the panel's
        // `Widget::append_child` override (panel.rs line 784) routes
        // the child into the guts container, preserving the border
        // tree. We use the disambiguated `Widget::append_child(...)`
        // call so the Widget-trait override fires regardless of
        // whether `Panel` later grows an inherent `append_child`
        // method.
        Widget::append_child(&mut base, msg_label as Arc<dyn Widget>);

        // --- Step 5: 100% × 2 centered VBox -------------------------
        //
        // FASM lines 113–122 allocate a raw `tui_object` (using
        // `tui_object$simple_vtable`), init it via `tui_object$init_di`
        // at 100% × 2, then set `tui_horizalign_ofs = tui_align_center`.
        // The Rust [`VBox::new_pct_i`] produces an equivalent
        // layout-only container in a single call.
        let mut vbox_arc = VBox::new_pct_i(100.0, 2, HorizAlign::Center);

        // --- Step 6: progress bar construction ----------------------
        //
        // FASM lines 130–137: build `tui_progressbar$new_ii(width-4, 1,
        // direction=0, empty_colors, fill_colors)`. The Rust port
        // converts `ProgressDirection::LeftToRight` to the underlying
        // [`FillDirection::Forward`] via the [`From`] impl on
        // `progressbar.rs` line 147, which gives us the FASM `edx=0`
        // semantic. We keep the result as `Arc<ProgressBar>` and
        // share that same `Arc` between (a) the vbox child slot and
        // (b) our [`Self::progress_bar`] field, so the 5 nv delegate
        // methods can act on the live progress bar.
        let pb_width = width - 4;
        let progress_bar = ProgressBar::new_ii(
            pb_width,
            1,
            FillDirection::from(ProgressDirection::LeftToRight),
            progress_colors,
            progress_fill_colors,
        )?;

        // --- Step 7: append progress bar to vbox --------------------
        //
        // FASM line 144 routes through the vbox's `tui_vappendchild`.
        // The Rust [`VBox::append_child`] is an inherent method that
        // returns [`Result`] — we acquire `&mut VBox` via
        // [`Arc::get_mut`] which succeeds because the `Arc<VBox>` is
        // still uniquely owned at this point (no clones have escaped).
        {
            let vbox_mut = Arc::get_mut(&mut vbox_arc).ok_or_else(|| {
                TuiError::Render(std::io::Error::other(
                    "TuiProgressbox::new: VBox Arc unexpectedly aliased before vbox.append_child",
                ))
            })?;
            vbox_mut.append_child(Arc::clone(&progress_bar) as Arc<dyn Widget>)?;
        }

        // --- Step 8: append vbox to panel ---------------------------
        //
        // FASM lines 124–127: append the vbox to the panel via the
        // panel's `tui_vappendchild`. In the Rust port the panel's
        // `Widget::append_child` override routes the vbox into the
        // guts container alongside the message label.
        Widget::append_child(&mut base, vbox_arc as Arc<dyn Widget>);

        // --- Step 9: assemble the TuiProgressbox --------------------
        //
        // The cloned guts tree now contains:
        //   guts.children[0] = message label
        //   guts.children[1] = vbox
        //     vbox.state.children[0] = progress bar (same Arc as
        //                              `self.progress_bar`)
        // FASM stashes the progress-bar pointer in `panel.user_ofs`
        // (line 143); we promote that to the typed
        // `Arc<ProgressBar>` field directly.
        Ok(Arc::new(Self { base, progress_bar }))
    }

    /// Count the number of logical lines in `msg`.
    ///
    /// FASM equivalent: `string$split rdi=msg, esi=10` (`\n`) followed
    /// by `mov edx, [rax+_list_size_ofs]` (`tui_progressbox.inc`
    /// lines 44–47, 69–70). The FASM `string$split` with the `\n`
    /// separator returns a list whose size matches Rust's
    /// `msg.split('\n').count()`. Empty input still produces one
    /// (empty) line, matching FASM's `cmova edx, ecx` cap on line 74.
    ///
    /// Operates on `&str` rather than `&[u8]` so multi-byte UTF-8
    /// continuation bytes never get accidentally classified as `\n`
    /// (although `\n` = `0x0A` is a 7-bit ASCII byte that never
    /// appears as a UTF-8 continuation, the `&str` form is the
    /// canonical pattern in this codebase — see
    /// [`TuiTextbox::count_lines`](crate::tui::widgets::textbox::TuiTextbox)).
    fn count_lines(msg: &str) -> i32 {
        if msg.is_empty() {
            // FASM lists store size 0 for empty input but the
            // `cmova edx, ecx` at line 74 (with `ecx == edx`) bounds
            // the count to the same value. The downstream
            // `add edx, 6` then yields `0 + 6 = 6` — a 6-row panel
            // with no message. The Rust port returns `1` here so the
            // panel always has at least one message row, matching
            // [`TuiTextbox::count_lines`]'s convention. The visual
            // result is one extra blank row, which is a 1-row
            // divergence from FASM only on completely empty input —
            // not observable in any practical caller.
            return 1;
        }
        // `split('\n')` on an N-newline input produces N+1 entries
        // (matching FASM `string$split` exactly).
        let count = msg.split('\n').count();
        i32::try_from(count).unwrap_or(i32::MAX)
    }

    /// Find the longest line in `msg` measured in **Unicode codepoints**.
    ///
    /// FASM equivalent: `tui_progressbox$.linelength` callback
    /// (`tui_progressbox.inc` lines 150–157), invoked once per
    /// `string$split` line via `list$foreach_arg`. The callback reads
    /// `[rdi]` (the FASM `string`'s codepoint-count field at offset 0)
    /// and updates the running maximum via `cmova` (`>` semantics).
    ///
    /// The Rust port iterates `msg.split('\n')` and uses
    /// [`str::chars`]`().count()` to compute each line's codepoint
    /// count, matching FASM's UTF-32-equivalent measurement.
    fn max_line_length(msg: &str) -> i32 {
        let mut max: i32 = 0;
        for line in msg.split('\n') {
            let chars = i32::try_from(line.chars().count()).unwrap_or(i32::MAX);
            if chars > max {
                max = chars;
            }
        }
        max
    }
}

// ============================================================================
// Non-virtual delegate methods — 5 nv functions from FASM
// ============================================================================

impl TuiProgressbox {
    /// Set integer-mode limits `[min, max]` on the embedded progress
    /// bar.
    ///
    /// FASM equivalent: `tui_progressbox$nvlimits`
    /// (`tui_progressbox.inc` lines 162–171). The FASM body reads
    /// `[rdi+tui_panel_user_ofs]` to recover the embedded progress
    /// bar pointer and tail-calls `tui_progressbar$nvlimits`. The
    /// Rust port stores the same pointer in [`Self::progress_bar`]
    /// and forwards directly via [`ProgressBar::set_limits`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the progress bar's redraw
    /// hook fails (typically only on a renderer write error, which
    /// in turn typically indicates a closed terminal / SSH channel).
    pub fn set_limits(&self, min: u64, max: u64) -> Result<(), TuiError> {
        self.progress_bar.set_limits(min, max)
    }

    /// Set double-mode limits `[min, max]` on the embedded progress
    /// bar.
    ///
    /// FASM equivalent: `tui_progressbox$nvlimitsd`
    /// (`tui_progressbox.inc` lines 173–182). Forwards to
    /// [`ProgressBar::set_limits_f64`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the progress bar's redraw
    /// hook fails.
    pub fn set_limits_f64(&self, min: f64, max: f64) -> Result<(), TuiError> {
        self.progress_bar.set_limits_f64(min, max)
    }

    /// Update the progress bar's current integer value.
    ///
    /// FASM equivalent: `tui_progressbox$nvupdate`
    /// (`tui_progressbox.inc` lines 184–193). Forwards to
    /// [`ProgressBar::update`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the progress bar's redraw
    /// hook fails.
    pub fn update(&self, current: u64) -> Result<(), TuiError> {
        self.progress_bar.update(current)
    }

    /// Update the progress bar's current double value.
    ///
    /// FASM equivalent: `tui_progressbox$nvupdated`
    /// (`tui_progressbox.inc` lines 195–204). Forwards to
    /// [`ProgressBar::update_f64`].
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if the progress bar's redraw
    /// hook fails.
    pub fn update_f64(&self, current: f64) -> Result<(), TuiError> {
        self.progress_bar.update_f64(current)
    }

    /// Read the current progress as a fraction in `[0.0, 1.0]`.
    ///
    /// FASM equivalent: `tui_progressbox$nvgetperc`
    /// (`tui_progressbox.inc` lines 206–216). Forwards to
    /// [`ProgressBar::get_percentage`]. May exceed `1.0` if `cur > max`
    /// or fall below `0.0` (in double mode) if `cur < min`,
    /// preserving FASM behavior.
    #[must_use]
    pub fn get_percentage(&self) -> f64 {
        self.progress_bar.get_percentage()
    }
}

// ============================================================================
// TuiProgressbox — Widget trait impl
// ============================================================================
//
// Per FASM, `tui_progressbox` reuses `tui_panel$vtable` directly with
// no overrides. The Rust translation honors this by delegating every
// trait slot to the embedded [`Panel`] — except for [`Widget::as_any`]
// which must return `self` (so `as_any().downcast_ref::<TuiProgressbox>()`
// recovers the concrete progressbox type) and [`Widget::clone_widget`]
// which has to recompute the [`Self::progress_bar`] field on the clone.
// ============================================================================

impl Widget for TuiProgressbox {
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
    /// [`TuiProgressbox`]) so callers using
    /// `widget.as_any().downcast_ref::<TuiProgressbox>()` recover
    /// the progressbox-specific type rather than the underlying
    /// [`Panel`].
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Override slot 0 — release progressbox-specific state, then
    /// delegate the panel-shaped cleanup body to [`Panel`].
    ///
    /// FASM `tui_progressbox` does not override `cleanup`; it
    /// inherits `tui_panel$cleanup` directly. The Rust translation
    /// can't simply call `Widget::cleanup` because that would invoke
    /// the trait default (which is the `tui_object$cleanup`
    /// equivalent — clears children/text but does **not** free the
    /// title resources owned by the panel). Instead we inline
    /// [`Panel::cleanup`]'s body via `self.base`, matching the FASM
    /// vtable lookup result.
    ///
    /// Note: dropping `self.progress_bar` is implicit — the
    /// [`Arc<ProgressBar>`] field is automatically released when
    /// the [`TuiProgressbox`] is deallocated. Forcing it to a
    /// dummy value here would require `Option<Arc<…>>` and
    /// complicate every access site.
    fn cleanup(&mut self) {
        // Delegate to Panel's cleanup, which clears the title and
        // titletext as well as the inherited children/text/etc.
        // We use the explicit [`Widget::cleanup`] call to bypass
        // the trait-default vtable lookup that would otherwise fire
        // for dot-notation calls on a non-`Sized`-receiver context.
        // Because `self.base` is an owned [`Panel`] (not `Arc`-
        // wrapped), dot-notation here resolves statically to
        // [`Panel`]'s [`Widget::cleanup`] override.
        Widget::cleanup(&mut self.base);
    }

    /// Override slot 1 — produce a deep clone of this progressbox.
    ///
    /// FASM `tui_panel$init_copy` (the inherited slot-1 vmethod)
    /// memcpy's the entire panel struct (including the descendant-
    /// private `user_ofs` pointer) and then deep-clones the children
    /// tree. The Rust port:
    ///
    /// 1. Calls [`Panel::clone_as_panel`] to deep-clone the panel
    ///    (which recursively clones the message label and the vbox,
    ///    and through that recursion clones the inner progress bar).
    ///    The cloned panel contains an entirely fresh
    ///    [`Arc<ProgressBar>`] inside its child tree.
    /// 2. Reuses [`Arc::clone`] of the **original** progress bar for
    ///    the cloned struct's [`Self::progress_bar`] field — matching
    ///    FASM `tui_panel$init_copy`'s memcpy semantics where the
    ///    `user_ofs` pointer is bytewise-copied verbatim from the
    ///    source. The cloned progressbox's nv methods therefore act
    ///    on the **same** progress bar as the original. This is a
    ///    documented divergence: in FASM the cloned progress bar
    ///    inside the clone's child tree shares no state with the
    ///    `user_ofs` pointer; the same is true here. In practice
    ///    [`Self::clone_widget`] is virtually never called for
    ///    progress-box widgets (which are constructed fresh per
    ///    operation), so the asymmetry is unobservable.
    ///
    /// Mirrors the same approach taken in
    /// [`TuiTextbox::clone_widget`](crate::tui::widgets::textbox::TuiTextbox)
    /// for the analogous `editor` field.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if [`Panel::clone_as_panel`]
    /// fails or if its returned `Arc` cannot be unwrapped (a
    /// defensive guard — the factory returns a fresh strong-count-1
    /// `Arc` on every successful call).
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // Deep-clone the panel + child tree.
        let panel_clone_arc = self.base.clone_as_panel()?;
        let panel_clone = Arc::try_unwrap(panel_clone_arc).map_err(|_arc| {
            TuiError::Render(std::io::Error::other(
                "TuiProgressbox::clone_widget: clone_as_panel returned a shared Arc (refcount > 1)",
            ))
        })?;

        // Build the cloned progressbox sharing the original progress
        // bar (FASM memcpy of `user_ofs`).
        let cloned = Arc::new(Self {
            base: panel_clone,
            progress_bar: Arc::clone(&self.progress_bar),
        });

        Ok(cloned as Arc<dyn Widget>)
    }

    /// Override slot 2 — render the panel border, title overlay,
    /// and background fill via the inherited [`Panel`] draw.
    ///
    /// The trait-default `Widget::draw` (`object.rs` line 737) is a
    /// no-op; without this delegation the border + title would never
    /// be painted. Routing through `self.base.draw(r)` invokes
    /// [`Panel::draw`] (the override on panel.rs line 744) directly,
    /// matching FASM's `tui_progressbox$vtable[2] = tui_panel$draw`.
    fn draw(&mut self, r: &mut dyn crate::tui::render::Renderer) -> Result<(), TuiError> {
        self.base.draw(r)
    }

    /// Override slot 28 — append a child to the panel's guts
    /// container (preserving the border).
    ///
    /// Delegates to [`Panel`]'s [`Widget::append_child`] override
    /// (panel.rs line 784), which routes the child into the guts
    /// container rather than the panel's top-level children list.
    /// Without this override the trait-default `append_child` would
    /// push directly into `self.state.children`, breaking the
    /// border / hbox / guts tree shape established by
    /// [`Panel::new_ii`].
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
    /// (panel.rs line 803), which searches the guts container's
    /// children list rather than the panel's top-level children.
    fn get_child_index(&self, child: &Arc<dyn Widget>) -> Option<usize> {
        Widget::get_child_index(&self.base, child)
    }

    /// Override slot 33 — remove `child` from the guts container.
    ///
    /// Delegates to [`Panel`]'s [`Widget::remove_child`] override
    /// (panel.rs line 811).
    fn remove_child(&mut self, child: &Arc<dyn Widget>) -> bool {
        Widget::remove_child(&mut self.base, child)
    }

    /// Override slot 12 — handle a key event.
    ///
    /// FASM `tui_progressbox` inherits `tui_panel$keyevent`. The
    /// trait-default `key_event` (`object.rs` line 850) returns
    /// `false`, which happens to coincide with [`Panel`]'s default
    /// (panel.rs line 1905 verifies this). We delegate explicitly
    /// through the panel anyway so that any future override on
    /// [`Panel`] flows through automatically.
    fn key_event(&mut self, event: KeyEvent) -> bool {
        Widget::key_event(&mut self.base, event)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // count_lines — empty / single / multiple / trailing-newline
    // ------------------------------------------------------------------

    #[test]
    fn count_lines_empty_returns_one() {
        // Even for empty input we want at least one panel row so the
        // border / message-area layout stays well-defined.
        assert_eq!(TuiProgressbox::count_lines(""), 1);
    }

    #[test]
    fn count_lines_single_line() {
        assert_eq!(TuiProgressbox::count_lines("hello world"), 1);
    }

    #[test]
    fn count_lines_two_lines() {
        assert_eq!(TuiProgressbox::count_lines("first\nsecond"), 2);
    }

    #[test]
    fn count_lines_three_lines() {
        assert_eq!(TuiProgressbox::count_lines("a\nb\nc"), 3);
    }

    #[test]
    fn count_lines_trailing_newline() {
        // FASM `string$split` produces N+1 entries for an N-newline
        // input — `"foo\nbar\n"` splits into ["foo", "bar", ""] → 3.
        assert_eq!(TuiProgressbox::count_lines("foo\nbar\n"), 3);
    }

    #[test]
    fn count_lines_only_newlines() {
        // 4 newlines → 5 (empty) lines.
        assert_eq!(TuiProgressbox::count_lines("\n\n\n\n"), 5);
    }

    // ------------------------------------------------------------------
    // max_line_length — empty / single / multiline / unicode
    // ------------------------------------------------------------------

    #[test]
    fn max_line_length_empty_string() {
        assert_eq!(TuiProgressbox::max_line_length(""), 0);
    }

    #[test]
    fn max_line_length_single_line() {
        assert_eq!(TuiProgressbox::max_line_length("hello"), 5);
    }

    #[test]
    fn max_line_length_picks_longest() {
        // Three lines of width 5, 11, 3 → max = 11.
        assert_eq!(TuiProgressbox::max_line_length("short\nlonger line\nmid"), 11);
    }

    #[test]
    fn max_line_length_picks_first_line_when_longest() {
        assert_eq!(TuiProgressbox::max_line_length("longest line\nshort"), 12);
    }

    #[test]
    fn max_line_length_with_trailing_newline() {
        // Trailing `\n` produces an empty line which doesn't change
        // the max.
        assert_eq!(TuiProgressbox::max_line_length("hello\n"), 5);
    }

    #[test]
    fn max_line_length_counts_codepoints_not_bytes() {
        // The `é` (U+00E9) takes 2 bytes in UTF-8 but is 1 codepoint.
        // FASM measures codepoints (UTF-32 storage) so the Rust port
        // must use `chars().count()`, not `len()`.
        assert_eq!(TuiProgressbox::max_line_length("café"), 4);
    }

    #[test]
    fn max_line_length_multibyte_emoji() {
        // 🦀 (U+1F980, "crab") is a 4-byte UTF-8 sequence but a
        // single codepoint.
        assert_eq!(TuiProgressbox::max_line_length("🦀"), 1);
    }

    // ------------------------------------------------------------------
    // Construction — full happy path
    // ------------------------------------------------------------------

    fn make_test_colors() -> (ColorPair, ColorPair, ColorPair) {
        let panel_colors = ColorPair { fg: 0xff, bg: 0x10 };
        let bar_empty = ColorPair { fg: 0x88, bg: 0x10 };
        let bar_fill = ColorPair { fg: 0x10, bg: 0xff };
        (panel_colors, bar_empty, bar_fill)
    }

    #[test]
    fn new_constructs_with_simple_inputs() {
        let (pc, be, bf) = make_test_colors();
        let pb = TuiProgressbox::new(b"Working", b"Please wait...", pc, be, bf)
            .expect("constructor should succeed for simple inputs");
        // Widget state should be reachable through the trait method.
        let state = pb.state();
        // FASM width = max(32, "Working"(7)+6=13, "Please wait..."(14)+6=20) = 32
        assert_eq!(state.width, 32, "width should clamp to minimum 32");
        // FASM height = lines(1) + 6 = 7
        assert_eq!(state.height, 7, "height should be line_count + 6");
    }

    #[test]
    fn new_widens_for_long_title() {
        let (pc, be, bf) = make_test_colors();
        // 30-char title + 6 = 36 > 32, so width should be 36.
        let title = b"This is a fairly long title!!!";
        assert_eq!(title.len(), 30);
        let pb = TuiProgressbox::new(title, b"x", pc, be, bf).expect("constructor should succeed");
        assert_eq!(pb.state().width, 36);
    }

    #[test]
    fn new_widens_for_long_message_line() {
        let (pc, be, bf) = make_test_colors();
        // Long line: 50 chars + 6 = 56 > 32 and > short title.
        let msg = b"This message line is exactly fifty characters wide";
        assert_eq!(msg.len(), 50);
        let pb = TuiProgressbox::new(b"t", msg, pc, be, bf).expect("constructor should succeed");
        assert_eq!(pb.state().width, 56);
    }

    #[test]
    fn new_height_grows_with_message_lines() {
        let (pc, be, bf) = make_test_colors();
        let pb =
            TuiProgressbox::new(b"t", b"l1\nl2\nl3\nl4", pc, be, bf).expect("constructor should succeed");
        // 4 lines + 6 = 10
        assert_eq!(pb.state().height, 10);
    }

    #[test]
    fn new_returns_arc_with_strong_count_one() {
        let (pc, be, bf) = make_test_colors();
        let pb = TuiProgressbox::new(b"t", b"m", pc, be, bf).expect("constructor should succeed");
        assert_eq!(
            Arc::strong_count(&pb),
            1,
            "fresh progressbox Arc should have strong-count 1"
        );
    }

    #[test]
    fn new_progress_bar_is_default_zero_state() {
        let (pc, be, bf) = make_test_colors();
        let pb = TuiProgressbox::new(b"t", b"m", pc, be, bf).expect("constructor should succeed");
        // Fresh progress bar: min=0, max=0, cur=0, percentage=0.0.
        assert_eq!(pb.get_percentage(), 0.0);
    }

    // ------------------------------------------------------------------
    // Non-virtual delegate methods — set_limits / update / get_percentage
    // ------------------------------------------------------------------

    #[test]
    fn set_limits_then_update_yields_expected_percentage() {
        let (pc, be, bf) = make_test_colors();
        let pb = TuiProgressbox::new(b"t", b"m", pc, be, bf).expect("constructor should succeed");
        pb.set_limits(0, 100).expect("set_limits should succeed");
        pb.update(25).expect("update should succeed");
        assert!((pb.get_percentage() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn set_limits_f64_then_update_f64_yields_expected_percentage() {
        let (pc, be, bf) = make_test_colors();
        let pb = TuiProgressbox::new(b"t", b"m", pc, be, bf).expect("constructor should succeed");
        pb.set_limits_f64(0.0, 1.0)
            .expect("set_limits_f64 should succeed");
        pb.update_f64(0.5).expect("update_f64 should succeed");
        assert!((pb.get_percentage() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn update_to_max_yields_one_hundred_percent() {
        let (pc, be, bf) = make_test_colors();
        let pb = TuiProgressbox::new(b"t", b"m", pc, be, bf).expect("constructor should succeed");
        pb.set_limits(0, 100).expect("set_limits should succeed");
        pb.update(100).expect("update should succeed");
        assert!((pb.get_percentage() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn nv_methods_share_progressbar_with_internal_tree() {
        // Verify that calling nv methods on the progressbox affects the
        // SAME progress bar that lives inside the panel's child tree.
        // This guards against accidental drift where the constructor
        // appends one progressbar to the vbox but stores a different
        // Arc in `self.progress_bar`.
        let (pc, be, bf) = make_test_colors();
        let pb = TuiProgressbox::new(b"t", b"m", pc, be, bf).expect("constructor should succeed");
        pb.set_limits(0, 200).expect("set_limits should succeed");
        pb.update(150).expect("update should succeed");
        assert!((pb.get_percentage() - 0.75).abs() < 1e-9);
        // Drive again to confirm the field is the same Arc.
        pb.update(50).expect("update should succeed");
        assert!((pb.get_percentage() - 0.25).abs() < 1e-9);
    }

    // ------------------------------------------------------------------
    // Widget trait — state delegation, downcast, clone
    // ------------------------------------------------------------------

    #[test]
    fn as_any_downcasts_to_tui_progressbox() {
        let (pc, be, bf) = make_test_colors();
        let pb = TuiProgressbox::new(b"t", b"m", pc, be, bf).expect("constructor should succeed");
        let dyn_widget: Arc<dyn Widget> = pb.clone();
        let recovered = dyn_widget.as_any().downcast_ref::<TuiProgressbox>();
        assert!(
            recovered.is_some(),
            "as_any should permit downcast back to TuiProgressbox"
        );
    }

    #[test]
    fn key_event_returns_false_by_default() {
        let (pc, be, bf) = make_test_colors();
        let mut pb_mut = {
            // Build a TuiProgressbox we can mutate by-value.
            let arc = TuiProgressbox::new(b"t", b"m", pc, be, bf).expect("constructor should succeed");
            Arc::try_unwrap(arc).unwrap_or_else(|_| panic!("Arc unexpectedly aliased"))
        };
        // Inherits Panel's default which returns `false` (no key
        // handling on the panel itself).
        assert!(!pb_mut.key_event(KeyEvent::Enter));
        assert!(!pb_mut.key_event(KeyEvent::Char('x')));
    }

    #[test]
    fn clone_widget_preserves_panel_dimensions() {
        let (pc, be, bf) = make_test_colors();
        let pb =
            TuiProgressbox::new(b"Title", b"line1\nline2", pc, be, bf).expect("constructor should succeed");
        let original_w = pb.state().width;
        let original_h = pb.state().height;

        let cloned = pb.clone_widget().expect("clone_widget should succeed");
        assert_eq!(cloned.state().width, original_w);
        assert_eq!(cloned.state().height, original_h);

        // The clone should also be a TuiProgressbox.
        assert!(
            cloned.as_any().downcast_ref::<TuiProgressbox>().is_some(),
            "clone should downcast back to TuiProgressbox"
        );
    }

    #[test]
    fn clone_widget_shares_progress_bar_with_original() {
        // Per the FASM `tui_panel$init_copy` `user_ofs` memcpy
        // semantics, the cloned progressbox's nv methods operate on
        // the SAME progress bar as the original (sharing
        // `Arc<ProgressBar>`).
        let (pc, be, bf) = make_test_colors();
        let pb = TuiProgressbox::new(b"t", b"m", pc, be, bf).expect("constructor should succeed");
        pb.set_limits(0, 100).expect("set_limits should succeed");
        pb.update(40).expect("update should succeed");

        let cloned_dyn = pb.clone_widget().expect("clone should succeed");
        let cloned_pb = cloned_dyn
            .as_any()
            .downcast_ref::<TuiProgressbox>()
            .expect("clone is a TuiProgressbox");
        // The cloned progressbox sees the same percentage.
        assert!((cloned_pb.get_percentage() - 0.40).abs() < 1e-9);
        // Updating the original is observed by the clone.
        pb.update(80).expect("update should succeed");
        assert!((cloned_pb.get_percentage() - 0.80).abs() < 1e-9);
    }

    #[test]
    fn unicode_title_and_message_compute_correct_dimensions() {
        let (pc, be, bf) = make_test_colors();
        // "café" = 4 codepoints (5 bytes); "🦀 status" = 8 codepoints
        // (10 bytes — `🦀` is 4 bytes UTF-8).
        let pb = TuiProgressbox::new("café".as_bytes(), "🦀 status\n🦀🦀 more".as_bytes(), pc, be, bf)
            .expect("constructor should succeed");
        // title = 4 codepoints + 6 = 10; max_line = 8 codepoints + 6
        // = 14 (the second line "🦀🦀 more" = 7 codepoints, the first
        // "🦀 status" = 8). max(32, 10, 14) = 32.
        assert_eq!(pb.state().width, 32);
        // 2 message lines + 6 = 8.
        assert_eq!(pb.state().height, 8);
    }
}
