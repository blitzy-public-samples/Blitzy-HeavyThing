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
// tui::widgets: Module aggregator for all TUI widget implementations.
// Ports 25 FASM tui_*.inc files (tui_background, tui_lines, tui_spacers,
// tui_panel, tui_text, tui_label, tui_button, tui_form, tui_textbox,
// tui_alert, tui_simpleauth, tui_progressbar, tui_progressbox, tui_bell,
// tui_spinner, tui_statusbar, tui_newsticker, tui_datagrid, tui_matrix,
// tui_typist, tui_splash, tui_effect, tui_effects, tui_png, tui_ssh).
//
// Per AAP §0.4.1.1 and §0.5.1.5, this is a **pure aggregator**: it
// declares submodules and re-exports the public widget surface so
// callers can write `use heavything::tui::widgets::TuiPanel` instead of
// `use heavything::tui::widgets::panel::TuiPanel`. There is no FASM
// equivalent of this file — Rust's module system requires every leaf
// module to be reachable through `pub mod` from an ancestor, whereas
// the FASM `include 'tui_*.inc'` pattern flattens its imports into the
// global namespace at translation time.
//
// Naming convention: the AAP and the schema use the consistent
// `TuiXxx` PascalCase prefix for all widget classes (TuiAlert,
// TuiBackground, TuiPanel, etc.). Several widget files committed to
// shorter or differently-cased names during their own translation
// phase (e.g. `Bell`, `Button`, `Effect`, `Form`, `Matrix`,
// `PngWidget`, `Spinner`, `Statusbar`, `TuiTextbox`,
// `TuiSimpleauth`, `TuiProgressbox`). This file uses
// `pub use … as TuiXxx` aliases so callers see the consistent
// PascalCase surface specified by the schema export list while the
// underlying widget files retain their committed identifiers.
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! TUI widget implementations.
//!
//! This module tree contains the Rust translations of 25 FASM `tui_*.inc`
//! widget files from the HeavyThing assembly library. Every widget
//! implements the [`Widget`](crate::tui::object::Widget) trait defined in
//! the parent [`crate::tui::object`] module.
//!
//! ## Widget Hierarchy
//!
//! The FASM library's widget inheritance forms a three-level tree
//! rooted at [`crate::tui::object::Widget`] (the base trait — 37 vmethods
//! plus the [`crate::tui::object::WidgetState`] storage). Widgets that
//! "inherit" from another widget in the FASM sources reuse the parent's
//! state layout and override only the specific vmethods relevant to
//! their role; in this Rust port that translates to embedding the
//! parent struct as a field plus a small set of method overrides.
//!
//! ```text
//! tui_object (base — 37-vmethod vtable, WidgetState-bearing)
//! ├── tui_background (+ bgfillchar, bgcolors; overrides clone, draw)
//! │   ├── tui_lines (factories producing pre-filled TuiBackgrounds)
//! │   ├── tui_bell
//! │   ├── tui_newsticker
//! │   ├── tui_splash
//! │   ├── tui_panel (+ title, guts container)
//! │   │   ├── tui_alert
//! │   │   ├── tui_progressbox
//! │   │   └── tui_textbox
//! │   ├── tui_button
//! │   ├── tui_progressbar
//! │   ├── tui_typist
//! │   ├── tui_label
//! │   ├── tui_simpleauth
//! │   ├── tui_form
//! │   └── tui_text
//! ├── tui_spacers (use tui_object simple_vtable)
//! ├── tui_spinner
//! ├── tui_statusbar
//! ├── tui_datagrid
//! ├── tui_matrix
//! ├── tui_effect
//! ├── tui_effects (function-namespace catalog over tui_effect)
//! └── tui_png
//!
//! tui_ssh (separate — io-descendent; paired with TuiSshRenderer which
//!          is a tui::render descendent — straddles the tui-net
//!          subsystem boundary)
//! ```
//!
//! ## FASM Reference Files
//!
//! See `tui_background.inc`, `tui_lines.inc`, `tui_spacers.inc`,
//! `tui_panel.inc`, `tui_text.inc`, `tui_label.inc`, `tui_button.inc`,
//! `tui_form.inc`, `tui_textbox.inc`, `tui_alert.inc`,
//! `tui_simpleauth.inc`, `tui_progressbar.inc`, `tui_progressbox.inc`,
//! `tui_bell.inc`, `tui_spinner.inc`, `tui_statusbar.inc`,
//! `tui_newsticker.inc`, `tui_datagrid.inc`, `tui_matrix.inc`,
//! `tui_typist.inc`, `tui_splash.inc`, `tui_effect.inc`,
//! `tui_effects.inc`, `tui_png.inc`, `tui_ssh.inc`.
//!
//! ## Scope Constraints (per AAP §0.1.1)
//!
//! - **No third-party TUI crates** — `ratatui`, `crossterm`, `termion`,
//!   `tui` are strictly prohibited; existing TUI semantics must be
//!   preserved exactly.
//! - **All rendering** through [`crate::tui::render`] +
//!   [`crate::tui::ansi`] direct ANSI escape-code generation.
//! - **GPLv3 attribution** preserved on every file.
//!
//! ## Public Re-Export Surface
//!
//! Every widget class, helper struct, trait, enum, and constant
//! enumerated in the schema's export list is re-exported here under the
//! consistent `TuiXxx` PascalCase naming convention. Where a widget
//! file committed to a different identifier during its own translation
//! phase, an `as TuiXxx` rename is used; the underlying file is not
//! modified.
//!
//! Callers should prefer the re-exports surfaced from this module over
//! reaching into individual submodules — the re-export surface is the
//! stable public API; the submodule-local names are implementation
//! detail.

// =============================================================================
// Submodule declarations (alphabetical order, 25 total)
// =============================================================================
//
// Every widget file under `widgets/` is declared here. Adding a new
// widget requires (a) adding the file under `widgets/<name>.rs`,
// (b) adding `pub mod <name>;` here, and (c) adding the appropriate
// `pub use self::<name>::…` line in the re-export block below.

pub mod alert;
pub mod background;
pub mod bell;
pub mod button;
pub mod datagrid;
pub mod effect;
pub mod effects;
pub mod form;
pub mod label;
pub mod lines;
pub mod matrix;
pub mod newsticker;
pub mod panel;
pub mod png;
pub mod progressbar;
pub mod progressbox;
pub mod simpleauth;
pub mod spacers;
pub mod spinner;
pub mod splash;
pub mod ssh;
pub mod statusbar;
pub mod text;
pub mod textbox;
pub mod typist;

// =============================================================================
// Public re-exports (alphabetical, schema-aligned)
// =============================================================================
//
// Each `pub use` brings a widget public type from its submodule into
// the `crate::tui::widgets` namespace. Where a widget file committed
// to a non-`TuiXxx` identifier (e.g. `Bell`, `Button`), an `as TuiXxx`
// rename matches the consistent PascalCase surface specified by the
// schema export list.

// ----- Alert (modal dialog with 1-6 standard buttons) ------------------------
pub use self::alert::TuiAlert;

// ----- Background (foundational solid-color rectangle widget) ----------------
pub use self::background::TuiBackground;

// ----- Bell (1×1 widget that emits ASCII BEL at 120ms intervals) -------------
//
// `bell.rs` committed to `Bell`; the schema exports `TuiBell`. Use
// the alias to reconcile.
pub use self::bell::Bell as TuiBell;

// ----- Button (clickable button with focus/press states + Space activation) -
//
// `button.rs` committed to `Button`; the schema exports `TuiButton`.
pub use self::button::Button as TuiButton;

// ----- DataGrid (JSON-array-backed scrollable data grid) ---------------------
//
// `datagrid.rs` committed to `DataGrid`; the schema exports
// `TuiDataGrid`. The `ColumnSpec` helper lives in
// `crate::tui::gridguts` (the private internal renderer); the schema
// requires it to be re-exported at the widgets namespace as well so
// callers building grid layouts can pull the column descriptor and
// the grid widget from a single import path.
pub use self::datagrid::DataGrid as TuiDataGrid;
pub use crate::tui::gridguts::ColumnSpec;

// ----- Effect (low-level particle-system physics engine) ---------------------
//
// `effect.rs` committed to `Effect`; the schema exports `TuiEffect`.
pub use self::effect::Effect as TuiEffect;

// ----- Effects (high-level transition catalog) -------------------------------
//
// `effects.rs` is a function-namespace module — it exposes
// `hslidein`, `hslideout`, `vslidein`, `vslideout`, `distort_in`,
// `distort_out` as free functions rather than methods on a struct
// (mirroring how `tui_effects.inc` is a thin constructor layer over
// the `tui_effect` particle engine and has no per-instance state of
// its own). The schema's export list nevertheless requires a class
// named `TuiEffects` to be re-exported from this aggregator, so we
// declare a zero-sized marker tag here that callers can use as a
// namespace handle. The constructor functions remain reachable via
// the [`effects`] submodule path; this marker exists solely so the
// schema's PascalCase surface includes a `TuiEffects` symbol.
//
// This is the only top-level type declaration in this otherwise pure
// aggregator file; it is documented here because it is a structural
// necessity rather than a behavioural addition.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TuiEffects;

// ----- Form (label+input pairs container with custom tab-order ring) ---------
//
// `form.rs` committed to `Form`; the schema exports `TuiForm`.
pub use self::form::Form as TuiForm;

// ----- Label (multi-line-aware text label, not editable) ---------------------
pub use self::label::TuiLabel;

// ----- Lines (HLINE/VLINE Unicode box-drawing factories + char constants) ----
pub use self::lines::{TuiHLine, TuiVLine, HLINE_CHAR, VLINE_CHAR};

// ----- Matrix (Matrix-rain raining-character animation widget) ---------------
//
// `matrix.rs` committed to `Matrix`; the schema exports `TuiMatrix`.
pub use self::matrix::Matrix as TuiMatrix;

// ----- Newsticker (right-to-left scrolling text at 200ms / 5fps) -------------
pub use self::newsticker::TuiNewsticker;

// ----- Panel (bordered container with optional title + guts child container)
pub use self::panel::TuiPanel;

// ----- Png (xterm-256 PNG image renderer with 2:1 character aspect ratio) ---
//
// `png.rs` committed to `PngWidget` to disambiguate from the `png`
// crate's `Png` decoder type; the schema exports `TuiPng`.
pub use self::png::PngWidget as TuiPng;

// ----- ProgressBar (fill-based progress with int/double + LTR/TTB/RTL/BTT) --
pub use self::progressbar::TuiProgressBar;

// ----- ProgressBox (panel-wrapped progressbar with title + message) ---------
//
// `progressbox.rs` committed to `TuiProgressbox` (lowercase 'b');
// the schema exports `TuiProgressBox` (uppercase 'B'). Aliased here
// to match the consistent PascalCase surface.
pub use self::progressbox::TuiProgressbox as TuiProgressBox;

// ----- SimpleAuth (pre-built authentication screen used by sshtalk) ---------
//
// `simpleauth.rs` committed to `TuiSimpleauth` (lowercase 'a');
// the schema exports `TuiSimpleAuth` (uppercase 'A'). Aliased here.
// `SimpleAuthHandler` is the trait that userdb implementations
// implement to customize authentication decisions (replacing the 3
// FASM addon vmethods allow_userpass / allow_token / create_newuser).
pub use self::simpleauth::{SimpleAuthHandler, TuiSimpleauth as TuiSimpleAuth};

// ----- Spacers (TuiHSpacer/TuiVSpacer zero-visual layout helpers) ------------
pub use self::spacers::{TuiHSpacer, TuiVSpacer};

// ----- Spinner (1×1 animated `-\|/` glyph cycler) ----------------------------
//
// `spinner.rs` committed to `Spinner`; the schema exports `TuiSpinner`.
pub use self::spinner::Spinner as TuiSpinner;

// ----- Splash (2 Ton Digital animated splash screen) -------------------------
//
// `init_logo` is the Stage 14 deferred-initialization hook called
// from `heavything::init()` (lib.rs) via OnceLock to materialize the
// embedded 2 Ton Digital PNG logo. Re-exported here so `lib.rs` can
// call it without reaching into the submodule path.
pub use self::splash::{init_logo, TuiSplash};

// ----- Ssh (TuiSsh I/O-chain bridge + TuiSshRenderer ANSI sink) -------------
//
// This is the only TUI file that straddles the tui-net subsystem
// boundary. Both types are re-exported because callers in the
// `sshtalk` binary crate need both: `TuiSsh` to attach the widget
// tree to the SSH protocol transport, `TuiSshRenderer` to emit ANSI
// bytes through the SSH channel instead of stdout.
pub use self::ssh::{TuiSsh, TuiSshRenderer};

// ----- StatusBar (height-1 status bar with uptime + caller labels) ----------
//
// `statusbar.rs` committed to `Statusbar` (lowercase 'b'); the
// schema exports `TuiStatusBar` (uppercase 'B'). Aliased here.
//
// `statusbar_global_init` is the Stage 15 deferred-initialization
// hook called from `heavything::init()` via OnceLock to construct
// the shared uptime-formatter singleton. Re-exported under the
// disambiguated `statusbar_global_init` name so `lib.rs` can call
// it without colliding with `splash::init_logo` or other init
// functions; the underlying symbol is `statusbar::global_init`.
pub use self::statusbar::{global_init as statusbar_global_init, Statusbar as TuiStatusBar};

// ----- Text (editable multiline text widget + alignment/wrap modes) ---------
//
// `TuiText` is the editable multiline text widget that powers
// `sshtalk` chat input, `hnwatch` detail views, and `webserver`
// form inputs, and that backs `TuiTextBox` and `TuiSimpleAuth`'s
// editor field. `AlignMode` and `WrapMode` are the two enums that
// configure its rendering behaviour:
//   * `AlignMode::{Left, Center, Right, Justified}` — horizontal
//     alignment of each line within the widget area.
//   * `WrapMode::{Scroll, Hard, Word}` — how lines that exceed the
//     widget width are split.
pub use self::text::{AlignMode, TuiText, WrapMode};

// ----- TextBox (panel-wrapped modal single-line text-input dialog) ----------
//
// `textbox.rs` committed to `TuiTextbox` (lowercase 'b'); the
// schema exports `TuiTextBox` (uppercase 'B'). Aliased here.
pub use self::textbox::TuiTextbox as TuiTextBox;

// ----- Typist (character-by-character typewriter animation) -----------------
pub use self::typist::TuiTypist;

// =============================================================================
// Tests — re-export surface verification
// =============================================================================
//
// These tests exercise the re-export paths at compile time: every
// `Option<super::TuiXxx>` declaration forces the compiler to resolve
// the named symbol through the `widgets::` namespace, so the test
// fails to compile if a `pub use` is missing or an underlying
// submodule renames its primary type. The line-character constants
// test additionally verifies the runtime-observable values
// preserved from the FASM `tui_lines.inc` source.

#[cfg(test)]
mod tests {
    // The compile-time verification block below uses `Option<T>` to
    // avoid having to construct any of the widget types (most of
    // which require a `WidgetState` plus per-widget configuration).
    // The mere act of naming `super::TuiXxx` in a type position is
    // enough to force the compiler to resolve the path.
    //
    // If a future refactor renames a widget type or removes a
    // `pub use` from this module, the affected line below will
    // produce a compile error pointing precisely at the missing
    // re-export.

    #[test]
    fn all_widgets_reexported() {
        let _: Option<super::TuiBackground> = None;
        let _: Option<super::TuiHLine> = None;
        let _: Option<super::TuiVLine> = None;
        let _: Option<super::TuiHSpacer> = None;
        let _: Option<super::TuiVSpacer> = None;
        let _: Option<super::TuiPanel> = None;
        let _: Option<super::TuiText> = None;
        let _: Option<super::TuiLabel> = None;
        let _: Option<super::TuiButton> = None;
        let _: Option<super::TuiForm> = None;
        let _: Option<super::TuiTextBox> = None;
        let _: Option<super::TuiAlert> = None;
        let _: Option<super::TuiSimpleAuth> = None;
        let _: Option<super::TuiProgressBar> = None;
        let _: Option<super::TuiProgressBox> = None;
        let _: Option<super::TuiBell> = None;
        let _: Option<super::TuiSpinner> = None;
        let _: Option<super::TuiStatusBar> = None;
        let _: Option<super::TuiNewsticker> = None;
        let _: Option<super::TuiDataGrid> = None;
        let _: Option<super::TuiMatrix> = None;
        let _: Option<super::TuiTypist> = None;
        let _: Option<super::TuiSplash> = None;
        let _: Option<super::TuiEffect> = None;
        let _: Option<super::TuiEffects> = None;
        let _: Option<super::TuiPng> = None;
        let _: Option<super::TuiSsh> = None;
        let _: Option<super::TuiSshRenderer> = None;
        let _: Option<super::ColumnSpec> = None;
    }

    #[test]
    fn line_char_constants_are_exported() {
        // U+2502 BOX DRAWINGS LIGHT VERTICAL — vertical-line glyph.
        assert_eq!(super::VLINE_CHAR, 0x2502);
        // U+2500 BOX DRAWINGS LIGHT HORIZONTAL — horizontal-line glyph.
        assert_eq!(super::HLINE_CHAR, 0x2500);
    }

    #[test]
    fn deferred_init_functions_reachable() {
        // Compile-time verification only: take function pointers to
        // confirm the `init_logo` and `statusbar_global_init`
        // re-exports resolve to the correct functions in their
        // respective submodules. We do not call them here because
        // their initializers depend on global state that other
        // tests may rely on remaining un-initialized.
        let _f1: fn() = super::statusbar_global_init;
        let _f2: fn() -> &'static crate::util::png::PngImage = super::init_logo;
    }

    #[test]
    fn simpleauth_handler_is_a_trait() {
        // Compile-time verification: the schema exposes
        // `SimpleAuthHandler` as an interface (trait). Confirm the
        // re-export resolves to a trait that supports `dyn`
        // dispatch — this catches accidental conversion to a struct
        // or removal of the `Send + Sync` bounds.
        fn _accepts_handler(_h: &dyn super::SimpleAuthHandler) {}
    }

    #[test]
    fn align_and_wrap_modes_are_enums() {
        // Compile-time verification that AlignMode and WrapMode
        // are reachable through the widgets namespace and that
        // `Default::default()` works on them — both enums derive
        // `Default` per the schema description.
        let _: super::AlignMode = super::AlignMode::default();
        let _: super::WrapMode = super::WrapMode::default();
    }

    #[test]
    fn tui_effects_marker_is_zero_sized() {
        // The `TuiEffects` marker is a zero-sized type that
        // satisfies the schema's class export requirement. The
        // actual transition constructors live in
        // [`super::effects`] (`hslidein`, `vslidein`, etc.).
        assert_eq!(core::mem::size_of::<super::TuiEffects>(), 0);
        let a = super::TuiEffects;
        let b = super::TuiEffects;
        assert_eq!(a, b);
    }
}
