// crates/heavything/src/tui/widgets/mod.rs — TUI widget module aggregator.
//
// Per AAP §0.5.1.5 this file is the root of the `widgets/` submodule
// tree and aggregates the 32 widget implementations ported from the
// FASM `tui_*.inc` files. Submodules are declared additively as
// sibling agents complete each widget translation; this file is
// therefore a work-in-progress scaffold and is expected to grow with
// each widget integration commit.
//
// ## Structural-necessity note (CP6 review acknowledgment)
//
// The CP6 scope listing nominally schedules `widgets/mod.rs` (file 116)
// for Checkpoint 7. However, Rust requires every module to be reachable
// from a `pub mod` declaration in an ancestor — there is no implicit
// module discovery. Without this aggregator, the 15 widget files added
// in CP6 (`background`, `bell`, `effect`, `effects`, `label`, `lines`,
// `matrix`, `newsticker`, `png`, `progressbar`, `spacers`, `spinner`,
// `ssh`, `text`, `typist`) would be unreachable from the crate root and
// would not compile. This file is therefore a structural prerequisite
// for the rest of CP6 and is created with no logic content beyond the
// `pub mod` declarations and module documentation. Subsequent
// checkpoints may extend this file with re-exports and additional
// widget modules without altering its scaffold nature.
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! TUI widget tree — ported from the 32 `tui_*.inc` files of HeavyThing.
//!
//! The widget tree mirrors the FASM hierarchy where every widget
//! inherits (semantically) from `tui_object` (see
//! [`crate::tui::object::Widget`]) and overrides only the specific
//! vmethods relevant to its role.
//!
//! Current submodule coverage:
//!
//! - [`background`] — solid-color rectangle base for ~12 descendants
//!   (`tui_background.inc`).
//! - [`bell`] — 1×1 [`background::TuiBackground`] descendant emitting
//!   the terminal BEL character (0x07) at a 120 ms cadence for a
//!   caller-specified number of ring cycles (`tui_bell.inc`).
//! - [`datagrid`] — JSON-array-backed scrollable data-grid widget with
//!   configurable columns, selectable rows, and a private
//!   [`crate::tui::gridguts::GridGuts`] internal renderer
//!   (`tui_datagrid.inc`).
//! - [`effect`] — particle-system effect base widget powering the
//!   six built-in transition effects (`tui_effect.inc`).
//! - [`effects`] — high-level transition catalog (slide-in, slide-out,
//!   distort-in, distort-out) — a thin constructor layer over
//!   [`effect::Effect`] (`tui_effects.inc`).
//! - [`label`] — multi-line text label with three text alignments
//!   (Left/Center/Right) and per-character highlight marking
//!   (`tui_label.inc`).
//! - [`lines`] — vertical/horizontal line factories producing
//!   pre-filled [`background::TuiBackground`] widgets (`tui_lines.inc`).
//! - [`matrix`] — Matrix-rain animation with 100 parallel character
//!   streams and a 50 ms (20 fps) tokio-driven ticker
//!   (`tui_matrix.inc`).
//! - [`newsticker`] — Height-1 [`background::TuiBackground`]
//!   descendant scrolling a text string right-to-left across its
//!   row at a 200 ms (5 fps) tokio-driven ticker
//!   (`tui_newsticker.inc`).
//! - [`png`] — PNG-to-ANSI-256 image widget with xterm 256-color
//!   quantization (`tui_png.inc`).
//! - [`progressbar`] — Background-descendant fill-based progress bar
//!   with int/double value modes and Forward/Reverse fill direction
//!   (`tui_progressbar.inc`).
//! - [`spacers`] — horizontal/vertical spacer + vertical-box layout
//!   container (`tui_spacers.inc`).
//! - [`spinner`] — 1×1 animated glyph indicator cycling `-\|/` at a
//!   configurable tick interval (`tui_spinner.inc`).
//! - [`ssh`] — SSH-side bridge between the widget tree and the
//!   `net::ssh` transport, providing the dual-class
//!   [`ssh::TuiSsh`] (I/O-chain descendant) and
//!   [`ssh::TuiSshRenderer`] (Renderer descendant) types
//!   (`tui_ssh.inc`).
//! - [`text`] — multi-line text display / editable text-area widget
//!   with cursor management, viewline composition (left/right
//!   alignment), word-wrap modes, and 15+ key handlers
//!   (`tui_text.inc`).
//! - [`typist`] — error-prone typewriter animation that emits a string
//!   character-by-character at a 50–160 ms human-typing cadence with
//!   QWERTY-aware typo simulation (`tui_typist.inc`).
//!
//! Additional widget submodules (`panel`,
//! `textbox`, `button`, `form`, `simpleauth`, `alert`,
//! `progressbox`, `statusbar`,
//! `splash`)
//! are added by subsequent translation agents per the AAP
//! file-by-file transformation plan.

pub mod background;
pub mod bell;
pub mod datagrid;
pub mod effect;
pub mod effects;
pub mod label;
pub mod lines;
pub mod matrix;
pub mod newsticker;
pub mod png;
pub mod progressbar;
pub mod spacers;
pub mod spinner;
pub mod ssh;
pub mod text;
pub mod typist;
