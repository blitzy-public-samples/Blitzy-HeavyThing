// crates/heavything/src/tui/widgets/mod.rs — TUI widget module aggregator.
//
// Per AAP §0.5.1.5 this file is the root of the `widgets/` submodule
// tree and aggregates the 32 widget implementations ported from the
// FASM `tui_*.inc` files. Submodules are declared additively as
// sibling agents complete each widget translation; this file is
// therefore a work-in-progress scaffold and is expected to grow with
// each widget integration commit.
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
//! - [`spacers`] — horizontal/vertical spacer + vertical-box layout
//!   container (`tui_spacers.inc`).
//!
//! Additional widget submodules (`panel`, `lines`, `label`, `text`,
//! `textbox`, `button`, `form`, `simpleauth`, `alert`, `bell`,
//! `progressbar`, `progressbox`, `spinner`, `datagrid`, `statusbar`,
//! `newsticker`, `matrix`, `typist`, `splash`, `effect`, `effects`,
//! `png`, `ssh`) are added by subsequent translation agents per the
//! AAP file-by-file transformation plan.

pub mod background;
pub mod spacers;
