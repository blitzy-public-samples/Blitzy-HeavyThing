// crates/heavything/src/tui/mod.rs — HeavyThing TUI subsystem module root.
//
// Aggregates the TUI submodules translated from the 32 `tui_*.inc` files
// of the HeavyThing assembly library per AAP §0.5.1.5. Submodules are
// declared additively as sibling agents complete each widget / engine
// port; this file is therefore a work-in-progress scaffold and is
// expected to grow with each integration commit.
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! TUI framework — ported from the 32 `tui_*.inc` files of HeavyThing.
//!
//! Current submodule coverage:
//!
//! - [`ansi`] — ANSI escape constants and formatters (`tui_ansi.inc`).
//! - [`geometry`] — `Point`, `Rect`, alignment math (`tui_geometry.inc`).
//! - [`lock`] — render-lock primitive (`tui_lock.inc`).
//! - [`object`] — base [`object::Widget`] trait (37-vmethod port of
//!   `tui_object.inc`) plus [`object::WidgetState`] and supporting
//!   types ([`object::Layout`], [`object::HorizAlign`],
//!   [`object::VertAlign`], [`object::ColorPair`],
//!   [`object::Attributes`], [`object::KeyEvent`],
//!   [`object::ClickEvent`], [`object::TimerAction`]).
//! - [`render`] — [`render::Renderer`] trait and supporting types that
//!   mediate between widget `draw` calls and the concrete terminal /
//!   SSH sinks (`tui_render.inc`).
//! - [`terminal`] — raw-mode terminal singleton + signal handlers
//!   (`tui_terminal.inc`, AAP §0.7.3).
//!
//! The remaining submodules (`gridguts` and the `widgets/` tree) are
//! added by subsequent translation agents per the AAP file-by-file
//! transformation plan.

pub mod ansi;
pub mod geometry;
pub mod lock;
pub mod object;
pub mod render;
pub mod terminal;
pub mod widgets;
