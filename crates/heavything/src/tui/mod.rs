// crates/heavything/src/tui/mod.rs — HeavyThing TUI subsystem aggregator.
//
// This file declares all submodules of the `tui` subsystem (port of the
// 32 `tui_*.inc` FASM files) and re-exports the commonly used public
// types for ergonomic callers. Per AAP §0.5.1.5 the aggregator is the
// LAST file created in the `tui/` directory — every sibling submodule
// can be referenced via `crate::tui::*` once this aggregator is in
// place. The module declarations here pull each sibling into the
// crate's compilation unit; the `pub use` re-exports below surface the
// commonly consumed public types at the `heavything::tui` root so that
// downstream callers (`crates/sshtalk`, `crates/hnwatch`,
// `crates/webserver`) can write
// `use heavything::tui::{Widget, Renderer, RawTerminal, Rect, Point};`
// without deep paths.
//
// Derived from HeavyThing © 2015–2018 2 Ton Digital, Jeff Marrison.
// Licensed under GPL-3.0-or-later. See LICENSE at the repository root.

//! Terminal User Interface subsystem for the HeavyThing library.
//!
//! This is the Rust translation of the 32 `tui_*.inc` FASM files
//! (~25 KLoC of assembly) per AAP §0.5.1.5. All widgets are built on
//! direct `libc::termios` syscalls (via [`terminal`]), hand-rolled ANSI
//! escape-code generation (via [`ansi`]), and a `struct + trait`
//! polymorphism model replacing the 37-vmethod virtual method table
//! from `tui_object.inc` (via [`object`]).
//!
//! # Prohibition on third-party TUI crates
//!
//! Per AAP §0.1.1, **third-party TUI crates (`ratatui`, `crossterm`,
//! `termion`, `tui`) are prohibited**. This subsystem uses only:
//!
//! - [`libc`] for direct `termios` / `ioctl` / `sigaction` syscalls
//!   (encapsulated in [`terminal::RawTerminal`]).
//! - `tokio` for async event streams, timers, and channels.
//! - `bytes` for ANSI byte-sequence buffers.
//! - `crate::ds` for internal `Buffer` / `List` / `OrderedMap` types
//!   consumed by individual widgets.
//! - `crate::util` for `Png`, `Formatter`, `Date`, string / unicodecase
//!   helpers consumed by individual widgets.
//!
//! [`libc`]: https://crates.io/crates/libc
//!
//! # Module layout
//!
//! | Module | Source (FASM) | Purpose |
//! |---|---|---|
//! | [`object`] | `tui_object.inc` | Base [`Widget`] trait with 37 virtual methods |
//! | [`render`] | `tui_render.inc` | [`Renderer`] trait and buffered wrapper |
//! | [`terminal`] | `tui_terminal.inc` | [`RawTerminal`] singleton, raw-mode, signal handlers |
//! | [`ansi`] | `tui_ansi.inc` | ANSI escape byte constants and parametric formatters |
//! | [`geometry`] | `tui_geometry.inc` | [`Point`] / [`Rect`] and layout math |
//! | [`gridguts`] | `tui_gridguts.inc` | Internal grid layout helper for [`widgets::datagrid`] |
//! | [`lock`] | `tui_lock.inc` | Render-serialization locks (sync + async) |
//! | [`widgets`] | 27 `tui_*.inc` | Concrete widget implementations |
//!
//! # Core re-exports
//!
//! Common types are re-exported at the subsystem root for convenience:
//!
//! ```no_run
//! use heavything::tui::{Widget, Renderer, RawTerminal, Rect, Point, KeyEvent};
//! ```
//!
//! Concrete widget types are intentionally **not** re-exported at the
//! `tui` root — callers must use the explicit `widgets::*` path:
//!
//! ```no_run
//! use heavything::tui::widgets::{TuiPanel, TuiButton, TuiDataGrid};
//! ```
//!
//! This keeps the `tui` root API surface focused on the widget
//! framework (traits, geometry, rendering primitives, terminal
//! singleton) while the concrete widget catalog lives under `widgets`.
//!
//! # `gridguts` visibility
//!
//! The [`gridguts`] submodule is declared `pub` for symmetry with the
//! other sibling modules and to permit the `widgets::datagrid` module
//! to reference [`gridguts::ColumnSpec`] across module boundaries.
//! Its types are intentionally **not** re-exported at the `tui` root —
//! this matches the FASM `prolog_silent` convention of omitting these
//! internal helper symbols from the documented public surface.
//!
//! # Feature gating
//!
//! This entire subsystem is reachable from the crate root via
//! `crate::tui` (see `lib.rs`). Internal submodules do not further
//! feature-gate each other.

// ---------------------------------------------------------------------------
// Submodule declarations (alphabetical for grep-ability)
// ---------------------------------------------------------------------------

pub mod ansi;
pub mod geometry;
pub mod gridguts;
pub mod lock;
pub mod object;
pub mod render;
pub mod terminal;
pub mod widgets;

// ---------------------------------------------------------------------------
// Public re-exports (grouped by origin module)
//
// Each `pub use` lists the types individually rather than a glob import
// so that drift between this aggregator and the source submodule is
// immediately visible at compile time, and so that the public surface
// of `heavything::tui` cannot accidentally widen when a new symbol is
// added to a sibling module.
// ---------------------------------------------------------------------------

// -------------------- Geometry --------------------
pub use geometry::{align_offset, Point, Rect};

// -------------------- Widget core --------------------
pub use object::{
    Attributes, ClickEvent, ColorPair, HorizAlign, KeyEvent, Layout, VertAlign, Widget, WidgetState,
};

// -------------------- Rendering --------------------
pub use render::{BufferedRenderer, RenderAttr, RenderState, Renderer};

// -------------------- Terminal singleton --------------------
pub use terminal::{RawTerminal, WindowSize};

// -------------------- Render locks --------------------
pub use lock::{AsyncRenderLock, AsyncRenderLockGuard, LockToken, RenderLock, RenderLockGuard};

// ---------------------------------------------------------------------------
// Sanity-check tests
//
// The Rust compiler verifies every `pub use` path at compile time, so the
// re-export block above is itself a compile-time integrity check.  These
// behavioral tests anchor a couple of FASM-derived invariants (the
// 8-byte `Point` size matches `point_size = 8` from `tui_geometry.inc`)
// and ensure the most-commonly-consumed re-exports are reachable through
// the `heavything::tui::*` namespace, which is the path the binary
// crates use.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{align_offset, Point, Rect};

    /// FASM `point_size = 8` (two `dd` fields). The Rust `Point` struct
    /// must mirror this layout exactly so widget bounds-storage shares
    /// the assembly memory profile.
    #[test]
    fn point_is_eight_bytes() {
        assert_eq!(
            core::mem::size_of::<Point>(),
            8,
            "Point must match FASM point_size=8"
        );
    }

    /// `Rect` re-export is reachable from the aggregator and its
    /// width/height accessors compute correctly under the half-open
    /// convention.
    #[test]
    fn rect_reexport_is_accessible() {
        let r = Rect::new(0, 0, 10, 10);
        assert_eq!(r.width(), 10);
        assert_eq!(r.height(), 10);
    }

    /// `align_offset` re-export is reachable; mode `1` (Center) yields
    /// `(container - child) / 2` per the FASM `align_offset` semantics.
    #[test]
    fn align_offset_reexport_is_accessible() {
        // container=100, child=20, mode=Center -> (100-20)/2 = 40
        assert_eq!(align_offset(100, 20, 1), 40);
    }
}
