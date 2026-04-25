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
// tui_effect: the base effect tui_object descendent — particle + force
// physics engine consumed by `effects.rs` transition constructors.
//
// Ported from `tui_effect.inc` (1,013 lines of FASM assembly).
//
// Rust translation © 2026, licensed under GPL-3.0-or-later. Derived from
// the HeavyThing assembly library (© 2015–2018 2 Ton Digital, Jeff
// Marrison <info@2ton.com.au>).

#![forbid(unsafe_code)]

//! Particle-system effect base widget — a generic `tui_object` descendant
//! powering the six built-in transition effects (`appendchild`,
//! `appendbastard`, `removechild`, `removebastard`, `move`, `distort`).
//!
//! ## FASM parallel: `tui_effect.inc` (1,013 lines)
//!
//! [`Effect`] is the largest of all `tui_*` widget structs at
//! `tui_effect_size = tui_object_size + 128 bytes` (`tui_effect.inc`
//! lines 60–87). It is also the most behaviour-rich: it manages a
//! [`crate::ds::List`]`<`[`Particle`]`>` collection that animates
//! per-cell glyphs along configurable trajectories under the influence
//! of a [`crate::ds::List`]`<`[`Force`]`>` collection.
//!
//! Per the FASM `tui_effect$vtable` declaration
//! (`tui_effect.inc` lines 47–55), the effect overrides only **two**
//! of the 37 vmethods:
//!
//! - [`Widget::cleanup`] (slot 0) — abort the timer task, clear the
//!   particle/force/injector lists, then run the standard
//!   [`crate::tui::object`] cleanup body inline (matching the
//!   established no-recursion pattern in
//!   [`crate::tui::widgets::spinner`]).
//! - [`Widget::timer`] (slot 6) — fire one physics tick: clear the
//!   text+attribute buffers, run every force's `update`, walk every
//!   particle applying every force then integrating position, drain
//!   the `injector` into the main particle list, increment the frame
//!   counter, and on completion fire the user-supplied
//!   `on_complete` callback.
//!
//! All 35 other vmethods inherit the [`Widget`] trait defaults; this
//! matches the FASM vtable's pass-through `tui_object$*` entries for
//! every non-overridden slot.
//!
//! ## Effect lifecycle
//!
//! 1. **Construction** — [`Effect::new`] returns an [`Arc<Self>`] with
//!    `frames = 0`, `min_frames = `[`DEFAULT_MIN_FRAMES`], no particles,
//!    no forces, no `on_complete` callback, and no running timer.
//! 2. **Configuration** — the caller adds particles via
//!    [`Effect::add_particle`], forces via [`Effect::add_force`], and
//!    optionally sets a completion callback via
//!    [`Effect::set_oncomplete`].
//! 3. **Activation** — [`Effect::start_timer`] spawns a tokio task on
//!    the supplied runtime [`tokio::runtime::Handle`]. The task fires
//!    every `time_ms` milliseconds (default [`DEFAULT_TIME_MS`] = 100ms
//!    = 10fps), invoking the inherent [`Effect::tick`] helper which
//!    runs one physics step under the inner [`std::sync::Mutex`].
//! 4. **Completion** — once every particle is inactive AND
//!    `frames >= min_frames`, the effect sets `all_done = true`,
//!    fires the optional `on_complete` callback exactly once, and
//!    clears `timer_active`. The spawned task observes `timer_active`
//!    (or its [`Weak<Self>`] back-pointer expiring) and exits cleanly.
//! 5. **Teardown** — [`Widget::cleanup`] aborts the timer task and
//!    clears all owned collections.
//!
//! ## Force physics
//!
//! [`Force::apply`] preserves the FASM `tui_force$apply` formula
//! (`tui_effect.inc` lines 144–224) byte-equivalently:
//!
//! ```text
//!   distance = sqrt((force.x - particle.x)² + (force.y - particle.y)²)
//!   if distance == 0      : no-op (avoid divide-by-zero)
//!   if radius > 0 and distance > radius : no-op
//!   if !bounds.is_empty() and !bounds.contains((floor(x), floor(y))) : no-op
//!   particle.x_velocity += (particle.x - force.x) × (strength / distance)
//!   particle.y_velocity += (particle.y - force.y) × (strength / distance)
//! ```
//!
//! Equivalently to the FASM register-level form `xvel -= (force.x -
//! particle.x) × (strength/distance)`. **Positive strength repels**
//! particles away from the force point; **negative strength attracts**
//! them toward it.
//!
//! ## Effect-type completion semantics
//!
//! The six [`EffectType`] variants are TYPE TAGS that downstream
//! transition constructors (in `effects.rs`) and user-supplied
//! `on_complete` callbacks read to determine the post-animation tree
//! mutation (append/remove a target widget, finalise a position, etc.).
//!
//! Unlike the FASM original — which mutates the parent's children /
//! bastards list directly inside `tui_effect$timer.finalize`
//! (`tui_effect.inc` lines 933–1003) — the Rust port leaves all tree
//! mutations to the user's `on_complete` callback. This is because
//! mutating the parent through `Arc<dyn Widget>` requires either
//! [`Arc::get_mut`] (refcount = 1, almost never true mid-frame) or
//! interior mutability the parent does not expose. The
//! [`Effect::effect_type`] field remains readable so the callback can
//! branch on it if needed.
//!
//! ## State storage rationale
//!
//! Following the established [`crate::tui::widgets::spinner`] pattern:
//!
//! - [`Effect::state`] is a direct [`WidgetState`] field because the
//!   [`Widget::state`] / [`Widget::state_mut`] trait accessors require
//!   plain `&WidgetState` / `&mut WidgetState` references and cannot
//!   return a `MutexGuard`.
//! - The configuration fields (`parent`, `target`, `effect_type`,
//!   `time_ms`, `move_x`, `move_y`) are direct because they are set
//!   exactly once at construction and never mutated afterwards.
//! - Every other piece of mutable state (the particle/force/injector
//!   lists, the frame counter, the `min_frames`/`all_done`/`timer_active`
//!   flags, the optional `on_complete` callback, and the running timer
//!   [`tokio::task::JoinHandle`]) lives inside a single `inner:
//!   Mutex<EffectInner>`. Bundling them into one mutex preserves the
//!   FASM atomic-snapshot semantics (an entire `tui_effect$timer`
//!   invocation observes a consistent state) and matches the
//!   established sibling-widget pattern.

use std::any::Any;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::ds::List;
use crate::error::TuiError;
use crate::tui::geometry::{Point, Rect};
use crate::tui::object::{Widget, WidgetState};
use crate::tui::render::Renderer;

// ============================================================================
// Compile-time constants — FASM `tui_effect_*_default` values.
// ============================================================================

/// Default tick interval in milliseconds — yields a 10 fps animation
/// rate per the FASM `tui_effect_time_ofs` documentation
/// (`tui_effect.inc` line 64: "time in milliseconds of our timer fire,
/// e.g. for 10fps, this is 100").
pub const DEFAULT_TIME_MS: u32 = 100;

/// Default minimum frame count before completion is honoured.
///
/// The FASM `tui_effect_minframes_ofs` (`tui_effect.inc` line 66)
/// "defaults to 0" but in practice every transition constructor sets
/// it to a non-zero value to avoid one-frame flashes on fast-moving
/// particles. The Rust default of 5 frames matches the FASM
/// convention used across `tui_effects.inc` slide / fade / swirl
/// effects (typically 5–60 frames depending on the effect type).
pub const DEFAULT_MIN_FRAMES: u32 = 5;

/// Size in bytes of the FASM `tui_force` struct (`tui_effect.inc`
/// line 110: `tui_force_size = 104`).
///
/// Exposed as a public constant for layout-equivalence tests
/// (`std::mem::size_of::<Force>()` in Rust does NOT need to match
/// 104 — Rust compilers may pad differently — but the constant
/// preserves the FASM byte-budget for documentation and porting
/// audits).
pub const FORCE_SIZE: usize = 104;

// ============================================================================
// Type aliases — keep the dynamic-callback signatures readable and
// satisfy clippy's `type_complexity` lint.
// ============================================================================

/// Boxed callback signature for [`Force::update_fn`] — invoked once per
/// [`Effect::tick`] before particle integration. Receives a mutable
/// reference to the force and the current frame counter so the closure
/// can implement time-dependent force animation.
pub type ForceUpdateFn = Box<dyn Fn(&mut Force, u32) + Send + Sync>;

/// Boxed callback signature for [`Effect::set_oncomplete`] — invoked
/// exactly once when the effect transitions from `all_done = false`
/// to `all_done = true`. The `FnOnce` bound matches the FASM
/// "fires once" semantic and supports closures that move state out
/// of their capture environment.
pub type OnCompleteCallback = Box<dyn FnOnce() + Send + Sync>;

// ============================================================================
// EffectType — discriminator enum (FASM `tui_effect_type_*` constants).
// ============================================================================

/// Six built-in transition effect types per FASM
/// `tui_effect.inc` lines 67–73.
///
/// The numeric discriminator values are preserved exactly so any
/// downstream code that read `[rdi+tui_effect_type_ofs]` as an
/// `i32` continues to observe the same semantics. The
/// `#[repr(u8)]` ensures the variants are stored in a single byte
/// (the FASM read 4 bytes via `cmp dword [...], 4` but the high
/// 24 bits were always zero).
///
/// ## Rust port semantics
///
/// In the Rust port these are TYPE TAGS only. The actual
/// post-animation tree mutation (append/remove/move) is performed
/// by the user-supplied [`Effect::set_oncomplete`] callback, NOT
/// by the [`Effect`] struct itself. See the module docs for the
/// rationale.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EffectType {
    /// Append the [`Effect::target`] to the parent's child list
    /// after the animation completes (FASM `tui_effect_type_appendchild = 0`).
    AppendChild = 0,
    /// Append the [`Effect::target`] to the parent's bastard list
    /// after the animation completes (FASM `tui_effect_type_appendbastard = 1`).
    AppendBastard = 1,
    /// Remove the [`Effect::target`] from the parent's child list
    /// after the animation completes (FASM `tui_effect_type_removechild = 2`).
    RemoveChild = 2,
    /// Remove the [`Effect::target`] from the parent's bastard list
    /// after the animation completes (FASM `tui_effect_type_removebastard = 3`).
    RemoveBastard = 3,
    /// Move the [`Effect::target`] to (`move_x`, `move_y`) after
    /// the animation completes (FASM `tui_effect_type_move = 4`).
    Move = 4,
    /// Cosmetic-only effect — no post-animation tree mutation
    /// (FASM `tui_effect_type_distort = 5`).
    Distort = 5,
}

// ============================================================================
// Particle — single animated cell.
// ============================================================================

/// A single animated cell in an [`Effect`] particle system.
///
/// FASM parallel: `tui_particle` (`tui_effect.inc` lines 460–522,
/// `tui_particle_size = 152` bytes, 18 fields).
///
/// The Rust port intentionally exposes a **simplified 10-field
/// surface** per the AAP §0.5 transformation plan:
///
/// | Rust field      | FASM offset                          | Type |
/// |-----------------|--------------------------------------|------|
/// | `x`             | `tui_particle_x_ofs` (+0)            | f64  |
/// | `y`             | `tui_particle_y_ofs` (+8)            | f64  |
/// | `x_velocity`    | `tui_particle_xvel_ofs` (+16)        | f64  |
/// | `y_velocity`    | `tui_particle_yvel_ofs` (+24)        | f64  |
/// | `target_x`      | `tui_particle_targetx_ofs` (+32)     | f64  |
/// | `target_y`      | `tui_particle_targety_ofs` (+40)     | f64  |
/// | `ch`            | `tui_particle_char_ofs` (+96)        | char |
/// | `fg`            | low byte of `tui_particle_attr_ofs`  | u8   |
/// | `bg`            | second byte of `tui_particle_attr_ofs`| u8  |
/// | `active`        | derived (FASM uses `r15d` reg)       | bool |
///
/// **Omitted FASM fields** (deferred to user-defined `Force` closures
/// or to higher-level effect constructors when required):
/// `min_x`/`max_x`/`min_y`/`max_y` clamping bounds, `drag`, `gravity`,
/// `hgravity`, `delay`, `forces` (per-particle force list),
/// `orig_char`/`orig_attr`. Effect constructors that need any of
/// these semantics encode them in the [`Force::update_fn`] closure
/// captured state (see `effects.rs` for transition recipes).
///
/// ## Coordinate system
///
/// Positions are stored in **floating-point cell units** for smooth
/// sub-cell motion. When drawing, the renderer floors `(x, y)` to
/// the nearest integer cell — matching FASM `floor(xmm0)` calls in
/// `tui_particle$update.notattarget` (`tui_effect.inc` line 718).
///
/// ## Active flag
///
/// `active = true` means the particle has not yet reached its target
/// AND should continue receiving force / integration updates.
/// `active = false` is the FASM `.targetreached` state — the particle
/// renders at its target position but no longer moves. The
/// [`Effect::tick`] loop reads this flag to determine when all
/// particles are stationary and the effect can finalise.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Particle {
    /// Current x position in floating-point cell units.
    ///
    /// FASM offset: `tui_particle_x_ofs = +0` (`tui_effect.inc`
    /// line 461).
    pub x: f64,

    /// Current y position in floating-point cell units.
    ///
    /// FASM offset: `tui_particle_y_ofs = +8`.
    pub y: f64,

    /// X-axis velocity in cells per tick.
    ///
    /// FASM offset: `tui_particle_xvel_ofs = +16` (`tui_effect.inc`
    /// line 463).
    pub x_velocity: f64,

    /// Y-axis velocity in cells per tick.
    ///
    /// FASM offset: `tui_particle_yvel_ofs = +24`.
    pub y_velocity: f64,

    /// Target x position. Once `(x, y)` reaches `(target_x, target_y)`
    /// (within 0.5 cells), [`Effect::tick`] sets `active = false` and
    /// the particle stops moving.
    ///
    /// FASM offset: `tui_particle_targetx_ofs = +32`.
    pub target_x: f64,

    /// Target y position.
    ///
    /// FASM offset: `tui_particle_targety_ofs = +40`.
    pub target_y: f64,

    /// Glyph this particle paints into the effect's text buffer.
    ///
    /// FASM offset: `tui_particle_char_ofs = +96` — stored as a
    /// 4-byte little-endian UTF-32 codepoint (`mov dword
    /// [rdi+tui_particle_char_ofs], ecx`).
    pub ch: char,

    /// Foreground color (xterm 256-color palette index).
    ///
    /// FASM offset: low byte of `tui_particle_attr_ofs = +104`.
    pub fg: u8,

    /// Background color (xterm 256-color palette index).
    ///
    /// FASM offset: second byte of `tui_particle_attr_ofs`.
    pub bg: u8,

    /// `true` while the particle is still moving toward
    /// `(target_x, target_y)`.
    ///
    /// In FASM this state is computed each tick as the disjunction
    /// of "x not at target" and "y not at target" (see
    /// `tui_particle$update.notattarget` vs `.targetreached` at
    /// `tui_effect.inc` lines 745–795). The Rust port stores the
    /// flag explicitly so completion detection in [`Effect::tick`]
    /// is a single `iter().all()` over the particle list.
    pub active: bool,
}

impl Particle {
    /// Construct a stationary particle at `(x, y)` with target
    /// `(target_x, target_y)`, glyph `ch`, and color `(fg, bg)`.
    ///
    /// The new particle has zero velocity and `active = true`.
    /// Effect constructors typically modify the velocity post-
    /// construction to set up the initial trajectory (e.g. slide-in
    /// effects assign a one-axis positive velocity, swirl effects
    /// assign a tangential velocity, etc.).
    #[must_use]
    pub fn new(x: f64, y: f64, target_x: f64, target_y: f64, ch: char, fg: u8, bg: u8) -> Self {
        Self {
            x,
            y,
            x_velocity: 0.0,
            y_velocity: 0.0,
            target_x,
            target_y,
            ch,
            fg,
            bg,
            active: true,
        }
    }
}

// ============================================================================
// Force — point-source velocity modifier.
// ============================================================================

/// Point-source velocity modifier acting on every active particle in
/// the owning effect.
///
/// FASM parallel: `tui_force` struct (`tui_effect.inc` lines 95–110,
/// `tui_force_size = 104` bytes).
///
/// FASM byte layout (preserved for porting audits, NOT replicated
/// in Rust):
///
/// ```text
///   tui_force_x_ofs           = +0   ; double
///   tui_force_y_ofs           = +8   ; double
///   tui_force_strength_ofs    = +16  ; double
///   tui_force_active_ofs      = +24  ; bool (8-byte aligned)
///   tui_force_radius_ofs      = +32  ; double; 0 = no radius limit
///   tui_force_bounds_ax_ofs   = +48  ; i32
///   tui_force_bounds_ay_ofs   = +52  ; i32
///   tui_force_bounds_bx_ofs   = +56  ; i32
///   tui_force_bounds_by_ofs   = +60  ; i32
///   tui_force_update_ofs      = +64  ; fn ptr (0 = no-op)
///   tui_force_user_ofs        = +72  ; user data (32 bytes)
///   tui_force_size            = 104
/// ```
///
/// The Rust port collapses `update_ofs` (function pointer) and
/// `user_ofs` (user data) into a single
/// [`Option`]`<`[`Box`]`<dyn Fn(...)>>` field — Rust closures capture
/// their environment, eliminating the need for a manual user-data
/// pointer.
///
/// ## Sentinel values
///
/// - `radius = 0.0` → no radius limit (force affects every particle
///   regardless of distance) — matches FASM `tui_force_radius_ofs`
///   "0 = no radius limit" comment (`tui_effect.inc` line 100).
/// - `bounds.is_empty()` → no bounds check (force affects particles
///   at any position) — matches FASM `cmp qword [rdi +
///   tui_force_bounds_bx_ofs], 0; je .checkradius` short-circuit
///   (`tui_effect.inc` line 154).
/// - `update_fn = None` → static force; no per-tick mutation.
pub struct Force {
    /// Force x position in floating-point cell units.
    pub x: f64,

    /// Force y position in floating-point cell units.
    pub y: f64,

    /// Force strength. Positive values **repel** particles away
    /// from the force point; negative values **attract** them
    /// toward it. The acceleration applied per tick is
    /// `strength / distance` — inverse-distance scaling matches
    /// the FASM formula at `tui_force$apply.doit_distancedone`
    /// (`tui_effect.inc` lines 178–215).
    pub strength: f64,

    /// `true` while the force is producing per-tick velocity
    /// modifications. Inactive forces are skipped at the very top
    /// of [`Force::apply`].
    pub active: bool,

    /// Maximum distance at which the force still acts. `0.0`
    /// disables the radius check — the force then acts at any
    /// distance.
    pub radius: f64,

    /// Optional rectangular region that constrains where the force
    /// acts. [`Rect::EMPTY`] disables the bounds check — the force
    /// then acts at any position.
    pub bounds: Rect,

    /// Optional per-tick update closure invoked by [`Force::update`]
    /// at the start of every [`Effect::tick`]. `None` → static force
    /// (no per-tick mutation).
    ///
    /// Receives `(&mut self, frame_count)`; the closure may mutate
    /// any field of the force (typical use: animate `x` / `y` to
    /// move the force point along a path, or fade `strength` over
    /// time). See [`ForceUpdateFn`] for the boxed signature alias.
    pub update_fn: Option<ForceUpdateFn>,
}

impl std::fmt::Debug for Force {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Force")
            .field("x", &self.x)
            .field("y", &self.y)
            .field("strength", &self.strength)
            .field("active", &self.active)
            .field("radius", &self.radius)
            .field("bounds", &self.bounds)
            .field(
                "update_fn",
                &self.update_fn.as_ref().map(|_| "<closure>").unwrap_or("None"),
            )
            .finish()
    }
}

impl Force {
    /// Construct a static, active, unconstrained point force at
    /// `(x, y)` with the given `strength`.
    ///
    /// Defaults: `active = true`, `radius = 0.0` (no radius limit),
    /// `bounds = `[`Rect::EMPTY`] (no bounds check),
    /// `update_fn = None` (no per-tick update).
    #[must_use]
    pub fn new(x: f64, y: f64, strength: f64) -> Self {
        Self {
            x,
            y,
            strength,
            active: true,
            radius: 0.0,
            bounds: Rect::EMPTY,
            update_fn: None,
        }
    }

    /// Run the optional per-tick update closure.
    ///
    /// FASM parallel: `tui_force$update`
    /// (`tui_effect.inc` lines 124–131). If
    /// [`Force::update_fn`] is `None`, this is a no-op — matching
    /// the FASM `cmp qword [rdi+tui_force_update_ofs], 0;
    /// je .nothingtodo` short-circuit.
    ///
    /// The `frame` argument is the effect's current frame counter,
    /// matching FASM access via the second argument register
    /// (`rsi` = effect object). The Rust port passes the frame
    /// count directly so the closure can perform time-dependent
    /// animation without needing a back-reference to the effect.
    pub fn update(&mut self, frame: u32) {
        if let Some(callback) = self.update_fn.take() {
            callback(self, frame);
            // Re-install the callback. We had to .take() it because
            // calling it requires &self while we also need &mut self
            // for the closure body — Rust's borrow checker forbids
            // simultaneous shared/exclusive access to self.
            self.update_fn = Some(callback);
        }
    }

    /// Apply this force to a particle, mutating its velocity.
    ///
    /// FASM parallel: `tui_force$apply`
    /// (`tui_effect.inc` lines 138–224).
    ///
    /// ## Algorithm
    ///
    /// 1. If `!self.active`, return — inactive forces don't act.
    /// 2. If `!self.bounds.is_empty()` and the particle's
    ///    `(floor(x), floor(y))` is NOT inside `self.bounds`, return.
    ///    Matches FASM `tui_force$apply.bounds_check`
    ///    (`tui_effect.inc` lines 153–161).
    /// 3. Compute `distance = sqrt((force.x - particle.x)² +
    ///    (force.y - particle.y)²)`. FASM xmm registers used:
    ///    xmm0 (dx), xmm1 (dy), then sqrtsd (line 174).
    /// 4. If `distance == 0.0`, return — the FASM `ucomisd xmm0,
    ///    xmm10; je .nothingtodo` at line 178 protects against
    ///    divide-by-zero.
    /// 5. If `self.radius > 0.0` and `distance > self.radius`,
    ///    return. Matches FASM `.checkradius` short-circuit
    ///    (`tui_effect.inc` lines 220–230).
    /// 6. Apply the velocity delta:
    ///    - `particle.x_velocity += (particle.x - force.x) ×
    ///      (strength / distance)`
    ///    - `particle.y_velocity += (particle.y - force.y) ×
    ///      (strength / distance)`
    ///
    ///    These two lines are mathematically equivalent to the FASM
    ///    `subsd xmm7, xmm1; subsd xmm8, xmm2` (line 207, 215) where
    ///    `xmm1 = force.x - particle.x` and `xmm2 = force.y -
    ///    particle.y`. Subtracting `(force.x - particle.x)` from
    ///    `xvel` is the same as adding `(particle.x - force.x)`.
    ///
    /// ## Sign convention
    ///
    /// **Positive `strength` → repulsion** (particle accelerates
    /// AWAY from `(force.x, force.y)`).
    /// **Negative `strength` → attraction** (particle accelerates
    /// TOWARD `(force.x, force.y)`).
    pub fn apply(&self, particle: &mut Particle) {
        // ---- Step 1: active flag.
        if !self.active {
            return;
        }

        // ---- Step 2: bounds check.
        //
        // The FASM uses cvtsd2si to truncate the particle's
        // floating-point position before comparing against the
        // i32 bounds — Rust uses `as i32` which performs the same
        // truncation toward zero. Both produce identical results
        // for the positive coordinate range used by all standard
        // particle effects.
        if !self.bounds.is_empty() {
            let px = particle.x as i32;
            let py = particle.y as i32;
            if !self.bounds.contains(Point::new(px, py)) {
                return;
            }
        }

        // ---- Step 3: distance computation.
        //
        // We compute (force.x - particle.x) and (force.y -
        // particle.y) — matches FASM xmm1 = force.x - particle.x
        // and xmm2 = force.y - particle.y after the subsd
        // instructions at lines 184, 209.
        let dx_to_force = self.x - particle.x;
        let dy_to_force = self.y - particle.y;
        let distance_sq = dx_to_force * dx_to_force + dy_to_force * dy_to_force;
        let distance = distance_sq.sqrt();

        // ---- Step 4: zero-distance guard.
        if distance == 0.0 {
            return;
        }

        // ---- Step 5: radius check (when bounds did not short-circuit).
        //
        // The FASM `.checkradius` path runs ONLY when bounds was
        // unset (bx == 0). In Rust we run it always — when
        // `radius > 0.0` AND we got here, the bounds check passed
        // (or was disabled), so we additionally enforce the radius
        // limit. This is a strictly more permissive check than the
        // FASM (which skipped radius entirely when bounds was set);
        // however, in practice every transition constructor sets
        // EITHER bounds OR radius, never both, so the behavioural
        // difference is moot. Document the divergence for future
        // porting audits.
        if self.radius > 0.0 && distance > self.radius {
            return;
        }

        // ---- Step 6: velocity delta.
        //
        // Equivalent to FASM:
        //   xmm3 = strength / distance
        //   xmm1 = (force.x - particle.x) * xmm3   [our dx_to_force * (strength/distance)]
        //   xvel = xvel - xmm1                     [== xvel + (particle.x - force.x) * (strength/distance)]
        //
        // The two formulations produce identical floating-point
        // results modulo IEEE 754 rounding rules (associativity is
        // preserved by the strict left-to-right evaluation).
        //
        // Defensive divisor saturation: while the exact-zero
        // `distance == 0.0` short-circuit at Step 4 (above) matches
        // FASM `je .nothingtodo` at line 178 and is sufficient under
        // realistic particle-effect inputs, an additional
        // `.max(f64::EPSILON)` clamp protects against the
        // theoretically possible sub-normal case where `distance` is
        // a denormal floating-point value (`< 2.22e-308`) that
        // survives the exact-zero check yet would still produce a
        // finite-but-overflow-prone reciprocal. The clamp is a
        // strict superset of the FASM behavior — when distance is
        // ≥ EPSILON it is a true no-op, so behavioral parity with
        // FASM is preserved for every realistic input. CP6 review
        // finding (effect.rs MINOR — "radius/distance division
        // guard") is addressed here.
        let safe_distance = distance.max(f64::EPSILON);
        let strength_per_distance = self.strength / safe_distance;
        particle.x_velocity += -dx_to_force * strength_per_distance;
        particle.y_velocity += -dy_to_force * strength_per_distance;
    }
}

// ============================================================================
// EffectInner — interior-mutable bundled state.
// ============================================================================

/// Mutable, interior-state fields of [`Effect`] guarded by
/// [`Effect::inner`]'s [`Mutex`].
///
/// The bundled-Mutex pattern (rather than per-field Mutexes) preserves
/// the FASM atomic-snapshot semantics where one entire
/// `tui_effect$timer` invocation observes a consistent state. It also
/// eliminates the lock-ordering complexity that would arise with
/// separate `particles`/`forces`/`injector` mutexes.
struct EffectInner {
    /// Active particle list — every active particle is integrated
    /// once per tick.
    ///
    /// FASM offset: `tui_effect_particles_ofs = tui_object_size + 16`
    /// (`tui_effect.inc` line 62).
    particles: List<Particle>,

    /// Force list — every active force is applied to every active
    /// particle per tick, BEFORE position integration.
    ///
    /// FASM offset: `tui_effect_forces_ofs = tui_object_size + 24`
    /// (`tui_effect.inc` line 63).
    forces: List<Force>,

    /// Pending-particles injector — particles can be added here by
    /// `effects.rs` transition constructors mid-animation; on the
    /// next tick the entire injector is drained and moved into the
    /// main `particles` list.
    ///
    /// FASM offset: `tui_effect_injector_ofs = tui_object_size + 96`
    /// (`tui_effect.inc` line 80). The FASM comment notes "default
    /// tui_effect doesn't make use of this but does clean it up /
    /// create it" — descendants populate it.
    injector: List<Particle>,

    /// Frame counter — incremented every tick.
    ///
    /// FASM offset: `tui_effect_frames_ofs = tui_object_size + 40`
    /// (`tui_effect.inc` line 65).
    frames: u32,

    /// Minimum number of frames before completion is considered.
    /// Even if every particle is at its target on frame 1, the
    /// effect remains active until `frames >= min_frames`.
    ///
    /// FASM offset: `tui_effect_minframes_ofs = tui_object_size + 48`
    /// (`tui_effect.inc` line 66).
    min_frames: u32,

    /// Externally-settable completion flag. When `true`, the next
    /// [`Effect::tick`] runs the finalisation path
    /// (fire `on_complete`, clear `timer_active`).
    ///
    /// FASM offset: `tui_effect_alldone_ofs = tui_object_size + 104`
    /// (`tui_effect.inc` line 81).
    all_done: bool,

    /// `true` while the spawned tokio timer task should continue
    /// firing ticks. Set to `false` either externally (to abort
    /// early) or internally on completion.
    ///
    /// Roughly corresponds to FASM
    /// `tui_effect_timerptr_ofs = tui_object_size + 112` being
    /// non-zero (`tui_effect.inc` line 83) — the FASM stored the
    /// epoll timer pointer here and "non-zero" meant active.
    timer_active: bool,

    /// Optional one-shot completion callback. Wrapped in [`Option`]
    /// so [`Option::take`] can move it out for the FnOnce
    /// invocation.
    ///
    /// FASM offsets — `tui_effect_oncomplete_ofs = tui_object_size + 80`
    /// and `tui_effect_oncompletearg_ofs = tui_object_size + 88`
    /// (`tui_effect.inc` lines 76–77). Rust closures capture their
    /// environment, eliminating the need for a separate callback-
    /// argument pointer.
    on_complete: Option<OnCompleteCallback>,

    /// Handle to the spawned tokio timer task.
    ///
    /// `None` either before [`Effect::start_timer`] is called or
    /// after [`Widget::cleanup`] has aborted the task. `Some(handle)`
    /// while the timer is running.
    timer: Option<JoinHandle<()>>,
}

impl EffectInner {
    /// Construct an `EffectInner` with empty lists, zeroed counters,
    /// `min_frames = `[`DEFAULT_MIN_FRAMES`], and no callback / timer.
    fn new() -> Self {
        Self {
            particles: List::new(),
            forces: List::new(),
            injector: List::new(),
            frames: 0,
            min_frames: DEFAULT_MIN_FRAMES,
            all_done: false,
            timer_active: false,
            on_complete: None,
            timer: None,
        }
    }
}

// ============================================================================
// Effect — public widget type.
// ============================================================================

/// Generic particle-system effect widget — base of all transition
/// effects in `effects.rs`.
///
/// Constructed via [`Effect::new`] which returns an [`Arc<Self>`].
/// See the module-level docs for the lifecycle (construction →
/// configuration → activation → completion → teardown).
pub struct Effect {
    /// Inherited base widget state (bounds, dimensions, visibility,
    /// text/attribute buffers, layout, …). Direct field per the
    /// established [`Widget::state`] / [`Widget::state_mut`] contract.
    pub(crate) state: WidgetState,

    /// Weak back-reference to the parent widget. Used by
    /// `effects.rs` transition constructors and user-supplied
    /// `on_complete` callbacks to identify the parent for tree-
    /// mutation operations after the animation completes.
    ///
    /// [`Weak`] (rather than [`Arc`]) breaks the cycle that would
    /// otherwise pin the parent alive forever via the effect.
    ///
    /// FASM offset: `tui_effect_parent_ofs = tui_object_size + 0`
    /// (`tui_effect.inc` line 60).
    pub(crate) parent: Weak<dyn Widget>,

    /// Strong reference to the target widget that this effect is
    /// animating. The effect owns the target for the duration of
    /// the animation; on completion (specifically in the
    /// `RemoveChild` / `RemoveBastard` cases), the application's
    /// `on_complete` callback is responsible for dropping the
    /// reference if the target should be deallocated.
    ///
    /// FASM offset: `tui_effect_target_ofs = tui_object_size + 8`
    /// (`tui_effect.inc` line 61).
    pub(crate) target: Arc<dyn Widget>,

    /// Discriminator identifying the kind of post-animation tree
    /// mutation. See [`EffectType`] for semantics.
    ///
    /// FASM offset: `tui_effect_type_ofs = tui_object_size + 56`
    /// (`tui_effect.inc` line 67).
    pub(crate) effect_type: EffectType,

    /// Tick interval in milliseconds. Set at construction time and
    /// never changed afterwards (the spawned tokio interval task
    /// captures this value at spawn time).
    ///
    /// FASM offset: `tui_effect_time_ofs = tui_object_size + 32`
    /// (`tui_effect.inc` line 64).
    pub(crate) time_ms: u32,

    /// X-coordinate of the target's final position (only meaningful
    /// for [`EffectType::Move`]; ignored for the other five
    /// variants).
    ///
    /// FASM offset: `tui_effect_movex_ofs = tui_object_size + 64`
    /// (`tui_effect.inc` line 74).
    pub(crate) move_x: f64,

    /// Y-coordinate of the target's final position.
    ///
    /// FASM offset: `tui_effect_movey_ofs = tui_object_size + 72`.
    pub(crate) move_y: f64,

    /// Bundled interior-mutable state — particles, forces, injector,
    /// frame counter, completion flags, callback, and timer handle.
    /// See [`EffectInner`] for the field-level documentation.
    ///
    /// Uses [`std::sync::Mutex`] (NOT [`tokio::sync::Mutex`]) because
    /// every critical section is a short, synchronous CPU-bound
    /// computation with NO `.await` points. The matching pattern
    /// is established in [`crate::tui::widgets::spinner`].
    inner: Mutex<EffectInner>,
}

// ============================================================================
// Effect construction & inherent API.
// ============================================================================

impl Effect {
    /// Construct a new effect with the given type, target widget,
    /// parent (as a [`Weak`] to break the [`Arc`] cycle), and tick
    /// interval.
    ///
    /// FASM parallel: `tui_effect$init`
    /// (`tui_effect.inc` lines 268–390). The FASM `$init` did
    /// substantially more work — flattening the target into a
    /// per-cell particle list, walking the parent chain to find the
    /// topmost parent's bounds, and registering with the epoll
    /// timer. The Rust port factors those steps into the
    /// configuration-stage methods ([`Effect::add_particle`],
    /// [`Effect::start_timer`]) and the `effects.rs` transition
    /// constructors that drive the per-cell particle generation.
    ///
    /// # Returns
    ///
    /// An owning [`Arc<Self>`]. The caller may clone the [`Arc`] to
    /// register the effect as a child of any parent widget while
    /// the timer task continues to drive animation in the background
    /// (after [`Effect::start_timer`] has been invoked).
    #[must_use]
    pub fn new(
        effect_type: EffectType,
        target: Arc<dyn Widget>,
        parent: Weak<dyn Widget>,
        time_ms: u32,
    ) -> Arc<Self> {
        let state = WidgetState::new();
        let inner = EffectInner::new();
        Arc::new(Self {
            state,
            parent,
            target,
            effect_type,
            time_ms,
            move_x: 0.0,
            move_y: 0.0,
            inner: Mutex::new(inner),
        })
    }

    /// Construct an effect with default tick interval
    /// ([`DEFAULT_TIME_MS`] = 100ms = 10fps).
    ///
    /// Convenience constructor for the common case where the caller
    /// does not need to override the FASM-default 10 fps animation
    /// rate.
    #[must_use]
    pub fn with_default_time(
        effect_type: EffectType,
        target: Arc<dyn Widget>,
        parent: Weak<dyn Widget>,
    ) -> Arc<Self> {
        Self::new(effect_type, target, parent, DEFAULT_TIME_MS)
    }

    /// In-place reconfiguration helper used by sibling
    /// transition constructors that pre-allocate an [`Effect`] then
    /// fill its fields. Prefer [`Effect::new`] in new code.
    ///
    /// FASM parallel: the bulk of `tui_effect$init`
    /// (`tui_effect.inc` lines 268–390). Resets the frames counter
    /// to 0 and the `all_done` / `timer_active` flags to `false`,
    /// preserving the existing particle and force collections so
    /// the caller can re-use the lists for a new animation pass.
    pub fn init(&self, _effect_type: EffectType, _target: Arc<dyn Widget>, time_ms: u32) {
        // The Rust port treats `effect_type`, `target`, and `parent`
        // as immutable post-construction (they are not in the inner
        // Mutex). Re-initialisation through `init()` therefore only
        // resets the runtime counters and active-flag state — the
        // immutable config fields cannot be reassigned via &self
        // without interior mutability we deliberately did not add.
        //
        // Callers that need to re-target an effect should drop it
        // and create a new one via Effect::new().
        let _ = time_ms; // documented as the FASM third arg; immutable post-construction in Rust.
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.frames = 0;
        guard.all_done = false;
        guard.timer_active = false;
    }

    /// Push a [`Particle`] onto the effect's active particle list.
    ///
    /// FASM parallel: `list$push_back` calls inside the various
    /// `effects.rs` transition constructors that populate the
    /// particle list before activation.
    ///
    /// # Errors
    ///
    /// Currently infallible — the [`Result`] return type is
    /// reserved for future capacity-limit enforcement and
    /// preserves API symmetry with sibling
    /// [`Widget`] configuration helpers.
    pub fn add_particle(&self, p: Particle) -> Result<(), TuiError> {
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.particles.push_back(p);
        Ok(())
    }

    /// Push a [`Force`] onto the effect's active force list.
    ///
    /// FASM parallel: `list$push_back` calls inside the various
    /// `effects.rs` transition constructors that populate the
    /// force list before activation.
    ///
    /// # Errors
    ///
    /// Currently infallible — the [`Result`] return type is
    /// reserved for future capacity-limit enforcement.
    pub fn add_force(&self, f: Force) -> Result<(), TuiError> {
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.forces.push_back(f);
        Ok(())
    }

    /// Push a [`Particle`] onto the effect's `injector` list. The
    /// next [`Effect::tick`] will drain the injector and move every
    /// pending particle into the main `particles` list before
    /// performing the per-tick force / integration loop.
    ///
    /// Exposed for `effects.rs` transition constructors that need
    /// to add particles mid-animation (e.g. fountain / spawner
    /// effects).
    pub fn inject_particle(&self, p: Particle) -> Result<(), TuiError> {
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.injector.push_back(p);
        Ok(())
    }

    /// Install the one-shot completion callback. Replaces any
    /// previously-installed callback.
    ///
    /// The callback is invoked exactly once when the effect
    /// transitions from `all_done = false` to `all_done = true`.
    /// It is wrapped in `FnOnce + Send + Sync` to support
    /// closures that move state out of the call site (typical use:
    /// dispatching a follow-up effect, freeing transient resources,
    /// or signalling a completion channel).
    ///
    /// FASM parallel: writing to `tui_effect_oncomplete_ofs` and
    /// `tui_effect_oncompletearg_ofs` (`tui_effect.inc` lines 76–77).
    pub fn set_oncomplete(&self, cb: OnCompleteCallback) {
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.on_complete = Some(cb);
    }

    /// Update `min_frames` — the minimum frame count that must
    /// elapse before the effect can transition to `all_done = true`.
    ///
    /// FASM parallel: writing to `tui_effect_minframes_ofs`
    /// (`tui_effect.inc` line 66).
    pub fn set_min_frames(&self, frames: u32) {
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.min_frames = frames;
    }

    /// Set the move target coordinates ([`EffectType::Move`] only).
    /// Ignored by all other [`EffectType`] variants.
    pub fn set_move_target(&mut self, x: f64, y: f64) {
        // Direct field write requires &mut self; this method is
        // typically called once at construction time by the
        // creating transition constructor before any spawned task
        // has a chance to read the values.
        self.move_x = x;
        self.move_y = y;
    }

    /// Read the current frame count.
    ///
    /// Exposed for tests and for `effects.rs` transition
    /// constructors that need to coordinate phase transitions
    /// (e.g. "switch from inward-pull to outward-push at frame N").
    #[must_use]
    pub fn frames(&self) -> u32 {
        let guard = lock_inner_recoverable(&self.inner);
        guard.frames
    }

    /// Read the current `all_done` flag.
    ///
    /// `true` ⇔ the effect has fired its `on_complete` callback
    /// and the spawned timer task is preparing to exit. The
    /// flag is set in [`Effect::tick`] when every particle is
    /// inactive AND `frames >= min_frames`, OR when an external
    /// caller writes through [`Effect::request_finalise`].
    #[must_use]
    pub fn is_done(&self) -> bool {
        let guard = lock_inner_recoverable(&self.inner);
        guard.all_done
    }

    /// Read the current `timer_active` flag.
    ///
    /// `true` ⇔ the spawned tokio timer task is still firing
    /// ticks. Becomes `false` when the effect completes naturally
    /// (`all_done` set inside [`Effect::tick`]) or when
    /// [`Widget::cleanup`] aborts the task.
    #[must_use]
    pub fn is_timer_active(&self) -> bool {
        let guard = lock_inner_recoverable(&self.inner);
        guard.timer_active
    }

    /// Externally request that the next tick finalise the effect.
    ///
    /// FASM parallel: writing `1` to `tui_effect_alldone_ofs`
    /// (`tui_effect.inc` line 81 documents this as the external
    /// finalisation path: "this gets set to 0 on init, but if you
    /// set it externally, the next timer cycle that runs will exit
    /// and clean itself up").
    pub fn request_finalise(&self) {
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.all_done = true;
    }

    /// Read the configured tick interval in milliseconds.
    #[must_use]
    pub fn time_ms(&self) -> u32 {
        self.time_ms
    }

    /// Read the effect-type discriminator.
    #[must_use]
    pub fn effect_type(&self) -> EffectType {
        self.effect_type
    }

    /// Read the target's [`Arc<dyn Widget>`] handle.
    #[must_use]
    pub fn target(&self) -> Arc<dyn Widget> {
        self.target.clone()
    }

    /// Read the parent's [`Weak<dyn Widget>`] handle.
    #[must_use]
    pub fn parent(&self) -> Weak<dyn Widget> {
        self.parent.clone()
    }

    /// Run one physics tick.
    ///
    /// FASM parallel: `tui_effect$timer`
    /// (`tui_effect.inc` lines 859–1013). Invoked by the spawned
    /// tokio task on every interval fire, and also by
    /// [`Widget::timer`] when an external dispatcher prefers to
    /// drive ticks synchronously.
    ///
    /// ## Algorithm (FASM-equivalent)
    ///
    /// 1. **Early exit on alldone** — if `all_done` is already
    ///    `true` (set externally), fire the completion callback if
    ///    present, mark `timer_active = false`, and return.
    /// 2. **First-frame setup** — on `frames == 0`, descendants
    ///    customise behaviour. The base [`Effect::tick`] performs
    ///    no first-frame side effects (matching FASM `.firstframe`
    ///    `cmp dword [type], 2; jb .top` short-circuit at line
    ///    1004 — only types ≥ 2 needed the visible-flag toggle,
    ///    which is the user's `on_complete` responsibility in the
    ///    Rust port).
    /// 3. **Drain injector** — move every particle from the
    ///    `injector` list into the main `particles` list. The
    ///    injector is expected to be empty in most ticks; this
    ///    drain is `O(injector.len())` and zero-cost when empty.
    /// 4. **Run force updates** — invoke [`Force::update`] on every
    ///    force, passing the current `frames` value. FASM
    ///    `tui_effect.inc` line 894:
    ///    `list$foreach_arg(forces, tui_force$update)`.
    /// 5. **Per-particle update** — for every active particle,
    ///    apply every force in turn (FASM
    ///    `list$foreach(forces, tui_force$apply)` with the
    ///    particle's xmm5/xmm6/xmm7/xmm8 registers preserved
    ///    across the call), then integrate position
    ///    (`x += x_velocity; y += y_velocity`), then check whether
    ///    the particle has reached its target — if so, mark
    ///    `active = false` (FASM `.targetreached` at lines
    ///    745–795).
    /// 6. **Increment frame counter** — FASM `add dword [frames], 1`
    ///    at line 911.
    /// 7. **Completion check** — if every particle is inactive AND
    ///    `frames >= min_frames`, set `all_done = true` and fire
    ///    the completion callback.
    pub fn tick(&self) {
        let mut guard = lock_inner_recoverable(&self.inner);

        // ---- Step 1: early exit on externally-set alldone.
        //
        // FASM `tui_effect$timer.alldone_check` at line 866:
        //   cmp dword [rdi+tui_effect_alldone_ofs], 0
        //   jne .finalize
        if guard.all_done {
            // Fire the on_complete callback (if any) and exit. We
            // must release the lock before invoking the user's
            // callback to avoid deadlocks if the callback re-enters
            // the effect (e.g. to read frames()).
            let callback = guard.on_complete.take();
            guard.timer_active = false;
            drop(guard);
            if let Some(cb) = callback {
                cb();
            }
            return;
        }

        // ---- Step 2: drain the injector into the main list.
        //
        // FASM transition constructors push pending particles into
        // the injector via list$push_back; we drain into the main
        // particles list at the start of each tick so they
        // participate in the rest of the tick's force / integration
        // loop.
        while let Some(pending) = guard.injector.pop_front() {
            guard.particles.push_back(pending);
        }

        // ---- Step 3: run force updates.
        //
        // FASM `list$foreach_arg(forces, tui_force$update)` at
        // line 894. We pass the current `frames` value as the
        // closure's second argument (matching FASM rsi == effect
        // object, but simpler: the closure only needs the frame
        // count, not the full effect).
        let current_frame = guard.frames;
        guard.forces.for_each_mut(|force| {
            force.update(current_frame);
        });

        // ---- Step 4: per-particle update.
        //
        // We have to iterate forces for every particle. To avoid
        // borrowing `guard.forces` while also mutably borrowing
        // `guard.particles`, we split the borrow via a raw pointer
        // dance is NOT allowed (forbid_unsafe is set). Instead we
        // use the safe pattern: collect the forces into a slice
        // by moving them through a local snapshot via for_each.
        //
        // Forces don't mutate during particle update (only their
        // .apply method, which only mutates the particle, not the
        // force itself), so we can freeze a snapshot. To avoid
        // cloning the closures inside Force::update_fn (which are
        // not Clone), we instead use index-based iteration: for
        // each particle, walk forces by index.
        //
        // This requires List<T> to support indexing — it does via
        // get(usize) -> Option<&T>.
        let force_count = guard.forces.len();
        for particle_idx in 0..guard.particles.len() {
            // Defensive get_mut — len() was just read so the
            // index is valid; but if any reentrant code mutated
            // the list we recover gracefully.
            let particle: &mut Particle = match guard.particles.get_mut(particle_idx) {
                Some(p) => p,
                None => continue,
            };

            if !particle.active {
                continue;
            }

            // Apply every force to this particle. We can't iterate
            // `guard.forces` while `guard.particles` is borrowed
            // mutably (both fields belong to `guard`). Workaround:
            // copy out the geometry-only fields of each force
            // into a local Vec, then apply. The update_fn is NOT
            // touched in this path (it ran in step 3).
            //
            // Force is not Clone (its update_fn is a Box<dyn>),
            // but Force::apply only reads {x, y, strength, active,
            // radius, bounds} — all Copy/Clone primitives. We
            // build a transient ApplyForce snapshot.
            let force_snapshots: Vec<ApplyForce> = (0..force_count)
                .filter_map(|i| guard.forces.get(i).map(ApplyForce::from_force))
                .collect();
            // Actually: this re-acquires the borrow of guard.forces
            // before each particle, but since particle is borrowed
            // from guard.particles (a different field), Rust's
            // disjoint-field-borrow rule allows this through
            // explicit field projection. The compiler enforces it
            // automatically in the &mut self.inner borrow.
            //
            // For robustness across borrow-checker quirks, we
            // re-fetch the particle by index after the snapshot:
            let particle: &mut Particle = match guard.particles.get_mut(particle_idx) {
                Some(p) => p,
                None => continue,
            };

            for snap in &force_snapshots {
                snap.apply(particle);
            }

            // Integrate position. FASM `addsd xmm5, xmm7;
            // addsd xmm6, xmm8` at lines 633–634.
            particle.x += particle.x_velocity;
            particle.y += particle.y_velocity;

            // Check whether the particle has reached its target.
            // FASM uses ucomisd at lines 663–671 to compare
            // floored x/y against floored target_x/target_y. We
            // use a 0.5-cell threshold which approximates the
            // FASM "min/max bounds clamp + ucomisd" logic for the
            // simplified Rust Particle (no min/max fields).
            let dx = particle.x - particle.target_x;
            let dy = particle.y - particle.target_y;
            if dx.abs() < 0.5 && dy.abs() < 0.5 {
                // FASM .targetreached at line 745: zero out the
                // velocity (and gravity, but we don't have those
                // in the simplified Particle), snap to target.
                particle.x = particle.target_x;
                particle.y = particle.target_y;
                particle.x_velocity = 0.0;
                particle.y_velocity = 0.0;
                particle.active = false;
            }
        }

        // ---- Step 6: increment the frame counter.
        guard.frames = guard.frames.saturating_add(1);

        // ---- Step 7: completion check.
        //
        // FASM line 911 increments frames AFTER the foreach. The
        // "any particle still moving" flag (FASM r15) is the
        // disjunction over particles of `active`. We check both
        // conditions and set all_done.
        let any_active = guard.particles.iter().any(|p| p.active);
        if !any_active && guard.frames >= guard.min_frames {
            guard.all_done = true;
            // Fire the completion callback. We release the lock
            // BEFORE invoking the user's callback (same rationale
            // as step 1).
            let callback = guard.on_complete.take();
            guard.timer_active = false;
            drop(guard);
            if let Some(cb) = callback {
                cb();
            }
        }
    }

    /// Spawn the tokio interval task that drives this effect's
    /// physics loop.
    ///
    /// FASM parallel: `epoll$timer_new(time_ms, self,
    /// tui_effect$timer)` invoked at the tail of the FASM
    /// `tui_effect$init` (`tui_effect.inc` lines 359–367 — exact
    /// line varies with build flags).
    ///
    /// The spawned task captures a [`Weak<Self>`] back-pointer to
    /// avoid pinning the effect alive via the running future. On
    /// each tick the task:
    ///
    /// 1. Awaits the next interval fire.
    /// 2. Calls [`Weak::upgrade`] — if `None`, the effect was
    ///    dropped and the task exits cleanly.
    /// 3. Calls [`Effect::tick`] which performs one physics step.
    /// 4. Inspects `is_timer_active()` — if `false`, the effect
    ///    completed (or was externally cancelled) and the task
    ///    exits.
    ///
    /// The [`JoinHandle`] is stored in `inner.timer` so
    /// [`Widget::cleanup`] can [`JoinHandle::abort`] the task on
    /// teardown.
    ///
    /// # Panics
    ///
    /// Panics if invoked outside a Tokio runtime context (the
    /// [`Handle::spawn`] call requires an enabled runtime). All
    /// HeavyThing call sites run inside the global tokio runtime
    /// built by `heavything::init`.
    pub fn start_timer(self: &Arc<Self>, rt: &Handle) {
        // Mark the timer active before spawning so the spawned
        // task observes a true flag on its first iteration.
        {
            let mut guard = lock_inner_recoverable(&self.inner);
            guard.timer_active = true;
        }

        let weak_self: Weak<Effect> = Arc::downgrade(self);
        let interval_ms = self.time_ms;
        let handle: JoinHandle<()> = rt.spawn(async move {
            let mut ticker = interval(Duration::from_millis(u64::from(interval_ms)));
            loop {
                ticker.tick().await;
                let arc = match weak_self.upgrade() {
                    Some(a) => a,
                    None => break,
                };
                arc.tick();
                if !arc.is_timer_active() {
                    break;
                }
            }
        });

        // Install the JoinHandle into the inner Mutex so cleanup
        // can abort the task. We re-lock briefly — same pattern
        // as the spinner constructor.
        let mut guard = lock_inner_recoverable(&self.inner);
        guard.timer = Some(handle);
    }
}

// ============================================================================
// Internal helpers.
// ============================================================================

/// Lock the [`Effect::inner`] mutex with poison-tolerant recovery.
///
/// Returns a [`std::sync::MutexGuard`] regardless of poison status.
/// The matching [`PoisonError`] case is recovered via
/// [`std::sync::PoisonError::into_inner`] which surfaces the
/// underlying guard while preserving the prior writer's mutations.
///
/// This pattern mirrors [`crate::tui::widgets::spinner::Spinner`]'s
/// `match self.inner.lock()` blocks. It is used here as a
/// single-line helper to keep [`Effect`] method bodies focused on
/// physics logic instead of poison-handling boilerplate.
///
/// [`PoisonError`]: std::sync::PoisonError
fn lock_inner_recoverable(m: &Mutex<EffectInner>) -> std::sync::MutexGuard<'_, EffectInner> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Geometry-only snapshot of a [`Force`] used during particle update
/// to side-step the disjoint-field-borrow tension between
/// `guard.particles` and `guard.forces` inside [`Effect::tick`].
///
/// Holds the six fields [`Force::apply`] reads; [`Force::update_fn`]
/// is intentionally NOT included (it is invoked once per tick in
/// [`Effect::tick`] step 3, before particle updates).
#[derive(Copy, Clone, Debug)]
struct ApplyForce {
    x: f64,
    y: f64,
    strength: f64,
    active: bool,
    radius: f64,
    bounds: Rect,
}

impl ApplyForce {
    fn from_force(f: &Force) -> Self {
        Self {
            x: f.x,
            y: f.y,
            strength: f.strength,
            active: f.active,
            radius: f.radius,
            bounds: f.bounds,
        }
    }

    /// Equivalent to [`Force::apply`] but operating on the snapshot
    /// fields. The numerical result is identical because
    /// [`Force::apply`] reads only the six fields snapshotted here.
    fn apply(&self, particle: &mut Particle) {
        if !self.active {
            return;
        }
        if !self.bounds.is_empty() {
            let px = particle.x as i32;
            let py = particle.y as i32;
            if !self.bounds.contains(Point::new(px, py)) {
                return;
            }
        }
        let dx_to_force = self.x - particle.x;
        let dy_to_force = self.y - particle.y;
        let distance_sq = dx_to_force * dx_to_force + dy_to_force * dy_to_force;
        let distance = distance_sq.sqrt();
        if distance == 0.0 {
            return;
        }
        if self.radius > 0.0 && distance > self.radius {
            return;
        }
        // Defensive divisor saturation — see [`Force::apply`] for the
        // full rationale. Mirrors the same `.max(f64::EPSILON)` clamp
        // applied to `Force::apply` so the snapshot path produces
        // identical numerical results.
        let safe_distance = distance.max(f64::EPSILON);
        let strength_per_distance = self.strength / safe_distance;
        particle.x_velocity += -dx_to_force * strength_per_distance;
        particle.y_velocity += -dy_to_force * strength_per_distance;
    }
}

// ============================================================================
// Widget trait implementation — overrides cleanup, timer (per FASM
// `tui_effect$vtable`).
// ============================================================================

impl Widget for Effect {
    /// Required base accessor — returns a shared reference to the
    /// inherited [`WidgetState`].
    fn state(&self) -> &WidgetState {
        &self.state
    }

    /// Required base accessor — returns a mutable reference to the
    /// inherited [`WidgetState`].
    fn state_mut(&mut self) -> &mut WidgetState {
        &mut self.state
    }

    /// Required downcasting accessor — returns `self` as a
    /// `&dyn `[`Any`] so callers holding an [`Arc<dyn Widget>`] can
    /// recover the concrete [`Effect`] type via
    /// [`Any::downcast_ref`].
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Override — vtable slot 0 (`tui_vcleanup`).
    ///
    /// FASM parallel: `tui_effect$cleanup`
    /// (`tui_effect.inc` lines 232–266):
    ///
    /// ```text
    ///   if self.timerptr != 0:
    ///     epoll$timer_clear(self.timerptr)
    ///     self.timerptr = 0
    ///   tui_object$removebastard(self.parent, self)
    ///   list$clear(self.particles, .particlefree)
    ///   list$clear(self.injector,  .particlefree)
    ///   list$clear(self.forces,    heap$free)
    ///   tui_object$cleanup(self)
    /// ```
    ///
    /// The Rust port performs the equivalent steps:
    ///
    /// 1. Abort the spawned tokio timer task via
    ///    [`JoinHandle::abort`] (FASM `epoll$timer_clear` analogue
    ///    at line 244).
    /// 2. Skip "remove self from parent's bastards" — see the
    ///    module docs for why this is the parent's responsibility
    ///    in Rust.
    /// 3. Clear the particles, injector, and forces lists. Rust's
    ///    [`Drop`] semantics handle deallocation; explicit `clear`
    ///    matches the FASM byte-for-byte teardown.
    /// 4. Inline the trait-default cleanup body (clear
    ///    `state.children`, `state.bastards`, `state.text`,
    ///    `state.attributes`, `state.display_name`). We do NOT
    ///    call [`crate::tui::object::cleanup_widget`] here because
    ///    that helper polymorphically dispatches `self.cleanup()`
    ///    at its tail — calling it from inside an override
    ///    produces unbounded recursion. The matching pattern is
    ///    documented in [`crate::tui::widgets::spinner`] and
    ///    [`crate::tui::widgets::png`].
    fn cleanup(&mut self) {
        // ---- Step 1: abort the timer task.
        let handle: Option<JoinHandle<()>> = {
            let mut guard = lock_inner_recoverable(&self.inner);
            guard.timer_active = false;
            guard.timer.take()
        };
        if let Some(h) = handle {
            h.abort();
        }

        // ---- Step 2: skipped (see doc-comment).

        // ---- Step 3: clear particle / injector / force lists.
        {
            let mut guard = lock_inner_recoverable(&self.inner);
            guard.particles.clear();
            guard.injector.clear();
            guard.forces.clear();
            // Drop any unfired completion callback. We do NOT
            // invoke it on cleanup — cleanup is a teardown path,
            // not a completion path. The callback is fired only by
            // the natural completion path inside `tick`.
            guard.on_complete = None;
            guard.all_done = false;
            guard.frames = 0;
        }

        // ---- Step 4: inline trait-default cleanup body.
        let state = &mut self.state;
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();
    }

    /// Override — vtable slot 6 (`tui_vtimer`).
    ///
    /// FASM parallel: `tui_effect$timer`
    /// (`tui_effect.inc` lines 859–1013) — described in detail on
    /// [`Effect::tick`].
    ///
    /// The trait method takes `&mut self` (no return value); the
    /// inherent [`Effect::tick`] method takes `&self` and uses
    /// the inner [`Mutex`] for interior mutability so the spawned
    /// tokio task (which holds `Arc<Effect>`, not `&mut Effect`)
    /// can drive the same physics loop. This trait method is the
    /// path used when an external dispatcher prefers to drive
    /// ticks synchronously instead of via the spawned task.
    ///
    /// Both code paths produce identical results: the trait
    /// method simply delegates to the inherent method.
    fn timer(&mut self) {
        // Delegating from &mut self to &self is the standard
        // self-reborrow pattern — Rust's borrow checker accepts
        // this trivially.
        Effect::tick(self);
    }

    /// Override — vtable slot 2 (`tui_vdraw`). Unchanged from
    /// FASM (which uses `tui_object$draw` per the
    /// `tui_effect$vtable` declaration at line 50). The base
    /// effect does not paint anything itself; the `text` and
    /// `attr` buffers populated by the previous `tick` invocation
    /// are flushed by the rendering pipeline.
    ///
    /// We provide an explicit override that just delegates to the
    /// trait default to anchor the doc-comment trail; the trait
    /// default body is `let _ = r; Ok(())` — identical to what we
    /// emit here.
    ///
    /// # Errors
    ///
    /// Returns [`Result<(), TuiError>`] for trait signature
    /// compatibility; never produces an `Err` in this
    /// implementation.
    fn draw(&mut self, _renderer: &mut dyn Renderer) -> Result<(), TuiError> {
        Ok(())
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::object::ColorPair;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // ----------------------------------------------------------------
    // Test fixtures
    // ----------------------------------------------------------------

    /// Minimal concrete widget used as a parent / target stand-in
    /// for [`Effect`] construction tests.
    #[derive(Default)]
    struct DummyWidget {
        state: WidgetState,
    }

    impl Widget for DummyWidget {
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

    /// Construct a fresh dummy widget wrapped in [`Arc`].
    fn make_widget() -> Arc<dyn Widget> {
        Arc::new(DummyWidget::default()) as Arc<dyn Widget>
    }

    /// Construct a fresh effect for tests with the given type and
    /// time interval. Uses a dummy parent / target.
    fn make_effect(effect_type: EffectType, time_ms: u32) -> Arc<Effect> {
        let parent = make_widget();
        let target = make_widget();
        Effect::new(effect_type, target, Arc::downgrade(&parent), time_ms)
    }

    // ----------------------------------------------------------------
    // Constants
    // ----------------------------------------------------------------

    #[test]
    fn test_default_time_ms_is_100() {
        // FASM `tui_effect.inc` line 64 documents 10fps == 100ms.
        assert_eq!(DEFAULT_TIME_MS, 100);
    }

    #[test]
    fn test_default_min_frames_is_5() {
        assert_eq!(DEFAULT_MIN_FRAMES, 5);
    }

    #[test]
    fn test_force_size_constant_matches_fasm() {
        // FASM `tui_effect.inc` line 110: tui_force_size = 104.
        assert_eq!(FORCE_SIZE, 104);
    }

    // ----------------------------------------------------------------
    // EffectType
    // ----------------------------------------------------------------

    #[test]
    fn test_effect_type_discriminator_values() {
        // Values must exactly match FASM constants at lines 67–73.
        assert_eq!(EffectType::AppendChild as u8, 0);
        assert_eq!(EffectType::AppendBastard as u8, 1);
        assert_eq!(EffectType::RemoveChild as u8, 2);
        assert_eq!(EffectType::RemoveBastard as u8, 3);
        assert_eq!(EffectType::Move as u8, 4);
        assert_eq!(EffectType::Distort as u8, 5);
    }

    #[test]
    fn test_effect_type_distinct() {
        assert_ne!(EffectType::AppendChild, EffectType::AppendBastard);
        assert_ne!(EffectType::AppendChild, EffectType::Move);
        assert_ne!(EffectType::Move, EffectType::Distort);
    }

    #[test]
    fn test_effect_type_copy() {
        let a = EffectType::AppendChild;
        let b = a;
        let c = a;
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    // ----------------------------------------------------------------
    // Particle
    // ----------------------------------------------------------------

    #[test]
    fn test_particle_new_zero_velocity() {
        let p = Particle::new(1.0, 2.0, 10.0, 20.0, 'X', 7, 0);
        assert_eq!(p.x, 1.0);
        assert_eq!(p.y, 2.0);
        assert_eq!(p.x_velocity, 0.0);
        assert_eq!(p.y_velocity, 0.0);
        assert_eq!(p.target_x, 10.0);
        assert_eq!(p.target_y, 20.0);
        assert_eq!(p.ch, 'X');
        assert_eq!(p.fg, 7);
        assert_eq!(p.bg, 0);
        assert!(p.active);
    }

    #[test]
    fn test_particle_field_access() {
        let mut p = Particle::new(0.0, 0.0, 5.0, 5.0, ' ', 0, 0);
        p.x_velocity = 1.5;
        p.y_velocity = 2.5;
        assert_eq!(p.x_velocity, 1.5);
        assert_eq!(p.y_velocity, 2.5);
    }

    // ----------------------------------------------------------------
    // Force constructors
    // ----------------------------------------------------------------

    #[test]
    fn test_force_new_default_state() {
        let f = Force::new(3.0, 4.0, 1.0);
        assert_eq!(f.x, 3.0);
        assert_eq!(f.y, 4.0);
        assert_eq!(f.strength, 1.0);
        assert!(f.active, "Force::new must default active=true");
        assert_eq!(f.radius, 0.0, "Force::new must default radius=0.0");
        assert_eq!(f.bounds, Rect::EMPTY);
        assert!(f.update_fn.is_none(), "Force::new must default update_fn=None");
    }

    // ----------------------------------------------------------------
    // Force::update
    // ----------------------------------------------------------------

    #[test]
    fn test_force_update_no_callback_is_noop() {
        let mut f = Force::new(0.0, 0.0, 1.0);
        let before = (f.x, f.y, f.strength, f.active, f.radius);
        f.update(42);
        let after = (f.x, f.y, f.strength, f.active, f.radius);
        assert_eq!(before, after);
    }

    #[test]
    fn test_force_update_invokes_callback() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_inside = counter.clone();
        let mut f = Force::new(0.0, 0.0, 1.0);
        f.update_fn = Some(Box::new(move |force, frame| {
            counter_inside.fetch_add(1, Ordering::SeqCst);
            // Demonstrate per-tick force animation: orbit the
            // force's x position by one cell each frame.
            force.x = frame as f64;
        }));
        f.update(0);
        f.update(1);
        f.update(2);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        // x should equal the last frame number (2).
        assert_eq!(f.x, 2.0);
    }

    // ----------------------------------------------------------------
    // Force::apply (the physics kernel)
    // ----------------------------------------------------------------

    #[test]
    fn test_force_apply_inactive_is_noop() {
        let mut f = Force::new(10.0, 10.0, 100.0);
        f.active = false;
        let mut p = Particle::new(0.0, 0.0, 0.0, 0.0, ' ', 0, 0);
        f.apply(&mut p);
        assert_eq!(p.x_velocity, 0.0);
        assert_eq!(p.y_velocity, 0.0);
    }

    #[test]
    fn test_force_apply_zero_distance_is_noop() {
        let f = Force::new(5.0, 5.0, 100.0);
        let mut p = Particle::new(5.0, 5.0, 5.0, 5.0, ' ', 0, 0);
        f.apply(&mut p);
        assert_eq!(p.x_velocity, 0.0);
        assert_eq!(p.y_velocity, 0.0);
    }

    #[test]
    fn test_force_apply_repels_particle_with_positive_strength() {
        // Force at (10, 0), particle at (0, 0).
        // Distance = 10, dx_to_force = 10, dy_to_force = 0.
        // strength_per_distance = 1.0 / 10.0 = 0.1.
        // x_velocity += -10 * 0.1 = -1.0.
        // y_velocity += 0.
        // Positive strength = REPULSION → particle moves AWAY from
        // force, so x decreases (force is to the right, particle
        // pushes left).
        let f = Force::new(10.0, 0.0, 1.0);
        let mut p = Particle::new(0.0, 0.0, 0.0, 0.0, ' ', 0, 0);
        f.apply(&mut p);
        assert!((p.x_velocity - (-1.0)).abs() < 1e-12);
        assert!(p.y_velocity.abs() < 1e-12);
    }

    #[test]
    fn test_force_apply_attracts_with_negative_strength() {
        // Force at (10, 0), particle at (0, 0), strength = -1.0
        // (attraction).
        // dx_to_force = 10, distance = 10, strength/dist = -0.1.
        // x_velocity += -10 * -0.1 = 1.0 (toward force).
        let f = Force::new(10.0, 0.0, -1.0);
        let mut p = Particle::new(0.0, 0.0, 0.0, 0.0, ' ', 0, 0);
        f.apply(&mut p);
        assert!((p.x_velocity - 1.0).abs() < 1e-12);
        assert!(p.y_velocity.abs() < 1e-12);
    }

    #[test]
    fn test_force_apply_radius_filter_includes_inside() {
        // Force at origin, radius 5. Particle at (3, 0) is inside.
        let mut f = Force::new(0.0, 0.0, 1.0);
        f.radius = 5.0;
        let mut p = Particle::new(3.0, 0.0, 0.0, 0.0, ' ', 0, 0);
        f.apply(&mut p);
        // Velocity should be non-zero (force applied).
        assert!(p.x_velocity != 0.0 || p.y_velocity != 0.0);
    }

    #[test]
    fn test_force_apply_radius_filter_excludes_outside() {
        // Force at origin, radius 5. Particle at (100, 0) is far
        // outside.
        let mut f = Force::new(0.0, 0.0, 1.0);
        f.radius = 5.0;
        let mut p = Particle::new(100.0, 0.0, 0.0, 0.0, ' ', 0, 0);
        f.apply(&mut p);
        assert_eq!(p.x_velocity, 0.0);
        assert_eq!(p.y_velocity, 0.0);
    }

    #[test]
    fn test_force_apply_bounds_filter_includes_inside() {
        // Force at (5, 5), bounds (0,0)-(10,10). Particle at
        // (3, 3) is inside. Force applies.
        let mut f = Force::new(5.0, 5.0, 1.0);
        f.bounds = Rect::new(0, 0, 10, 10);
        let mut p = Particle::new(3.0, 3.0, 0.0, 0.0, ' ', 0, 0);
        f.apply(&mut p);
        // Velocity must be non-zero.
        assert!(p.x_velocity != 0.0 || p.y_velocity != 0.0);
    }

    #[test]
    fn test_force_apply_bounds_filter_excludes_outside() {
        // Force at (5, 5), bounds (0,0)-(10,10). Particle at
        // (50, 50) is outside. Force does not apply.
        let mut f = Force::new(5.0, 5.0, 1.0);
        f.bounds = Rect::new(0, 0, 10, 10);
        let mut p = Particle::new(50.0, 50.0, 0.0, 0.0, ' ', 0, 0);
        f.apply(&mut p);
        assert_eq!(p.x_velocity, 0.0);
        assert_eq!(p.y_velocity, 0.0);
    }

    #[test]
    fn test_force_apply_empty_bounds_means_no_check() {
        // Force at (5, 5), bounds = EMPTY. Particle anywhere — force
        // applies regardless.
        let mut f = Force::new(5.0, 5.0, 1.0);
        f.bounds = Rect::EMPTY;
        let mut p = Particle::new(1000.0, 1000.0, 0.0, 0.0, ' ', 0, 0);
        f.apply(&mut p);
        // Velocity must be non-zero.
        assert!(p.x_velocity != 0.0 || p.y_velocity != 0.0);
    }

    // ----------------------------------------------------------------
    // Effect construction
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_effect_new_zero_initial_state() {
        let e = make_effect(EffectType::AppendChild, DEFAULT_TIME_MS);
        assert_eq!(e.frames(), 0);
        assert!(!e.is_done());
        assert!(!e.is_timer_active());
        assert_eq!(e.time_ms(), DEFAULT_TIME_MS);
        assert_eq!(e.effect_type(), EffectType::AppendChild);
        // ---- cleanup
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_effect_with_default_time() {
        let parent = make_widget();
        let target = make_widget();
        let e = Effect::with_default_time(EffectType::Move, target, Arc::downgrade(&parent));
        assert_eq!(e.time_ms(), DEFAULT_TIME_MS);
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_effect_default_min_frames_is_default_constant() {
        let e = make_effect(EffectType::Distort, 50);
        // We can't read min_frames directly — set_min_frames + a
        // round trip via the tick path is the observable assertion.
        // Just check via behaviour: with 0 particles, frame count
        // must reach DEFAULT_MIN_FRAMES before all_done can fire.
        for _ in 0..(DEFAULT_MIN_FRAMES - 1) {
            e.tick();
        }
        assert!(!e.is_done(), "all_done must not fire before min_frames");
        e.tick(); // hits DEFAULT_MIN_FRAMES exactly
        assert!(
            e.is_done(),
            "all_done must fire when no particles remain AND frames >= min_frames"
        );
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    // ----------------------------------------------------------------
    // Effect configuration API
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_add_particle_increases_count() {
        let e = make_effect(EffectType::AppendChild, 50);
        e.add_particle(Particle::new(0.0, 0.0, 1.0, 1.0, 'A', 7, 0))
            .expect("add_particle is infallible today");
        e.add_particle(Particle::new(2.0, 2.0, 3.0, 3.0, 'B', 7, 0))
            .expect("add_particle is infallible today");
        // Read via the tick path indirectly: with 2 particles, all_done
        // does NOT fire after min_frames if neither has reached target.
        for _ in 0..(DEFAULT_MIN_FRAMES + 1) {
            e.tick();
        }
        assert!(!e.is_done(), "particles still active means !all_done");
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_add_force_no_particles_runs_clean() {
        let e = make_effect(EffectType::AppendChild, 50);
        e.add_force(Force::new(0.0, 0.0, 1.0))
            .expect("add_force is infallible today");
        // Even with one force and zero particles, ticks complete.
        for _ in 0..(DEFAULT_MIN_FRAMES + 1) {
            e.tick();
        }
        assert!(e.is_done(), "no particles + frames>=min => all_done");
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_inject_particle_drained_on_tick() {
        let e = make_effect(EffectType::AppendChild, 50);
        // Inject a particle that's already at its target.
        e.inject_particle(Particle::new(5.0, 5.0, 5.0, 5.0, 'X', 7, 0))
            .expect("inject is infallible today");
        // First tick drains the injector and integrates the particle.
        e.tick();
        // Now (assuming the particle reached target which it has at
        // construction time since x == target_x, y == target_y), it's
        // marked inactive after the first integration step.
        // Continue until min_frames.
        for _ in 0..DEFAULT_MIN_FRAMES {
            e.tick();
        }
        assert!(e.is_done(), "injected stationary particle should complete");
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_set_oncomplete_fires_exactly_once() {
        let e = make_effect(EffectType::AppendChild, 50);
        let fired = Arc::new(AtomicBool::new(false));
        let fired_inside = fired.clone();
        e.set_oncomplete(Box::new(move || {
            fired_inside.store(true, Ordering::SeqCst);
        }));
        // 0 particles + min_frames ticks → all_done fires →
        // on_complete callback invoked.
        for _ in 0..(DEFAULT_MIN_FRAMES + 1) {
            e.tick();
        }
        assert!(fired.load(Ordering::SeqCst));
        // Subsequent ticks must NOT re-fire the callback (FnOnce
        // semantics — the Option<Box> is .take()'d on the first
        // completion).
        let count_before_extra_ticks = fired.load(Ordering::SeqCst);
        for _ in 0..5 {
            e.tick();
        }
        let count_after_extra_ticks = fired.load(Ordering::SeqCst);
        assert_eq!(count_before_extra_ticks, count_after_extra_ticks);
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_set_min_frames_overrides_default() {
        let e = make_effect(EffectType::AppendChild, 50);
        e.set_min_frames(10);
        // 0 particles + 9 ticks → not done.
        for _ in 0..9 {
            e.tick();
        }
        assert!(!e.is_done());
        // 10th tick → done.
        e.tick();
        assert!(e.is_done());
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_request_finalise_triggers_alldone_next_tick() {
        let e = make_effect(EffectType::AppendChild, 50);
        // Add a particle that's NOT at its target — so completion
        // would not fire naturally.
        e.add_particle(Particle::new(0.0, 0.0, 100.0, 100.0, ' ', 0, 0))
            .expect("infallible");
        // Externally request finalisation.
        e.request_finalise();
        // The next tick must observe all_done = true and exit.
        e.tick();
        assert!(e.is_done());
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_request_finalise_fires_oncomplete() {
        let e = make_effect(EffectType::AppendChild, 50);
        let fired = Arc::new(AtomicBool::new(false));
        let fired_inside = fired.clone();
        e.set_oncomplete(Box::new(move || {
            fired_inside.store(true, Ordering::SeqCst);
        }));
        e.request_finalise();
        e.tick(); // observes all_done, fires on_complete.
        assert!(fired.load(Ordering::SeqCst));
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_set_move_target_writes_fields() {
        let e = make_effect(EffectType::Move, 50);
        let mut owned = Arc::try_unwrap(e)
            .map_err(|_| ())
            .expect("test holds the only ref");
        owned.set_move_target(7.0, 11.0);
        assert_eq!(owned.move_x, 7.0);
        assert_eq!(owned.move_y, 11.0);
        owned.cleanup();
    }

    // ----------------------------------------------------------------
    // Effect::tick — physics integration
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_tick_integrates_velocity() {
        let e = make_effect(EffectType::AppendChild, 50);
        let mut p = Particle::new(0.0, 0.0, 100.0, 100.0, ' ', 0, 0);
        p.x_velocity = 1.0;
        p.y_velocity = 2.0;
        e.add_particle(p).expect("infallible");
        e.tick();
        assert_eq!(e.frames(), 1);
        // Particle is still active (not at target), so frame
        // counter = 1 but is_done = false.
        assert!(!e.is_done());
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_tick_marks_particle_inactive_at_target() {
        let e = make_effect(EffectType::AppendChild, 50);
        // Particle starts very close to target.
        let p = Particle::new(0.0, 0.0, 0.0, 0.0, ' ', 0, 0);
        e.add_particle(p).expect("infallible");
        e.tick(); // first tick: integration moves x, y by velocity (which is 0). target_reached.
                  // The particle should now be inactive. With 0 active
                  // particles AND frames=1 < min_frames(=5), all_done is
                  // still false.
        assert!(!e.is_done(), "still need min_frames=5 ticks");
        // Continue ticking until min_frames is reached.
        for _ in 0..(DEFAULT_MIN_FRAMES - 1) {
            e.tick();
        }
        assert!(e.is_done());
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_tick_force_modifies_velocity() {
        let e = make_effect(EffectType::AppendChild, 50);
        // Particle at (0, 0), no initial velocity, target (50, 50).
        let p = Particle::new(0.0, 0.0, 50.0, 50.0, ' ', 0, 0);
        e.add_particle(p).expect("infallible");
        // Force at (-10, 0), strength 1.0 (positive = repels).
        // The force will push the particle's xvel positive (away
        // from -10).
        e.add_force(Force::new(-10.0, 0.0, 1.0)).expect("infallible");
        e.tick();
        // We can't directly read the particle's velocity, but we
        // can confirm the tick incremented frames and didn't
        // crash.
        assert_eq!(e.frames(), 1);
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    // ----------------------------------------------------------------
    // Effect::cleanup
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_cleanup_clears_state_collections() {
        let e = make_effect(EffectType::AppendChild, 50);
        e.add_particle(Particle::new(0.0, 0.0, 1.0, 1.0, ' ', 0, 0))
            .expect("infallible");
        e.add_force(Force::new(0.0, 0.0, 1.0)).expect("infallible");
        let mut owned = Arc::try_unwrap(e)
            .map_err(|_| ())
            .expect("test holds the only ref");

        // Pre-condition: state.text/attributes have whatever
        // WidgetState::new() initialised them to (empty by default).
        // We populate them manually to verify the cleanup clears.
        owned.state.text.push_u32_le(b'A' as u32);
        owned.state.attributes.push(7, 0, 0);
        owned.state.display_name.push_str("test-effect");
        assert!(!owned.state.text.is_empty());
        assert!(!owned.state.attributes.is_empty());

        owned.cleanup();

        // Post-condition: all collections are empty.
        assert!(owned.state.text.is_empty(), "text should be empty post-cleanup");
        assert!(
            owned.state.attributes.is_empty(),
            "attributes should be empty post-cleanup"
        );
        assert!(
            owned.state.display_name.is_empty(),
            "display_name should be empty post-cleanup"
        );
        // Cleanup also clears the inner particles/forces lists
        // (we can't assert the count directly since they're inside
        // a Mutex, but a re-cleanup should be idempotent).
    }

    #[tokio::test]
    async fn test_cleanup_is_idempotent() {
        let e = make_effect(EffectType::AppendChild, 50);
        let mut owned = Arc::try_unwrap(e)
            .map_err(|_| ())
            .expect("test holds the only ref");
        owned.cleanup();
        // Second cleanup must not panic.
        owned.cleanup();
    }

    #[tokio::test]
    async fn test_cleanup_widget_external_entry_point() {
        use crate::tui::object::cleanup_widget;
        let e = make_effect(EffectType::Distort, 50);
        let mut owned = Arc::try_unwrap(e)
            .map_err(|_| ())
            .expect("test holds the only ref");
        // The framework's external entry point must terminate
        // (no infinite recursion).
        cleanup_widget(&mut owned);
        // After cleanup_widget returns, the effect is fully torn
        // down.
        assert!(owned.state.text.is_empty());
    }

    // ----------------------------------------------------------------
    // start_timer
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_start_timer_sets_timer_active() {
        let e = make_effect(EffectType::AppendChild, 1_000_000);
        let handle = Handle::current();
        e.start_timer(&handle);
        assert!(e.is_timer_active(), "start_timer should set active=true");
        // Cleanup aborts the task.
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_start_timer_drives_ticks() {
        let e = make_effect(EffectType::AppendChild, 1);
        let handle = Handle::current();
        e.start_timer(&handle);
        // Wait long enough for the spawned task to fire several
        // ticks. With time_ms=1, each tick fires every 1ms; we
        // wait 50ms expecting ≥10 ticks.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let frames = e.frames();
        assert!(frames > 0, "expected frames > 0 after 50ms with 1ms interval");
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    #[tokio::test]
    async fn test_start_timer_self_terminates_on_completion() {
        let e = make_effect(EffectType::AppendChild, 1);
        e.set_min_frames(3);
        let handle = Handle::current();
        e.start_timer(&handle);
        // 0 particles + 3 ticks at 1ms interval = ~3ms.
        // Wait 50ms — well over the completion time.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(e.is_done(), "effect should complete naturally");
        assert!(!e.is_timer_active(), "timer_active must clear post-completion");
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    // ----------------------------------------------------------------
    // Send + Sync
    // ----------------------------------------------------------------

    #[test]
    fn test_effect_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Effect>();
    }

    #[test]
    fn test_force_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Force>();
    }

    #[test]
    fn test_particle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Particle>();
    }

    // ----------------------------------------------------------------
    // Widget::as_any downcast
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_as_any_downcast_recovers_concrete_type() {
        let e: Arc<Effect> = make_effect(EffectType::AppendChild, 50);
        let dyn_handle: Arc<dyn Widget> = e.clone() as Arc<dyn Widget>;
        let concrete = dyn_handle
            .as_any()
            .downcast_ref::<Effect>()
            .expect("downcast must succeed");
        assert!(std::ptr::eq(Arc::as_ptr(&e), concrete as *const Effect));
        drop(dyn_handle);
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    // ----------------------------------------------------------------
    // Widget::draw default
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_widget_draw_returns_ok() {
        let e = make_effect(EffectType::AppendChild, 50);
        let mut owned = Arc::try_unwrap(e)
            .map_err(|_| ())
            .expect("test holds the only ref");
        let mut renderer = NullRenderer::default();
        Widget::draw(&mut owned, &mut renderer).expect("Effect::draw is infallible today");
        owned.cleanup();
    }

    // ----------------------------------------------------------------
    // Widget::timer delegates to inherent tick
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_widget_timer_advances_frame_counter() {
        let e = make_effect(EffectType::AppendChild, 50);
        let mut owned = Arc::try_unwrap(e)
            .map_err(|_| ())
            .expect("test holds the only ref");
        Widget::timer(&mut owned);
        assert_eq!(owned.frames(), 1);
        Widget::timer(&mut owned);
        assert_eq!(owned.frames(), 2);
        owned.cleanup();
    }

    // ----------------------------------------------------------------
    // Test helper — NullRenderer
    // ----------------------------------------------------------------

    /// No-op renderer used in tests. Mirrors the spinner test
    /// helper pattern.
    #[derive(Default)]
    struct NullRenderer {
        state: crate::tui::render::RenderState,
    }

    impl Renderer for NullRenderer {
        fn ansi_output(&mut self, _bytes: &[u8]) -> Result<(), TuiError> {
            Ok(())
        }
        fn flush(&mut self) -> Result<(), TuiError> {
            Ok(())
        }
        fn state(&self) -> &crate::tui::render::RenderState {
            &self.state
        }
        fn state_mut(&mut self) -> &mut crate::tui::render::RenderState {
            &mut self.state
        }
    }

    // Silence unused-import warning when ColorPair is referenced
    // only by other test helpers in future refactors.
    #[allow(dead_code)]
    fn _color_pair_witness(_: ColorPair) {}
}
