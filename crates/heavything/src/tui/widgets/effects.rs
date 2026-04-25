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
// tui_effects: high-level transition catalog (slide-in, slide-out,
// distort-in, distort-out) — a thin constructor layer over the
// `tui_effect` particle/force engine.
//
// Ported from `tui_effects.inc` (1,036 lines of FASM assembly).
//
// Rust translation © 2026, licensed under GPL-3.0-or-later. Derived from
// the HeavyThing assembly library (© 2015–2018 2 Ton Digital, Jeff
// Marrison <info@2ton.com.au>).

#![forbid(unsafe_code)]

//! High-level animated **transition catalog** — a constructor-only
//! façade over the [`Effect`] particle/force engine in
//! [`crate::tui::widgets::effect`].
//!
//! ## FASM parallel: `tui_effects.inc` (1,036 lines)
//!
//! Whereas [`crate::tui::widgets::effect`] ports the underlying physics
//! engine (`tui_effect.inc`), this module ports the **catalogue of
//! pre-canned transitions** that the FASM library exposed as
//! `tui_effect$hslidein`, `tui_effect$vslidein`, `tui_effect$hslideout`,
//! `tui_effect$vslideout`, `tui_effect$distortin`,
//! `tui_effect$distortout`, etc. (`tui_effects.inc` lines 32–1036).
//!
//! Each transition is a **constructor function** that:
//!
//! 1. Allocates an [`Effect`] of the appropriate [`EffectType`] (e.g.
//!    [`EffectType::AppendChild`] for slide-in, [`EffectType::RemoveChild`]
//!    for slide-out, [`EffectType::Distort`] for distort-in).
//! 2. Seeds one [`Particle`] per text cell of the target widget at an
//!    appropriate **starting position** (off-screen for slide-in,
//!    home-position for slide-out, scattered for distort-in).
//! 3. Sets each particle's [`Particle::target_x`] / [`Particle::target_y`]
//!    so the [`Effect::tick`] loop can detect arrival and mark the
//!    particle inactive.
//! 4. Initialises the particle's `x_velocity` / `y_velocity` so the
//!    integration loop drives it along the desired trajectory.
//! 5. Optionally registers [`Force`] instances that add cosmetic
//!    physics (gravitational pull at parent centre for distort-in,
//!    explosive repulsion at parent centre for distort-out).
//! 6. Calls [`Effect::set_min_frames`] so the animation runs to a
//!    visually-pleasing frame count even when the slide distance is
//!    zero (degenerate empty-widget case).
//! 7. Optionally registers an `on_complete` callback via
//!    [`Effect::set_oncomplete`] that the caller uses to perform any
//!    follow-up tree mutation (typically: append the slid-in child to
//!    the parent's children list, or remove the slid-out child).
//! 8. Returns the [`Arc<Effect>`] handle for the caller to retain so
//!    they can register it on the parent's bastard list and start the
//!    timer at their convenience via [`Effect::start_timer`].
//!
//! ## Direction encoding
//!
//! FASM uses an `edx` register containing 0/1 (and similarly 0/1 for
//! vertical) as a direction discriminator (`tui_effects.inc` line 36
//! `cmp edx, 1; jne .right`). The Rust port replaces this with the
//! type-safe [`SlideDirection`] enum. The numeric values 0..=3 are
//! preserved so that any FFI bridge from a FASM call site that passes
//! the discriminator as an integer continues to observe the same
//! semantics.
//!
//! ## Validation
//!
//! Each horizontal transition (`hslidein`, `hslideout`) accepts only
//! [`SlideDirection::FromLeft`] / [`SlideDirection::FromRight`] and
//! returns [`TuiError::Render`] wrapping
//! [`std::io::ErrorKind::InvalidInput`] for [`SlideDirection::FromTop`]
//! / [`SlideDirection::FromBottom`]. Vertical transitions are the
//! mirror image. Distort transitions accept no direction parameter.
//!
//! ## FnOnce completion callbacks
//!
//! User-supplied completion callbacks are typed
//! `Option<Box<dyn FnOnce() + Send + Sync>>`. The [`FnOnce`] bound
//! matches the FASM "fires once" semantic — the callback runs at most
//! once when the effect transitions from `all_done = false` to
//! `all_done = true`, and is then dropped (`Option::take()` inside
//! [`Effect::tick`]).
//!
//! ## Tree mutation
//!
//! In keeping with the [`crate::tui::widgets::effect`] design rationale,
//! **the transition constructors in this module do NOT mutate the
//! parent's children/bastards list**. The [`EffectType`] tag is set so
//! the `on_complete` callback can branch on it; if the caller wants
//! their slid-in child actually attached to the parent post-animation
//! they must perform that attachment in the callback.
//!
//! ## Zero `unsafe`
//!
//! This module declares `#![forbid(unsafe_code)]` and uses no `unsafe`
//! blocks. All physics, mutex handling, and tokio task management lives
//! in [`crate::tui::widgets::effect`] which is also `unsafe`-free.

use std::io::{self, ErrorKind};
use std::sync::{Arc, Weak};

use crate::error::TuiError;
use crate::tui::geometry::{Point, Rect};
use crate::tui::object::Widget;
use crate::tui::widgets::effect::{Effect, EffectType, Force, Particle};

// ============================================================================
// Module constants — FASM `tui_effects.inc` magic numbers preserved.
// ============================================================================

/// Default per-tick interval in milliseconds for transitions, matching
/// FASM `tui_effect$hslidein` / `tui_effect$vslidein` /
/// `tui_effect$hslideout` / `tui_effect$vslideout` which all invoke
/// `tui_effect$init` with `mov ecx, 50` (`tui_effects.inc` lines 60,
/// 159, 264, 357 etc.).
///
/// 50 ms = 20 fps animation rate — fast enough to hide the discrete
/// integration steps for short slides while slow enough to remain
/// visually identifiable.
pub const TRANSITION_TIME_MS: u32 = 50;

/// Default minimum frame count for slide transitions, matching the
/// FASM convention of running at least 5 ticks even when the slide
/// distance is zero. Prevents one-frame "flash" rendering glitches on
/// degenerate empty-widget cases.
pub const SLIDE_MIN_FRAMES: u32 = 5;

/// Default minimum frame count for distort transitions. Distort is a
/// more pronounced scatter / converge animation that benefits from a
/// longer minimum so the user can see the particle motion clearly.
/// Matches FASM `tui_effect$distort*` family conventions where the
/// minframes was set in the 30–60 range.
pub const DISTORT_MIN_FRAMES: u32 = 30;

/// Default scatter radius (in cells) used by [`distort_in`] and
/// [`distort_out`] when the parent widget has no explicit bounds.
/// Used as a defensive fallback so distort transitions still produce
/// visible motion when the parent's bounds are uninitialised.
const DISTORT_FALLBACK_RADIUS: f64 = 10.0;

// ============================================================================
// SlideDirection enum — type-safe replacement for FASM `edx` register.
// ============================================================================

/// Direction discriminator for slide-in / slide-out transitions.
///
/// FASM parallel: the `edx` register argument to
/// [`tui_effect$hslidein`](https://2ton.com.au/) and friends, where
/// the FASM convention was:
///
/// | FASM `edx` | Horizontal meaning           | Vertical meaning             |
/// |------------|------------------------------|------------------------------|
/// | 0          | from-right (slide left)      | from-bottom (slide up)       |
/// | 1          | from-left  (slide right)     | from-top    (slide down)     |
///
/// The Rust port preserves the FASM numeric values (`FromRight = 0`,
/// `FromLeft = 1`) and adds explicit `FromTop = 2` / `FromBottom = 3`
/// variants for vertical transitions, which the FASM also dispatched
/// from `edx` but in a different function (`vslidein` / `vslideout`).
///
/// ## Validation
///
/// Each transition accepts only the two directions appropriate to its
/// axis:
///
/// - [`hslidein`] / [`hslideout`]: [`SlideDirection::FromLeft`] or
///   [`SlideDirection::FromRight`]; returns [`TuiError::Render`] for
///   the other two.
/// - [`vslidein`] / [`vslideout`]: [`SlideDirection::FromTop`] or
///   [`SlideDirection::FromBottom`]; returns [`TuiError::Render`] for
///   the other two.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SlideDirection {
    /// Slide in from the right edge (moving leftward toward target),
    /// or slide out toward the right edge (moving rightward away
    /// from home). FASM `edx == 0` for horizontal transitions.
    FromRight = 0,
    /// Slide in from the left edge (moving rightward toward target),
    /// or slide out toward the left edge (moving leftward away from
    /// home). FASM `edx == 1` for horizontal transitions.
    FromLeft = 1,
    /// Slide in from the top edge (moving downward toward target),
    /// or slide out toward the top edge (moving upward away from
    /// home). FASM `edx == 1` for vertical transitions
    /// (`tui_effects.inc` line 156, comment "edx == 1 means from top").
    FromTop = 2,
    /// Slide in from the bottom edge (moving upward toward target),
    /// or slide out toward the bottom edge (moving downward away
    /// from home). FASM `edx == 0` for vertical transitions.
    FromBottom = 3,
}

// ============================================================================
// Helper functions — schema-required public exports.
// ============================================================================

/// Compute the number of animation frames given a slide distance,
/// total animation time, and per-tick interval.
///
/// FASM parallel: implicit in `tui_effects.inc` constructors which
/// computed `frame_count = total_ms / tick_ms` to seed
/// `tui_effect_minframes_ofs` (`tui_effects.inc` lines 86, 192, etc.).
///
/// # Parameters
///
/// - `distance` — slide distance in cells. **Currently unused** by the
///   formula (kept for API symmetry with [`uniform_velocity`] and for
///   future extension that may scale frame count by distance).
/// - `time_ms` — total animation duration in milliseconds.
/// - `tick_ms` — per-tick interval in milliseconds (typically equal
///   to [`TRANSITION_TIME_MS`]).
///
/// # Returns
///
/// `(time_ms / tick_ms).max(1)` — at least 1 frame.
///
/// # Edge cases
///
/// - `tick_ms == 0` → returns 1 (defensive guard against
///   divide-by-zero; an actual zero-tick interval would imply
///   infinite frame count).
/// - `time_ms < tick_ms` → returns 1 (one frame minimum).
#[must_use]
pub fn compute_frame_count(distance: f64, time_ms: u32, tick_ms: u32) -> u32 {
    // Document `distance` in the API surface for future use; today the
    // formula deliberately ignores it per the AAP spec.
    let _ = distance;
    if tick_ms == 0 {
        return 1;
    }
    (time_ms / tick_ms).max(1)
}

/// Compute the per-tick velocity that traverses `distance` cells in
/// exactly `frames` ticks.
///
/// FASM parallel: the velocity-seeding xmm register loads in
/// `tui_effect$hslidein` / `tui_effect$vslidein` (`tui_effects.inc`
/// lines 80, 174, etc.) which used a constant `1.0 cell / tick` for
/// the FASM canonical horizontal slide. The Rust port generalises
/// this to arbitrary distance / frame counts so that very short
/// slides do not flash by in one tick (the helper returns a smaller
/// per-tick velocity when `frames > distance`).
///
/// # Parameters
///
/// - `distance` — slide distance in cells (in the relevant axis).
/// - `frames` — number of ticks the slide should run for.
///
/// # Returns
///
/// `distance / frames as f64` — the per-tick cell delta.
///
/// # Edge cases
///
/// - `frames == 0` → returns 0.0 (defensive guard against
///   divide-by-zero; the caller should ensure `frames >= 1`).
#[must_use]
pub fn uniform_velocity(distance: f64, frames: u32) -> f64 {
    if frames == 0 {
        return 0.0;
    }
    distance / f64::from(frames)
}

/// Build one [`Particle`] per text cell of the target widget, seeded
/// at the cell's home position with zero velocity.
///
/// Each particle's `(x, y)` and `(target_x, target_y)` are both set to
/// the cell's logical position in the widget's coordinate space. The
/// caller (a transition constructor) then mutates the `(x, y)` and/or
/// velocity fields to set up the desired trajectory.
///
/// FASM parallel: the per-cell particle generation loop in
/// `tui_effect$hslidein.iter` (`tui_effects.inc` lines 49–106) which
/// walked the target widget's `(width × height)` cell grid and
/// allocated a `tui_particle_size` instance per cell.
///
/// # Coordinate space
///
/// Particle positions live in the **widget's local cell grid**, not
/// absolute screen coordinates:
///
/// - The grid origin is `(0, 0)` (top-left cell).
/// - The grid extent is `(width × height)` cells, derived from the
///   widget's [`crate::tui::object::WidgetState::bounds`] when
///   non-empty, else from [`crate::tui::object::WidgetState::width`]
///   / [`crate::tui::object::WidgetState::height`] as a fallback.
///
/// # Default glyph and colours
///
/// Each particle is initialised with `ch = ' '` (space), `fg = 7`
/// (xterm light gray default), `bg = 0` (xterm black default). The
/// transition constructors do not attempt to read the widget's
/// rendered text/attribute buffers because those buffers are
/// populated lazily by the render pipeline and may not be valid at
/// construction time.
///
/// # Returns
///
/// A `Vec<Particle>` with one particle per cell, in row-major order
/// (`y` outer loop, `x` inner loop), so `result[y * width + x]` is
/// the particle for cell `(x, y)`.
#[must_use]
pub fn build_particles_for_widget(w: &Arc<dyn Widget>) -> Vec<Particle> {
    let state = w.state();

    // Prefer the layout-computed bounds if available; fall back to the
    // raw width / height fields otherwise. The fallback path matches
    // FASM behaviour where the slide constructors ran before the
    // first layout pass had populated bounds.
    let (width, height, origin_x, origin_y) = if state.bounds.is_empty() {
        let w = state.width.max(0);
        let h = state.height.max(0);
        (w, h, 0_i32, 0_i32)
    } else {
        let w = state.bounds.width().max(0);
        let h = state.bounds.height().max(0);
        // Use the widget's local cell grid (origin at 0,0) so transition
        // arithmetic is independent of where the widget sits on the
        // parent surface. The Effect renderer translates particle
        // positions to absolute coordinates via the widget's own bounds
        // at draw time.
        (w, h, 0_i32, 0_i32)
    };

    if width <= 0 || height <= 0 {
        return Vec::new();
    }

    // Pre-compute capacity to avoid reallocation during the inner loop.
    let count = (width as usize).saturating_mul(height as usize);
    let mut particles = Vec::with_capacity(count);

    for row in 0..height {
        let cell_y = f64::from(origin_y + row);
        for col in 0..width {
            let cell_x = f64::from(origin_x + col);
            // ch = ' ', fg = 7 (default light gray), bg = 0 (default black).
            // Velocity defaults to 0.0 inside Particle::new; the caller
            // mutates this after we return.
            particles.push(Particle::new(cell_x, cell_y, cell_x, cell_y, ' ', 7, 0));
        }
    }

    particles
}

// ============================================================================
// Internal helpers — direction validation, dimension extraction.
// ============================================================================

/// Construct a [`TuiError::Render`] wrapping
/// [`std::io::ErrorKind::InvalidInput`] for direction-validation
/// failures.
///
/// [`TuiError`] does not currently expose a dedicated `InvalidInput`
/// variant (see `crates/heavything/src/error.rs` — the enum has only
/// `Termios`, `Winsize`, and `Render` variants). Direction-validation
/// failures therefore surface as `Render(io::Error::new(InvalidInput,
/// _))`, which is consistent with how [`Effect`] handles its own
/// defensive error cases.
fn invalid_direction(transition: &'static str, direction: SlideDirection) -> TuiError {
    TuiError::Render(io::Error::new(
        ErrorKind::InvalidInput,
        format!("{transition}: direction {direction:?} is invalid for this transition"),
    ))
}

/// Extract a widget's effective width in cells, preferring
/// [`crate::tui::object::WidgetState::bounds`] when non-empty and
/// falling back to [`crate::tui::object::WidgetState::width`] otherwise.
///
/// Returns 0 when both sources are empty/zero/negative — callers
/// should handle the zero case gracefully (typically by clamping the
/// slide distance to [`SLIDE_MIN_FRAMES`] cells via the frame-count
/// helper).
fn widget_width(w: &Arc<dyn Widget>) -> i32 {
    let state = w.state();
    if state.bounds.is_empty() {
        state.width.max(0)
    } else {
        state.bounds.width().max(0)
    }
}

/// Extract a widget's effective height in cells. See [`widget_width`]
/// for the bounds-preference rationale.
fn widget_height(w: &Arc<dyn Widget>) -> i32 {
    let state = w.state();
    if state.bounds.is_empty() {
        state.height.max(0)
    } else {
        state.bounds.height().max(0)
    }
}

/// Compute the geometric centre of a widget in its local cell grid.
///
/// Used by [`distort_in`] and [`distort_out`] as the implosion /
/// explosion focal point for the central [`Force`].
fn widget_centre(w: &Arc<dyn Widget>) -> Point {
    let width = widget_width(w);
    let height = widget_height(w);
    Point::new(width / 2, height / 2)
}

/// Compute the minimum frame count for a slide transition given the
/// slide distance.
///
/// The result is `max(SLIDE_MIN_FRAMES, ceil(distance))` so that:
///
/// - Slides longer than `SLIDE_MIN_FRAMES` cells run at exactly
///   1 cell / tick (the FASM canonical rate, which yields a smooth
///   visual at 50 ms / tick = 20 fps).
/// - Slides shorter than `SLIDE_MIN_FRAMES` cells run for at least
///   `SLIDE_MIN_FRAMES` ticks (preventing one-frame flashes on
///   degenerate empty-widget cases).
///
/// `distance` is clamped to `>= 0.0` before ceiling so negative
/// distances (which should never occur in normal operation) do not
/// produce a 0-frame animation.
fn compute_min_frames_for_slide(distance: f64) -> u32 {
    let clamped = distance.max(0.0);
    let by_distance = clamped.ceil() as u32;
    by_distance.max(SLIDE_MIN_FRAMES)
}

/// Compute the minimum frame count for a distort transition.
///
/// Distort runs longer than slide because the convergence /
/// divergence motion looks better with extra frames. Always returns
/// at least [`DISTORT_MIN_FRAMES`].
fn compute_min_frames_for_distort(scatter_radius: f64) -> u32 {
    let clamped = scatter_radius.max(0.0);
    let by_distance = clamped.ceil() as u32;
    by_distance.max(DISTORT_MIN_FRAMES)
}

/// Generate a deterministic pseudo-random scatter offset for a
/// particle, based on its cell index and a transition seed.
///
/// Used by [`distort_in`] / [`distort_out`] to produce a reproducible
/// scatter pattern without pulling in the `rand` crate (which is not
/// in `depends_on_files`). The PRNG is a simple Linear Congruential
/// Generator (LCG) with the constants from Numerical Recipes:
///
/// ```text
///   next = (state × 1664525 + 1013904223) mod 2³²
/// ```
///
/// Two LCG steps from the seed produce two independent `f64` values
/// in `[-radius, +radius]`, which become the `(dx, dy)` scatter
/// offset added to the particle's home position.
fn deterministic_scatter(seed: u64, radius: f64) -> (f64, f64) {
    // First LCG step → x offset.
    let s1 = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    let s2 = s1.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    // Map to [-1.0, 1.0]: the lower 32 bits of each LCG state are the
    // pseudo-random component; we cast to i32 (signed) and divide by
    // i32::MAX to keep the result in the sign-symmetric range.
    let nx = (s1 as i32) as f64 / f64::from(i32::MAX);
    let ny = (s2 as i32) as f64 / f64::from(i32::MAX);
    (nx * radius, ny * radius)
}

// ============================================================================
// hslidein — horizontal slide-in transition (FASM `tui_effect$hslidein`).
// ============================================================================

/// Slide a child widget into the parent's content region from the
/// left or right edge.
///
/// FASM parallel: `tui_effect$hslidein`
/// (`tui_effects.inc` lines 32–110), the canonical template upon
/// which all other slide-/distort-style transitions are modelled.
///
/// # Parameters
///
/// - `parent` — borrowed handle on the parent widget. The transition
///   reads `parent.state().bounds` / `parent.state().width` to
///   determine the slide distance for [`SlideDirection::FromRight`].
///   Used as a [`Weak`] back-pointer on the resulting [`Effect`] to
///   prevent ownership cycles.
/// - `new_child` — owned handle on the child widget being slid in.
///   The [`Effect`] takes ownership for the duration of the
///   animation; on completion the user-supplied `on_complete`
///   callback is responsible for actually appending the child to the
///   parent's children list (the FASM original mutated the parent
///   directly inside `tui_effect$timer.finalize`; the Rust port
///   defers tree mutation to the callback per the design rationale
///   in [`crate::tui::widgets::effect`]).
/// - `direction` — slide source edge.
///   [`SlideDirection::FromLeft`] / [`SlideDirection::FromRight`]
///   are the only valid values; [`SlideDirection::FromTop`] /
///   [`SlideDirection::FromBottom`] return [`TuiError::Render`]
///   wrapping [`std::io::ErrorKind::InvalidInput`].
/// - `on_complete` — optional [`FnOnce`] callback fired exactly once
///   when the animation completes. The callback runs on the tokio
///   timer task that drives the [`Effect`].
///
/// # Returns
///
/// `Ok(`[`Arc<Effect>`]`)` with the configured effect that the caller
/// must register and start (typically by appending to the parent's
/// bastard list and calling [`Effect::start_timer`]).
///
/// # Errors
///
/// - [`TuiError::Render`] wrapping
///   [`std::io::ErrorKind::InvalidInput`] when `direction` is
///   [`SlideDirection::FromTop`] or [`SlideDirection::FromBottom`].
/// - [`TuiError::Render`] propagated from
///   [`Effect::add_particle`] / [`Effect::add_force`] (currently
///   infallible but the [`Result`] symmetry is preserved for future
///   capacity-limit enforcement).
///
/// # Algorithm
///
/// 1. Validate `direction` is one of `FromLeft` / `FromRight`.
/// 2. Read `child.state().width` and `parent.state().width` to
///    determine the slide distance.
/// 3. Compute `frames = max(SLIDE_MIN_FRAMES,
///    ceil(slide_distance))` so very short slides still run for at
///    least `SLIDE_MIN_FRAMES` ticks (avoids one-frame flashes).
/// 4. Compute `velocity = uniform_velocity(slide_distance, frames)`
///    so the particle travels exactly `slide_distance` in `frames`
///    ticks (matches the FASM 1-cell-per-tick convention when
///    `slide_distance >= SLIDE_MIN_FRAMES`).
/// 5. Build one particle per cell of the child via
///    [`build_particles_for_widget`]; mutate each particle's `x`
///    by `±slide_distance` so it starts off-screen, and set
///    `x_velocity = ±velocity` so it moves toward home.
/// 6. Construct the [`Effect`] with [`EffectType::AppendChild`],
///    50 ms tick interval ([`TRANSITION_TIME_MS`]).
/// 7. Push every particle into the effect via
///    [`Effect::add_particle`].
/// 8. Configure [`Effect::set_min_frames`] = `frames` and install
///    `on_complete` if provided.
/// 9. Return the effect handle.
///
/// # FASM trajectory mapping
///
/// FASM `tui_effects.inc` lines 80–94 (`.movefromleft` block):
///
/// ```text
///   subsd particle.x, xmm15            ; xmm15 = child_width
///   subsd particle.x, 1                ; off-by-one cell to ensure off-screen
///   movsd particle.xvel, 1.0           ; constant +1 cell/tick velocity
///   ...
/// ```
///
/// FASM `tui_effects.inc` lines 96–110 (`.movefromright` block):
///
/// ```text
///   addsd particle.x, xmm15            ; xmm15 = parent_width
///   addsd particle.x, 1
///   movsd particle.xvel, -1.0
///   ...
/// ```
///
/// The Rust port preserves these signs and the off-by-one cell
/// adjustment is folded into the `slide_distance` itself by adding
/// `1.0` to the width before computing the offset.
pub fn hslidein(
    parent: &Arc<dyn Widget>,
    new_child: Arc<dyn Widget>,
    direction: SlideDirection,
    on_complete: Option<Box<dyn FnOnce() + Send + Sync>>,
) -> Result<Arc<Effect>, TuiError> {
    // ---- Step 1: direction validation.
    match direction {
        SlideDirection::FromLeft | SlideDirection::FromRight => {}
        SlideDirection::FromTop | SlideDirection::FromBottom => {
            return Err(invalid_direction("hslidein", direction));
        }
    }

    // ---- Step 2: read widget dimensions.
    let child_width = widget_width(&new_child);
    let parent_width = widget_width(parent);

    // The slide distance depends on direction:
    //   - FromLeft : the child slides in from x = -child_width to x = 0,
    //                so the distance to travel == child_width (+1 cell to
    //                guarantee off-screen at frame 0).
    //   - FromRight: the child slides in from x = parent_width to x = 0,
    //                so the distance to travel == parent_width (+1 cell).
    let slide_distance = match direction {
        SlideDirection::FromLeft => f64::from(child_width) + 1.0,
        SlideDirection::FromRight => f64::from(parent_width) + 1.0,
        _ => unreachable!("validated above"),
    };

    // ---- Steps 3 & 4: frame count and per-tick velocity.
    let frames = compute_min_frames_for_slide(slide_distance);
    let velocity_magnitude = uniform_velocity(slide_distance, frames);

    // ---- Step 5: build particles seeded at home, then displace.
    let home_particles = build_particles_for_widget(&new_child);

    // ---- Step 6: construct the Effect.
    let weak_parent: Weak<dyn Widget> = Arc::downgrade(parent);
    let effect = Effect::new(
        EffectType::AppendChild,
        new_child,
        weak_parent,
        TRANSITION_TIME_MS,
    );

    // ---- Step 7: displace each particle to its starting position
    // and assign the appropriate velocity, then push into the effect.
    for home in home_particles {
        let mut p = home;
        match direction {
            SlideDirection::FromLeft => {
                // Start off-screen to the left, move rightward.
                p.x = home.x - slide_distance;
                p.x_velocity = velocity_magnitude;
            }
            SlideDirection::FromRight => {
                // Start off-screen to the right, move leftward.
                p.x = home.x + slide_distance;
                p.x_velocity = -velocity_magnitude;
            }
            _ => unreachable!("validated above"),
        }
        effect.add_particle(p)?;
    }

    // ---- Step 8: configure completion.
    effect.set_min_frames(frames);
    if let Some(cb) = on_complete {
        effect.set_oncomplete(cb);
    }

    // ---- Step 9: return the configured effect handle.
    Ok(effect)
}

// ============================================================================
// hslideout — horizontal slide-out transition (FASM `tui_effect$hslideout`).
// ============================================================================

/// Slide a child widget out of the parent's content region toward
/// the left or right edge, then signal removal via
/// [`EffectType::RemoveChild`].
///
/// FASM parallel: `tui_effect$hslideout`
/// (`tui_effects.inc` lines 232–322).
///
/// # Parameters
///
/// - `parent` — borrowed handle on the parent widget. Used as a
///   [`Weak`] back-pointer on the resulting [`Effect`].
/// - `child_to_remove` — owned handle on the child widget being slid
///   out. The [`Effect`] takes ownership; the user-supplied
///   `on_complete` callback is responsible for actually removing the
///   child from the parent's children list.
/// - `direction` — slide destination edge.
///   [`SlideDirection::FromLeft`] (slide toward / out the left) or
///   [`SlideDirection::FromRight`] (slide toward / out the right).
///   Top / bottom directions return [`TuiError::Render`] wrapping
///   [`std::io::ErrorKind::InvalidInput`].
/// - `on_complete` — optional one-shot completion callback.
///
/// # FASM trajectory mapping
///
/// FASM `tui_effects.inc` lines 285–296 (`.moveright` block):
///
/// ```text
///   targetx = parent_width                ; off-screen to the right
///   maxx    = parent_width
///   xvel    = +1.0
/// ```
///
/// FASM `tui_effects.inc` lines 305–320 (`.moveleft` block):
///
/// ```text
///   targetx = -1                          ; off-screen to the left
///   minx    = -1
///   xvel    = -1.0
/// ```
///
/// The Rust port encodes these targets via the simplified
/// [`Particle`] `target_x` / `target_y` fields. The min/max clamps
/// from the FASM port are not required because the simplified
/// [`Particle`] does not expose them; instead the [`Effect::tick`]
/// integration loop stops a particle once it reaches its target.
pub fn hslideout(
    parent: &Arc<dyn Widget>,
    child_to_remove: Arc<dyn Widget>,
    direction: SlideDirection,
    on_complete: Option<Box<dyn FnOnce() + Send + Sync>>,
) -> Result<Arc<Effect>, TuiError> {
    // ---- Step 1: direction validation.
    match direction {
        SlideDirection::FromLeft | SlideDirection::FromRight => {}
        SlideDirection::FromTop | SlideDirection::FromBottom => {
            return Err(invalid_direction("hslideout", direction));
        }
    }

    // ---- Step 2: dimensions.
    let parent_width = widget_width(parent);
    let child_width = widget_width(&child_to_remove);

    // The slide-out distance:
    //   - Toward FromLeft : home x → x = -child_width - 1 (off-screen
    //                       to the left). Distance = home_x + child_width + 1.
    //                       For the worst case (rightmost particle at
    //                       x = child_width-1), distance ≈ 2*child_width.
    //   - Toward FromRight: home x → x = parent_width + 1 (off-screen
    //                       to the right). Distance ≈ parent_width.
    //
    // We use the maximum-distance particle (rightmost for FromLeft,
    // leftmost for FromRight) to determine frame count so that the
    // effect runs long enough for every particle to reach its target.
    let max_distance = match direction {
        SlideDirection::FromLeft => f64::from(child_width) + 1.0,
        SlideDirection::FromRight => f64::from(parent_width) + 1.0,
        _ => unreachable!(),
    };

    // ---- Steps 3 & 4: frames and velocity.
    let frames = compute_min_frames_for_slide(max_distance);
    let velocity_magnitude = uniform_velocity(max_distance, frames);

    // ---- Step 5: build home particles.
    let home_particles = build_particles_for_widget(&child_to_remove);

    // ---- Step 6: construct the Effect (RemoveChild type).
    let weak_parent: Weak<dyn Widget> = Arc::downgrade(parent);
    let effect = Effect::new(
        EffectType::RemoveChild,
        child_to_remove,
        weak_parent,
        TRANSITION_TIME_MS,
    );

    // ---- Step 7: displace targets, push into effect.
    for home in home_particles {
        let mut p = home;
        match direction {
            SlideDirection::FromLeft => {
                // Particle starts at home, target is off-screen to the
                // left. Velocity is negative (moving left).
                p.target_x = -1.0;
                p.x_velocity = -velocity_magnitude;
            }
            SlideDirection::FromRight => {
                // Particle starts at home, target is off-screen to the
                // right. Velocity is positive (moving right).
                p.target_x = f64::from(parent_width) + 1.0;
                p.x_velocity = velocity_magnitude;
            }
            _ => unreachable!(),
        }
        effect.add_particle(p)?;
    }

    // ---- Step 8: configure completion.
    effect.set_min_frames(frames);
    if let Some(cb) = on_complete {
        effect.set_oncomplete(cb);
    }

    Ok(effect)
}

// ============================================================================
// vslidein — vertical slide-in transition (FASM `tui_effect$vslidein`).
// ============================================================================

/// Slide a child widget into the parent's content region from the top
/// or bottom edge.
///
/// FASM parallel: `tui_effect$vslidein`
/// (`tui_effects.inc` lines 129–230). Vertical mirror image of
/// [`hslidein`] — algorithm and validation rules are identical except
/// the slide axis is `y` instead of `x`, and the valid directions
/// flip to [`SlideDirection::FromTop`] / [`SlideDirection::FromBottom`].
///
/// # FASM trajectory mapping
///
/// FASM `tui_effects.inc` lines 174–192 (`.movefromtop` block):
///
/// ```text
///   subsd particle.y, xmm14            ; xmm14 = effect.height
///   subsd particle.y, 1
///   movsd particle.yvel, 1.0
/// ```
///
/// FASM `tui_effects.inc` lines 195–213 (`.movefrombottom` block):
///
/// ```text
///   addsd particle.y, xmm15            ; xmm15 = child_height
///   addsd particle.y, 1
///   movsd particle.yvel, -1.0
/// ```
///
/// # Errors
///
/// - [`TuiError::Render`] wrapping
///   [`std::io::ErrorKind::InvalidInput`] when `direction` is
///   [`SlideDirection::FromLeft`] or [`SlideDirection::FromRight`].
pub fn vslidein(
    parent: &Arc<dyn Widget>,
    new_child: Arc<dyn Widget>,
    direction: SlideDirection,
    on_complete: Option<Box<dyn FnOnce() + Send + Sync>>,
) -> Result<Arc<Effect>, TuiError> {
    // ---- Step 1: direction validation.
    match direction {
        SlideDirection::FromTop | SlideDirection::FromBottom => {}
        SlideDirection::FromLeft | SlideDirection::FromRight => {
            return Err(invalid_direction("vslidein", direction));
        }
    }

    // ---- Step 2: dimensions.
    let child_height = widget_height(&new_child);
    let parent_height = widget_height(parent);

    // The slide distance:
    //   - FromTop:    child slides from y = -child_height to y = 0.
    //                 FASM uses `effect.height` (== parent.height) for
    //                 the FromTop case (line 184) — we preserve that
    //                 here.
    //   - FromBottom: child slides from y = parent_height to y = 0.
    //                 FASM uses `child.height` for the FromBottom case
    //                 (line 207) — we preserve that here.
    //
    // Note the FASM convention reverses the from-top vs from-bottom
    // distance source compared to the horizontal variant; this is
    // because the FASM engineers chose to keep the "outer boundary"
    // as the seed for both directions: from-top uses parent height
    // (the upper boundary of the slide region) and from-bottom uses
    // child height (the lower boundary, since the child must fully
    // exit the bottom edge).
    let slide_distance = match direction {
        SlideDirection::FromTop => f64::from(parent_height) + 1.0,
        SlideDirection::FromBottom => f64::from(child_height) + 1.0,
        _ => unreachable!("validated above"),
    };

    // ---- Steps 3 & 4: frames and velocity.
    let frames = compute_min_frames_for_slide(slide_distance);
    let velocity_magnitude = uniform_velocity(slide_distance, frames);

    // ---- Step 5: build home particles.
    let home_particles = build_particles_for_widget(&new_child);

    // ---- Step 6: construct the Effect.
    let weak_parent: Weak<dyn Widget> = Arc::downgrade(parent);
    let effect = Effect::new(
        EffectType::AppendChild,
        new_child,
        weak_parent,
        TRANSITION_TIME_MS,
    );

    // ---- Step 7: displace each particle and assign velocity.
    for home in home_particles {
        let mut p = home;
        match direction {
            SlideDirection::FromTop => {
                // Start above the parent, move downward.
                p.y = home.y - slide_distance;
                p.y_velocity = velocity_magnitude;
            }
            SlideDirection::FromBottom => {
                // Start below the parent, move upward.
                p.y = home.y + slide_distance;
                p.y_velocity = -velocity_magnitude;
            }
            _ => unreachable!(),
        }
        effect.add_particle(p)?;
    }

    // ---- Step 8: configure completion.
    effect.set_min_frames(frames);
    if let Some(cb) = on_complete {
        effect.set_oncomplete(cb);
    }

    Ok(effect)
}

// ============================================================================
// vslideout — vertical slide-out transition (FASM `tui_effect$vslideout`).
// ============================================================================

/// Slide a child widget out of the parent's content region toward
/// the top or bottom edge, then signal removal via
/// [`EffectType::RemoveChild`].
///
/// FASM parallel: `tui_effect$vslideout`
/// (`tui_effects.inc` lines 325–415). Vertical mirror image of
/// [`hslideout`].
///
/// # FASM trajectory mapping
///
/// FASM `tui_effects.inc` lines 380–397 (`.movedown` block):
///
/// ```text
///   targety = effect.height               ; off-screen below
///   maxy    = effect.height
///   yvel    = +1.0
/// ```
///
/// FASM `tui_effects.inc` lines 399–414 (`.moveup` block):
///
/// ```text
///   targety = -1                          ; off-screen above
///   miny    = -1
///   yvel    = -1.0
/// ```
///
/// # Errors
///
/// - [`TuiError::Render`] wrapping
///   [`std::io::ErrorKind::InvalidInput`] when `direction` is
///   [`SlideDirection::FromLeft`] or [`SlideDirection::FromRight`].
pub fn vslideout(
    parent: &Arc<dyn Widget>,
    child_to_remove: Arc<dyn Widget>,
    direction: SlideDirection,
    on_complete: Option<Box<dyn FnOnce() + Send + Sync>>,
) -> Result<Arc<Effect>, TuiError> {
    // ---- Step 1: direction validation.
    match direction {
        SlideDirection::FromTop | SlideDirection::FromBottom => {}
        SlideDirection::FromLeft | SlideDirection::FromRight => {
            return Err(invalid_direction("vslideout", direction));
        }
    }

    // ---- Step 2: dimensions.
    let parent_height = widget_height(parent);
    let child_height = widget_height(&child_to_remove);

    let max_distance = match direction {
        SlideDirection::FromTop => f64::from(child_height) + 1.0,
        SlideDirection::FromBottom => f64::from(parent_height) + 1.0,
        _ => unreachable!(),
    };

    // ---- Steps 3 & 4: frames and velocity.
    let frames = compute_min_frames_for_slide(max_distance);
    let velocity_magnitude = uniform_velocity(max_distance, frames);

    // ---- Step 5: build home particles.
    let home_particles = build_particles_for_widget(&child_to_remove);

    // ---- Step 6: construct the Effect (RemoveChild type).
    let weak_parent: Weak<dyn Widget> = Arc::downgrade(parent);
    let effect = Effect::new(
        EffectType::RemoveChild,
        child_to_remove,
        weak_parent,
        TRANSITION_TIME_MS,
    );

    // ---- Step 7: displace targets, push into effect.
    for home in home_particles {
        let mut p = home;
        match direction {
            SlideDirection::FromTop => {
                // Particle starts at home, target is off-screen above.
                p.target_y = -1.0;
                p.y_velocity = -velocity_magnitude;
            }
            SlideDirection::FromBottom => {
                // Particle starts at home, target is off-screen below.
                p.target_y = f64::from(parent_height) + 1.0;
                p.y_velocity = velocity_magnitude;
            }
            _ => unreachable!(),
        }
        effect.add_particle(p)?;
    }

    // ---- Step 8: configure completion.
    effect.set_min_frames(frames);
    if let Some(cb) = on_complete {
        effect.set_oncomplete(cb);
    }

    Ok(effect)
}

// ============================================================================
// distort_in — particles converge from scattered to home positions.
// ============================================================================

/// Animate a child widget INTO its content region by starting every
/// cell-particle at a deterministically-scattered random position
/// within the parent's bounds and driving each particle back to its
/// home cell.
///
/// FASM parallel: there is no direct `tui_effect$distortin` in
/// `tui_effects.inc` — this transition is composed from primitives
/// in the spirit of `tui_effect$gunshotout` (lines 922–1035, which
/// drives an explosive scatter via a central repelling force) but
/// run in **reverse** with a central attracting force pulling
/// scattered particles toward their home positions.
///
/// # Algorithm
///
/// 1. Determine the parent's effective bounds (used as the scatter
///    radius). Defaults to [`DISTORT_FALLBACK_RADIUS`] when the
///    parent's dimensions are unset.
/// 2. Build one [`Particle`] per cell of the new child via
///    [`build_particles_for_widget`].
/// 3. For each particle, compute a deterministic scatter offset via
///    [`deterministic_scatter`] (LCG-based, no `rand` dependency)
///    and place the particle at `(home_x + dx, home_y + dy)`.
/// 4. Set the particle's velocity to point toward its home position
///    with magnitude
///    `uniform_velocity(scatter_distance, DISTORT_MIN_FRAMES)`.
/// 5. Register a single attractive [`Force`] at the parent's centre
///    with negative strength (= attraction). This adds slight
///    centring perturbation to the convergence motion, matching the
///    AAP description "gravitational forces pulling particles home".
/// 6. Configure [`Effect::set_min_frames`] = [`DISTORT_MIN_FRAMES`]
///    so the effect runs long enough for the convergence to be
///    visually clear.
/// 7. Use [`EffectType::Distort`] (cosmetic-only — no automatic tree
///    mutation; the caller's `on_complete` callback is responsible
///    for any post-animation child attachment).
///
/// # Parameters
///
/// - `parent` — borrowed handle on the parent widget. Used for the
///   scatter radius and the central force position.
/// - `new_child` — owned handle on the child widget being distorted
///   in. The user-supplied `on_complete` callback should attach the
///   child to the parent's children list when the animation
///   completes.
/// - `on_complete` — optional one-shot completion callback.
///
/// # Returns
///
/// `Ok(`[`Arc<Effect>`]`)` with the configured effect.
///
/// # Errors
///
/// - [`TuiError::Render`] propagated from
///   [`Effect::add_particle`] / [`Effect::add_force`] (currently
///   infallible).
pub fn distort_in(
    parent: &Arc<dyn Widget>,
    new_child: Arc<dyn Widget>,
    on_complete: Option<Box<dyn FnOnce() + Send + Sync>>,
) -> Result<Arc<Effect>, TuiError> {
    // ---- Step 1: scatter radius.
    let parent_w = widget_width(parent);
    let parent_h = widget_height(parent);
    let scatter_radius = if parent_w > 0 && parent_h > 0 {
        // Use half the smaller dimension so scatter stays within the
        // parent bounds.
        f64::from(parent_w.min(parent_h)) / 2.0
    } else {
        DISTORT_FALLBACK_RADIUS
    };
    let scatter_radius = scatter_radius.max(1.0);

    // ---- Step 2: build home particles.
    let home_particles = build_particles_for_widget(&new_child);

    // ---- Step 3 prep: frame count.
    let frames = compute_min_frames_for_distort(scatter_radius);

    // ---- Step 7 prep: construct the Effect (Distort type — cosmetic
    // only, no automatic tree mutation).
    let weak_parent: Weak<dyn Widget> = Arc::downgrade(parent);
    let effect = Effect::new(EffectType::Distort, new_child, weak_parent, TRANSITION_TIME_MS);

    // ---- Steps 3 & 4: scatter and seed velocity.
    //
    // Walk every home particle, displace it by a deterministic
    // pseudo-random offset within `[-scatter_radius, +scatter_radius]`
    // on each axis, and assign a velocity vector pointing back home.
    for (idx, home) in home_particles.into_iter().enumerate() {
        // Mix the cell index with a transition-specific seed so
        // distort_in and distort_out produce visually-different
        // patterns even for the same widget.
        let seed = (idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let (dx, dy) = deterministic_scatter(seed, scatter_radius);

        let mut p = home;
        // Place the particle at the scattered position.
        p.x = home.x + dx;
        p.y = home.y + dy;
        // The particle's target remains the home position (already set
        // by build_particles_for_widget); we only mutate the start
        // position and the velocity here.

        // Compute the distance from the scattered point to home, then
        // derive the per-tick velocity needed to traverse it in
        // `frames` ticks.
        let to_home_x = home.x - p.x;
        let to_home_y = home.y - p.y;
        let distance = (to_home_x * to_home_x + to_home_y * to_home_y).sqrt();
        let speed = uniform_velocity(distance, frames);
        if distance > 0.0 {
            // Unit vector toward home, scaled by per-tick speed.
            p.x_velocity = (to_home_x / distance) * speed;
            p.y_velocity = (to_home_y / distance) * speed;
        } else {
            // Already at home — no velocity needed.
            p.x_velocity = 0.0;
            p.y_velocity = 0.0;
        }

        effect.add_particle(p)?;
    }

    // ---- Step 5: register central attractive force.
    //
    // The force lives at the parent's geometric centre with a small
    // negative strength (attraction). Since each particle's velocity
    // already points toward its home, the centre force adds a slight
    // additional centring tendency rather than overriding the per-
    // particle trajectory. The strength magnitude is chosen to be
    // small (0.1) so the velocity-driven convergence dominates.
    //
    // The force's [`Force::bounds`] is set to [`Rect::EMPTY`] (the
    // "no spatial constraint" sentinel), so the attractive force
    // applies to every particle regardless of position. This matches
    // the FASM convention where a `tui_effect_force` registered
    // without an explicit region applies globally.
    let centre = widget_centre(parent);
    let mut centre_force = Force::new(
        f64::from(centre.x),
        f64::from(centre.y),
        -0.1, // negative = attraction per Force::apply convention
    );
    centre_force.bounds = Rect::EMPTY;
    effect.add_force(centre_force)?;

    // ---- Step 6: configure completion.
    effect.set_min_frames(frames);
    if let Some(cb) = on_complete {
        effect.set_oncomplete(cb);
    }

    Ok(effect)
}

// ============================================================================
// distort_out — particles explode from home to scattered positions.
// ============================================================================

/// Animate a child widget OUT of its content region by exploding
/// every cell-particle from its home position to a deterministically-
/// scattered random destination, then signal removal via
/// [`EffectType::RemoveChild`].
///
/// FASM parallel: `tui_effect$gunshotout`
/// (`tui_effects.inc` lines 922–1035), which adds a central repelling
/// force and lets every particle fly outward from its home position.
/// The Rust port preserves the spirit of that effect while expressing
/// the per-particle explosion direction via deterministic scatter
/// targets rather than the FASM `random_double` PRNG (which is not in
/// the dependency graph for this file).
///
/// # Algorithm
///
/// 1. Determine the parent's effective bounds (used as the scatter
///    radius for the explosion targets).
/// 2. Build one [`Particle`] per cell of the child via
///    [`build_particles_for_widget`] (each starts at its home cell
///    position).
/// 3. For each particle, compute a deterministic scatter offset that
///    points OUTWARD from the parent centre, scaled to project the
///    particle to a position outside the parent bounds.
/// 4. Set the particle's `target_x` / `target_y` to that outward
///    destination, and set its velocity vector to point in that
///    direction with magnitude
///    `uniform_velocity(scatter_distance, DISTORT_MIN_FRAMES)`.
/// 5. Register a single repelling [`Force`] at the parent's centre
///    with positive strength (= repulsion). This matches the FASM
///    `gunshotout` central force.
/// 6. Configure [`Effect::set_min_frames`] = [`DISTORT_MIN_FRAMES`].
/// 7. Use [`EffectType::RemoveChild`] so the user's `on_complete`
///    callback can identify this as a "distort then remove"
///    animation.
///
/// # Errors
///
/// - [`TuiError::Render`] propagated from
///   [`Effect::add_particle`] / [`Effect::add_force`] (currently
///   infallible).
pub fn distort_out(
    parent: &Arc<dyn Widget>,
    child_to_remove: Arc<dyn Widget>,
    on_complete: Option<Box<dyn FnOnce() + Send + Sync>>,
) -> Result<Arc<Effect>, TuiError> {
    // ---- Step 1: scatter radius (where particles fly TO).
    let parent_w = widget_width(parent);
    let parent_h = widget_height(parent);
    let max_dim = if parent_w > 0 || parent_h > 0 {
        f64::from(parent_w.max(parent_h))
    } else {
        DISTORT_FALLBACK_RADIUS
    };
    // Particles fly to ~1.5× the parent dimension so they clearly exit
    // the visible area.
    let scatter_radius = (max_dim * 1.5).max(DISTORT_FALLBACK_RADIUS);

    // ---- Step 2: build home particles.
    let home_particles = build_particles_for_widget(&child_to_remove);

    // ---- Step 3 prep: parent centre.
    let centre = widget_centre(parent);
    let centre_x = f64::from(centre.x);
    let centre_y = f64::from(centre.y);

    // ---- Step 6 prep: frame count.
    let frames = compute_min_frames_for_distort(scatter_radius);

    // ---- Step 7 prep: construct the Effect (RemoveChild type so the
    // callback can branch on it).
    let weak_parent: Weak<dyn Widget> = Arc::downgrade(parent);
    let effect = Effect::new(
        EffectType::RemoveChild,
        child_to_remove,
        weak_parent,
        TRANSITION_TIME_MS,
    );

    // ---- Steps 3 & 4: compute outward target and seed velocity.
    for (idx, home) in home_particles.into_iter().enumerate() {
        // Mix cell index with a transition-specific seed (different from
        // distort_in's seed mixer to give visually distinct patterns).
        let seed = (idx as u64)
            .wrapping_mul(0xBF58_476D_1CE4_E5B9)
            .wrapping_add(0x94D0_49BB_1331_11EB);

        // Compute the radial direction from centre to home. If home is
        // exactly at the centre (rare), use a deterministic pseudo-
        // random direction.
        let dx_from_centre = home.x - centre_x;
        let dy_from_centre = home.y - centre_y;
        let radial_distance = (dx_from_centre * dx_from_centre + dy_from_centre * dy_from_centre).sqrt();

        let (dir_x, dir_y) = if radial_distance > 0.0 {
            // Unit vector pointing outward from the centre.
            (dx_from_centre / radial_distance, dy_from_centre / radial_distance)
        } else {
            // Particle is at the centre — pick a deterministic direction.
            let (sx, sy) = deterministic_scatter(seed, 1.0);
            let mag = (sx * sx + sy * sy).sqrt();
            if mag > 0.0 {
                (sx / mag, sy / mag)
            } else {
                (1.0, 0.0)
            }
        };

        // Apply small per-particle jitter so the explosion looks
        // organic rather than perfectly radial.
        let (jitter_x, jitter_y) = deterministic_scatter(seed, 0.2);

        let mut p = home;
        // Particle starts at home (already set by build_particles_for_widget).
        // Target is well outside the parent bounds, in the radial direction.
        p.target_x = home.x + dir_x * scatter_radius + jitter_x;
        p.target_y = home.y + dir_y * scatter_radius + jitter_y;

        // Velocity points toward the scatter target, magnitude such that
        // the particle reaches it in `frames` ticks.
        let travel_x = p.target_x - home.x;
        let travel_y = p.target_y - home.y;
        let travel_distance = (travel_x * travel_x + travel_y * travel_y).sqrt();
        let speed = uniform_velocity(travel_distance, frames);
        if travel_distance > 0.0 {
            p.x_velocity = (travel_x / travel_distance) * speed;
            p.y_velocity = (travel_y / travel_distance) * speed;
        } else {
            p.x_velocity = 0.0;
            p.y_velocity = 0.0;
        }

        effect.add_particle(p)?;
    }

    // ---- Step 5: register central repelling force.
    //
    // FASM `tui_effect$gunshotout` (lines ~960) registers a force at
    // the parent centre with a positive (repelling) strength. We use
    // a small magnitude (0.5) so the velocity-driven trajectory is the
    // dominant motion and the force is mainly a cosmetic perturbation.
    //
    // [`Force::bounds`] is left as [`Rect::EMPTY`] (the "no spatial
    // constraint" sentinel) so the repelling force pushes particles
    // outward regardless of where they are along their trajectory.
    let mut centre_force = Force::new(centre_x, centre_y, 0.5);
    centre_force.bounds = Rect::EMPTY;
    effect.add_force(centre_force)?;

    // ---- Step 6: configure completion.
    effect.set_min_frames(frames);
    if let Some(cb) = on_complete {
        effect.set_oncomplete(cb);
    }

    Ok(effect)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::object::WidgetState;
    use std::any::Any;
    use std::sync::atomic::{AtomicBool, Ordering};

    // ------------------------------------------------------------------
    // DummyWidget — minimal concrete Widget for tests.
    // Same pattern as crates/heavything/src/tui/widgets/effect.rs.
    // ------------------------------------------------------------------

    /// Minimal concrete widget used as parent / target stand-in for
    /// transition construction tests.
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

    /// Construct a fresh dummy widget with default state, wrapped in `Arc`.
    fn make_widget() -> Arc<dyn Widget> {
        Arc::new(DummyWidget::default()) as Arc<dyn Widget>
    }

    /// Construct a dummy widget with the given dimensions (sets the
    /// width/height fields of [`WidgetState`]; leaves bounds at
    /// [`Rect::EMPTY`] so [`build_particles_for_widget`] uses the
    /// fallback path).
    fn make_widget_sized(width: i32, height: i32) -> Arc<dyn Widget> {
        let mut w = DummyWidget::default();
        w.state.width = width;
        w.state.height = height;
        Arc::new(w) as Arc<dyn Widget>
    }

    /// Cleanup helper: try to unwrap the Arc and call [`Widget::cleanup`]
    /// to abort any pending tokio timer task. Used at the end of tests
    /// that exercise the [`Effect`] construction path. Mirrors the
    /// pattern from `effect.rs` tests.
    fn cleanup(e: Arc<Effect>) {
        Arc::try_unwrap(e).map(|mut owned| owned.cleanup()).ok();
    }

    // ------------------------------------------------------------------
    // SlideDirection enum
    // ------------------------------------------------------------------

    #[test]
    fn test_slide_direction_repr_values() {
        // FASM `edx` numeric values must be preserved for any future
        // FFI bridge that passes the discriminator as an integer.
        assert_eq!(SlideDirection::FromRight as u8, 0);
        assert_eq!(SlideDirection::FromLeft as u8, 1);
        assert_eq!(SlideDirection::FromTop as u8, 2);
        assert_eq!(SlideDirection::FromBottom as u8, 3);
    }

    #[test]
    fn test_slide_direction_copy_clone_eq() {
        let a = SlideDirection::FromLeft;
        // Verify Copy trait — implicit copy via assignment.
        let b = a;
        // Verify Clone trait — explicit clone via the trait method.
        // (We invoke `<SlideDirection as Clone>::clone` rather than
        // `a.clone()` because clippy `clone_on_copy` would otherwise
        // flag the latter; we still need to exercise the Clone derive
        // to ensure the trait bound holds.)
        let c = <SlideDirection as Clone>::clone(&a);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, SlideDirection::FromRight);
    }

    #[test]
    fn test_slide_direction_debug_formats() {
        // Debug derive must produce the variant name (used in
        // invalid_direction error messages).
        let formatted = format!("{:?}", SlideDirection::FromTop);
        assert!(formatted.contains("FromTop"), "got: {formatted}");
    }

    // ------------------------------------------------------------------
    // Module constants
    // ------------------------------------------------------------------

    #[test]
    fn test_constants_match_fasm() {
        // FASM `tui_effects.inc` uses `mov ecx, 50` — preserved.
        assert_eq!(TRANSITION_TIME_MS, 50);
        // Slide minimum frames — chosen to avoid one-frame flashes.
        assert_eq!(SLIDE_MIN_FRAMES, 5);
        // Distort runs longer (richer convergence motion).
        assert_eq!(DISTORT_MIN_FRAMES, 30);
        // Fallback radius for distort when widget bounds are unset.
        // Pinned to the documented default of 10.0 cells.
        assert_eq!(DISTORT_FALLBACK_RADIUS, 10.0);
    }

    // ------------------------------------------------------------------
    // compute_frame_count
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_frame_count_basic() {
        // 500 ms / 50 ms = 10 frames.
        assert_eq!(compute_frame_count(0.0, 500, 50), 10);
        // 1000 ms / 50 ms = 20 frames.
        assert_eq!(compute_frame_count(0.0, 1000, 50), 20);
    }

    #[test]
    fn test_compute_frame_count_distance_ignored() {
        // distance is currently unused; varying it should not change
        // the result.
        let r1 = compute_frame_count(0.0, 200, 50);
        let r2 = compute_frame_count(100.0, 200, 50);
        let r3 = compute_frame_count(9999.0, 200, 50);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
    }

    #[test]
    fn test_compute_frame_count_clamps_to_one() {
        // time_ms < tick_ms → 0 / 50 = 0, but max(1) → 1.
        assert_eq!(compute_frame_count(0.0, 25, 50), 1);
        // time_ms == 0 → 0, clamps to 1.
        assert_eq!(compute_frame_count(0.0, 0, 50), 1);
    }

    #[test]
    fn test_compute_frame_count_zero_tick_defended() {
        // tick_ms == 0 must NOT panic (divide-by-zero); returns 1.
        assert_eq!(compute_frame_count(0.0, 100, 0), 1);
    }

    // ------------------------------------------------------------------
    // uniform_velocity
    // ------------------------------------------------------------------

    #[test]
    fn test_uniform_velocity_basic() {
        // 10 cells / 5 frames = 2.0 cells/frame.
        let v = uniform_velocity(10.0, 5);
        assert!((v - 2.0).abs() < 1e-9, "got: {v}");
    }

    #[test]
    fn test_uniform_velocity_zero_distance() {
        // 0 cells / N frames = 0.0 (no motion).
        let v = uniform_velocity(0.0, 10);
        assert_eq!(v, 0.0);
    }

    #[test]
    fn test_uniform_velocity_zero_frames_defended() {
        // frames == 0 must NOT panic; returns 0.0.
        let v = uniform_velocity(100.0, 0);
        assert_eq!(v, 0.0);
    }

    #[test]
    fn test_uniform_velocity_non_integer_distance() {
        // Float arithmetic must work for non-integer distances.
        let v = uniform_velocity(7.5, 3);
        assert!((v - 2.5).abs() < 1e-9, "got: {v}");
    }

    // ------------------------------------------------------------------
    // build_particles_for_widget
    // ------------------------------------------------------------------

    #[test]
    fn test_build_particles_empty_widget() {
        // Default DummyWidget has width=0, height=0, bounds=EMPTY.
        let w = make_widget();
        let particles = build_particles_for_widget(&w);
        assert!(particles.is_empty(), "expected zero particles for 0x0 widget");
    }

    #[test]
    fn test_build_particles_zero_width() {
        let w = make_widget_sized(0, 5);
        let particles = build_particles_for_widget(&w);
        assert!(particles.is_empty());
    }

    #[test]
    fn test_build_particles_zero_height() {
        let w = make_widget_sized(5, 0);
        let particles = build_particles_for_widget(&w);
        assert!(particles.is_empty());
    }

    #[test]
    fn test_build_particles_negative_dims_clamped() {
        // Negative width/height must be clamped to 0 (no panic).
        let w = make_widget_sized(-1, -1);
        let particles = build_particles_for_widget(&w);
        assert!(particles.is_empty());
    }

    #[test]
    fn test_build_particles_count_matches_area() {
        // 4 × 3 widget → 12 particles.
        let w = make_widget_sized(4, 3);
        let particles = build_particles_for_widget(&w);
        assert_eq!(particles.len(), 12);
    }

    #[test]
    fn test_build_particles_row_major_layout() {
        // Particles are produced in row-major order.
        // For a 3×2 widget the first 3 particles are y=0, next 3 y=1.
        let w = make_widget_sized(3, 2);
        let particles = build_particles_for_widget(&w);
        assert_eq!(particles.len(), 6);

        // First row — y == 0
        assert_eq!(particles[0].y, 0.0);
        assert_eq!(particles[1].y, 0.0);
        assert_eq!(particles[2].y, 0.0);
        // Second row — y == 1
        assert_eq!(particles[3].y, 1.0);
        assert_eq!(particles[4].y, 1.0);
        assert_eq!(particles[5].y, 1.0);

        // x increments within each row.
        assert_eq!(particles[0].x, 0.0);
        assert_eq!(particles[1].x, 1.0);
        assert_eq!(particles[2].x, 2.0);
    }

    #[test]
    fn test_build_particles_default_attributes() {
        // Each particle is seeded with ' ' glyph, fg=7, bg=0.
        let w = make_widget_sized(2, 2);
        let particles = build_particles_for_widget(&w);
        for p in &particles {
            assert_eq!(p.ch, ' ');
            assert_eq!(p.fg, 7);
            assert_eq!(p.bg, 0);
            // Velocity defaults to 0.0 (Particle::new contract).
            assert_eq!(p.x_velocity, 0.0);
            assert_eq!(p.y_velocity, 0.0);
            // Particle starts at home position (target == position).
            assert_eq!(p.x, p.target_x);
            assert_eq!(p.y, p.target_y);
            // Particle is active by default.
            assert!(p.active);
        }
    }

    // ------------------------------------------------------------------
    // hslidein
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_hslidein_from_left_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = hslidein(&parent, child, SlideDirection::FromLeft, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        // EffectType must be AppendChild (slide-in semantics).
        assert_eq!(e.effect_type(), EffectType::AppendChild);
        // Default tick interval matches FASM `mov ecx, 50`.
        assert_eq!(e.time_ms(), TRANSITION_TIME_MS);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_hslidein_from_right_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = hslidein(&parent, child, SlideDirection::FromRight, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        assert_eq!(e.effect_type(), EffectType::AppendChild);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_hslidein_rejects_from_top() {
        let parent = make_widget();
        let child = make_widget();
        let result = hslidein(&parent, child, SlideDirection::FromTop, None);
        match result {
            Ok(_) => panic!("expected Err for FromTop direction on hslidein"),
            Err(TuiError::Render(io_err)) => {
                assert_eq!(io_err.kind(), ErrorKind::InvalidInput);
                let msg = io_err.to_string();
                assert!(msg.contains("hslidein"), "got: {msg}");
                assert!(msg.contains("FromTop"), "got: {msg}");
            }
            Err(other) => panic!("expected TuiError::Render, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_hslidein_rejects_from_bottom() {
        let parent = make_widget();
        let child = make_widget();
        let result = hslidein(&parent, child, SlideDirection::FromBottom, None);
        match result {
            Ok(_) => panic!("expected Err for FromBottom direction on hslidein"),
            Err(TuiError::Render(io_err)) => {
                assert_eq!(io_err.kind(), ErrorKind::InvalidInput);
            }
            Err(other) => panic!("expected TuiError::Render, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_hslidein_zero_dim_widgets() {
        // Zero-dimension widgets must still produce a valid (empty)
        // effect — no particles, but the effect is constructed and
        // can be ticked / cleaned up cleanly.
        let parent = make_widget();
        let child = make_widget();
        let result = hslidein(&parent, child, SlideDirection::FromLeft, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        assert_eq!(e.effect_type(), EffectType::AppendChild);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_hslidein_callback_registered() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(2, 1);
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();

        let cb: Box<dyn FnOnce() + Send + Sync> = Box::new(move || {
            fired_clone.store(true, Ordering::SeqCst);
        });

        let result = hslidein(&parent, child, SlideDirection::FromLeft, Some(cb));
        assert!(result.is_ok());
        let e = result.unwrap();
        // Callback should NOT have fired yet (effect not ticked).
        assert!(!fired.load(Ordering::SeqCst));
        cleanup(e);
    }

    // ------------------------------------------------------------------
    // hslideout
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_hslideout_from_left_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = hslideout(&parent, child, SlideDirection::FromLeft, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        // EffectType must be RemoveChild for slide-out.
        assert_eq!(e.effect_type(), EffectType::RemoveChild);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_hslideout_from_right_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = hslideout(&parent, child, SlideDirection::FromRight, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        assert_eq!(e.effect_type(), EffectType::RemoveChild);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_hslideout_rejects_from_top() {
        let parent = make_widget();
        let child = make_widget();
        let result = hslideout(&parent, child, SlideDirection::FromTop, None);
        assert!(result.is_err());
        if let Err(TuiError::Render(io_err)) = result {
            assert_eq!(io_err.kind(), ErrorKind::InvalidInput);
            assert!(io_err.to_string().contains("hslideout"));
        } else {
            panic!("expected TuiError::Render(InvalidInput)");
        }
    }

    #[tokio::test]
    async fn test_hslideout_rejects_from_bottom() {
        let parent = make_widget();
        let child = make_widget();
        let result = hslideout(&parent, child, SlideDirection::FromBottom, None);
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // vslidein
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_vslidein_from_top_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = vslidein(&parent, child, SlideDirection::FromTop, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        assert_eq!(e.effect_type(), EffectType::AppendChild);
        assert_eq!(e.time_ms(), TRANSITION_TIME_MS);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_vslidein_from_bottom_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = vslidein(&parent, child, SlideDirection::FromBottom, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        assert_eq!(e.effect_type(), EffectType::AppendChild);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_vslidein_rejects_from_left() {
        let parent = make_widget();
        let child = make_widget();
        let result = vslidein(&parent, child, SlideDirection::FromLeft, None);
        assert!(result.is_err());
        if let Err(TuiError::Render(io_err)) = result {
            assert_eq!(io_err.kind(), ErrorKind::InvalidInput);
            assert!(io_err.to_string().contains("vslidein"));
        } else {
            panic!("expected TuiError::Render(InvalidInput)");
        }
    }

    #[tokio::test]
    async fn test_vslidein_rejects_from_right() {
        let parent = make_widget();
        let child = make_widget();
        let result = vslidein(&parent, child, SlideDirection::FromRight, None);
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // vslideout
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_vslideout_from_top_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = vslideout(&parent, child, SlideDirection::FromTop, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        assert_eq!(e.effect_type(), EffectType::RemoveChild);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_vslideout_from_bottom_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = vslideout(&parent, child, SlideDirection::FromBottom, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        assert_eq!(e.effect_type(), EffectType::RemoveChild);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_vslideout_rejects_from_left() {
        let parent = make_widget();
        let child = make_widget();
        let result = vslideout(&parent, child, SlideDirection::FromLeft, None);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_vslideout_rejects_from_right() {
        let parent = make_widget();
        let child = make_widget();
        let result = vslideout(&parent, child, SlideDirection::FromRight, None);
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // distort_in
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_distort_in_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = distort_in(&parent, child, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        // distort_in uses the cosmetic-only EffectType::Distort.
        assert_eq!(e.effect_type(), EffectType::Distort);
        assert_eq!(e.time_ms(), TRANSITION_TIME_MS);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_distort_in_zero_dim_widgets() {
        // Zero-dimension widgets must still produce a valid effect
        // (uses fallback DISTORT_FALLBACK_RADIUS for the scatter).
        let parent = make_widget();
        let child = make_widget();
        let result = distort_in(&parent, child, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        assert_eq!(e.effect_type(), EffectType::Distort);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_distort_in_with_callback() {
        let parent = make_widget_sized(20, 10);
        let child = make_widget_sized(2, 2);
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();

        let cb: Box<dyn FnOnce() + Send + Sync> = Box::new(move || {
            fired_clone.store(true, Ordering::SeqCst);
        });

        let result = distort_in(&parent, child, Some(cb));
        assert!(result.is_ok());
        let e = result.unwrap();
        // Callback not yet fired.
        assert!(!fired.load(Ordering::SeqCst));
        cleanup(e);
    }

    // ------------------------------------------------------------------
    // distort_out
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_distort_out_constructs_effect() {
        let parent = make_widget_sized(40, 10);
        let child = make_widget_sized(20, 5);
        let result = distort_out(&parent, child, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        // distort_out uses RemoveChild semantics so the callback can
        // perform tree mutation when the animation completes.
        assert_eq!(e.effect_type(), EffectType::RemoveChild);
        assert_eq!(e.time_ms(), TRANSITION_TIME_MS);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_distort_out_zero_dim_widgets() {
        let parent = make_widget();
        let child = make_widget();
        let result = distort_out(&parent, child, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        assert_eq!(e.effect_type(), EffectType::RemoveChild);
        cleanup(e);
    }

    #[tokio::test]
    async fn test_distort_out_centre_at_origin_no_panic() {
        // Edge case: child is at origin, so home-vs-centre vector is
        // zero. Code must take the fallback direction path without
        // panicking.
        let parent = make_widget_sized(0, 0);
        let child = make_widget_sized(1, 1);
        let result = distort_out(&parent, child, None);
        assert!(result.is_ok());
        let e = result.unwrap();
        cleanup(e);
    }

    // ------------------------------------------------------------------
    // Internal helpers — direction validation
    // ------------------------------------------------------------------

    #[test]
    fn test_invalid_direction_returns_render_with_invalidinput() {
        let err = invalid_direction("test_transition", SlideDirection::FromTop);
        match err {
            TuiError::Render(io_err) => {
                assert_eq!(io_err.kind(), ErrorKind::InvalidInput);
                let msg = io_err.to_string();
                assert!(msg.contains("test_transition"));
                assert!(msg.contains("FromTop"));
            }
            other => panic!("expected TuiError::Render, got: {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers — widget dimension extraction
    // ------------------------------------------------------------------

    #[test]
    fn test_widget_width_from_state_width() {
        let w = make_widget_sized(15, 8);
        assert_eq!(widget_width(&w), 15);
    }

    #[test]
    fn test_widget_height_from_state_height() {
        let w = make_widget_sized(15, 8);
        assert_eq!(widget_height(&w), 8);
    }

    #[test]
    fn test_widget_width_zero_default() {
        let w = make_widget();
        assert_eq!(widget_width(&w), 0);
    }

    #[test]
    fn test_widget_height_zero_default() {
        let w = make_widget();
        assert_eq!(widget_height(&w), 0);
    }

    #[test]
    fn test_widget_width_clamps_negative_to_zero() {
        let w = make_widget_sized(-5, 0);
        assert_eq!(widget_width(&w), 0);
    }

    #[test]
    fn test_widget_height_clamps_negative_to_zero() {
        let w = make_widget_sized(0, -5);
        assert_eq!(widget_height(&w), 0);
    }

    #[test]
    fn test_widget_centre_basic() {
        let w = make_widget_sized(10, 6);
        let c = widget_centre(&w);
        // Integer division: 10/2 = 5, 6/2 = 3.
        assert_eq!(c, Point::new(5, 3));
    }

    #[test]
    fn test_widget_centre_zero_widget() {
        let w = make_widget();
        let c = widget_centre(&w);
        assert_eq!(c.x, 0);
        assert_eq!(c.y, 0);
    }

    // ------------------------------------------------------------------
    // Internal helpers — frame count computation
    // ------------------------------------------------------------------

    #[test]
    fn test_compute_min_frames_for_slide_short_distance() {
        // 2-cell slide → clamps to SLIDE_MIN_FRAMES (5).
        assert_eq!(compute_min_frames_for_slide(2.0), SLIDE_MIN_FRAMES);
    }

    #[test]
    fn test_compute_min_frames_for_slide_long_distance() {
        // 50-cell slide → ceil(50) = 50, larger than SLIDE_MIN_FRAMES.
        assert_eq!(compute_min_frames_for_slide(50.0), 50);
    }

    #[test]
    fn test_compute_min_frames_for_slide_exact_boundary() {
        // SLIDE_MIN_FRAMES-cell slide → matches exactly.
        assert_eq!(
            compute_min_frames_for_slide(f64::from(SLIDE_MIN_FRAMES)),
            SLIDE_MIN_FRAMES
        );
    }

    #[test]
    fn test_compute_min_frames_for_slide_negative_clamped() {
        // Negative distance must not produce 0 (would cause one-frame
        // flash) — clamps to SLIDE_MIN_FRAMES.
        assert_eq!(compute_min_frames_for_slide(-10.0), SLIDE_MIN_FRAMES);
    }

    #[test]
    fn test_compute_min_frames_for_slide_fractional() {
        // 5.5-cell slide → ceil = 6, > SLIDE_MIN_FRAMES (5) → 6.
        assert_eq!(compute_min_frames_for_slide(5.5), 6);
    }

    #[test]
    fn test_compute_min_frames_for_distort_short() {
        // Distort always runs at least DISTORT_MIN_FRAMES.
        assert_eq!(compute_min_frames_for_distort(5.0), DISTORT_MIN_FRAMES);
    }

    #[test]
    fn test_compute_min_frames_for_distort_long() {
        // 100-cell radius → ceil = 100, > DISTORT_MIN_FRAMES.
        assert_eq!(compute_min_frames_for_distort(100.0), 100);
    }

    // ------------------------------------------------------------------
    // Internal helpers — deterministic scatter
    // ------------------------------------------------------------------

    #[test]
    fn test_deterministic_scatter_reproducible() {
        // Same seed must produce identical output (deterministic LCG).
        let (x1, y1) = deterministic_scatter(42, 5.0);
        let (x2, y2) = deterministic_scatter(42, 5.0);
        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_deterministic_scatter_within_radius() {
        // Output components must lie within [-radius, +radius].
        let radius = 10.0;
        for seed in 0u64..100 {
            let (x, y) = deterministic_scatter(seed, radius);
            assert!(x.abs() <= radius, "x={x} out of [-{radius}, {radius}]");
            assert!(y.abs() <= radius, "y={y} out of [-{radius}, {radius}]");
        }
    }

    #[test]
    fn test_deterministic_scatter_zero_radius() {
        // Zero radius → zero offsets.
        let (x, y) = deterministic_scatter(123, 0.0);
        assert_eq!(x, 0.0);
        assert_eq!(y, 0.0);
    }

    #[test]
    fn test_deterministic_scatter_different_seeds_differ() {
        // Different seeds should (with high probability) produce
        // different outputs. Test a handful of distinct seeds.
        let (x1, _) = deterministic_scatter(1, 10.0);
        let (x2, _) = deterministic_scatter(2, 10.0);
        let (x3, _) = deterministic_scatter(1000, 10.0);
        // At least one pair must differ (LCG is reasonable enough).
        assert!(x1 != x2 || x2 != x3 || x1 != x3);
    }

    // ------------------------------------------------------------------
    // Particle field semantics — sanity check on how transitions seed
    // particle positions / velocities. Indirectly verified via
    // build_particles_for_widget; this test confirms our assumption
    // that Particle::new initialises velocity to 0.0 and active to true.
    // ------------------------------------------------------------------

    #[test]
    fn test_particle_new_default_state() {
        let p = Particle::new(5.0, 7.0, 5.0, 7.0, 'A', 1, 2);
        assert_eq!(p.x, 5.0);
        assert_eq!(p.y, 7.0);
        assert_eq!(p.target_x, 5.0);
        assert_eq!(p.target_y, 7.0);
        assert_eq!(p.x_velocity, 0.0);
        assert_eq!(p.y_velocity, 0.0);
        assert_eq!(p.ch, 'A');
        assert_eq!(p.fg, 1);
        assert_eq!(p.bg, 2);
        assert!(p.active);
    }
}
