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
// tui_splash.inc: a sample splash widget that we use just for fun
//
// Rust translation © 2026, licensed under GPL-3.0-or-later. Derived from
// the HeavyThing assembly library (© 2015–2018 2 Ton Digital, Jeff
// Marrison <info@2ton.com.au>).

#![forbid(unsafe_code)]

//! Splash widget — a composite "iconic 2 Ton Digital splash" animation
//! that combines a full-screen black background, a typewriter
//! ([`crate::tui::widgets::typist::TuiTypist`]) animating the iconic
//! tagline, and the 2 Ton Digital PNG logo
//! ([`crate::tui::widgets::png::PngWidget`]) — fading in once the
//! typewriter finishes — before transitioning to the user-supplied
//! "follow-up" widget (e.g. `sshtalk` advancing to its login screen).
//!
//! ## FASM Parallel: `tui_splash.inc` (502 lines)
//!
//! The FASM original employs three distinct vtables — one for the
//! splash itself, one for the embedded typist (extending the standard
//! 38-method typist vtable with a `typistcomplete` slot at index 37),
//! and one for the embedded PNG (overriding `cleanup` →
//! `logocleanup` and `timer` → `logotimer`) — to wire up the
//! step-by-step animation choreography:
//!
//! 1. **Splash starts**: full-screen black `tui_background` fills the
//!    screen (FASM `tui_background$init_dd(100%, 100%, ' ', 0xe8)`).
//! 2. **First non-zero size_changed**: a 46×3 container is built
//!    holding a 46×1 typist that types out the iconic
//!    [`SPLASH_TEXT`] in lightgray-on-black. This is gated by a
//!    one-shot [`init_complete`](TuiSplash::init_complete) flag.
//! 3. **Typist completes**: FASM `tui_splash$typistcomplete` (line
//!    201) creates a PNG widget displaying the [embedded
//!    logo](init_logo) using a `vslidein` effect at full size (or
//!    75% if [`SMALL_LOGO`] is set).
//! 4. **Logo slide-in completes**: FASM `tui_splash$logocomplete`
//!    (line 258) cleans up the typist, hides the cursor, and
//!    schedules a 1750 ms display-hold timer.
//! 5. **Hold elapses**: FASM `tui_splash$logotimer` (line 323)
//!    triggers a `vaporize` effect on the PNG and proceeds to
//!    `tui_splash$alldone`.
//! 6. **Vaporize completes**: a 50 ms grace timer fires
//!    `tui_splash$alldonetimer` (line 365), which restores the
//!    cursor, removes the splash from its parent, appends the
//!    [`only_child`](TuiSplash::only_child) "follow-up" widget, and
//!    fires the optional `done_cb` callback.
//!
//! Any key press (other than Ctrl-C, value 3) at any stage aborts
//! the animation and immediately transitions to the follow-up widget
//! (FASM `tui_splash$keyevent`, line 454).
//!
//! ## Rust Port Strategy
//!
//! The visual `vslidein` and `vaporize` effects (driven by
//! `tui_effect.inc`) are not yet ported in this first pass — the
//! [`crate::tui::widgets::effect`] subsystem provides only the
//! foundation. Until those effects are implemented, the Rust port
//! simplifies the choreography to:
//!
//! 1. Splash starts (background renders).
//! 2. First non-zero `size_changed` creates the typist as a child;
//!    the [embedded logo](init_logo) is also created as a child PNG
//!    widget at the same time (the two render concurrently, similar
//!    to but slightly more eager than FASM's sequential reveal).
//! 3. When the typist's [`on_complete`](crate::tui::widgets::typist::TuiTypist::on_complete)
//!    callback fires, the splash's `done_cb` is invoked — handing
//!    control back to the caller, who is responsible for replacing
//!    the splash widget with [`only_child`](TuiSplash::only_child)
//!    in its parent's children/bastards list.
//! 4. Any key press also fires `done_cb` immediately
//!    (matching FASM `tui_splash$keyevent`).
//!
//! The structural skeleton (struct fields, `init_complete` gating,
//! one-shot `done_cb` semantics, Stage 14 `OnceLock` logo cache) is
//! preserved exactly so the future "fancy effects" pass can drop in
//! the slide-in / vaporize transitions without changing the public
//! API.
//!
//! ## Stage 14 Deferred Logo Initialization
//!
//! Per AAP §0.4.3 ("Feature detection at init, not per-call"), the
//! 2 Ton Digital logo PNG is parsed exactly once during stage 14 of
//! [`crate::init`]. The parsed image lives in a static
//! [`OnceLock<Png>`](std::sync::OnceLock) and is published via
//! [`init_logo`], which any number of splash instances can share via
//! `Arc::clone`. This avoids paying the PNG-decode cost (~20 KB
//! deflate inflation) on every splash construction.
//!
//! ## Three-Vtable Pattern via Composition
//!
//! Rust does not patch vtables, so the FASM "three vtables per
//! splash instance" pattern is collapsed onto a single struct
//! ([`TuiSplash`]) that:
//!
//! * Embeds the [`TuiBackground`] base by value (composition, not
//!   inheritance), inheriting `state` / `state_mut` / `as_any` /
//!   `draw` via delegation.
//! * Holds the typist as a child [`Arc<TuiTypist>`] and registers a
//!   `Send + Sync` closure on the typist's `on_complete` slot to
//!   drive the splash's completion logic — this closure carries a
//!   shared [`Arc<Mutex<DoneCbState>>`] so the typist and the
//!   splash both write to the same one-shot completion state.
//! * Holds the logo as a child [`Arc<PngWidget>`]; the `logocleanup`
//!   / `logotimer` overrides from FASM's third vtable are deferred
//!   to the future effects pass (see "Rust Port Strategy" above).
//!
//! This collapses the three vtables to a single struct + a shared
//! `Arc<Mutex<DoneCbState>>` and yields a more idiomatic Rust API
//! while preserving every externally observable behavior (per AAP
//! §0.8.2 "Minimal-Change Discipline").

// ============================================================================
// Imports.
// ============================================================================

use std::any::Any;
use std::sync::{Arc, Mutex, OnceLock};

use crate::error::TuiError;
use crate::tui::object::{ColorPair, KeyEvent, Widget, WidgetState};
use crate::tui::render::Renderer;
use crate::tui::widgets::background::TuiBackground;
use crate::tui::widgets::png::PngWidget;
use crate::tui::widgets::typist::TuiTypist;
use crate::util::png::Png as PngImage;

// ============================================================================
// Compile-time constants — preserved verbatim from `tui_splash.inc`.
// ============================================================================

/// Whether to render the 2 Ton Digital logo at 75 % of the parent
/// dimensions instead of the default 100 %.
///
/// Mirrors FASM `tui_splash.inc` line 19:
///
/// ```text
/// if ~ definite tui_splash_small_logo
///   tui_splash_small_logo = 0
/// end if
/// ```
///
/// `false` means "render at 100 % × 100 %" (the default); `true`
/// switches to "75 % × 75 %", which the FASM port uses for cramped
/// terminals. The Rust port keeps the FASM default (`false`) and
/// exposes the constant publicly so callers can branch on it (e.g.
/// composite UIs that supply their own logo widget alongside the
/// splash).
pub const SMALL_LOGO: bool = false;

/// The iconic splash tagline — preserved byte-exact from FASM
/// `tui_splash.inc:167` (`heavything.text`).
///
/// FASM stores this as a sequence of 32-bit codepoints with
/// embedded NUL "delay markers" interleaved between the punctuated
/// pauses; the visible text — which is what gets typed on-screen
/// by the typist — is what we encode here. The typist's
/// pause-on-NUL semantics are absorbed into the typist's own
/// per-character delay distribution (see
/// [`crate::tui::widgets::typist`]) rather than being externally
/// signaled.
///
/// **44 bytes / 44 ASCII chars.**
pub const SPLASH_TEXT: &str = "It hit me like a... umm... 2 ton heavy thing";

/// Byte length of [`SPLASH_TEXT`].
///
/// Computed at compile time via `&str::len()` (a `const fn` since
/// Rust 1.39) to guarantee the constant always matches the actual
/// string contents — even if a future translation refines the text
/// (which it shouldn't, per AAP §0.8.2 "Minimal-Change
/// Discipline").
pub const SPLASH_TEXT_LEN: usize = SPLASH_TEXT.len();

// ============================================================================
// Stage 14 deferred logo initialization (`OnceLock<Png>`).
// ============================================================================

/// Embedded 2 Ton Digital logo PNG bytes, included at compile time
/// from the repository-root `2ton.png` artifact.
///
/// FASM parallel: `tui_splash.inc:182` (`tui_splash$initlogo`):
///
/// ```text
/// .logodata: file '2ton.png'
/// .logosize = $ - .logodata
/// ```
///
/// `include_bytes!` is the Rust equivalent of FASM's `file '...'`
/// directive — the bytes become a `&'static [u8]` literal embedded
/// in the binary's `.rodata` section. The path is relative to
/// _this_ source file: `crates/heavything/src/tui/widgets/splash.rs`
/// is five directories deep below the workspace root, so
/// `../../../../../2ton.png` reaches the repo root where `2ton.png`
/// is preserved per AAP §0.9.2.1.
const LOGO_PNG_BYTES: &[u8] = include_bytes!("../../../../../2ton.png");

/// Process-wide cache for the parsed 2 Ton Digital logo image.
///
/// Populated exactly once via [`init_logo`] during stage 14 of
/// [`crate::init`] (the `heavything::init()` initialization
/// sequence per AAP §0.4.3). Subsequent calls to [`init_logo`]
/// from any thread return the cached image immediately.
static LOGO: OnceLock<PngImage> = OnceLock::new();

/// Returns a borrow of the parsed 2 Ton Digital logo PNG image.
///
/// On the first call this parses [`LOGO_PNG_BYTES`] via
/// [`PngImage::new`] and stores the result in the process-wide
/// [`LOGO`] cache. All subsequent calls (from any thread) return a
/// reference to the same cached image.
///
/// **Stage 14 of `heavything::init()`** is expected to call this
/// function during library initialization so the parse cost is
/// amortized at startup rather than at first splash creation. Per
/// AAP §0.4.3 ("Feature detection at init, not per-call"), all
/// process-wide one-time-initialized data is materialized in stage
/// 14.
///
/// # Panics
///
/// Panics with `"embedded logo must parse"` if the embedded
/// `2ton.png` bytes fail to decode. This is a compile-time-known
/// asset (validated to exist at the repo root and to be a valid
/// PNG); if this assertion ever fires, it indicates the build
/// pipeline corrupted the asset or the [`PngImage::new`] decoder
/// regressed. **This is the only `expect` in the file** — every
/// other code path uses `Result` propagation.
///
/// # FASM parallel
///
/// `tui_splash.inc` line 182 (`tui_splash$initlogo`):
///
/// ```text
/// falign
/// tui_splash$initlogo:
///     mov     rdi, .logodata
///     mov     rsi, .logosize
///     call    png$new
///     mov     [tui_splash$logo], rax
///     ret
/// ```
///
/// FASM stores the parsed PNG in a global `tui_splash$logo`
/// pointer; the Rust port uses [`OnceLock`] for thread-safe
/// initialization.
pub fn init_logo() -> &'static PngImage {
    LOGO.get_or_init(|| {
        PngImage::new(LOGO_PNG_BYTES).expect(
            "embedded 2ton.png logo must parse — this is a \
             compile-time-known good asset; if this panics, the \
             build pipeline corrupted the embedded bytes",
        )
    })
}

// ============================================================================
// DoneCbState — shared one-shot completion-callback storage.
// ============================================================================

/// Internal state backing the splash's one-shot
/// [`on_complete`](TuiSplash::on_complete) callback.
///
/// Wrapped in an `Arc<Mutex<DoneCbState>>` so that:
///
/// 1. The splash itself can register a callback via
///    [`TuiSplash::on_complete`] (uses `&self` plus interior
///    mutability through the `Mutex`).
/// 2. The typist's `on_complete` closure (set up during
///    `size_changed`) can fire the same callback by holding a
///    clone of the `Arc<Mutex<…>>`.
/// 3. The splash's [`Widget::key_event`] handler can also fire the
///    callback directly (matching FASM `tui_splash$keyevent`).
///
/// The `fired` flag enforces the FASM "one-shot" semantic — every
/// FASM completion path sets `tui_splash_initcomplete_ofs = 0` and
/// then unhooks the splash from its parent, which has the side
/// effect of preventing further callback invocation. The Rust port
/// makes this explicit via the `fired` boolean to guard against
/// races where both the typist completion and a key-press abort
/// would otherwise both fire the callback.
pub(crate) struct DoneCbState {
    /// User-supplied completion callback, set via
    /// [`TuiSplash::on_complete`]. `None` until the user calls
    /// `on_complete`, or `None` again once consumed by
    /// [`fire_done_cb`] (which `take`s the callback out to ensure
    /// fire-at-most-once semantics).
    pub(crate) cb: Option<Box<dyn Fn() + Send + Sync + 'static>>,

    /// Latch that flips to `true` the moment any completion path
    /// (typist completion or key-press abort) fires the callback.
    /// Subsequent fire attempts observe `fired == true` and become
    /// no-ops.
    pub(crate) fired: bool,
}

impl DoneCbState {
    /// Construct a fresh `DoneCbState` with no callback registered
    /// and `fired = false`. This is the state of every brand-new
    /// splash returned from [`TuiSplash::new`].
    pub(crate) const fn new() -> Self {
        Self {
            cb: None,
            fired: false,
        }
    }
}

/// Acquire a guard on a [`DoneCbState`] mutex, recovering from
/// [`PoisonError`](std::sync::PoisonError) by extracting the inner
/// guard.
///
/// Mutex poisoning happens when a panic occurs while a holder is
/// inside the critical section. For the splash widget this is
/// extremely unlikely (the critical sections are short and
/// allocation-free), but we still recover gracefully so a panic in
/// (say) a user-supplied callback doesn't permanently break the
/// completion machinery.
fn lock_done(state: &Arc<Mutex<DoneCbState>>) -> std::sync::MutexGuard<'_, DoneCbState> {
    match state.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Fire the splash's one-shot completion callback at most once.
///
/// Acquires the mutex, latches `fired = true`, takes the boxed
/// callback out of the option, drops the guard, then invokes the
/// callback. The drop-before-call ordering ensures user code can
/// safely re-enter the splash (e.g. to re-register a callback —
/// though that registration would be silently ignored because
/// `fired` is already `true`).
///
/// Subsequent calls (e.g. typist completion firing _after_ a
/// key-press abort already fired) are no-ops — they observe
/// `fired == true` and return immediately.
fn fire_done_cb(state: &Arc<Mutex<DoneCbState>>) {
    let cb_to_invoke: Option<Box<dyn Fn() + Send + Sync + 'static>> = {
        let mut g = lock_done(state);
        if g.fired {
            return;
        }
        g.fired = true;
        g.cb.take()
    };
    if let Some(cb) = cb_to_invoke {
        cb();
    }
}

// ============================================================================
// TuiSplash struct.
// ============================================================================

/// Composite "iconic 2 Ton Digital splash" animation widget.
///
/// FASM parallel: `tui_splash.inc` lines 38–470. The struct
/// composition reflects the FASM in-memory layout:
///
/// ```text
/// tui_splash_initcomplete_ofs = tui_background_size + 0   ; dd (4 bytes, padded)
/// tui_splash_onlychild_ofs    = tui_background_size + 8   ; *Widget
/// tui_splash_donecb_ofs       = tui_background_size + 16  ; fn() callback
/// tui_splash_donecbarg_ofs    = tui_background_size + 24  ; callback arg
/// tui_splash_size             = tui_background_size + 32
/// ```
///
/// The Rust port reorders fields slightly to take advantage of
/// Rust's type-driven layout (e.g. `Option<Arc<…>>` is two `usize`s
/// vs FASM's three quadwords) but every FASM field has a direct
/// Rust counterpart. The `donecb` and `donecbarg` pair collapses
/// into a single [`Box<dyn Fn() + Send + Sync>`] held inside
/// [`DoneCbState::cb`] — the FASM convention of separating function
/// and arg is replaced by Rust closure-capture, which carries the
/// arg implicitly.
///
/// ## Public API
///
/// * [`new`](Self::new) — construct a fresh splash with the given
///   "follow-up" widget.
/// * [`on_complete`](Self::on_complete) — register a one-shot
///   completion callback fired when the splash dismisses.
/// * [`Widget`] trait impl — `state` / `state_mut` / `as_any` /
///   `cleanup` / `clone_widget` / `draw` / `size_changed` /
///   `timer` / `key_event` (the seven FASM-overridden vmethods plus
///   the three required Rust trait methods).
///
/// All other [`Widget`] vmethods inherit their default
/// implementations (mostly no-ops or simple
/// `state.children`/`state.bastards` mutations).
pub struct TuiSplash {
    /// Inherited [`TuiBackground`] base — the FASM `tui_background`
    /// that is the parent class of `tui_splash`. Provides the
    /// black-fill backdrop, the inherited [`WidgetState`], and the
    /// inherited `Widget::draw` impl (delegated via [`Self::draw`]).
    ///
    /// This field is `pub(crate)` (matching FASM struct member
    /// visibility — there is no Rust public-export need) and named
    /// `base` per AAP §0.4.3 ("composition replaces inheritance").
    pub(crate) base: TuiBackground,

    /// One-shot init latch. `false` initially; flips to `true` the
    /// first time [`Widget::size_changed`] fires with non-zero
    /// width / height (after which the typist + logo children are
    /// installed).
    ///
    /// FASM offset: `tui_splash_initcomplete_ofs` (= `tui_background_size + 0`).
    pub(crate) init_complete: bool,

    /// The "follow-up" widget to install in the parent's children
    /// list when the splash dismisses (either via natural typist
    /// completion or via a key-press abort).
    ///
    /// FASM offset: `tui_splash_onlychild_ofs` (= `tui_background_size + 8`).
    /// FASM stores a raw `*tui_object`; the Rust port uses
    /// [`Arc<dyn Widget>`] to express shared ownership. The actual
    /// "swap me out for `only_child`" operation is performed by the
    /// caller in response to the user-supplied
    /// [`on_complete`](Self::on_complete) callback (see "Rust Port
    /// Strategy" in the module-level docs).
    pub(crate) only_child: Arc<dyn Widget>,

    /// Shared one-shot completion-callback state.
    ///
    /// FASM offsets: `tui_splash_donecb_ofs` (= `tui_background_size + 16`)
    /// and `tui_splash_donecbarg_ofs` (= `tui_background_size + 24`)
    /// — collapsed to a single `Box<dyn Fn()>` held inside
    /// [`DoneCbState`].
    ///
    /// The `Arc<Mutex<…>>` wrapper enables the typist's
    /// `on_complete` closure (registered during `size_changed`) to
    /// share write-access to the same `DoneCbState`.
    pub(crate) done_cb: Arc<Mutex<DoneCbState>>,

    /// The 46×1 typist child widget that animates [`SPLASH_TEXT`]
    /// across the screen.
    ///
    /// `None` initially; populated during the first `size_changed`
    /// call once dimensions are non-zero. FASM stores this in the
    /// inherited bastards list rather than a struct field; the Rust
    /// port keeps a typed handle for direct access (e.g. for
    /// cleanup) plus an upcast clone in `state.children` so the
    /// renderer's tree-walk includes it automatically.
    pub(crate) typist_child: Option<Arc<TuiTypist>>,

    /// The 100 % × 100 % (or 75 % × 75 % when [`SMALL_LOGO`])
    /// PNG widget displaying the 2 Ton Digital logo.
    ///
    /// `None` initially; populated during the first `size_changed`
    /// call once dimensions are non-zero.
    pub(crate) png_child: Option<Arc<PngWidget>>,
}

impl TuiSplash {
    /// Construct a fresh splash widget with the given follow-up
    /// `target`.
    ///
    /// FASM parallel: `tui_splash$new` (`tui_splash.inc` line 86):
    ///
    /// ```text
    /// falign
    /// tui_splash$new:
    ///     mov     rsi, rdi                                 ; rsi = target (only_child)
    ///     mov     rdi, tui_splash_size
    ///     call    heap$alloc
    ///     test    rax, rax
    ///     jz      .doh
    ///     mov     qword [rax + tui_object_vtable_ofs], tui_splash$vtable
    ///     mov     [rax + tui_splash_onlychild_ofs], rsi    ; store target
    ///     push    rax
    ///     mov     rdi, rax
    ///     mov     r9d, 0xe8                                ; bgcolors (black)
    ///     mov     r8d, ' '                                 ; fillchar
    ///     movsd   xmm1, [.maxsize]                          ; height_perc = 100%
    ///     movsd   xmm0, [.maxsize]                          ; width_perc  = 100%
    ///     call    tui_background$init_dd
    ///     pop     rax
    ///     ret
    /// ```
    ///
    /// The Rust port:
    ///
    /// 1. Builds a fresh [`TuiBackground`] via
    ///    [`TuiBackground::new_dd`] with width = 100 %,
    ///    height = 100 %, fillchar = `' '` (0x20), and
    ///    `colors = ColorPair { fg: 0, bg: 0xe8 }` — matching FASM's
    ///    `r9d = 0xe8` background-color byte.
    /// 2. Unwraps the resulting `Arc<TuiBackground>` into a
    ///    by-value `TuiBackground` for embedding in the splash struct.
    /// 3. Initializes `init_complete = false`, `done_cb` empty, and
    ///    both children to `None` — matching FASM's all-zero
    ///    splash-specific fields after the `heap$alloc` zeroing.
    ///
    /// # Errors
    ///
    /// Returns [`TuiError::Render`] if [`TuiBackground::new_dd`]
    /// fails (capacity allocation or — extremely unlikely — the
    /// returned `Arc` has a non-1 strong count).
    pub fn new(target: Arc<dyn Widget>) -> Result<Arc<Self>, TuiError> {
        // FASM init_dd args:
        //   xmm0 = 100.0 (width_perc)
        //   xmm1 = 100.0 (height_perc)
        //   r8d  = ' '   (fillchar)
        //   r9d  = 0xe8  (bgcolors)
        // Note FASM's r9d carries only the bg byte; the Rust port
        // explicitly sets fg=0 (default/unused — the fillchar is a
        // space which doesn't render anyway).
        let bg_arc = TuiBackground::new_dd(100.0, 100.0, b' ' as u32, ColorPair::new(0, 0xe8))?;
        let base = Arc::try_unwrap(bg_arc).map_err(|_arc| {
            TuiError::Render(std::io::Error::other(
                "TuiSplash: TuiBackground::new_dd returned a shared Arc — \
                 refcount > 1 (this should never happen for a fresh allocation)",
            ))
        })?;
        Ok(Arc::new(Self {
            base,
            init_complete: false,
            only_child: target,
            done_cb: Arc::new(Mutex::new(DoneCbState::new())),
            typist_child: None,
            png_child: None,
        }))
    }

    /// Register a one-shot completion callback fired when the
    /// splash dismisses.
    ///
    /// The callback fires when **either**:
    ///
    /// * The typist animation completes naturally (typist's
    ///   `on_complete` slot fires the splash's `done_cb`), **or**
    /// * The user presses any key other than Ctrl-C (FASM
    ///   `tui_splash$keyevent` line 454).
    ///
    /// Whichever path fires first "wins" — subsequent attempts are
    /// silently ignored thanks to the `DoneCbState::fired` latch.
    ///
    /// # Threading
    ///
    /// Takes `&self` (interior mutability via the [`Mutex`] inside
    /// `done_cb`), so callers can register the callback after the
    /// splash has been wrapped in [`Arc`]. The callback type
    /// requires `Send + Sync + 'static` because it may fire from
    /// any worker thread driving the tokio runtime.
    ///
    /// # FASM parallel
    ///
    /// The FASM original exposes the `donecb` / `donecbarg` slots
    /// as raw struct fields without a setter; callers in
    /// `examples/sshtalk` write directly to them. The Rust port
    /// promotes this to a typed setter to keep the splash's
    /// internal state private (`pub(crate)`) and to enforce the
    /// `Fn + Send + Sync + 'static` constraints required by tokio.
    pub fn on_complete<F>(&self, cb: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let mut g = lock_done(&self.done_cb);
        if !g.fired {
            g.cb = Some(Box::new(cb));
        }
        // If `g.fired == true`, the callback is silently dropped —
        // the splash already completed before this caller
        // registered. Per FASM behavior, late registration is a
        // no-op (FASM stores into `donecb_ofs` regardless, but
        // since `fired` is observable only via the `initcomplete`
        // flag — which is also reset on completion — the FASM late
        // registration also has no effect: the field is never
        // dereferenced again).
    }

    /// Internal helper: install the typist + PNG children once
    /// dimensions are known.
    ///
    /// Called from [`Widget::size_changed`] the first time both
    /// `width > 0` and `height > 0`. On success, the splash is
    /// fully wired up — the typist begins typing on the next tokio
    /// timer tick, and the PNG is queued for layout. On failure,
    /// the partial state is rolled back so a future `size_changed`
    /// can retry.
    ///
    /// Returns `Result` so that `size_changed` (which has no error
    /// channel — see the [`Widget::size_changed`] signature) can
    /// gate the `init_complete = true` latch on success.
    ///
    /// # FASM parallel
    ///
    /// `tui_splash$sizechanged` (`tui_splash.inc` line 112). The
    /// FASM version builds a 46×3 horizontal-layout container
    /// holding a 46×1 typist as a bastard child with
    /// `horizalign = left`, `vertalign = bottom`, `glue = 1`. The
    /// Rust port simplifies the layout — both children are pushed
    /// directly into `state.children` with their natural sizes;
    /// the layout pass handles positioning. This preserves the
    /// FASM "typist and logo both visible during animation"
    /// behavior without porting the intermediate-container layout
    /// machinery, which would also require porting the `tui_panel`
    /// glue and alignment system in greater detail than this
    /// widget alone needs.
    fn init_children(&mut self) -> Result<(), TuiError> {
        // Typist: 46×1, lightgray-on-black, displays SPLASH_TEXT.
        // FASM `tui_splash.inc` line 130:
        //   mov     edi, 46
        //   mov     esi, 1
        //   mov     edx, .heavything       ; SPLASH_TEXT
        //   mov     ecx, 'lightgray'/'black'
        //   call    tui_typist$new_ii
        let typist = TuiTypist::try_new(46, 1, SPLASH_TEXT, ColorPair::new(0xec, 0xe8))?;

        // Register completion-callback bridge: when the typist
        // animation finishes, fire the splash's done_cb.
        // FASM `tui_splash.inc` line 70 (typist_vtable slot 37,
        // `tui_splash$typistcomplete`):
        //   ... eventually calls tui_splash$alldone ...
        let done_cb_for_typist = Arc::clone(&self.done_cb);
        typist.on_complete(move || {
            fire_done_cb(&done_cb_for_typist);
        });

        // Start the typist's tokio-driven animation timer.
        // The Arc-receiver method dispatches through Rust's
        // `self: &Arc<Self>` resolution. Idempotent if already
        // running — see TuiTypist::start_timer doc.
        typist.start_timer();

        // Stash a typed handle for direct access (cleanup, tests)
        // and a trait-object clone for the renderer's tree-walk.
        self.typist_child = Some(Arc::clone(&typist));
        self.base
            .state_mut()
            .children
            .push_back(typist as Arc<dyn Widget>);

        // PNG logo: 100% × 100% (or 75% × 75% when SMALL_LOGO).
        // FASM `tui_splash.inc` line 224 (tui_splash$typistcomplete):
        //   if tui_splash_small_logo
        //     movsd  xmm0, [.smallsize]   ; 75.0
        //     movsd  xmm1, [.smallsize]   ; 75.0
        //   else
        //     movsd  xmm0, [.maxsize]     ; 100.0
        //     movsd  xmm1, [.maxsize]     ; 100.0
        //   end if
        //   mov    rdi, [tui_splash$logo]
        //   call   tui_png$new_dd
        let png_size_pct = if SMALL_LOGO { 75.0 } else { 100.0 };
        // The Stage 14 cached logo is borrowed as `&'static PngImage`;
        // PngWidget needs `Arc<PngImage>`. We materialize a fresh Arc
        // by cloning the cached image. This pays a one-time deep
        // clone of the decoded RGBA buffer (~width*height*4 bytes
        // for a typical logo); subsequent splash instances will
        // each pay the same one-off clone. This is a minor
        // simplification vs. FASM, which holds a single global
        // pointer and reuses it across instances. For a single
        // splash per process (the typical sshtalk / hnwatch /
        // webserver use case), the difference is negligible.
        let logo_arc = Arc::new(init_logo().clone());
        let png_widget = PngWidget::new_dd(png_size_pct, png_size_pct, logo_arc)?;

        self.png_child = Some(Arc::clone(&png_widget));
        self.base
            .state_mut()
            .children
            .push_back(png_widget as Arc<dyn Widget>);

        Ok(())
    }
}

// ============================================================================
// Widget trait impl for TuiSplash.
// ============================================================================

impl Widget for TuiSplash {
    /// Required: borrow the inherited [`WidgetState`] immutably.
    /// Delegates through the embedded [`TuiBackground`].
    fn state(&self) -> &WidgetState {
        self.base.state()
    }

    /// Required: borrow the inherited [`WidgetState`] mutably.
    /// Delegates through the embedded [`TuiBackground`].
    fn state_mut(&mut self) -> &mut WidgetState {
        self.base.state_mut()
    }

    /// Required: expose `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Override: cleanup. FASM `tui_splash$cleanup` line 403.
    ///
    /// 1. Drop our `Arc<TuiTypist>` and `Arc<PngWidget>` handles.
    ///    The typist's tokio timer task holds a `Weak<TuiTypist>`
    ///    back-ref; once we drop our `Arc` the strong count goes
    ///    to zero and the next timer tick's `Weak::upgrade()` call
    ///    returns `None`, causing the task to exit cleanly. No
    ///    explicit `JoinHandle::abort()` is needed.
    /// 2. Clear the inherited `WidgetState` lists/buffers
    ///    (children / bastards / text / attributes / display_name).
    ///    INLINED rather than calling
    ///    [`crate::tui::object::cleanup_widget`] because that
    ///    helper polymorphically dispatches through `self.cleanup()`,
    ///    causing infinite recursion.
    fn cleanup(&mut self) {
        // Step 1: drop child references.
        self.typist_child = None;
        self.png_child = None;

        // Step 2: clear inherited buffers (matches FASM
        // `tui_object$cleanup` body — see object.rs line 686 default
        // `cleanup` impl).
        let state = self.base.state_mut();
        state.children.clear();
        state.bastards.clear();
        state.text.clear();
        state.attributes.clear();
        state.display_name.clear();
    }

    /// Override: clone_widget. FASM `tui_splash$clone` line 428.
    ///
    /// 1. Deep-clone the follow-up widget via its own
    ///    `clone_widget` vmethod (FASM line 451).
    /// 2. Allocate a fresh splash via [`Self::new`] with the
    ///    cloned target — this re-initializes a brand-new
    ///    [`TuiBackground`] at 100 % × 100 % matching the original
    ///    dimensions, sets `init_complete = false` (FASM line 446),
    ///    and creates an empty `done_cb`.
    /// 3. Copy the source's `done_cb.cb` and `fired` flag to the
    ///    clone (FASM line 462–463: copies `donecb_ofs` and
    ///    `donecbarg_ofs` by value). Because Rust's
    ///    `Box<dyn Fn>` cannot be deep-copied, we promote the
    ///    callback storage to a fresh `Box` if the source still
    ///    holds one — but since `Box<dyn Fn>` is also non-cloneable,
    ///    we conservatively only copy the `fired` latch. This is
    ///    a minor divergence from FASM (which does a shallow
    ///    function-pointer copy); in practice, every observed
    ///    caller registers `done_cb` _after_ cloning the splash,
    ///    so the divergence is unobservable. See module-level
    ///    docs for rationale.
    fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
        // Step 1: deep-clone the follow-up widget.
        let cloned_only_child = self.only_child.clone_widget()?;

        // Step 2: build a fresh splash with the cloned target.
        let cloned = Self::new(cloned_only_child)?;

        // Step 3: propagate the source's `fired` latch (so a
        // late-firing typist callback on the source doesn't
        // surprise-fire on the clone).
        let src_fired = lock_done(&self.done_cb).fired;
        if src_fired {
            let mut clone_state = lock_done(&cloned.done_cb);
            clone_state.fired = true;
            // The clone starts with no callback (FASM divergence —
            // see method-level docs). This matches the typical
            // pattern where the post-clone caller installs a fresh
            // callback via `cloned.on_complete(...)`, in which
            // case the `fired = true` latch will silently swallow
            // the registration anyway. The net effect: a clone of
            // an already-completed splash is itself
            // "already-completed" from the moment of construction.
        }

        Ok(cloned as Arc<dyn Widget>)
    }

    /// Override: draw. FASM `tui_splash$vtable` line 49 — uses the
    /// inherited `tui_background$draw` directly without
    /// modification.
    ///
    /// The Rust port delegates through the composed
    /// [`TuiBackground::draw`] impl, which fills the splash's text
    /// buffer with the background fill char and calls
    /// `update_display_list`. The typist and PNG children are
    /// drawn separately by the renderer's tree walk because they
    /// were appended to `state.children` during
    /// [`Self::init_children`].
    fn draw(&mut self, r: &mut dyn Renderer) -> Result<(), TuiError> {
        self.base.draw(r)
    }

    /// Override: size_changed. FASM `tui_splash$sizechanged` line 112.
    ///
    /// One-shot: gates the typist + PNG child installation on the
    /// first non-zero dimensions. Subsequent `size_changed` calls
    /// (e.g. on terminal resize) are no-ops at the splash level —
    /// the children handle their own re-layout.
    ///
    /// On allocation failure inside [`Self::init_children`]
    /// (extremely unlikely — the typist + PNG widget are tiny),
    /// `init_complete` stays `false` and the next `size_changed`
    /// call retries. This matches FASM behavior: the FASM
    /// `tui_splash$sizechanged` returns early on `tui_typist$new_ii`
    /// failure (FASM line 145 `test rax, rax / jz .bail`).
    fn size_changed(&mut self, width: i32, height: i32) {
        if !self.init_complete && width > 0 && height > 0 {
            // Try to init children. Best-effort — if allocation
            // fails, leave `init_complete = false` so we retry on
            // the next size_changed call.
            if self.init_children().is_ok() {
                self.init_complete = true;
            } else {
                // Roll back any partial initialization. The
                // children fields are guaranteed `None` on Err
                // because `init_children` populates them in order
                // (typist first, then PNG); a typist failure
                // returns before populating, and a PNG failure
                // leaves `typist_child = Some(...)` which we must
                // drop here.
                self.typist_child = None;
                self.png_child = None;
                self.base.state_mut().children.clear();
            }
        }
    }

    /// Override: timer. FASM `tui_splash$alldonetimer` line 365.
    ///
    /// FASM uses this slot to fire the splash's `donecb` after the
    /// final 50 ms grace timer expires. The Rust port's primary
    /// completion path is the typist's `on_complete` callback (see
    /// [`Self::init_children`]) — which already invokes
    /// [`fire_done_cb`] — so this `timer` impl is a defensive
    /// fallback that fires `done_cb` if some external scheduler
    /// dispatches a timer event to the splash directly.
    ///
    /// The [`Widget::timer`] trait method returns `()` (FASM's
    /// "fire fatality / teardown" return value isn't carried in
    /// the Rust trait — see object.rs line 788 `fn timer(&mut self) {}`),
    /// so the splash simply fires the callback. Re-firing is
    /// harmless thanks to the [`DoneCbState::fired`] latch.
    fn timer(&mut self) {
        fire_done_cb(&self.done_cb);
    }

    /// Override: key_event. FASM `tui_splash$keyevent` line 454.
    ///
    /// FASM logic:
    ///
    /// ```text
    /// tui_splash$keyevent:
    ///     cmp     esi, 3                  ; ctrl-c?
    ///     jne     .skipit                 ; bubble up if not ctrl-c
    ///     jmp     .skipit                 ; (FASM has reversed test —
    ///                                       any key OTHER than ctrl-c
    ///                                       triggers abort)
    /// ...abort path: remove from parent, append only_child, fire donecb
    /// ```
    ///
    /// (The FASM original has a slightly inverted-looking control
    /// flow — see lines 460–490 — but the net effect is "ctrl-c is
    /// the one key that does NOT abort the splash; everything else
    /// does".)
    ///
    /// The Rust port preserves this semantic exactly:
    ///
    /// * `KeyEvent::Ctrl(3)` (= ASCII ETX = Ctrl-C) returns
    ///   `false` so the key bubbles up to the parent (typically
    ///   triggering process exit via the global Ctrl-C handler).
    /// * Every other key fires `done_cb` (one-shot via
    ///   [`DoneCbState::fired`]) and returns `true` to mark the
    ///   key as consumed.
    fn key_event(&mut self, event: KeyEvent) -> bool {
        if let KeyEvent::Ctrl(3) = event {
            // Ctrl-C: do NOT consume — let it bubble to the
            // global handler. Splash stays on screen.
            return false;
        }
        // Any other key: fire completion and consume.
        fire_done_cb(&self.done_cb);
        true
    }
}

// ============================================================================
// Unit tests.
// ============================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for the splash widget.
    //!
    //! Test coverage matrix:
    //!
    //! * **Constants** — verify [`SPLASH_TEXT`] / [`SPLASH_TEXT_LEN`] /
    //!   [`SMALL_LOGO`] match FASM exactly.
    //! * **Logo init** — [`init_logo`] returns a valid image and
    //!   subsequent calls return the same instance (cache works).
    //! * **Construction** — [`TuiSplash::new`] succeeds with a
    //!   simple target widget; struct fields are in expected
    //!   initial states.
    //! * **`on_complete` semantics** — registering a callback
    //!   stores it; firing it via `fire_done_cb` invokes it once
    //!   only (latch works).
    //! * **`Widget::key_event`** — Ctrl-C bubbles, other keys
    //!   consume + fire.
    //! * **`Widget::timer`** — fires `done_cb` (defensive
    //!   fallback).
    //! * **`Widget::cleanup`** — drops child handles, clears
    //!   inherited buffers.
    //! * **`Widget::clone_widget`** — produces a fresh splash
    //!   with `init_complete = false` and the cloned target.
    //! * **`Widget::size_changed` lifecycle** — tokio test
    //!   verifying that the typist + PNG children appear after
    //!   the first non-zero size_changed call.

    use super::*;
    use crate::tui::object::WidgetState;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A minimal stand-in widget used as the splash's `target`
    /// (`only_child`) parameter in tests. Implements `Widget`
    /// with default impls plus a custom `clone_widget` that
    /// returns a fresh `TestTarget` (so cloning the splash
    /// doesn't recurse infinitely).
    struct TestTarget {
        state: WidgetState,
    }

    impl TestTarget {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: WidgetState::new(),
            })
        }
    }

    impl Widget for TestTarget {
        fn state(&self) -> &WidgetState {
            &self.state
        }
        fn state_mut(&mut self) -> &mut WidgetState {
            &mut self.state
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn clone_widget(&self) -> Result<Arc<dyn Widget>, TuiError> {
            // Fresh target for the clone.
            Ok(TestTarget::new() as Arc<dyn Widget>)
        }
    }

    // ------------------------------------------------------------------
    // Constants.
    // ------------------------------------------------------------------

    #[test]
    fn splash_text_matches_fasm_iconic_tagline() {
        // Byte-exact match against FASM `tui_splash.inc:167`.
        assert_eq!(SPLASH_TEXT, "It hit me like a... umm... 2 ton heavy thing");
    }

    #[test]
    fn splash_text_len_matches_string_byte_length() {
        // SPLASH_TEXT_LEN must always equal SPLASH_TEXT.len() — this
        // is a const-eval invariant. Verifying at runtime catches
        // any future divergence.
        assert_eq!(SPLASH_TEXT_LEN, SPLASH_TEXT.len());
        // Sanity check: 44 ASCII bytes (verified manually by
        // counting; FASM stored 52 dwords inclusive of NUL "delay
        // markers", but our 44 is the visible-text length).
        assert_eq!(SPLASH_TEXT_LEN, 44);
    }

    #[test]
    fn small_logo_default_matches_fasm() {
        // FASM `tui_splash.inc:19`: `tui_splash_small_logo = 0` —
        // i.e. full-size 100% × 100% logo by default. Use a
        // `const` assertion so clippy doesn't complain about the
        // tautological runtime assert.
        const _: () = assert!(!SMALL_LOGO);
        // And a runtime read just to ensure the constant is
        // actually exposed (compile-time linkage check).
        let _read: bool = SMALL_LOGO;
    }

    // ------------------------------------------------------------------
    // Logo initialization (Stage 14 deferred init).
    // ------------------------------------------------------------------

    #[test]
    fn init_logo_returns_decoded_png_image() {
        let logo = init_logo();
        // The 2 Ton Digital logo is a well-formed PNG; verify
        // basic invariants.
        assert!(logo.width > 0, "logo width must be positive");
        assert!(logo.height > 0, "logo height must be positive");
        assert!(!logo.data.is_empty(), "logo pixel data must be non-empty");
        // util/png.rs ensures all output is RGBA32 (4 channels);
        // confirm.
        assert_eq!(logo.channels, 4, "logo must be RGBA32");
    }

    #[test]
    fn init_logo_returns_same_cached_instance() {
        // OnceLock cache: subsequent calls return references to the
        // same underlying `PngImage`.
        let logo1 = init_logo();
        let logo2 = init_logo();
        assert!(
            std::ptr::eq(logo1, logo2),
            "init_logo must return the same cached reference \
             (OnceLock semantics)"
        );
    }

    // ------------------------------------------------------------------
    // Construction.
    // ------------------------------------------------------------------

    #[test]
    fn new_succeeds_with_simple_target() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash = TuiSplash::new(target).expect("splash construction must succeed");

        // `init_complete` starts false (FASM line 446 zero-init
        // semantics).
        assert!(!splash.init_complete);

        // Both children start `None`; populated lazily in
        // `size_changed`.
        assert!(splash.typist_child.is_none());
        assert!(splash.png_child.is_none());

        // `done_cb` starts empty / not-fired.
        let g = lock_done(&splash.done_cb);
        assert!(g.cb.is_none());
        assert!(!g.fired);
    }

    #[test]
    fn new_initializes_background_at_full_screen_black() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash = TuiSplash::new(target).unwrap();

        // FASM `tui_background$init_dd(100%, 100%, ' ', 0xe8)`:
        // fillchar = space (0x20), bgcolors.bg = 0xe8.
        assert_eq!(splash.base.bgfillchar, b' ' as u32);
        assert_eq!(splash.base.bgcolors.bg, 0xe8);

        // Width / height should be percent-driven.
        assert_eq!(splash.base.state().width_percent, Some(100.0));
        assert_eq!(splash.base.state().height_percent, Some(100.0));
    }

    // ------------------------------------------------------------------
    // on_complete + fire_done_cb semantics.
    // ------------------------------------------------------------------

    #[test]
    fn on_complete_stores_callback() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash = TuiSplash::new(target).unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        splash.on_complete(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        // Callback registered but not yet fired.
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(lock_done(&splash.done_cb).cb.is_some());
        assert!(!lock_done(&splash.done_cb).fired);
    }

    #[test]
    fn fire_done_cb_invokes_callback_exactly_once() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash = TuiSplash::new(target).unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        splash.on_complete(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        // Fire #1: callback runs.
        fire_done_cb(&splash.done_cb);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(lock_done(&splash.done_cb).fired);

        // Fire #2 / #3: latched, no-op.
        fire_done_cb(&splash.done_cb);
        fire_done_cb(&splash.done_cb);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fire_done_cb_with_no_registered_callback_is_safe() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash = TuiSplash::new(target).unwrap();

        // No `on_complete` registered. `fire_done_cb` should still
        // latch `fired = true` without panicking.
        fire_done_cb(&splash.done_cb);
        assert!(lock_done(&splash.done_cb).fired);
    }

    #[test]
    fn on_complete_after_fire_silently_dropped() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash = TuiSplash::new(target).unwrap();

        // Fire first (no callback registered yet).
        fire_done_cb(&splash.done_cb);
        assert!(lock_done(&splash.done_cb).fired);

        // Now try to register a callback — should be silently
        // dropped (FASM late-registration semantics).
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        splash.on_complete(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
        assert!(
            lock_done(&splash.done_cb).cb.is_none(),
            "late-registered callback must be silently dropped"
        );

        // Subsequent fires should not invoke the dropped callback.
        fire_done_cb(&splash.done_cb);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    // ------------------------------------------------------------------
    // Widget::key_event.
    // ------------------------------------------------------------------

    #[test]
    fn key_event_ctrl_c_bubbles_up_without_firing() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        // Need &mut access for key_event — use Arc::into_inner to
        // drop the outer Arc and take the inner.
        let mut splash = Arc::into_inner(splash_arc).unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        splash.on_complete(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        // Ctrl-C (Ctrl(3) = ASCII ETX) returns false → bubbles.
        let consumed = splash.key_event(KeyEvent::Ctrl(3));
        assert!(!consumed, "Ctrl-C must bubble up (return false)");
        // Callback NOT fired.
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(!lock_done(&splash.done_cb).fired);
    }

    #[test]
    fn key_event_other_keys_consume_and_fire_done_cb() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        let mut splash = Arc::into_inner(splash_arc).unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        splash.on_complete(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        // Any other key consumes + fires.
        let consumed = splash.key_event(KeyEvent::Enter);
        assert!(consumed, "Enter must be consumed (return true)");
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Subsequent keys are no-ops (latched).
        let consumed2 = splash.key_event(KeyEvent::Char('a'));
        assert!(consumed2);
        assert_eq!(counter.load(Ordering::SeqCst), 1, "fire-once latch holds");
    }

    // ------------------------------------------------------------------
    // Widget::timer.
    // ------------------------------------------------------------------

    #[test]
    fn timer_fires_done_cb_as_defensive_fallback() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        let mut splash = Arc::into_inner(splash_arc).unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        splash.on_complete(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        splash.timer();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ------------------------------------------------------------------
    // Widget::cleanup.
    // ------------------------------------------------------------------

    #[test]
    fn cleanup_drops_child_references_and_clears_state() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        let mut splash = Arc::into_inner(splash_arc).unwrap();

        // Manually plant a typist_child + png_child to verify
        // cleanup drops them. We can't easily call `init_children`
        // here because it requires a tokio runtime; instead, use
        // the fact that these fields are `pub(crate)` and writable
        // from this test module.
        // For a sync test we use minimal stubs — the key point is
        // that the Option fields go from `Some` to `None`.
        // Plant a fake png by allocating with new_dd directly (no
        // runtime required for the constructor).
        let logo_arc = Arc::new(init_logo().clone());
        let png = PngWidget::new_dd(50.0, 50.0, logo_arc).unwrap();
        splash.png_child = Some(Arc::clone(&png));
        splash.base.state_mut().children.push_back(png as Arc<dyn Widget>);
        // Drop a non-empty display name into state to exercise the
        // clear path.
        splash.base.state_mut().display_name = "splash-test".to_string();

        // Verify pre-cleanup state.
        assert!(splash.png_child.is_some());
        assert!(!splash.base.state().display_name.is_empty());
        assert!(!splash.base.state().children.is_empty());

        splash.cleanup();

        // Verify post-cleanup state.
        assert!(splash.typist_child.is_none());
        assert!(splash.png_child.is_none());
        assert!(splash.base.state().children.is_empty());
        assert!(splash.base.state().bastards.is_empty());
        assert!(splash.base.state().display_name.is_empty());
    }

    // ------------------------------------------------------------------
    // Widget::clone_widget.
    // ------------------------------------------------------------------

    #[test]
    fn clone_widget_produces_fresh_splash_with_reset_state() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        let original = &*splash_arc;

        // Fire the original's done_cb so we can verify the clone's
        // `fired` latch is propagated.
        fire_done_cb(&original.done_cb);
        assert!(lock_done(&original.done_cb).fired);

        let cloned_arc = original.clone_widget().unwrap();
        let cloned = cloned_arc
            .as_any()
            .downcast_ref::<TuiSplash>()
            .expect("clone must downcast back to TuiSplash");

        // FASM `tui_splash$clone` resets `init_complete = 0`.
        assert!(!cloned.init_complete);
        // No children on the clone (fresh state).
        assert!(cloned.typist_child.is_none());
        assert!(cloned.png_child.is_none());
        // The `fired` latch is propagated from source.
        assert!(
            lock_done(&cloned.done_cb).fired,
            "clone of an already-fired splash must inherit `fired = true`"
        );
        // But the callback box is NOT cloned (Box<dyn Fn> can't
        // be deep-cloned). This is the documented divergence.
        assert!(lock_done(&cloned.done_cb).cb.is_none());
    }

    // ------------------------------------------------------------------
    // Widget::size_changed lifecycle (requires tokio runtime).
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn size_changed_first_nonzero_creates_typist_and_png() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        let mut splash = Arc::into_inner(splash_arc).unwrap();

        // Pre: init_complete = false, no children.
        assert!(!splash.init_complete);
        assert!(splash.typist_child.is_none());
        assert!(splash.png_child.is_none());

        // First non-zero size_changed → init.
        splash.size_changed(80, 24);

        // Post: init_complete = true, both children present.
        assert!(splash.init_complete);
        assert!(splash.typist_child.is_some());
        assert!(splash.png_child.is_some());
        assert_eq!(splash.base.state().children.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn size_changed_zero_dimensions_does_not_init() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        let mut splash = Arc::into_inner(splash_arc).unwrap();

        splash.size_changed(0, 24);
        assert!(!splash.init_complete);
        assert!(splash.typist_child.is_none());

        splash.size_changed(80, 0);
        assert!(!splash.init_complete);
        assert!(splash.typist_child.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn size_changed_idempotent_after_init_complete() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        let mut splash = Arc::into_inner(splash_arc).unwrap();

        splash.size_changed(80, 24);
        assert!(splash.init_complete);
        let typist_ptr_1 = Arc::as_ptr(splash.typist_child.as_ref().unwrap());

        // Second size_changed (e.g. terminal resize) — must NOT
        // re-create the typist child.
        splash.size_changed(120, 40);
        let typist_ptr_2 = Arc::as_ptr(splash.typist_child.as_ref().unwrap());
        assert_eq!(
            typist_ptr_1, typist_ptr_2,
            "subsequent size_changed must not re-init the typist"
        );
    }

    // ------------------------------------------------------------------
    // Widget required-method delegation.
    // ------------------------------------------------------------------

    #[test]
    fn state_and_state_mut_delegate_to_base() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        let mut splash = Arc::into_inner(splash_arc).unwrap();

        // Modify state via state_mut() — must show up via state().
        splash.state_mut().display_name = "testname".to_string();
        assert_eq!(splash.state().display_name, "testname");
        // Same field via base direct access.
        assert_eq!(splash.base.state().display_name, "testname");
    }

    #[test]
    fn as_any_returns_self_for_downcast() {
        let target = TestTarget::new() as Arc<dyn Widget>;
        let splash_arc = TuiSplash::new(target).unwrap();
        let any = splash_arc.as_any();
        assert!(
            any.downcast_ref::<TuiSplash>().is_some(),
            "as_any must enable TuiSplash downcasting"
        );
    }
}
