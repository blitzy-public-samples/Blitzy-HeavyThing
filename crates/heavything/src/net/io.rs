// HeavyThing x86_64 assembly language library — Rust translation.
//
// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! IO chain trait — the foundational abstraction of the `net` subsystem.
//!
//! This module is the Rust translation of the FASM assembly source
//! `io.inc` (9 public entry points: `io$new`, `io$addchild`, `io$destroy`,
//! `io$clone`, `io$connected`, `io$send`, `io$receive`, `io$error`,
//! `io$timeout`, plus the externally-linked `io$link`). It replaces the
//! hand-rolled 7-method virtual-method table described at
//! `io.inc` lines 31–54 with a Rust trait ([`IoChain`]) whose method
//! dispatch is handled by the compiler-generated vtable of
//! `Arc<dyn IoChain>` trait objects per AAP §0.4.3 and §0.7.1.1.
//!
//! # Directional dispatch
//!
//! Protocol layers stack into a doubly-linked chain with each layer
//! holding a strong `Arc` reference to its `child` (downstream) and a
//! `Weak` reference to its `parent` (upstream). The `Weak` parent link
//! is what prevents the stack from forming an uncollectible reference
//! cycle — this is verified by the `test_parent_weak_no_cycle`
//! unit test.
//!
//! Methods split into two directional groups preserved verbatim from
//! the FASM comment at `io.inc` lines 23–25:
//!
//! ```text
//!                                 Application
//!                                      │
//!                            ┌─────────┴─────────┐
//!                            │  BACKWARD methods │
//!                            │   connected       │
//!                            │   receive         │
//!                            │   error           │
//!                            │   timeout         │
//!                            └─────────▲─────────┘
//!                                      │ parent (Weak)
//!                                      │
//!                                  TLS layer
//!                                      │
//!                                      │ parent (Weak)
//!                                      │
//!                                  TCP socket
//!                                      │
//!                            ┌─────────▼─────────┐
//!                            │  FORWARD methods  │
//!                            │   destroy         │
//!                            │   clone_chain     │
//!                            │   send            │
//!                            └───────────────────┘
//!                                      │
//!                                   Kernel
//! ```
//!
//! * **FORWARD** — [`IoChain::destroy`], [`IoChain::clone_chain`], and
//!   [`IoChain::send`] walk *down* the chain toward the child (kernel).
//! * **BACKWARD** — [`IoChain::connected`], [`IoChain::receive`],
//!   [`IoChain::error`], and [`IoChain::timeout`] walk *up* the chain
//!   toward the parent (application).
//!
//! # Return-value conventions
//!
//! Two methods return a `bool` with load-bearing semantics preserved
//! byte-for-byte from FASM:
//!
//! * [`IoChain::receive`] — `true` means "the chain should be
//!   destroyed". Most intermediate layers simply forward the parent's
//!   return.
//! * [`IoChain::timeout`] — `true` means "the chain should die"; when a
//!   layer's parent returns `true`, the layer walks up to the topmost
//!   ancestor, destroys it, then **always returns `false`** so the
//!   caller does not re-destroy. This "walk-to-topmost-and-destroy"
//!   pattern is the canonical FASM `io$timeout .death` loop at
//!   `io.inc` lines 249–258.
//!
//! # Object-safety
//!
//! [`IoChain`] is dyn-object-safe on stable Rust without the
//! `async_trait` macro crate (which is not in AAP §0.6.1). This is
//! achieved by having every async method return a manually-boxed
//! [`BoxFuture`] rather than using `async fn` in trait, which is what
//! enables `Arc<dyn IoChain>` to work for both trait-object storage
//! and dynamic dispatch.
//!
//! # Memory-management differences from FASM
//!
//! The FASM `io$destroy` path explicitly calls `heap$free(self)` as its
//! final step (`io.inc` line 102). In Rust, deallocation happens
//! automatically when the final `Arc<Self>` reference count drops to
//! zero: the [`IoChain::destroy`] method consumes its `Arc<Self>`
//! receiver, and when no other references remain the `Drop` impl runs,
//! transitively dropping child `Arc`s. An explicit free is not needed.
//!
//! # Concurrency
//!
//! Link mutations use [`std::sync::Mutex`] (not `tokio::sync::Mutex`):
//! parent/child pointer updates are sub-microsecond operations and
//! never cross an `.await`, making an async mutex pointless. Mutex
//! poisoning is handled gracefully without `unwrap()` / `expect()`
//! per AAP §0.8.3 — a poisoned lock degrades to a best-effort no-op
//! rather than panicking.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};

use bytes::Bytes;

use crate::error::NetError;

/// Boxed, `Send`-able, `'static` future type used as the return type of
/// every async method on [`IoChain`].
///
/// Manually boxing the future is what makes [`IoChain`] dyn-object-safe
/// on stable Rust without pulling in the `async_trait` crate (not in
/// AAP §0.6.1). Concrete implementations produce these futures with
/// `Box::pin(async move { … })`.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Parent/child link state shared by every [`IoChain`] implementor.
///
/// Layout mirrors the FASM base-object offsets at `io.inc` lines
/// 31–35:
///
/// ```text
///   io_parent_ofs = 8    →  IoLinks.parent  (now Weak to break cycles)
///   io_child_ofs  = 16   →  IoLinks.child   (Arc — parent owns child)
///   io_base_size  = 24
/// ```
///
/// * `parent` is a [`Weak`] reference — the child does **not** keep
///   its parent alive. This breaks what would otherwise be an
///   uncollectible reference cycle (parent holds `Arc<Child>`; child
///   holds `Arc<Parent>`).
/// * `child` is a strong [`Arc`] — the parent **does** keep its child
///   alive for the full duration of the parent's own lifetime. When
///   the final `Arc<Parent>` is released, the `Drop` chain releases
///   the child `Arc`, which (if it holds the last reference) drops
///   the child's `Arc`, and so on down the stack.
///
/// Both fields are wrapped in [`Mutex`] because link re-wiring
/// (e.g., reconnection, renegotiation) can race with other threads
/// that are traversing the chain. The critical sections are tiny and
/// never cross `.await`, so the synchronous `std` mutex is the right
/// choice.
pub struct IoLinks {
    parent: Mutex<Weak<dyn IoChain>>,
    child: Mutex<Option<Arc<dyn IoChain>>>,
}

impl IoLinks {
    /// Construct a new empty-links state with no parent and no child.
    ///
    /// This is the Rust equivalent of the two `mov qword [… + io_parent_ofs], 0`
    /// and `mov qword [… + io_child_ofs], 0` instructions at
    /// `io.inc` lines 65–66. The
    /// [`Weak::<ConcreteNever>::new()`][Weak::new] expression yields a
    /// never-upgradable weak pointer, which coerces transparently to
    /// `Weak<dyn IoChain>` thanks to Rust's unsized-coercion rules.
    pub fn new() -> Self {
        Self {
            parent: Mutex::new(Weak::<ConcreteNever>::new()),
            child: Mutex::new(None),
        }
    }

    /// Return the current parent (upgrading the stored [`Weak`]) or
    /// `None` if no parent has been set or the parent has been
    /// dropped.
    ///
    /// A poisoned lock is treated as "no parent" rather than
    /// panicking — the caller sees the same behaviour as if the
    /// chain had not yet been linked. Poisoning can occur only if a
    /// prior holder of the lock panicked; in the HeavyThing trait
    /// the critical sections are trivial pointer moves so poisoning
    /// is effectively impossible in practice.
    pub fn parent(&self) -> Option<Arc<dyn IoChain>> {
        self.parent.lock().ok()?.upgrade()
    }

    /// Return the current child (cloning the stored [`Arc`]) or
    /// `None` if no child has been set.
    ///
    /// A poisoned lock is treated as "no child" — see [`Self::parent`]
    /// for the rationale.
    pub fn child(&self) -> Option<Arc<dyn IoChain>> {
        self.child.lock().ok()?.clone()
    }

    /// Internal: set or clear the child pointer. Used by [`link`].
    ///
    /// Lock poisoning is swallowed silently — after a panic in a
    /// sibling thread we prefer to leave the link in its previous
    /// state rather than escalate the panic.
    fn set_child(&self, c: Option<Arc<dyn IoChain>>) {
        if let Ok(mut g) = self.child.lock() {
            *g = c;
        }
    }

    /// Internal: set the parent pointer. Used by [`link`].
    fn set_parent(&self, p: Weak<dyn IoChain>) {
        if let Ok(mut g) = self.parent.lock() {
            *g = p;
        }
    }
}

impl Default for IoLinks {
    fn default() -> Self {
        Self::new()
    }
}

/// Uninhabited-in-practice placeholder used only as the phantom type
/// argument to `Weak::<T>::new()` when initializing an empty
/// `Weak<dyn IoChain>`.
///
/// [`Weak::new`] requires `T: Sized`, which `dyn IoChain` is not.
/// The idiomatic Rust trick is to construct the `Weak` with a
/// concrete sized type that implements the trait, then rely on
/// unsized coercion to convert the `Weak<ConcreteNever>` into a
/// `Weak<dyn IoChain>` automatically.
///
/// Because the weak pointer is produced by
/// [`Weak::new`][std::sync::Weak::new] with **no** corresponding
/// strong `Arc`, it is permanently un-upgradable — no
/// `ConcreteNever` instance is ever actually allocated on the heap,
/// and none of the `unreachable!()` method bodies can ever execute
/// in safe code.
struct ConcreteNever;

impl IoChain for ConcreteNever {
    fn links(&self) -> &IoLinks {
        unreachable!("ConcreteNever is never instantiated")
    }
    fn destroy(self: Arc<Self>) -> BoxFuture<()> {
        unreachable!("ConcreteNever is never instantiated")
    }
    fn clone_chain(self: Arc<Self>) -> BoxFuture<Option<Arc<dyn IoChain>>> {
        unreachable!("ConcreteNever is never instantiated")
    }
    fn connected(self: Arc<Self>, _: Option<std::net::SocketAddr>) -> BoxFuture<()> {
        unreachable!("ConcreteNever is never instantiated")
    }
    fn send(self: Arc<Self>, _: Bytes) -> BoxFuture<Result<(), NetError>> {
        unreachable!("ConcreteNever is never instantiated")
    }
    fn receive(self: Arc<Self>, _: Bytes) -> BoxFuture<bool> {
        unreachable!("ConcreteNever is never instantiated")
    }
    fn error(self: Arc<Self>, _: NetError) -> BoxFuture<()> {
        unreachable!("ConcreteNever is never instantiated")
    }
    fn timeout(self: Arc<Self>) -> BoxFuture<bool> {
        unreachable!("ConcreteNever is never instantiated")
    }
}

/// Link two IO layers together: `parent` becomes the parent of
/// `child`, `child` becomes the child of `parent`.
///
/// This is the combined Rust equivalent of FASM `io$addchild`
/// (`io.inc` lines 74–80) and `io$link` (lines 265–273), which were
/// textually identical in the assembly source.
///
/// * `parent.child` is set to a strong clone of `child` (the parent
///   owns the child for its entire lifetime).
/// * `child.parent` is set to a downgraded [`Weak`] of `parent` (the
///   child does **not** keep the parent alive; this breaks the
///   reference cycle).
pub fn link(parent: &Arc<dyn IoChain>, child: Arc<dyn IoChain>) {
    parent.links().set_child(Some(Arc::clone(&child)));
    child.links().set_parent(Arc::downgrade(parent));
}

/// Default `destroy` helper — walks FORWARD to the child (if any)
/// and invokes its [`IoChain::destroy`] method.
///
/// This is the Rust equivalent of the FASM `io$destroy` base body
/// at `io.inc` lines 86–106. The FASM additionally performs a
/// `heap$free(self)` at line 102; this has no Rust counterpart
/// because `Drop` on the containing `Arc<Self>` handles deallocation
/// automatically once the last reference is released.
///
/// Concrete layers override [`IoChain::destroy`] and typically call
/// this helper as their final step (after releasing any
/// layer-specific resources).
pub async fn default_destroy(links: &IoLinks) {
    if let Some(child) = links.child() {
        child.destroy().await;
    }
}

/// Default `connected` helper — walks BACKWARD to the parent (if
/// any) and invokes its [`IoChain::connected`] method with the
/// passed-through peer address.
///
/// Rust equivalent of FASM `io$connected` base body at `io.inc`
/// lines 151–164. The optional `peer` is populated on ingress
/// (i.e., `accept()`-side) and typically `None` on egress.
pub async fn default_connected(links: &IoLinks, peer: Option<std::net::SocketAddr>) {
    if let Some(parent) = links.parent() {
        parent.connected(peer).await;
    }
}

/// Default `send` helper — walks FORWARD to the child (if any) and
/// invokes its [`IoChain::send`] method.
///
/// Rust equivalent of FASM `io$send` base body at `io.inc`
/// lines 168–182. When there is no child the call is a silent no-op
/// returning `Ok(())`; the bottom-most layer (typically a TCP
/// socket) is expected to override `send` to actually write bytes.
pub async fn default_send(links: &IoLinks, data: Bytes) -> Result<(), NetError> {
    if let Some(child) = links.child() {
        return child.send(data).await;
    }
    Ok(())
}

/// Default `receive` helper — walks BACKWARD to the parent (if any)
/// and returns the parent's `bool` indicating whether the chain
/// should be destroyed.
///
/// Rust equivalent of FASM `io$receive` base body at `io.inc` lines
/// 188–205. When there is no parent (i.e., the top of the chain has
/// been reached) the method returns `false`, matching the FASM's
/// `xor eax, eax` / `ret` fall-through path at line 200.
pub async fn default_receive(links: &IoLinks, data: Bytes) -> bool {
    if let Some(parent) = links.parent() {
        parent.receive(data).await
    } else {
        false
    }
}

/// Default `error` helper — walks BACKWARD to the parent (if any)
/// and invokes its [`IoChain::error`] method.
///
/// Rust equivalent of FASM `io$error` base body at `io.inc` lines
/// 211–224. Notification only; this path is **not** responsible for
/// destroying the chain (that is the caller's decision after the
/// error has been observed).
pub async fn default_error(links: &IoLinks, err: NetError) {
    if let Some(parent) = links.parent() {
        parent.error(err).await;
    }
}

/// Default `timeout` helper — walks BACKWARD to the parent asking
/// whether it considers the timer a fatality, and if so destroys
/// the topmost ancestor.
///
/// Rust equivalent of the FASM `io$timeout` base body at `io.inc`
/// lines 229–258. The logic is:
///
/// 1. If there is no parent, return `false` (no death requested).
/// 2. Ask the parent via [`IoChain::timeout`]. If it returns `false`,
///    return `false` ourselves — the chain lives.
/// 3. If the parent returned `true`, walk up from `parent` to the
///    topmost ancestor (the first node with no parent of its own),
///    invoke its [`IoChain::destroy`] method, and return `false`.
///
/// The "always return `false` after destruction" convention is
/// load-bearing: it tells the caller that the chain has already
/// been torn down (via the topmost-destroy walk) and therefore does
/// **not** need a second destroy pass. This matches FASM's
/// `.death_topmost:` path which explicitly sets `xor eax, eax`
/// before `ret` at `io.inc` lines 257–258.
pub async fn default_timeout(links: &IoLinks) -> bool {
    let Some(parent) = links.parent() else {
        return false;
    };
    let parent_wants_death = parent.clone().timeout().await;
    if !parent_wants_death {
        return false;
    }

    // Walk up from `parent` (not self!) to the topmost ancestor.
    // This matches the FASM loop at lines 250–256 where rdi starts
    // pre-advanced to parent before the .death label is entered.
    let mut topmost = parent;
    loop {
        let Some(grand) = topmost.links().parent() else {
            break;
        };
        topmost = grand;
    }
    topmost.destroy().await;
    false
}

/// Protocol-layer trait — every IO layer (TCP, TLS, SSH, HTTP, …)
/// implements this trait and is held as `Arc<dyn IoChain>` by the
/// chain's neighbours.
///
/// Implementors typically store an [`IoLinks`] field for
/// parent/child state and delegate the default methods to the
/// `default_*` free functions in this module, overriding only the
/// methods they specialize. For example, a TCP layer overrides
/// [`send`][Self::send] to actually write bytes to the socket, and
/// overrides [`destroy`][Self::destroy] to close the file
/// descriptor before forwarding to children.
///
/// See the [module-level documentation](self) for the FORWARD vs
/// BACKWARD directional semantics that the method set embodies.
pub trait IoChain: Send + Sync + 'static {
    /// Return a reference to this layer's parent/child link state.
    ///
    /// This is the single piece of plumbing every implementor must
    /// provide; all other methods' default forms can be implemented
    /// in terms of this plus the `default_*` helpers.
    fn links(&self) -> &IoLinks;

    /// FORWARD — destroy this layer and its subchain.
    ///
    /// The base-default behavior delegates to [`default_destroy`],
    /// which walks FORWARD to the child (if any) and invokes the
    /// child's `destroy`. The containing `Arc<Self>` receiver is
    /// consumed; when the last reference is released, `Drop` runs
    /// and the layer is deallocated automatically.
    ///
    /// This method does **not** walk up to the parent; callers that
    /// need to tear down the entire chain (e.g.,
    /// [`default_timeout`]) are responsible for walking to the
    /// topmost ancestor first.
    fn destroy(self: Arc<Self>) -> BoxFuture<()>;

    /// FORWARD — clone this layer and, optionally, its subchain.
    ///
    /// Returns a new `Arc<dyn IoChain>` that is a duplicate of the
    /// receiving layer and is **not** linked to any parent (i.e.,
    /// the clone's `parent` is empty). Returns `None` for layers
    /// that are not safely clonable.
    ///
    /// Rust equivalent of FASM `io$clone` at `io.inc` lines 112–146.
    fn clone_chain(self: Arc<Self>) -> BoxFuture<Option<Arc<dyn IoChain>>>;

    /// FORWARD — send `data` downstream toward the kernel.
    ///
    /// The base-default behavior delegates to [`default_send`],
    /// which walks FORWARD to the child (if any) and forwards. The
    /// leaf layer (typically a TCP socket) overrides this method to
    /// perform the actual write.
    fn send(self: Arc<Self>, data: Bytes) -> BoxFuture<Result<(), NetError>>;

    /// BACKWARD — notify the parent that the underlying transport
    /// has connected.
    ///
    /// The base-default behavior delegates to [`default_connected`],
    /// which walks BACKWARD to the parent (if any). The `peer`
    /// argument is the remote socket address on ingress (i.e.,
    /// `accept()`-side); it is typically `None` on egress.
    fn connected(self: Arc<Self>, peer: Option<std::net::SocketAddr>) -> BoxFuture<()>;

    /// BACKWARD — deliver received `data` upstream.
    ///
    /// The base-default behavior delegates to [`default_receive`],
    /// which walks BACKWARD to the parent (if any) and returns the
    /// parent's `bool`. A return of `true` tells the caller that
    /// the chain should be destroyed; `false` means the chain
    /// remains live.
    fn receive(self: Arc<Self>, data: Bytes) -> BoxFuture<bool>;

    /// BACKWARD — notify the parent of an error.
    ///
    /// The base-default behavior delegates to [`default_error`],
    /// which walks BACKWARD to the parent (if any). This path is
    /// notification-only — it is **not** responsible for destroying
    /// the chain; that decision is made by the caller after observing
    /// the error.
    fn error(self: Arc<Self>, err: NetError) -> BoxFuture<()>;

    /// BACKWARD — report a timer expiry to the parent and, if the
    /// parent considers it fatal, tear down the entire chain.
    ///
    /// The base-default behavior delegates to [`default_timeout`],
    /// which implements the three-step FASM `io$timeout` logic: ask
    /// the parent; if the parent returns `true`, walk up to the
    /// topmost ancestor and destroy it; **always** return `false`
    /// after a destruction has occurred so the caller does not
    /// re-destroy.
    fn timeout(self: Arc<Self>) -> BoxFuture<bool>;
}

/// No-op IO layer matching the FASM `io$new` constructor at
/// `io.inc` lines 62–69.
///
/// [`IoBase`] provides a trivial [`IoChain`] implementation whose
/// methods all delegate to the `default_*` free helpers. It is
/// useful as:
///
/// * A placeholder while building larger chains.
/// * A unit-test fixture that exercises chain-topology behavior
///   (linking, cycle-freedom, forward/backward traversal) without
///   depending on any real protocol implementation.
///
/// Concrete protocol layers (TCP, TLS, SSH, HTTP, …) do **not**
/// extend `IoBase`; they implement [`IoChain`] directly and embed
/// an [`IoLinks`] field of their own.
///
/// [`Default`] is derived — it produces the same state as
/// [`IoBase::new`] minus the `Arc` wrapping (i.e., an owned
/// [`IoBase`] with empty [`IoLinks`]). Use [`IoBase::new`] when
/// you need the conventional `Arc<Self>` form, or
/// `IoBase::default()` when you need plain ownership.
#[derive(Default)]
pub struct IoBase {
    links: IoLinks,
}

impl IoBase {
    /// Construct a new no-op layer wrapped in an `Arc`.
    ///
    /// Returns `Arc<Self>` rather than `Self` because [`IoChain`]
    /// methods take `self: Arc<Self>` receivers — callers virtually
    /// always want the `Arc` form anyway.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            links: IoLinks::new(),
        })
    }
}

impl IoChain for IoBase {
    fn links(&self) -> &IoLinks {
        &self.links
    }

    fn destroy(self: Arc<Self>) -> BoxFuture<()> {
        Box::pin(async move { default_destroy(&self.links).await })
    }

    fn clone_chain(self: Arc<Self>) -> BoxFuture<Option<Arc<dyn IoChain>>> {
        Box::pin(async move { Some(IoBase::new() as Arc<dyn IoChain>) })
    }

    fn connected(self: Arc<Self>, peer: Option<std::net::SocketAddr>) -> BoxFuture<()> {
        Box::pin(async move { default_connected(&self.links, peer).await })
    }

    fn send(self: Arc<Self>, data: Bytes) -> BoxFuture<Result<(), NetError>> {
        Box::pin(async move { default_send(&self.links, data).await })
    }

    fn receive(self: Arc<Self>, data: Bytes) -> BoxFuture<bool> {
        Box::pin(async move { default_receive(&self.links, data).await })
    }

    fn error(self: Arc<Self>, err: NetError) -> BoxFuture<()> {
        Box::pin(async move { default_error(&self.links, err).await })
    }

    fn timeout(self: Arc<Self>) -> BoxFuture<bool> {
        Box::pin(async move { default_timeout(&self.links).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_iobase_solo() {
        // A solitary IoBase (no parent, no child) should accept a
        // destroy call without panicking — all default paths simply
        // no-op when the relevant neighbour link is absent.
        let io = IoBase::new();
        io.clone().destroy().await;
    }

    #[tokio::test]
    async fn test_iobase_send_noop_when_no_child() {
        // send() with no child returns Ok(()) silently (FASM
        // io$send base body fall-through at io.inc line 171).
        let io = IoBase::new();
        let r = io.send(Bytes::from_static(b"hello")).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn test_iobase_receive_returns_false_at_top() {
        // receive() with no parent returns false (FASM io$receive
        // xor eax, eax fall-through at io.inc line 200).
        let io = IoBase::new();
        let destroyed = io.receive(Bytes::from_static(b"hello")).await;
        assert!(!destroyed);
    }

    #[tokio::test]
    async fn test_link_parent_child() {
        // link() wires parent→child (strong Arc) and child→parent
        // (Weak, upgradable while parent is alive).
        let p: Arc<dyn IoChain> = IoBase::new();
        let c: Arc<dyn IoChain> = IoBase::new();
        link(&p, Arc::clone(&c));
        assert!(p.links().child().is_some(), "parent should see child");
        assert!(c.links().parent().is_some(), "child should upgrade weak parent");
    }

    #[tokio::test]
    async fn test_chain_three_layers() {
        // Exercise a 3-layer chain: top ← mid ← bot.
        // send() from top walks DOWN through mid to bot.
        // receive() from bot walks UP through mid to top.
        let top: Arc<dyn IoChain> = IoBase::new();
        let mid: Arc<dyn IoChain> = IoBase::new();
        let bot: Arc<dyn IoChain> = IoBase::new();
        link(&top, Arc::clone(&mid));
        link(&mid, Arc::clone(&bot));

        let r = top.clone().send(Bytes::from_static(b"x")).await;
        assert!(r.is_ok(), "send should propagate forward without error");

        let destroyed = bot.clone().receive(Bytes::from_static(b"x")).await;
        assert!(
            !destroyed,
            "receive walked up to topmost (no parent) and returned false"
        );
    }

    #[tokio::test]
    async fn test_timeout_default_returns_false() {
        // A solitary IoBase with no parent returns false from
        // timeout (FASM io$timeout fall-through when io_parent_ofs
        // is zero at io.inc lines 233–234).
        let io = IoBase::new();
        assert!(!io.timeout().await);
    }

    #[tokio::test]
    async fn test_parent_weak_no_cycle() {
        // CRITICAL: verifies that the parent→child strong Arc +
        // child→parent Weak design avoids reference cycles. After
        // all external Arcs are dropped, the parent's Weak should
        // fail to upgrade — proving the allocation was freed.
        let weak_check: std::sync::Weak<dyn IoChain>;
        {
            let p: Arc<dyn IoChain> = IoBase::new();
            let c: Arc<dyn IoChain> = IoBase::new();
            link(&p, Arc::clone(&c));
            weak_check = Arc::downgrade(&p);
            drop(c);
            drop(p);
        }
        assert!(
            weak_check.upgrade().is_none(),
            "parent should be freed once no external Arc remains"
        );
    }

    /// Custom IoChain layer that always signals death from its
    /// `timeout` method. Used by
    /// [`test_timeout_propagation_to_topmost`] below to force the
    /// walk-to-topmost-and-destroy path in [`default_timeout`].
    struct DeathyTimeout(IoLinks);

    impl IoChain for DeathyTimeout {
        fn links(&self) -> &IoLinks {
            &self.0
        }
        fn destroy(self: Arc<Self>) -> BoxFuture<()> {
            Box::pin(async move { default_destroy(&self.0).await })
        }
        fn clone_chain(self: Arc<Self>) -> BoxFuture<Option<Arc<dyn IoChain>>> {
            Box::pin(async move { None })
        }
        fn connected(self: Arc<Self>, peer: Option<std::net::SocketAddr>) -> BoxFuture<()> {
            Box::pin(async move { default_connected(&self.0, peer).await })
        }
        fn send(self: Arc<Self>, data: Bytes) -> BoxFuture<Result<(), NetError>> {
            Box::pin(async move { default_send(&self.0, data).await })
        }
        fn receive(self: Arc<Self>, data: Bytes) -> BoxFuture<bool> {
            Box::pin(async move { default_receive(&self.0, data).await })
        }
        fn error(self: Arc<Self>, err: NetError) -> BoxFuture<()> {
            Box::pin(async move { default_error(&self.0, err).await })
        }
        /// Override: always return true, forcing the caller into
        /// the `default_timeout` .death path.
        fn timeout(self: Arc<Self>) -> BoxFuture<bool> {
            Box::pin(async move { true })
        }
    }

    #[tokio::test]
    async fn test_timeout_propagation_to_topmost() {
        // Chain: top (DeathyTimeout) ← mid (IoBase) ← bot (IoBase).
        //
        // Tracing:
        //   bot.timeout() → default_timeout walks up to mid
        //   mid.timeout() → default_timeout walks up to top
        //   top.timeout() → DeathyTimeout returns TRUE
        //   Back in mid's default_timeout: parent_wants_death = true
        //     → walk up from parent(=top) to topmost (top has no parent)
        //     → topmost.destroy() is invoked
        //     → return false
        //   Back in bot's default_timeout: parent_wants_death = false
        //     (mid's default_timeout always returns false after
        //     destruction, per FASM convention at io.inc lines 257–258)
        //     → return false
        //
        // Overall bot.timeout() returns false, and the whole chain
        // has been destroyed via the topmost-destroy walk.
        let top: Arc<dyn IoChain> = Arc::new(DeathyTimeout(IoLinks::new()));
        let mid: Arc<dyn IoChain> = IoBase::new();
        let bot: Arc<dyn IoChain> = IoBase::new();
        link(&top, Arc::clone(&mid));
        link(&mid, Arc::clone(&bot));

        let died = bot.clone().timeout().await;
        assert!(
            !died,
            "bot.timeout() returns false even though top signalled death"
        );
    }
}
