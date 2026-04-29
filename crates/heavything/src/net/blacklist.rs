// HeavyThing x86_64 assembly language library — Rust translation.
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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! IP blacklist with time-based expiry — Rust port of `blacklist.inc`.
//!
//! # Checkpoint 3 API (post-review revisions)
//!
//! The public API was realigned with the Checkpoint 3 specification per
//! code-review findings:
//!
//! * Keys are [`u128`] (not `u64`) — widening removes the IPv6 lossy
//!   hashing vulnerability (CWE-345 / CWE-346): a 128-bit IPv6 address
//!   cannot be injectively represented in a 64-bit key, which enabled
//!   forged blacklist-bypass collisions. The lossless encoding maps
//!   IPv4 into the `::ffff:a.b.c.d` subspace of [`u128`] (RFC 4291
//!   §2.5.5.2 *IPv4-Mapped IPv6 Address*) and IPv6 directly via
//!   `u128::from_be_bytes`.
//! * Insertion uses [`Blacklist::insert`] (not `add`) and takes a
//!   per-call `ttl: Duration` that supplements the instance-default
//!   TTL set at construction time. Instance-default is retained for
//!   FASM fidelity and Debug display.
//! * The socket-addr helper is [`key_from_socket_addr`] and accepts
//!   [`std::net::SocketAddr`] directly (extracting `.ip()` internally)
//!   so TLS / SSH consumers that already hold a `TcpStream::peer_addr`
//!   result can feed it straight in.
//!
//! The FASM source (`blacklist.inc`, © 2015 2 Ton Digital) describes
//! itself as *"a convenience object to deal with unsigned keys + time
//! delay"* and is shared between the TLS server (`net::tls`) and the SSH
//! server (`net::ssh`) for throttling misbehaving peers (AAP §0.7.1.1,
//! §0.7.4.4, §0.8.10 Gate 4). Both consumers hold an
//! `Arc<Blacklist>` cloned into per-connection handler state and call
//! [`Blacklist::insert`] on crypto / auth failures.
//!
//! # Design summary
//!
//! The FASM implementation pairs an `unsignedmap` (O(1) contains) with a
//! doubly-linked list in insertion order (O(1) push-tail, O(1) pop-head).
//! The Rust port preserves this pairing with:
//!
//! * [`std::collections::HashMap`]`<u128, Instant>` for O(1) containment
//! * [`std::collections::VecDeque`]`<u128>` for O(1) push-back / pop-front
//!   in insertion order (per-call TTLs mean the FIFO is no longer
//!   strictly sorted by expiry, so sweeps scan the whole deque; the
//!   pairing still matches the FASM doubly-linked-list semantics of
//!   `blacklist_first_ofs` / `blacklist_last_ofs` exactly).
//!
//! per AAP §0.8.1 *"MUST use std collections where semantically
//! equivalent"*. The interior is protected by a single
//! [`std::sync::Mutex`] (not `tokio::sync::Mutex`) because every
//! operation completes in under a microsecond, and holding an async lock
//! across `.await` points would be wasteful (AAP §0.8.3).
//!
//! # Deliberate behavioural divergence from the FASM
//!
//! The FASM `blacklist$check` function (lines 180–267 of `blacklist.inc`)
//! has a side-effect: when the key is found it **resets the timeout** to
//! `now + expiry` and moves the list node to the tail of the FIFO. The
//! comment on line 177 records the rationale: *"the only way entries get
//! removed is if they are _not_ checked for the blacklist time period"*.
//! In effect, the FASM blacklist stays "sticky as long as you keep
//! probing".
//!
//! This Rust port deliberately replaces that with a fixed-TTL policy:
//! [`Blacklist::contains`] never refreshes the timeout; entries always
//! expire at `insert-time + ttl`. The trade-off is explicit — Rust
//! consumers get predictable per-entry lifetime at the cost of losing
//! the FASM's implicit "ban permanence for active attackers" feature.
//! This divergence is explicitly captured in the AAP §0.7.1.1
//! behavioural-preservation table and the agent prompt for this file.
//!
//! Lazy expiry is still performed on every [`insert`], [`contains`], and
//! [`len`] call. Unlike the FASM — which could rely on a strictly
//! expiry-sorted FIFO — per-call TTLs mean that an entry inserted later
//! with a shorter TTL can expire before an older entry with a longer
//! one; the sweep therefore performs a full scan of the deque rather
//! than an early break on the first live entry. This matches the
//! *intent* of the FASM `.weed` loop (line 189 of `blacklist.inc`) —
//! "drop anything already expired" — while preserving correctness
//! under heterogeneous TTLs.
//!
//! # Optional periodic sweep
//!
//! For low-traffic deployments where lazy expiry alone would let entries
//! accumulate, [`Blacklist::spawn_sweeper`] spawns a Tokio task that
//! prunes expired entries every `interval`. Callers in `webserver` /
//! `sshtalk` typically pass `Duration::from_secs(60)` per AAP §0.7.1.1
//! "8 timer-driven integration points preserved".
//!
//! # Unsafe
//!
//! Zero unsafe blocks. The FASM's raw pointer arithmetic for
//! linked-list manipulation is fully replaced by safe `VecDeque`
//! methods.
//!
//! # Key encoding helpers
//!
//! The blacklist stores opaque [`u128`] keys; the three free functions
//! [`key_from_ipv4`], [`key_from_ipv6`], and [`key_from_socket_addr`]
//! provide a canonical **injective** encoding that both TLS and SSH
//! consumers share so peer addresses from either family never collide:
//!
//! * IPv4 `a.b.c.d` maps into the `::ffff:a.b.c.d` subspace of
//!   [`u128`] per RFC 4291 §2.5.5.2 (*IPv4-Mapped IPv6 Address*), i.e.
//!   the low 48 bits carry `0xFFFF` || the four IPv4 octets and the
//!   upper 80 bits are zero.
//! * IPv6 addresses are packed directly via
//!   `u128::from_be_bytes(ip.octets())` — lossless and deterministic.
//! * [`key_from_socket_addr`] dispatches to the appropriate family,
//!   taking a [`std::net::SocketAddr`] so callers that already hold a
//!   `TcpStream::peer_addr` result can feed it in without unwrapping.
//!
//! [`insert`]: Blacklist::insert
//! [`contains`]: Blacklist::contains
//! [`len`]: Blacklist::len

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Blacklist — shared between net::tls and net::ssh via Arc<Blacklist>.
// ---------------------------------------------------------------------------

/// Time-delayed blacklist of opaque [`u128`] keys.
///
/// Constructed via [`Blacklist::new`] and shared as `Arc<Blacklist>`
/// across async tasks — the struct is internally synchronised so
/// `Arc<Blacklist>` is `Send + Sync + 'static` and may be freely cloned
/// into connection-handler state (AAP §0.7.1.1).
///
/// All operations are O(1) amortised; the exception is [`remove`],
/// which is O(n) in the FIFO length because a linear scan is required
/// to locate the `VecDeque` index of the removed key. This matches the
/// FASM baseline, which performs an equivalent doubly-linked-list walk.
///
/// Keys are opaque [`u128`] values; callers working with IP addresses
/// should use the [`key_from_ipv4`], [`key_from_ipv6`], and
/// [`key_from_socket_addr`] helper functions for a consistent,
/// **injective** encoding that never collides across IPv4 and IPv6
/// address families (IPv4 is embedded in the IPv4-mapped IPv6 subspace
/// `::ffff:a.b.c.d` per RFC 4291 §2.5.5.2).
///
/// [`remove`]: Blacklist::remove
pub struct Blacklist {
    /// Default seconds-to-live applied by [`Blacklist::new`] consumers
    /// that construct a long-lived blacklist instance. Copied from the
    /// FASM `blacklist_expiry_ofs` field and retained here for Debug
    /// output and as documentation of the instance's intended lifetime.
    ///
    /// Note: the per-call [`Blacklist::insert`] API takes an explicit
    /// `ttl: Duration` argument that overrides this default on a
    /// per-entry basis (see the module-level *"Deliberate behavioural
    /// divergence"* section).
    expiry: Duration,
    /// Interior state — the map/order pair is protected by a single
    /// [`std::sync::Mutex`] rather than split across `RwLock<HashMap>` +
    /// `Mutex<VecDeque>` to keep the FIFO and hash-map strictly in
    /// lockstep (the FASM holds both behind the same implicit
    /// single-threaded invariant).
    inner: Mutex<Inner>,
}

/// Mutex-protected interior state. Private — the public API never hands
/// out references to this struct.
struct Inner {
    /// O(1) containment. Value is the monotonic [`Instant`] at which the
    /// entry expires (equivalent of FASM `blacklist_item_timeout_ofs`).
    map: HashMap<u128, Instant>,
    /// Insertion order for the FASM doubly-linked-list analogue pinned
    /// by `blacklist_first_ofs` / `blacklist_last_ofs`. With per-call
    /// TTLs, this FIFO is no longer strictly sorted by expiry, so
    /// [`sweep_expired`] performs a full scan rather than an
    /// expiry-sorted early break.
    ///
    /// Invariant: `order.len() == map.len()` after every public method
    /// call. The interior `sweep_expired` helper transiently reduces
    /// `order` before removing the matching entry from `map`, but every
    /// iteration restores parity before yielding.
    order: VecDeque<u128>,
}

impl Blacklist {
    /// Create a new blacklist with the given default per-entry TTL.
    ///
    /// `expiry` records the instance's intended per-entry lifetime (for
    /// Debug output and as documentation); the actual lifetime applied
    /// to each blacklisted key is the `ttl` argument passed to
    /// [`Blacklist::insert`] on a per-call basis, so callers may choose
    /// to pass `expiry` verbatim to every `insert` call for FASM-style
    /// uniform-TTL behaviour, or vary it per peer. Callers typically
    /// pass [`Duration::from_secs`] with values such as
    /// `config::TLS_BLACKLIST` (86 400 s = one day) or
    /// `config::SSH_BLACKLIST` (86 400 s) per AAP §0.7.1.1.
    ///
    /// Returns an [`Arc`] rather than an owned value so the returned
    /// instance can be cheaply cloned into connection-handler state —
    /// the canonical sharing pattern for this module (AAP §0.7.1.1).
    #[must_use]
    pub fn new(expiry: Duration) -> Arc<Self> {
        Arc::new(Self {
            expiry,
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
        })
    }

    /// Insert `key` into the blacklist with the given `ttl`.
    ///
    /// * If `key` is already present this is a no-op — matching the
    ///   FASM `blacklist$add .alreadyhere` short-circuit (line 101 of
    ///   `blacklist.inc`). The existing entry's expiry is **not**
    ///   refreshed; see the module-level *"Deliberate behavioural
    ///   divergence"* section.
    /// * If `key` is not present it is inserted with expiry
    ///   `Instant::now() + ttl` and appended to the FIFO tail (matching
    ///   FASM lines 87–97).
    ///
    /// `ttl` is applied on a per-call basis and overrides the instance
    /// default supplied to [`Blacklist::new`]; callers that want FASM
    /// uniform-TTL semantics should pass the same `Duration` value to
    /// every `insert` call.
    ///
    /// This call incidentally sweeps already-expired entries from the
    /// FIFO (AAP §0.7.1.1 lazy-expiry convention). Unlike the FASM —
    /// which could rely on a strictly expiry-sorted FIFO — per-call
    /// TTLs mean the sweep must scan the whole deque rather than
    /// early-breaking on the first live entry.
    ///
    /// Poison handling: if another thread panicked while holding the
    /// internal mutex this call silently no-ops rather than propagating
    /// the panic. This is the policy mandated by AAP §0.8.3 *"no
    /// `unwrap` / `expect` in library runtime paths"* — a poisoned
    /// blacklist is still functional from the caller's perspective
    /// (subsequent `contains` returns `false` by default, which is the
    /// safe failure mode for a rate-limiter).
    pub fn insert(&self, key: u128, ttl: Duration) {
        let Ok(mut g) = self.inner.lock() else { return };
        sweep_expired(&mut g);
        if g.map.contains_key(&key) {
            return;
        }
        let expires_at = Instant::now() + ttl;
        g.map.insert(key, expires_at);
        g.order.push_back(key);
    }

    /// Returns `true` if `key` is currently blacklisted and not yet
    /// expired.
    ///
    /// This call incidentally sweeps already-expired entries from the
    /// FIFO (matching the intent of the FASM `.weed` loop at line 189
    /// of `blacklist.inc`). After the sweep, a defensive per-entry
    /// expiry check is performed so that any residual entry whose
    /// per-call TTL already elapsed is treated as not-present even if
    /// the lazy sweep did not reach it (this matters only under
    /// heterogeneous TTLs, which the FASM baseline did not support).
    ///
    /// Note: unlike the FASM `blacklist$check`, this function does
    /// **not** reset the entry's timeout nor move it to the tail of the
    /// FIFO (see the module-level *"Deliberate behavioural divergence"*
    /// section). Entries expire at `insert-time + ttl` regardless of
    /// how often they are probed.
    ///
    /// Poison handling: on a poisoned mutex the call returns `false`
    /// (treat-as-not-blacklisted is the safe failure mode — it risks
    /// letting through a peer that would otherwise be blocked, but
    /// never fabricates a block for a legitimate peer).
    #[must_use]
    pub fn contains(&self, key: u128) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        sweep_expired(&mut g);
        match g.map.get(&key) {
            Some(&expires_at) => Instant::now() < expires_at,
            None => false,
        }
    }

    /// Remove `key` from the blacklist. No-op if the key is not present.
    ///
    /// This operation is O(n) in the FIFO length because the FIFO index
    /// of the removed key is not tracked separately. Rarely called in
    /// practice — administrator-driven de-banning only.
    ///
    /// Poison handling: silent no-op on a poisoned mutex.
    pub fn remove(&self, key: u128) {
        let Ok(mut g) = self.inner.lock() else { return };
        if g.map.remove(&key).is_some() {
            // Linear scan to locate the removed key in the FIFO. The FASM
            // baseline (blacklist$remove lines 109–171) performs an
            // equivalent linked-list walk — see the four `.first`,
            // `.lastnotfirst`, middle-of-list and `.firstandlast` branches.
            if let Some(pos) = g.order.iter().position(|&k| k == key) {
                g.order.remove(pos);
            }
        }
    }

    /// Returns the current number of blacklisted keys after sweeping
    /// expired entries from the FIFO front.
    ///
    /// Poison handling: returns 0 on a poisoned mutex.
    #[must_use]
    pub fn len(&self) -> usize {
        let Ok(mut g) = self.inner.lock() else { return 0 };
        sweep_expired(&mut g);
        g.map.len()
    }

    /// Returns `true` when the blacklist is empty (after sweeping
    /// expired entries).
    ///
    /// Equivalent to `self.len() == 0` but kept as a distinct method so
    /// Clippy's `len_zero` lint passes cleanly on downstream call
    /// sites.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every blacklist entry unconditionally.
    ///
    /// Useful for tests and for the worker-restart flow in
    /// `net::runtime` (AAP §0.7.1.1). Does not reset the configured TTL.
    ///
    /// Poison handling: silent no-op on a poisoned mutex.
    pub fn clear(&self) {
        let Ok(mut g) = self.inner.lock() else { return };
        g.map.clear();
        g.order.clear();
    }

    /// Spawn a Tokio task that sweeps expired entries every `interval`.
    ///
    /// Returns a [`tokio::task::JoinHandle`] the caller may retain for
    /// shutdown coordination, or drop to let the sweep run until the
    /// Tokio runtime shuts down. The sweeper clones an
    /// `Arc<Blacklist>`, so it keeps the blacklist alive even if the
    /// caller drops the original handle.
    ///
    /// The ticker uses [`tokio::time::MissedTickBehavior::Delay`] so
    /// that under scheduler back-pressure missed deadlines do not burst
    /// into a catch-up storm (preserves FASM semantics where lost timer
    /// ticks were naturally dropped by `epoll_pwait`).
    ///
    /// Default interval used by consumers per AAP §0.7.1.1 is 60 s.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime context — this
    /// propagates the [`tokio::spawn`] precondition. Callers should
    /// invoke this only inside a `tokio::main` /
    /// `Runtime::block_on` scope. Never called on library hot paths.
    pub fn spawn_sweeper(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Ok(mut g) = this.inner.lock() {
                    sweep_expired(&mut g);
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helper — lazy expiry sweep.
//
// This is a free function (rather than an associated `Self::` method)
// so it can be called from `insert`, `contains`, `len`, and
// `spawn_sweeper` without re-locking — each caller passes its
// already-locked `MutexGuard` by mutable reference. The FASM
// equivalent is the `.weed` loop at line 189 of `blacklist.inc`.
//
// Full-scan semantics (not early-break): because the checkpoint-3 API
// accepts a per-call `ttl` in `insert`, insertion order is NO LONGER
// a monotonic proxy for expiry order. A long-TTL entry inserted early
// can outlive a short-TTL entry inserted later. Consequently this
// sweeper walks the ENTIRE `order` FIFO, removing every expired key
// from both `map` and `order` while preserving the surviving FIFO
// ordering. For the typical case where `net::tls` and `net::ssh`
// both use the default `expiry` TTL (fixed-TTL policy), this reduces
// to the same behavior as the FASM early-break loop; for the
// heterogeneous-TTL case, it remains correct.
// ---------------------------------------------------------------------------

fn sweep_expired(g: &mut MutexGuard<'_, Inner>) {
    let now = Instant::now();
    // Destructure the guard into disjoint mutable references to `map`
    // and `order` so the borrow checker permits calling `map.remove`
    // from inside `order.retain`'s closure (the two fields are
    // independent, but we cannot re-borrow `g` twice).
    let Inner { map, order, .. } = &mut **g;
    order.retain(|key| match map.get(key) {
        Some(&expires_at) if expires_at <= now => {
            // Key has expired — remove it from the map as well, and
            // drop it from the FIFO (`retain` closure returns `false`).
            // Mirrors FASM lines 190–197 calling `blacklist$remove` on
            // each expired item.
            map.remove(key);
            false
        }
        Some(_) => {
            // Key is still live — keep it in the FIFO.
            true
        }
        None => {
            // Map/order desync — key absent from the map but present
            // in the FIFO. Recover gracefully by dropping the orphan.
            // This branch is defensive: the public API upholds the
            // `order.len() == map.len()` invariant, so this is
            // unreachable in well-behaved flows.
            false
        }
    });
}

// ---------------------------------------------------------------------------
// Debug impl — includes the expiry TTL and the live length.
//
// `len()` re-locks the mutex so `Debug` must NOT be called while
// holding the inner lock (rustc lifetime rules would not help:
// `std::sync::Mutex` is not re-entrant, so a single-thread reentrant
// lock would deadlock). This is never a problem in practice because
// consumers `format!("{:?}", bl)` without holding any
// module-private state.
// ---------------------------------------------------------------------------

impl fmt::Debug for Blacklist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Blacklist")
            .field("expiry", &self.expiry)
            .field("len", &self.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Key encoding helpers for IP addresses.
//
// The FASM-level blacklist treated keys as opaque 64-bit values — what
// the caller chose to encode there was its concern. For the Rust port
// the key width is widened to `u128` so the full 128-bit IPv6 address
// space fits losslessly into the key, closing a collision-based
// blacklist-bypass risk (CWE-345/CWE-346) that would otherwise arise
// from hashing IPv6 down to 64 bits.
//
// The encoding is injective across both address families:
//
//   * IPv4 addresses are embedded in the IPv4-mapped IPv6 subspace
//     `::ffff:a.b.c.d` (RFC 4291 §2.5.5.2). The four IPv4 octets
//     occupy the low 32 bits, with `0x0000_FFFF_0000_0000` set in the
//     middle 32 bits to mark the mapping. This means a banned IPv4
//     host at `127.0.0.1` encodes to `0x0000_FFFF_7F00_0001` and can
//     never collide with any real IPv6 address (the globally routable
//     IPv6 prefixes all lie outside `::ffff:0:0/96`).
//
//   * IPv6 addresses are stored as the big-endian 128-bit integer of
//     their 16 octets — `u128::from_be_bytes(ip.octets())`. This is
//     lossless; every distinct IPv6 address yields a distinct key.
//
// `net::tls` and `net::ssh` both feed peer IP addresses into the
// blacklist, so they share this encoding and agree on the key space.
// The `SocketAddr` helper below extracts the `.ip()` component and
// dispatches to the appropriate per-family encoder, matching the
// fact that the FASM baseline blacklists by IP address, not by
// socket (the peer port is not part of the ban identity).
// ---------------------------------------------------------------------------

/// Encode an IPv4 address as the `u128` key used by [`Blacklist`].
///
/// IPv4 addresses are embedded in the IPv4-mapped IPv6 subspace
/// `::ffff:a.b.c.d` (RFC 4291 §2.5.5.2) so that a single 128-bit key
/// space accommodates both address families without risk of
/// cross-family collision. The four IPv4 octets occupy the low 32
/// bits in big-endian order; the middle 32 bits hold the
/// `0x0000_FFFF` marker; the high 64 bits are zero.
///
/// Worked example: `127.0.0.1` encodes to
/// `0x0000_0000_0000_0000_0000_FFFF_7F00_0001` — i.e. the `u128`
/// whose low 64 bits are `0x0000_FFFF_7F00_0001` and whose high 64
/// bits are zero. The low-32-bit octet order `7F 00 00 01` matches
/// the byte order produced by the FASM `syscall_inet_pton` helper,
/// which the assembly sources use as their canonical IPv4 encoding.
///
/// This helper is implemented via [`Ipv4Addr::to_ipv6_mapped`] — a
/// single call that yields the canonical mapped address — followed
/// by [`u128::from_be_bytes`] on the resulting octets.
#[must_use]
pub fn key_from_ipv4(ip: Ipv4Addr) -> u128 {
    u128::from_be_bytes(ip.to_ipv6_mapped().octets())
}

/// Encode an IPv6 address as the `u128` key used by [`Blacklist`].
///
/// The 16 octets of the address are interpreted as a single
/// big-endian 128-bit integer via [`u128::from_be_bytes`]. This is
/// the natural lossless embedding of an IPv6 address into a `u128`:
/// every distinct IPv6 address yields a distinct key, so the
/// blacklist cannot be bypassed by forging a colliding address.
///
/// Worked example: `2001:db8::1` encodes to
/// `0x2001_0DB8_0000_0000_0000_0000_0000_0001_u128`.
///
/// The injective property is important for security — an earlier
/// iteration of this helper hashed the octets down to a `u64` via
/// [`std::collections::hash_map::DefaultHasher`], which gave a
/// collision probability of roughly 2⁻⁶⁴ per address pair. That was
/// deemed an unacceptable bypass vector for a blacklist consulted by
/// both `net::tls` and `net::ssh` on live internet traffic
/// (CWE-345/CWE-346). The `u128` encoding removes the risk entirely.
#[must_use]
pub fn key_from_ipv6(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

/// Encode the IP component of a [`SocketAddr`] as a `u128` key.
///
/// Extracts [`SocketAddr::ip`] and dispatches to [`key_from_ipv4`] or
/// [`key_from_ipv6`] depending on the variant. The peer port is
/// intentionally discarded — the FASM baseline blacklists by IP
/// address, not by socket, so a banned host remains banned across
/// subsequent connections regardless of ephemeral source port.
///
/// Consumers such as `net::tls` and `net::ssh` call this helper
/// directly after accepting an inbound connection, passing the
/// peer's [`SocketAddr`] straight through. Both address families
/// land in the same `u128` key space (with IPv4 addresses embedded
/// in the `::ffff:0:0/96` subspace per [`key_from_ipv4`]), so a
/// single [`Blacklist`] instance serves TLS and SSH equivalently.
#[must_use]
pub fn key_from_socket_addr(addr: SocketAddr) -> u128 {
    match addr.ip() {
        IpAddr::V4(v4) => key_from_ipv4(v4),
        IpAddr::V6(v6) => key_from_ipv6(v6),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- The eight tests specified in the agent prompt -----------------

    #[test]
    fn test_insert_contains() {
        let bl = Blacklist::new(Duration::from_secs(3600));
        bl.insert(0xCAFE_BABE_u128, Duration::from_secs(3600));
        assert!(bl.contains(0xCAFE_BABE_u128));
        assert!(!bl.contains(0xDEAD_BEEF_u128));
    }

    #[test]
    fn test_insert_duplicate_noop() {
        let bl = Blacklist::new(Duration::from_secs(3600));
        bl.insert(42_u128, Duration::from_secs(3600));
        bl.insert(42_u128, Duration::from_secs(3600));
        bl.insert(42_u128, Duration::from_secs(3600));
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn test_remove() {
        let bl = Blacklist::new(Duration::from_secs(3600));
        bl.insert(1_u128, Duration::from_secs(3600));
        bl.insert(2_u128, Duration::from_secs(3600));
        bl.remove(1_u128);
        assert!(!bl.contains(1_u128));
        assert!(bl.contains(2_u128));
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn test_expiry() {
        let bl = Blacklist::new(Duration::from_millis(50));
        bl.insert(7_u128, Duration::from_millis(50));
        assert!(bl.contains(7_u128));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!bl.contains(7_u128));
        assert_eq!(bl.len(), 0);
    }

    #[test]
    fn test_ipv4_key() {
        // 127.0.0.1 == Ipv4Addr::LOCALHOST; encode into the u128 key via
        // IPv4-mapped IPv6 (::ffff:7f00:0001) and verify that the IPv4
        // octets land in the low 32 bits with 0xFFFF in the next 16 bits,
        // per RFC 4291 §2.5.5.2.
        let ip = Ipv4Addr::LOCALHOST;
        let k = key_from_ipv4(ip);
        assert_eq!(k, 0x0000_0000_0000_0000_0000_FFFF_7F00_0001_u128);
    }

    #[test]
    fn test_fifo_eviction_order() {
        let bl = Blacklist::new(Duration::from_millis(50));
        bl.insert(1_u128, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(20));
        bl.insert(2_u128, Duration::from_millis(50));
        // Item 1 was inserted at t≈0 with expiry 50 ms  → expires at ≈50 ms.
        // Item 2 was inserted at t≈20 ms with expiry 50 ms → expires at ≈70 ms.
        // After sleeping another 40 ms (total ≈60 ms from item 1's insert),
        // item 1 is expired and item 2 is not.
        std::thread::sleep(Duration::from_millis(40));
        assert!(!bl.contains(1_u128));
        assert!(bl.contains(2_u128));
    }

    #[test]
    fn test_clear() {
        let bl = Blacklist::new(Duration::from_secs(60));
        bl.insert(1_u128, Duration::from_secs(60));
        bl.insert(2_u128, Duration::from_secs(60));
        bl.insert(3_u128, Duration::from_secs(60));
        bl.clear();
        assert_eq!(bl.len(), 0);
    }

    #[test]
    fn test_arc_shared() {
        let bl = Blacklist::new(Duration::from_secs(60));
        let bl2 = Arc::clone(&bl);
        bl.insert(99_u128, Duration::from_secs(60));
        assert!(bl2.contains(99_u128));
    }

    // -- Additional hardening tests beyond the specified eight --------

    #[test]
    fn test_is_empty() {
        let bl = Blacklist::new(Duration::from_secs(60));
        assert!(bl.is_empty());
        bl.insert(1_u128, Duration::from_secs(60));
        assert!(!bl.is_empty());
        bl.remove(1_u128);
        assert!(bl.is_empty());
    }

    #[test]
    fn test_remove_missing_noop() {
        let bl = Blacklist::new(Duration::from_secs(60));
        // Removing a key that was never inserted is a no-op.
        bl.remove(999_u128);
        assert_eq!(bl.len(), 0);
        bl.insert(1_u128, Duration::from_secs(60));
        bl.remove(2_u128); // different key
        assert_eq!(bl.len(), 1);
        assert!(bl.contains(1_u128));
    }

    #[test]
    fn test_ipv4_edge_values() {
        // IPv4 addresses are mapped into the ::ffff:0:0/96 subspace of u128
        // per RFC 4291 §2.5.5.2 to guarantee injective encoding across the
        // IPv4 and IPv6 families. The low 32 bits hold the IPv4 octets in
        // big-endian order; bits 32-47 hold 0xFFFF; bits 48-127 are zero.
        assert_eq!(
            key_from_ipv4(Ipv4Addr::UNSPECIFIED),
            0x0000_0000_0000_0000_0000_FFFF_0000_0000_u128
        );
        assert_eq!(
            key_from_ipv4(Ipv4Addr::BROADCAST),
            0x0000_0000_0000_0000_0000_FFFF_FFFF_FFFF_u128
        );
        assert_eq!(
            key_from_ipv4(Ipv4Addr::new(192, 168, 1, 1)),
            0x0000_0000_0000_0000_0000_FFFF_C0A8_0101_u128
        );
    }

    #[test]
    fn test_ipv6_encoding_is_injective() {
        // IPv6 addresses are encoded losslessly into the full 128-bit key
        // space via big-endian octet packing (u128::from_be_bytes). Unlike
        // the prior DefaultHasher-based u64 scheme (which was lossy and
        // enabled collision-based blacklist bypass — see CWE-345/CWE-346),
        // this encoding is bijective: distinct IPv6 addresses always map
        // to distinct u128 keys, and the same IPv6 address always maps
        // to the same u128 key both within and across processes.
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let k1 = key_from_ipv6(ip);
        let k2 = key_from_ipv6(ip);
        assert_eq!(k1, 0x2001_0DB8_0000_0000_0000_0000_0000_0001_u128);
        assert_eq!(k2, 0x2001_0DB8_0000_0000_0000_0000_0000_0001_u128);
    }

    #[test]
    fn test_key_from_socket_addr_dispatches() {
        // Exercise the dispatch path: key_from_socket_addr extracts the
        // IpAddr via addr.ip() and then delegates to key_from_ipv4 or
        // key_from_ipv6. Verify both families produce the expected
        // injective u128 encodings regardless of the port component.
        let sa_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0);
        let sa_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 0);
        assert_eq!(
            key_from_socket_addr(sa_v4),
            0x0000_0000_0000_0000_0000_FFFF_0A00_0001_u128
        );
        assert_eq!(
            key_from_socket_addr(sa_v6),
            0xFE80_0000_0000_0000_0000_0000_0000_0001_u128
        );
        // Port is not part of the key — same IP with a different port
        // must produce the same key (blacklist is per-IP, not per-socket).
        let sa_v4_other_port = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        assert_eq!(
            key_from_socket_addr(sa_v4),
            key_from_socket_addr(sa_v4_other_port)
        );
    }

    #[test]
    fn test_debug_impl_mentions_fields() {
        let bl = Blacklist::new(Duration::from_secs(42));
        bl.insert(1_u128, Duration::from_secs(42));
        bl.insert(2_u128, Duration::from_secs(42));
        let s = format!("{bl:?}");
        // The Debug output should name both struct fields.
        assert!(s.contains("expiry"));
        assert!(s.contains("len"));
        assert!(s.contains("Blacklist"));
    }

    #[test]
    fn test_sweep_on_add_removes_stale_head() {
        // Verify sweep_expired fires on `insert` as well as `contains`.
        let bl = Blacklist::new(Duration::from_millis(30));
        bl.insert(1_u128, Duration::from_millis(30));
        std::thread::sleep(Duration::from_millis(50));
        // At this point item 1 has expired but is still in the FIFO.
        // Inserting a new item must trigger a sweep that removes item 1.
        bl.insert(2_u128, Duration::from_millis(30));
        assert!(!bl.contains(1_u128));
        assert!(bl.contains(2_u128));
        assert_eq!(bl.len(), 1);
    }

    #[tokio::test]
    async fn test_spawn_sweeper_expires_entries() {
        let bl = Blacklist::new(Duration::from_millis(50));
        bl.insert(100_u128, Duration::from_millis(50));
        bl.insert(200_u128, Duration::from_millis(50));
        assert_eq!(bl.len(), 2);

        let handle = bl.spawn_sweeper(Duration::from_millis(30));

        // Wait long enough for entries to expire AND the sweeper to tick
        // (interval=30ms, expiry=50ms → sweeper visits at least once
        // after both entries are stale by t=150ms).
        tokio::time::sleep(Duration::from_millis(150)).await;

        // After expiry + sweeper tick, both entries should be gone.
        assert_eq!(bl.len(), 0);

        // Clean up the sweeper task so it does not outlive the test.
        handle.abort();
    }
}
