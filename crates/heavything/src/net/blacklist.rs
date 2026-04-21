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
//! The FASM source (`blacklist.inc`, © 2015 2 Ton Digital) describes
//! itself as *"a convenience object to deal with unsigned keys + time
//! delay"* and is shared between the TLS server (`net::tls`) and the SSH
//! server (`net::ssh`) for throttling misbehaving peers (AAP §0.7.1.1,
//! §0.7.4.4, §0.8.10 Gate 4). Both consumers hold an
//! `Arc<Blacklist>` cloned into per-connection handler state and call
//! [`Blacklist::add`] on crypto / auth failures.
//!
//! # Design summary
//!
//! The FASM implementation pairs an `unsignedmap` (O(1) contains) with a
//! doubly-linked list in insertion order (O(1) push-tail, O(1) pop-head).
//! The Rust port preserves this pairing with:
//!
//! * [`std::collections::HashMap`]`<u64, Instant>` for O(1) containment
//! * [`std::collections::VecDeque`]`<u64>` for O(1) push-back / pop-front
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
//! expire at `add-time + expiry`. The trade-off is explicit — Rust
//! consumers get predictable per-entry lifetime at the cost of losing
//! the FASM's implicit "ban permanence for active attackers" feature.
//! This divergence is explicitly captured in the AAP §0.7.1.1
//! behavioural-preservation table and the agent prompt for this file.
//!
//! Lazy expiry is still performed on every [`add`], [`contains`], and
//! [`len`] call by sweeping the front of the FIFO. This matches the FASM
//! `.weed` loop (line 189 of `blacklist.inc`) and keeps memory bounded
//! under sustained probing without needing a background task.
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
//! The blacklist stores opaque [`u64`] keys; the three free functions
//! [`key_from_ipv4`], [`key_from_ipv6`], and [`key_from_ip`] provide a
//! canonical encoding that both TLS and SSH consumers share so peer
//! addresses from either subsystem never collide.
//!
//! [`add`]: Blacklist::add
//! [`contains`]: Blacklist::contains
//! [`len`]: Blacklist::len

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Blacklist — shared between net::tls and net::ssh via Arc<Blacklist>.
// ---------------------------------------------------------------------------

/// Time-delayed blacklist of opaque [`u64`] keys.
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
/// Keys are opaque [`u64`] values; callers working with IP addresses
/// should use the [`key_from_ipv4`], [`key_from_ipv6`], and
/// [`key_from_ip`] helper functions for a consistent encoding.
///
/// [`remove`]: Blacklist::remove
pub struct Blacklist {
    /// Seconds-to-live for newly-added entries. Copied from the FASM
    /// `blacklist_expiry_ofs` field.
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
    map: HashMap<u64, Instant>,
    /// Insertion order for O(1) oldest-first expiry. This is the Rust
    /// analogue of the FASM doubly-linked list pinned by
    /// `blacklist_first_ofs` / `blacklist_last_ofs`.
    ///
    /// Invariant: `order.len() == map.len()` after every public method
    /// call. The interior `sweep_expired` helper transiently reduces
    /// `order` before removing the matching entry from `map`, but every
    /// iteration restores parity before yielding.
    order: VecDeque<u64>,
}

impl Blacklist {
    /// Create a new blacklist with the given per-entry TTL.
    ///
    /// The TTL is applied at `add` time: an entry inserted at instant
    /// `t` expires at `t + expiry`. Callers typically pass
    /// [`Duration::from_secs`] with values such as `config::TLS_BLACKLIST`
    /// (86 400 s = one day) or `config::SSH_BLACKLIST` (86 400 s) per
    /// AAP §0.7.1.1.
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

    /// Add `key` to the blacklist.
    ///
    /// * If `key` is already present this is a no-op — matching the
    ///   FASM `blacklist$add .alreadyhere` short-circuit (line 101 of
    ///   `blacklist.inc`).
    /// * If `key` is not present it is inserted with expiry
    ///   `Instant::now() + self.expiry` and appended to the FIFO tail
    ///   (matching FASM lines 87–97).
    ///
    /// This call incidentally sweeps already-expired entries from the
    /// front of the FIFO (AAP §0.7.1.1 lazy-expiry convention).
    ///
    /// Poison handling: if another thread panicked while holding the
    /// internal mutex this call silently no-ops rather than propagating
    /// the panic. This is the policy mandated by AAP §0.8.3 *"no
    /// `unwrap` / `expect` in library runtime paths"* — a poisoned
    /// blacklist is still functional from the caller's perspective
    /// (subsequent `contains` returns `false` by default, which is the
    /// safe failure mode for a rate-limiter).
    pub fn add(&self, key: u64) {
        let Ok(mut g) = self.inner.lock() else { return };
        sweep_expired(&mut g);
        if g.map.contains_key(&key) {
            return;
        }
        let expires_at = Instant::now() + self.expiry;
        g.map.insert(key, expires_at);
        g.order.push_back(key);
    }

    /// Returns `true` if `key` is currently blacklisted and not yet
    /// expired.
    ///
    /// This call incidentally sweeps already-expired entries from the
    /// front of the FIFO (matching the FASM `.weed` loop at line 189 of
    /// `blacklist.inc`).
    ///
    /// Note: unlike the FASM `blacklist$check`, this function does
    /// **not** reset the entry's timeout nor move it to the tail of the
    /// FIFO (see the module-level *"Deliberate behavioural divergence"*
    /// section). Entries expire at `add-time + expiry` regardless of
    /// how often they are probed.
    ///
    /// Poison handling: on a poisoned mutex the call returns `false`
    /// (treat-as-not-blacklisted is the safe failure mode — it risks
    /// letting through a peer that would otherwise be blocked, but
    /// never fabricates a block for a legitimate peer).
    #[must_use]
    pub fn contains(&self, key: u64) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        sweep_expired(&mut g);
        g.map.contains_key(&key)
    }

    /// Remove `key` from the blacklist. No-op if the key is not present.
    ///
    /// This operation is O(n) in the FIFO length because the FIFO index
    /// of the removed key is not tracked separately. Rarely called in
    /// practice — administrator-driven de-banning only.
    ///
    /// Poison handling: silent no-op on a poisoned mutex.
    pub fn remove(&self, key: u64) {
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
// Internal helper — front-of-queue lazy expiry.
//
// This is a free function (rather than an associated `Self::` method)
// so it can be called from `add`, `contains`, `len`, and
// `spawn_sweeper` without re-locking — each caller passes its
// already-locked `MutexGuard` by mutable reference. The FASM
// equivalent is the `.weed` loop at line 189 of `blacklist.inc`.
// ---------------------------------------------------------------------------

fn sweep_expired(g: &mut MutexGuard<'_, Inner>) {
    let now = Instant::now();
    while let Some(&head) = g.order.front() {
        match g.map.get(&head) {
            Some(&expires_at) if expires_at <= now => {
                // Front entry has expired — pop from the FIFO and remove
                // from the map. Mirrors FASM lines 190–197 calling
                // `blacklist$remove` on the head item.
                g.order.pop_front();
                g.map.remove(&head);
            }
            Some(_) => {
                // FIFO is ordered by insertion time; the first non-expired
                // entry implies every later entry is also non-expired
                // (their expiry times are monotonically ≥ the head's).
                break;
            }
            None => {
                // Map/order desync — key absent from the map but present
                // in the FIFO. Recover gracefully by popping the orphan.
                // This branch is defensive: the public API upholds the
                // `order.len() == map.len()` invariant, so this is
                // unreachable in well-behaved flows. Kept to avoid an
                // infinite loop in the presence of a subtle future bug.
                g.order.pop_front();
            }
        }
    }
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
// The FASM-level blacklist treats keys as opaque `u64` values — what
// the caller chose to encode there was its concern. For the Rust port
// we provide a canonical encoding so `net::tls` and `net::ssh` (which
// both feed peer IP addresses into the blacklist) agree on the key
// space and never collide on overlapping spans of IPv6.
// ---------------------------------------------------------------------------

/// Encode an IPv4 address as the `u64` key used by [`Blacklist`].
///
/// The encoding places the four octets in the low 32 bits of the `u64`
/// in big-endian order — that is, `127.0.0.1` maps to `0x7F00_0001`.
/// This matches the byte order produced by the FASM `syscall_inet_pton`
/// helper, which the assembly sources use as their canonical IPv4
/// encoding.
#[must_use]
pub fn key_from_ipv4(ip: Ipv4Addr) -> u64 {
    u64::from(u32::from(ip))
}

/// Encode an IPv6 address as a `u64` key by hashing the 128-bit
/// octets.
///
/// The full 16-byte representation is fed through
/// [`std::collections::hash_map::DefaultHasher`] and the resulting
/// 64-bit digest is used as the key. This lossy encoding is acceptable
/// for a rate-limiting / rejection cache — the hashing layer has a
/// random seed per process, so collisions between IPv6 addresses are
/// probabilistically negligible (~ 2⁻⁶⁴) and the impact of a collision
/// is at worst a spurious blacklist hit, never a missed one.
#[must_use]
pub fn key_from_ipv6(ip: Ipv6Addr) -> u64 {
    let mut hasher = DefaultHasher::new();
    ip.octets().hash(&mut hasher);
    hasher.finish()
}

/// Encode an [`IpAddr`] (either IPv4 or IPv6) as a `u64` key.
///
/// Dispatches to [`key_from_ipv4`] or [`key_from_ipv6`] depending on
/// the variant. Consumers such as `net::tls` and `net::ssh` call this
/// helper directly when handing the remote peer address to the
/// blacklist.
#[must_use]
pub fn key_from_ip(ip: IpAddr) -> u64 {
    match ip {
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
    fn test_add_contains() {
        let bl = Blacklist::new(Duration::from_secs(3600));
        bl.add(0xCAFE_BABE);
        assert!(bl.contains(0xCAFE_BABE));
        assert!(!bl.contains(0xDEAD_BEEF));
    }

    #[test]
    fn test_add_duplicate_noop() {
        let bl = Blacklist::new(Duration::from_secs(3600));
        bl.add(42);
        bl.add(42);
        bl.add(42);
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn test_remove() {
        let bl = Blacklist::new(Duration::from_secs(3600));
        bl.add(1);
        bl.add(2);
        bl.remove(1);
        assert!(!bl.contains(1));
        assert!(bl.contains(2));
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn test_expiry() {
        let bl = Blacklist::new(Duration::from_millis(50));
        bl.add(7);
        assert!(bl.contains(7));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!bl.contains(7));
        assert_eq!(bl.len(), 0);
    }

    #[test]
    fn test_ipv4_key() {
        // 127.0.0.1 == Ipv4Addr::LOCALHOST; encode into the u64 key and
        // verify the expected big-endian-octet packing.
        let ip = Ipv4Addr::LOCALHOST;
        let k = key_from_ipv4(ip);
        assert_eq!(k, 0x7F00_0001);
    }

    #[test]
    fn test_fifo_eviction_order() {
        let bl = Blacklist::new(Duration::from_millis(50));
        bl.add(1);
        std::thread::sleep(Duration::from_millis(20));
        bl.add(2);
        // Item 1 was added at t≈0 with expiry 50 ms  → expires at ≈50 ms.
        // Item 2 was added at t≈20 ms with expiry 50 ms → expires at ≈70 ms.
        // After sleeping another 40 ms (total ≈60 ms from item 1's add),
        // item 1 is expired and item 2 is not.
        std::thread::sleep(Duration::from_millis(40));
        assert!(!bl.contains(1));
        assert!(bl.contains(2));
    }

    #[test]
    fn test_clear() {
        let bl = Blacklist::new(Duration::from_secs(60));
        bl.add(1);
        bl.add(2);
        bl.add(3);
        bl.clear();
        assert_eq!(bl.len(), 0);
    }

    #[test]
    fn test_arc_shared() {
        let bl = Blacklist::new(Duration::from_secs(60));
        let bl2 = Arc::clone(&bl);
        bl.add(99);
        assert!(bl2.contains(99));
    }

    // -- Additional hardening tests beyond the specified eight --------

    #[test]
    fn test_is_empty() {
        let bl = Blacklist::new(Duration::from_secs(60));
        assert!(bl.is_empty());
        bl.add(1);
        assert!(!bl.is_empty());
        bl.remove(1);
        assert!(bl.is_empty());
    }

    #[test]
    fn test_remove_missing_noop() {
        let bl = Blacklist::new(Duration::from_secs(60));
        // Removing a key that was never added is a no-op.
        bl.remove(999);
        assert_eq!(bl.len(), 0);
        bl.add(1);
        bl.remove(2); // different key
        assert_eq!(bl.len(), 1);
        assert!(bl.contains(1));
    }

    #[test]
    fn test_ipv4_edge_values() {
        assert_eq!(key_from_ipv4(Ipv4Addr::UNSPECIFIED), 0);
        assert_eq!(key_from_ipv4(Ipv4Addr::BROADCAST), 0xFFFF_FFFF);
        assert_eq!(key_from_ipv4(Ipv4Addr::new(192, 168, 1, 1)), 0xC0A8_0101);
    }

    #[test]
    fn test_ipv6_hash_deterministic_within_process() {
        // DefaultHasher uses RandomState which is process-global; within
        // a single process, hashing the same IPv6 address yields the
        // same u64.
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let k1 = key_from_ipv6(ip);
        let k2 = key_from_ipv6(ip);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_key_from_ip_dispatches() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(key_from_ip(v4), 0x0A00_0001);
        // The IPv6 path produces a hash whose exact value depends on the
        // process-local RandomState of DefaultHasher, so we assert only
        // that it dispatches without panicking and is stable.
        let hash_once = key_from_ip(v6);
        let hash_twice = key_from_ip(v6);
        assert_eq!(hash_once, hash_twice);
    }

    #[test]
    fn test_debug_impl_mentions_fields() {
        let bl = Blacklist::new(Duration::from_secs(42));
        bl.add(1);
        bl.add(2);
        let s = format!("{bl:?}");
        // The Debug output should name both struct fields.
        assert!(s.contains("expiry"));
        assert!(s.contains("len"));
        assert!(s.contains("Blacklist"));
    }

    #[test]
    fn test_sweep_on_add_removes_stale_head() {
        // Verify sweep_expired fires on `add` as well as `contains`.
        let bl = Blacklist::new(Duration::from_millis(30));
        bl.add(1);
        std::thread::sleep(Duration::from_millis(50));
        // At this point item 1 has expired but is still in the FIFO.
        // Adding a new item must trigger a sweep that removes item 1.
        bl.add(2);
        assert!(!bl.contains(1));
        assert!(bl.contains(2));
        assert_eq!(bl.len(), 1);
    }

    #[tokio::test]
    async fn test_spawn_sweeper_expires_entries() {
        let bl = Blacklist::new(Duration::from_millis(50));
        bl.add(100);
        bl.add(200);
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
