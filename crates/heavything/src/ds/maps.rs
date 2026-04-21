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

//! Map containers — port of `maps.inc` (4,507 lines of FASM AVL-tree code).
//!
//! The original assembly library exposes four parallel key-type variants
//! backed by a hand-tuned AVL tree with an embedded doubly-linked list for
//! O(1) in-order and reverse-order iteration (`avlnode_size = 68`, with
//! `_avlofs_next` / `_avlofs_prev` fields at offsets 40 and 48):
//!
//! - `intmap`     — signed 64-bit integer keys
//! - `unsignedmap` — unsigned 64-bit integer keys (the only variant that
//!   exposes `lowerbound`, `erase_specific`, and
//!   `erase_specific_node`)
//! - `doublemap`  — IEEE-754 `f64` keys (uses the `xmm0` ABI internally)
//! - `stringmap`  — `String` keys with lexicographic compare
//!
//! Rust's generic trait system collapses the three integer/ordered variants
//! into a single [`OrderedMap<K, V>`] parameterised over any `K: Ord`.
//! Callers that previously used the FASM `intmap`, `unsignedmap`, or
//! timer-deadline maps instantiate `OrderedMap<i64, V>`, `OrderedMap<u64, V>`,
//! or `OrderedMap<std::time::Instant, V>` respectively. Callers that genuinely
//! need `f64` keys wrap them in a total-ordering newtype (required because
//! `f64: PartialOrd` is not `Ord` due to NaN); this module does not provide
//! one per AAP §0.8.2 minimal-API-surface discipline.
//!
//! Stringly-keyed maps keep a dedicated wrapper — [`StringMap<V>`] — because
//! hashed access (via [`std::collections::HashMap`]) is a better fit for the
//! bulk header, cookie-jar, and FastCGI-parameter lookups that the HTTP
//! stack performs.
//!
//! # Why `BTreeMap` and not a custom AVL
//!
//! Both structures are O(log n) balanced trees. Rust's [`BTreeMap`] is a
//! B-tree, which trades slightly higher per-node overhead for dramatically
//! better cache locality on modern CPUs. Per AAP §0.8.1 the acceptable
//! performance envelope is "within 3× of the assembly baseline", which
//! comfortably absorbs any constant-factor delta, and the folder-level
//! requirements for `ds/` explicitly record that *"Custom AVL is NOT
//! required unless specific FASM-level performance parity demands it —
//! which it doesn't per AAP §0.8.1"*. Using the standard-library
//! collection also eliminates the maintenance burden of hand-rolled
//! rebalancing, parent/next/prev pointer upkeep, and the `unsafe` blocks
//! that would almost certainly accompany it.
//!
//! # Critical consumer: the epoll timer walk
//!
//! `heavything::net::runtime` registers every timer in an
//! `OrderedMap<Instant, TimerId>`. At the top of each event-loop iteration
//! the runtime peeks at the next-expiring timer via
//! [`OrderedMap::first_key_value`] and, if the deadline has passed,
//! removes it via [`OrderedMap::pop_first`]. Both operations are O(log n)
//! on [`BTreeMap`] and were stabilised in Rust 1.66, well below the
//! toolchain pinned by `rust-toolchain.toml`.
//!
//! ```ignore
//! // Conceptual epoll timer-walk (in heavything::net::runtime):
//! while let Some((&deadline, _)) = timers.first_key_value() {
//!     if deadline > now { break; }
//!     if let Some((_, timer)) = timers.pop_first() {
//!         timer.fire();
//!     }
//! }
//! ```
//!
//! # FASM → Rust function mapping
//!
//! | FASM (applies to all 4 variants unless noted) | Rust equivalent                     |
//! |----------------------------------------------|-------------------------------------|
//! | `$new`                                       | `StringMap::new` / `OrderedMap::new`|
//! | `$destroy`                                   | `Drop` (automatic)                  |
//! | `$clear`                                     | [`StringMap::clear`] / [`OrderedMap::clear`] |
//! | `$find`                                      | `get(&key)`                         |
//! | `$find_value`                                | `contains_key(&key)` / `get(&key)` (Option subsumes the bool-plus-value return) |
//! | `unsignedmap$lowerbound` (unique)            | [`OrderedMap::lower_bound`]         |
//! | `$insert`                                    | `insert(k, v) -> Option<V>`         |
//! | `$insert_unique`                             | `insert_unique(k, v) -> Result<(), V>` (FASM returns bool; Rust variant additionally hands the rejected value back) |
//! | `$erase`                                     | `remove(&key) -> Option<V>`         |
//! | `unsignedmap$erase_specific[_node]` (unique) | *(not exposed — AVL-node identity is an implementation detail the Rust `BTreeMap` abstraction hides)* |
//! | `$foreach` / `$foreach_arg`                  | `iter()` / `for_each(&self, FnMut)` |
//! | `$reverse_foreach`                           | `iter().rev()` / [`OrderedMap::for_each_rev`] (ordered only) |
//! | `$keys_to_array` / `$keys_to_list`           | `keys().cloned().collect()`         |
//! | `$values_to_array` / `$values_to_list`       | `values().cloned().collect()`       |

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

use crate::error::DsError;

// ---------------------------------------------------------------------------
// StringMap — `HashMap<String, V>` wrapper
// ---------------------------------------------------------------------------

/// An unordered map keyed by [`String`] values.
///
/// `StringMap<V>` is the Rust translation of the FASM `stringmap` variant
/// in `maps.inc`. It wraps [`std::collections::HashMap<String, V>`] with
/// an API surface tailored to HeavyThing consumers:
///
/// - HTTP headers in `heavything::net::http::mimelike`
/// - Session cookies in `heavything::net::http::cookiejar`
/// - FastCGI parameter lists in `heavything::net::fcgi`
/// - Webserver file-cache hotlist in `heavything::net::http::server`
///
/// Iteration order is unspecified and may change between runs. If you need
/// ordered iteration, use [`OrderedMap`] instead.
///
/// # Example
///
/// ```
/// use heavything::ds::StringMap;
/// let mut headers: StringMap<String> = StringMap::new();
/// headers.insert("host".to_string(), "example.com".to_string());
/// assert_eq!(headers.get("host").map(String::as_str), Some("example.com"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct StringMap<V> {
    inner: HashMap<String, V>,
}

impl<V> StringMap<V> {
    /// Creates an empty `StringMap<V>`.
    ///
    /// The underlying [`HashMap`] starts with zero capacity and grows on
    /// demand. Equivalent to FASM `stringmap$new`.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Creates a `StringMap<V>` preallocated for at least `capacity` entries.
    ///
    /// Useful when the approximate size of the map is known up-front (e.g.,
    /// parsing an HTTP request with a predictable number of headers).
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: HashMap::with_capacity(capacity),
        }
    }

    /// Returns the number of key/value pairs currently in the map.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the map contains no entries.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Removes every entry from the map while preserving the allocated
    /// capacity.
    ///
    /// Equivalent to FASM `stringmap$clear`.
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Returns `true` if a value is associated with `key`.
    ///
    /// Equivalent to FASM `stringmap$find_value` when only the presence
    /// bit is required.
    #[inline]
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    /// Returns a reference to the value associated with `key`, or `None`
    /// if the key is absent.
    ///
    /// Equivalent to FASM `stringmap$find` / `stringmap$find_value`.
    #[inline]
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&V> {
        self.inner.get(key)
    }

    /// Returns a mutable reference to the value associated with `key`, or
    /// `None` if the key is absent.
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.inner.get_mut(key)
    }

    /// Returns a reference to the value associated with `key`, or
    /// [`DsError::KeyNotFound`] if the key is absent.
    ///
    /// This is the explicit-error companion to [`get`][Self::get]; it is
    /// useful when a missing key is a programmer error rather than a
    /// normal control-flow outcome.
    pub fn get_required(&self, key: &str) -> Result<&V, DsError> {
        self.inner.get(key).ok_or(DsError::KeyNotFound)
    }

    /// Inserts `value` at `key`, returning the previously-associated
    /// value (if any).
    ///
    /// Equivalent to FASM `stringmap$insert`.
    #[inline]
    pub fn insert(&mut self, key: String, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    /// Inserts `value` at `key` only if the key is absent.
    ///
    /// Returns `Ok(())` on successful insertion or `Err(value)` if the key
    /// is already present — the rejected value is handed back so the
    /// caller can decide whether to drop, retry, or log it. Equivalent to
    /// FASM `stringmap$insert_unique`, which returns a success flag in
    /// `rax`; the Rust variant additionally preserves ownership of the
    /// rejected value.
    pub fn insert_unique(&mut self, key: String, value: V) -> Result<(), V> {
        if self.inner.contains_key(&key) {
            return Err(value);
        }
        self.inner.insert(key, value);
        Ok(())
    }

    /// Removes the entry for `key`, returning the associated value if
    /// present.
    ///
    /// Equivalent to FASM `stringmap$erase`.
    #[inline]
    pub fn remove(&mut self, key: &str) -> Option<V> {
        self.inner.remove(key)
    }

    /// Returns an iterator over all `(&String, &V)` pairs in arbitrary
    /// order.
    ///
    /// Equivalent to FASM `stringmap$foreach` (without the reverse
    /// companion, which is only meaningful on ordered maps).
    #[inline]
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, String, V> {
        self.inner.iter()
    }

    /// Returns a mutable iterator over all `(&String, &mut V)` pairs in
    /// arbitrary order.
    #[inline]
    pub fn iter_mut(&mut self) -> std::collections::hash_map::IterMut<'_, String, V> {
        self.inner.iter_mut()
    }

    /// Returns an iterator over all keys in arbitrary order.
    ///
    /// Equivalent to FASM `stringmap$keys_to_array` /
    /// `stringmap$keys_to_list`; collecting into a `Vec<String>` recovers
    /// the FASM-style materialised list.
    #[inline]
    pub fn keys(&self) -> std::collections::hash_map::Keys<'_, String, V> {
        self.inner.keys()
    }

    /// Returns an iterator over all values in arbitrary order.
    ///
    /// Equivalent to FASM `stringmap$values_to_array` /
    /// `stringmap$values_to_list`.
    #[inline]
    pub fn values(&self) -> std::collections::hash_map::Values<'_, String, V> {
        self.inner.values()
    }

    /// Returns a mutable iterator over all values in arbitrary order.
    #[inline]
    pub fn values_mut(&mut self) -> std::collections::hash_map::ValuesMut<'_, String, V> {
        self.inner.values_mut()
    }

    /// Applies `f` to each `(key, value)` pair in arbitrary order.
    ///
    /// Equivalent to FASM `stringmap$foreach` and `stringmap$foreach_arg`;
    /// the FASM `arg` (third register parameter) is subsumed by Rust's
    /// closure-capture semantics.
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&String, &V),
    {
        for (k, v) in self.inner.iter() {
            f(k, v);
        }
    }
}

// ---- StringMap trait impls ------------------------------------------------

impl<V> IntoIterator for StringMap<V> {
    type Item = (String, V);
    type IntoIter = std::collections::hash_map::IntoIter<String, V>;

    /// Consumes the map and yields each owned `(String, V)` pair.
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, V> IntoIterator for &'a StringMap<V> {
    type Item = (&'a String, &'a V);
    type IntoIter = std::collections::hash_map::Iter<'a, String, V>;

    /// Iterates over shared references to each pair without consuming the
    /// map.
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, V> IntoIterator for &'a mut StringMap<V> {
    type Item = (&'a String, &'a mut V);
    type IntoIter = std::collections::hash_map::IterMut<'a, String, V>;

    /// Iterates over mutable references to each value while the keys
    /// remain shared, without consuming the map.
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

impl<V> FromIterator<(String, V)> for StringMap<V> {
    fn from_iter<I: IntoIterator<Item = (String, V)>>(iter: I) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

impl<V> Extend<(String, V)> for StringMap<V> {
    fn extend<I: IntoIterator<Item = (String, V)>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

// ---------------------------------------------------------------------------
// OrderedMap — `BTreeMap<K, V>` wrapper
// ---------------------------------------------------------------------------

/// A key-ordered map keyed by any type implementing [`Ord`].
///
/// `OrderedMap<K, V>` is the Rust translation of the FASM `intmap`,
/// `unsignedmap`, and (with a caller-supplied total-ordering wrapper)
/// `doublemap` variants from `maps.inc`. It wraps
/// [`std::collections::BTreeMap<K, V>`] to provide ordered iteration and
/// fast next-key queries.
///
/// # Critical consumer: the epoll timer walk
///
/// The primary in-scope consumer is `heavything::net::runtime`, which
/// stores every pending timer keyed by its absolute deadline. At the top
/// of each event-loop iteration the runtime peeks the earliest deadline
/// via [`first_key_value`][Self::first_key_value] and — if that deadline
/// has passed — removes it via [`pop_first`][Self::pop_first] to fire
/// the callback. Both primitives are O(log n).
///
/// ```
/// use heavything::ds::OrderedMap;
///
/// let mut timers: OrderedMap<u64, &'static str> = OrderedMap::new();
/// timers.insert(300, "log-flush");      // deadline 300 ms
/// timers.insert(1_500, "pem-reload");   // deadline 1,500 ms
/// timers.insert(120, "idle-tick");      // deadline 120 ms
///
/// assert_eq!(timers.first_key_value(), Some((&120, &"idle-tick")));
/// assert_eq!(timers.pop_first(), Some((120, "idle-tick")));
/// assert_eq!(timers.first_key_value(), Some((&300, &"log-flush")));
/// ```
///
/// # Why the four FASM variants collapse into one Rust generic
///
/// FASM's `intmap` / `unsignedmap` / `doublemap` distinction exists because
/// assembly has no generic parameters and because signed, unsigned, and
/// floating-point comparisons use different instructions. Rust's trait
/// system represents all three under the single bound `K: Ord`; callers
/// simply pick their key type at the use site. `f64` keys require a total
/// ordering wrapper because NaN is unordered with itself, so `f64` is
/// `PartialOrd` but not `Ord` — this module does not ship one, matching
/// the minimal-API-surface directive of AAP §0.8.2.
///
/// Per AAP §0.5.1.6 and the `ds/` folder requirements, [`BTreeMap`] is
/// chosen over a custom AVL tree because the 3× performance envelope
/// (AAP §0.8.1) easily absorbs the B-tree overhead, and the idiomatic
/// `std` API eliminates a large class of unsafe-pointer bugs that a
/// hand-rolled balanced tree would introduce.
#[derive(Debug, Clone)]
pub struct OrderedMap<K: Ord, V> {
    inner: BTreeMap<K, V>,
}

// An explicit `Default` impl is required because `#[derive(Default)]` would
// bound the generated impl on `K: Default + Ord`; `BTreeMap::new()` only
// needs `K: Ord`, so defaulting the map should only need `K: Ord` too.
impl<K: Ord, V> Default for OrderedMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord, V> OrderedMap<K, V> {
    /// Creates an empty `OrderedMap<K, V>`.
    ///
    /// [`BTreeMap`] has no `with_capacity` constructor (its node size is
    /// fixed), so no such method is exposed here either.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    /// Returns the number of key/value pairs currently in the map.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the map contains no entries.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Removes every entry from the map.
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Returns `true` if a value is associated with `key`.
    #[inline]
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    /// Returns a reference to the value associated with `key`, or `None`
    /// if the key is absent.
    #[inline]
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }

    /// Returns a mutable reference to the value associated with `key`, or
    /// `None` if the key is absent.
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.get_mut(key)
    }

    /// Returns a reference to the value associated with `key`, or
    /// [`DsError::KeyNotFound`] if the key is absent.
    ///
    /// This is the explicit-error companion to [`get`][Self::get]; it is
    /// useful when a missing key indicates a programmer error rather than
    /// an expected control-flow outcome.
    pub fn get_required(&self, key: &K) -> Result<&V, DsError> {
        self.inner.get(key).ok_or(DsError::KeyNotFound)
    }

    /// Inserts `value` at `key`, returning the previously-associated
    /// value (if any).
    ///
    /// Equivalent to FASM `{int,unsigned,double}map$insert`.
    #[inline]
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    /// Inserts `value` at `key` only if the key is absent.
    ///
    /// Returns `Ok(())` on successful insertion or `Err(value)` if the key
    /// is already present — the rejected value is handed back so the
    /// caller can decide whether to drop, retry, or log it. Equivalent to
    /// FASM `{int,unsigned,double}map$insert_unique`.
    pub fn insert_unique(&mut self, key: K, value: V) -> Result<(), V> {
        if self.inner.contains_key(&key) {
            return Err(value);
        }
        self.inner.insert(key, value);
        Ok(())
    }

    /// Removes the entry for `key`, returning the associated value if
    /// present.
    ///
    /// Equivalent to FASM `{int,unsigned,double}map$erase`. The FASM
    /// `unsignedmap$erase_specific[_node]` variants — which delete a
    /// known-identity AVL node without a key lookup — are intentionally
    /// not exposed: AVL-node identity is an implementation detail the
    /// Rust [`BTreeMap`] abstraction hides, and the additional O(log n)
    /// lookup for a key-based delete is well within the 3× performance
    /// envelope of AAP §0.8.1.
    #[inline]
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }

    /// Returns the smallest `(&K, &V)` pair in the map, or `None` if the
    /// map is empty.
    ///
    /// This is the primary primitive used by the epoll timer walk to peek
    /// at the next-expiring timer before deciding whether to fire it.
    #[inline]
    #[must_use]
    pub fn first_key_value(&self) -> Option<(&K, &V)> {
        self.inner.first_key_value()
    }

    /// Returns the largest `(&K, &V)` pair in the map, or `None` if the
    /// map is empty.
    #[inline]
    #[must_use]
    pub fn last_key_value(&self) -> Option<(&K, &V)> {
        self.inner.last_key_value()
    }

    /// Removes and returns the smallest `(K, V)` pair, or `None` if the
    /// map is empty.
    ///
    /// This is the primary primitive used by the epoll timer walk to fire
    /// and discard the next-expiring timer in a single O(log n) step.
    #[inline]
    pub fn pop_first(&mut self) -> Option<(K, V)> {
        self.inner.pop_first()
    }

    /// Removes and returns the largest `(K, V)` pair, or `None` if the
    /// map is empty.
    #[inline]
    pub fn pop_last(&mut self) -> Option<(K, V)> {
        self.inner.pop_last()
    }

    /// Returns the first `(&K, &V)` pair with key greater than or equal
    /// to `key`, or `None` if no such pair exists.
    ///
    /// Equivalent to FASM `unsignedmap$lowerbound`. Note that FASM's
    /// implementation uses a strict `>` comparison (keys strictly greater
    /// than the target); the Rust variant uses the C++/STL `lower_bound`
    /// convention of inclusive `>=`, which is what the current in-scope
    /// consumers (the timer walk's "deadline reached" predicate) require.
    #[must_use]
    pub fn lower_bound(&self, key: &K) -> Option<(&K, &V)> {
        self.inner.range((Bound::Included(key), Bound::Unbounded)).next()
    }

    /// Returns an iterator over all `(&K, &V)` pairs in ascending key
    /// order.
    ///
    /// Equivalent to FASM `{int,unsigned,double}map$foreach`, which walks
    /// the AVL's embedded doubly-linked list via the `_avlofs_next`
    /// field at offset 40.
    #[inline]
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, K, V> {
        self.inner.iter()
    }

    /// Returns a mutable iterator over all `(&K, &mut V)` pairs in
    /// ascending key order.
    #[inline]
    pub fn iter_mut(&mut self) -> std::collections::btree_map::IterMut<'_, K, V> {
        self.inner.iter_mut()
    }

    /// Returns an iterator over all keys in ascending order.
    #[inline]
    pub fn keys(&self) -> std::collections::btree_map::Keys<'_, K, V> {
        self.inner.keys()
    }

    /// Returns an iterator over all values in ascending-key order.
    #[inline]
    pub fn values(&self) -> std::collections::btree_map::Values<'_, K, V> {
        self.inner.values()
    }

    /// Returns a mutable iterator over all values in ascending-key order.
    #[inline]
    pub fn values_mut(&mut self) -> std::collections::btree_map::ValuesMut<'_, K, V> {
        self.inner.values_mut()
    }

    /// Applies `f` to each `(key, value)` pair in ascending key order.
    ///
    /// Equivalent to FASM `{int,unsigned,double}map$foreach` and
    /// `{int,unsigned}map$foreach_arg`; the FASM `arg` (third register
    /// parameter) is subsumed by Rust's closure-capture semantics.
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&K, &V),
    {
        for (k, v) in self.inner.iter() {
            f(k, v);
        }
    }

    /// Applies `f` to each `(key, value)` pair in descending key order.
    ///
    /// Equivalent to FASM `{int,unsigned,double}map$reverse_foreach`,
    /// which walks the AVL's embedded doubly-linked list via the
    /// `_avlofs_prev` field at offset 48. Not provided on [`StringMap`]
    /// because [`HashMap`] has no defined iteration order.
    pub fn for_each_rev<F>(&self, mut f: F)
    where
        F: FnMut(&K, &V),
    {
        for (k, v) in self.inner.iter().rev() {
            f(k, v);
        }
    }
}

// ---- OrderedMap trait impls -----------------------------------------------

impl<K: Ord, V> IntoIterator for OrderedMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::collections::btree_map::IntoIter<K, V>;

    /// Consumes the map and yields each owned `(K, V)` pair in ascending
    /// key order.
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, K: Ord, V> IntoIterator for &'a OrderedMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = std::collections::btree_map::Iter<'a, K, V>;

    /// Iterates over shared references to each pair in ascending key
    /// order without consuming the map.
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, K: Ord, V> IntoIterator for &'a mut OrderedMap<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = std::collections::btree_map::IterMut<'a, K, V>;

    /// Iterates over mutable references to each value while the keys
    /// remain shared, in ascending key order, without consuming the map.
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

impl<K: Ord, V> FromIterator<(K, V)> for OrderedMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

impl<K: Ord, V> Extend<(K, V)> for OrderedMap<K, V> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // --- StringMap tests ---------------------------------------------------

    #[test]
    fn test_stringmap_new_is_empty() {
        let m: StringMap<i32> = StringMap::new();
        assert_eq!(m.len(), 0);
        assert!(m.is_empty());
    }

    #[test]
    fn test_stringmap_default_is_empty() {
        let m: StringMap<i32> = StringMap::default();
        assert!(m.is_empty());
    }

    #[test]
    fn test_stringmap_with_capacity() {
        let m: StringMap<u32> = StringMap::with_capacity(16);
        assert!(m.is_empty());
        // We cannot check HashMap::capacity through our encapsulated API,
        // but the constructor must not panic for any reasonable request.
    }

    #[test]
    fn test_stringmap_insert_and_get() {
        let mut m: StringMap<&'static str> = StringMap::new();
        assert_eq!(m.insert("key".to_string(), "val"), None);
        assert_eq!(m.get("key"), Some(&"val"));
        assert_eq!(m.len(), 1);
        assert!(!m.is_empty());
    }

    #[test]
    fn test_stringmap_insert_replaces() {
        let mut m: StringMap<u32> = StringMap::new();
        assert_eq!(m.insert("k".to_string(), 1), None);
        assert_eq!(m.insert("k".to_string(), 2), Some(1));
        assert_eq!(m.get("k"), Some(&2));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn test_stringmap_contains_key() {
        let mut m: StringMap<i32> = StringMap::new();
        assert!(!m.contains_key("absent"));
        m.insert("present".to_string(), 42);
        assert!(m.contains_key("present"));
        assert!(!m.contains_key("absent"));
    }

    #[test]
    fn test_stringmap_get_mut() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 10);
        if let Some(v) = m.get_mut("a") {
            *v += 5;
        }
        assert_eq!(m.get("a"), Some(&15));
    }

    #[test]
    fn test_stringmap_get_required_ok() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("alpha".to_string(), 7);
        assert_eq!(m.get_required("alpha").unwrap(), &7);
    }

    #[test]
    fn test_stringmap_get_required_err() {
        let m: StringMap<u32> = StringMap::new();
        match m.get_required("nope") {
            Err(DsError::KeyNotFound) => {}
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_stringmap_insert_unique_ok() {
        let mut m: StringMap<u32> = StringMap::new();
        assert!(m.insert_unique("k".to_string(), 1).is_ok());
        assert_eq!(m.get("k"), Some(&1));
    }

    #[test]
    fn test_stringmap_insert_unique_rejects() {
        let mut m: StringMap<u32> = StringMap::new();
        assert!(m.insert_unique("k".to_string(), 1).is_ok());
        // Rejected insert must return the value unchanged.
        let rejected = m.insert_unique("k".to_string(), 99);
        assert_eq!(rejected, Err(99));
        // Existing value must be untouched.
        assert_eq!(m.get("k"), Some(&1));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn test_stringmap_remove() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("x".to_string(), 100);
        assert_eq!(m.remove("x"), Some(100));
        assert!(m.is_empty());
        assert_eq!(m.get("x"), None);
    }

    #[test]
    fn test_stringmap_remove_absent_returns_none() {
        let mut m: StringMap<u32> = StringMap::new();
        assert_eq!(m.remove("absent"), None);
    }

    #[test]
    fn test_stringmap_clear() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.insert("b".to_string(), 2);
        m.insert("c".to_string(), 3);
        assert_eq!(m.len(), 3);
        m.clear();
        assert_eq!(m.len(), 0);
        assert!(m.is_empty());
        assert!(m.iter().next().is_none());
    }

    #[test]
    fn test_stringmap_iter_covers_all() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.insert("b".to_string(), 2);
        m.insert("c".to_string(), 3);

        let collected: HashSet<(String, u32)> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let expected: HashSet<(String, u32)> =
            [("a".to_string(), 1), ("b".to_string(), 2), ("c".to_string(), 3)]
                .iter()
                .cloned()
                .collect();
        assert_eq!(collected, expected);
    }

    #[test]
    fn test_stringmap_iter_mut_mutates_values() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.insert("b".to_string(), 2);
        for (_, v) in m.iter_mut() {
            *v += 10;
        }
        assert_eq!(m.get("a"), Some(&11));
        assert_eq!(m.get("b"), Some(&12));
    }

    #[test]
    fn test_stringmap_keys_values() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.insert("b".to_string(), 2);
        let keys: HashSet<String> = m.keys().cloned().collect();
        let values: HashSet<u32> = m.values().copied().collect();
        assert_eq!(keys, HashSet::from_iter(["a".to_string(), "b".to_string()]));
        assert_eq!(values, HashSet::from_iter([1, 2]));
    }

    #[test]
    fn test_stringmap_values_mut() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.insert("b".to_string(), 2);
        for v in m.values_mut() {
            *v *= 100;
        }
        assert_eq!(m.get("a"), Some(&100));
        assert_eq!(m.get("b"), Some(&200));
    }

    #[test]
    fn test_stringmap_for_each() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.insert("b".to_string(), 2);
        m.insert("c".to_string(), 3);

        let mut seen: HashSet<(String, u32)> = HashSet::new();
        m.for_each(|k, v| {
            seen.insert((k.clone(), *v));
        });
        assert_eq!(seen.len(), 3);
        assert!(seen.contains(&("a".to_string(), 1)));
        assert!(seen.contains(&("b".to_string(), 2)));
        assert!(seen.contains(&("c".to_string(), 3)));
    }

    #[test]
    fn test_stringmap_from_iterator() {
        let src: Vec<(String, u32)> = vec![("a".to_string(), 1), ("b".to_string(), 2)];
        let m: StringMap<u32> = src.into_iter().collect();
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("a"), Some(&1));
        assert_eq!(m.get("b"), Some(&2));
    }

    #[test]
    fn test_stringmap_extend() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.extend([("b".to_string(), 2), ("c".to_string(), 3)]);
        assert_eq!(m.len(), 3);
        assert_eq!(m.get("a"), Some(&1));
        assert_eq!(m.get("b"), Some(&2));
        assert_eq!(m.get("c"), Some(&3));
    }

    #[test]
    fn test_stringmap_owned_into_iterator() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.insert("b".to_string(), 2);
        let collected: HashSet<(String, u32)> = m.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_stringmap_ref_into_iterator() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.insert("b".to_string(), 2);
        let mut count = 0usize;
        for (_, _) in &m {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_stringmap_ref_mut_into_iterator() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        m.insert("b".to_string(), 2);
        for (_, v) in &mut m {
            *v += 1;
        }
        assert_eq!(m.get("a"), Some(&2));
        assert_eq!(m.get("b"), Some(&3));
    }

    #[test]
    fn test_stringmap_clone_is_independent() {
        let mut m: StringMap<u32> = StringMap::new();
        m.insert("a".to_string(), 1);
        let mut c = m.clone();
        c.insert("a".to_string(), 99);
        // Original value must not be affected by mutation of the clone.
        assert_eq!(m.get("a"), Some(&1));
        assert_eq!(c.get("a"), Some(&99));
    }

    // --- OrderedMap tests --------------------------------------------------

    #[test]
    fn test_orderedmap_new_is_empty() {
        let m: OrderedMap<i64, u32> = OrderedMap::new();
        assert_eq!(m.len(), 0);
        assert!(m.is_empty());
    }

    #[test]
    fn test_orderedmap_default_is_empty() {
        let m: OrderedMap<i64, u32> = OrderedMap::default();
        assert!(m.is_empty());
    }

    #[test]
    fn test_orderedmap_insert_and_get() {
        let mut m: OrderedMap<i64, &'static str> = OrderedMap::new();
        assert_eq!(m.insert(42, "forty-two"), None);
        assert_eq!(m.get(&42), Some(&"forty-two"));
        assert!(m.contains_key(&42));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn test_orderedmap_insert_replaces() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        assert_eq!(m.insert(1, 100), None);
        assert_eq!(m.insert(1, 200), Some(100));
        assert_eq!(m.get(&1), Some(&200));
    }

    #[test]
    fn test_orderedmap_insert_unique_rejects_duplicate() {
        let mut m: OrderedMap<u64, &'static str> = OrderedMap::new();
        assert!(m.insert_unique(10, "first").is_ok());
        let rejected = m.insert_unique(10, "second");
        assert_eq!(rejected, Err("second"));
        assert_eq!(m.get(&10), Some(&"first"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn test_orderedmap_get_mut() {
        let mut m: OrderedMap<u32, u32> = OrderedMap::new();
        m.insert(1, 10);
        if let Some(v) = m.get_mut(&1) {
            *v += 5;
        }
        assert_eq!(m.get(&1), Some(&15));
    }

    #[test]
    fn test_orderedmap_get_required_ok_and_err() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(1, 100);
        assert_eq!(m.get_required(&1).unwrap(), &100);
        match m.get_required(&2) {
            Err(DsError::KeyNotFound) => {}
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_orderedmap_remove() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(1, 10);
        m.insert(2, 20);
        assert_eq!(m.remove(&1), Some(10));
        assert_eq!(m.get(&1), None);
        assert_eq!(m.len(), 1);
        assert_eq!(m.remove(&999), None);
    }

    #[test]
    fn test_orderedmap_clear() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(1, 10);
        m.insert(2, 20);
        m.insert(3, 30);
        m.clear();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn test_orderedmap_first_key_value() {
        let mut m: OrderedMap<i64, &'static str> = OrderedMap::new();
        assert_eq!(m.first_key_value(), None);
        // Insert deliberately out of order to exercise ordering.
        m.insert(3, "c");
        m.insert(1, "a");
        m.insert(2, "b");
        assert_eq!(m.first_key_value(), Some((&1, &"a")));
    }

    #[test]
    fn test_orderedmap_last_key_value() {
        let mut m: OrderedMap<i64, &'static str> = OrderedMap::new();
        assert_eq!(m.last_key_value(), None);
        m.insert(3, "c");
        m.insert(1, "a");
        m.insert(2, "b");
        assert_eq!(m.last_key_value(), Some((&3, &"c")));
    }

    #[test]
    fn test_orderedmap_pop_first_drains_in_order() {
        let mut m: OrderedMap<i64, &'static str> = OrderedMap::new();
        m.insert(3, "c");
        m.insert(1, "a");
        m.insert(2, "b");
        assert_eq!(m.pop_first(), Some((1, "a")));
        assert_eq!(m.pop_first(), Some((2, "b")));
        assert_eq!(m.pop_first(), Some((3, "c")));
        assert_eq!(m.pop_first(), None);
        assert!(m.is_empty());
    }

    #[test]
    fn test_orderedmap_pop_last_drains_in_reverse() {
        let mut m: OrderedMap<i64, &'static str> = OrderedMap::new();
        m.insert(3, "c");
        m.insert(1, "a");
        m.insert(2, "b");
        assert_eq!(m.pop_last(), Some((3, "c")));
        assert_eq!(m.pop_last(), Some((2, "b")));
        assert_eq!(m.pop_last(), Some((1, "a")));
        assert_eq!(m.pop_last(), None);
    }

    #[test]
    fn test_orderedmap_pop_first_empty_returns_none() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        assert_eq!(m.pop_first(), None);
        assert_eq!(m.pop_last(), None);
    }

    #[test]
    fn test_orderedmap_lower_bound_exact_match() {
        let mut m: OrderedMap<u64, &'static str> = OrderedMap::new();
        m.insert(10, "ten");
        m.insert(20, "twenty");
        m.insert(30, "thirty");
        // `lower_bound` is inclusive, so an exact hit must return that entry.
        assert_eq!(m.lower_bound(&20), Some((&20, &"twenty")));
    }

    #[test]
    fn test_orderedmap_lower_bound_gap() {
        let mut m: OrderedMap<u64, &'static str> = OrderedMap::new();
        m.insert(10, "ten");
        m.insert(20, "twenty");
        m.insert(30, "thirty");
        // 15 is in the gap between 10 and 20; first key >= 15 is 20.
        assert_eq!(m.lower_bound(&15), Some((&20, &"twenty")));
    }

    #[test]
    fn test_orderedmap_lower_bound_past_end() {
        let mut m: OrderedMap<u64, &'static str> = OrderedMap::new();
        m.insert(10, "ten");
        m.insert(20, "twenty");
        m.insert(30, "thirty");
        // 100 exceeds every key in the map.
        assert_eq!(m.lower_bound(&100), None);
    }

    #[test]
    fn test_orderedmap_lower_bound_before_start() {
        let mut m: OrderedMap<u64, &'static str> = OrderedMap::new();
        m.insert(10, "ten");
        m.insert(20, "twenty");
        m.insert(30, "thirty");
        // 5 is below every key; the first >= 5 is 10.
        assert_eq!(m.lower_bound(&5), Some((&10, &"ten")));
    }

    #[test]
    fn test_orderedmap_lower_bound_empty() {
        let m: OrderedMap<u64, &'static str> = OrderedMap::new();
        assert_eq!(m.lower_bound(&42), None);
    }

    #[test]
    fn test_orderedmap_iter_is_sorted() {
        let mut m: OrderedMap<i64, &'static str> = OrderedMap::new();
        // Insert in deliberately scrambled order.
        m.insert(5, "e");
        m.insert(1, "a");
        m.insert(4, "d");
        m.insert(2, "b");
        m.insert(3, "c");

        let keys: Vec<i64> = m.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_orderedmap_iter_mut_mutates_values() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(1, 10);
        m.insert(2, 20);
        for (_, v) in m.iter_mut() {
            *v *= 3;
        }
        assert_eq!(m.get(&1), Some(&30));
        assert_eq!(m.get(&2), Some(&60));
    }

    #[test]
    fn test_orderedmap_keys_and_values_sorted() {
        let mut m: OrderedMap<i64, &'static str> = OrderedMap::new();
        m.insert(3, "c");
        m.insert(1, "a");
        m.insert(2, "b");
        let keys: Vec<i64> = m.keys().copied().collect();
        let values: Vec<&'static str> = m.values().copied().collect();
        assert_eq!(keys, vec![1, 2, 3]);
        assert_eq!(values, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_orderedmap_values_mut() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(1, 10);
        m.insert(2, 20);
        for v in m.values_mut() {
            *v += 1;
        }
        assert_eq!(m.get(&1), Some(&11));
        assert_eq!(m.get(&2), Some(&21));
    }

    #[test]
    fn test_orderedmap_for_each_ascending() {
        let mut m: OrderedMap<i64, &'static str> = OrderedMap::new();
        m.insert(3, "c");
        m.insert(1, "a");
        m.insert(2, "b");
        let mut collected: Vec<(i64, &'static str)> = Vec::new();
        m.for_each(|k, v| collected.push((*k, *v)));
        assert_eq!(collected, vec![(1, "a"), (2, "b"), (3, "c")]);
    }

    #[test]
    fn test_orderedmap_for_each_rev() {
        let mut m: OrderedMap<i64, &'static str> = OrderedMap::new();
        m.insert(3, "c");
        m.insert(1, "a");
        m.insert(2, "b");
        let mut collected: Vec<(i64, &'static str)> = Vec::new();
        m.for_each_rev(|k, v| collected.push((*k, *v)));
        assert_eq!(collected, vec![(3, "c"), (2, "b"), (1, "a")]);
    }

    #[test]
    fn test_orderedmap_with_instant_keys_simulates_timer_walk() {
        // Exercises the critical timer-AVL consumer pattern documented on
        // `OrderedMap` with `u64` millisecond-deadline keys (Instant would
        // require time to pass and is non-deterministic).
        let mut timers: OrderedMap<u64, &'static str> = OrderedMap::new();
        timers.insert(300, "pem-reload");
        timers.insert(120, "idle-tick");
        timers.insert(7_200, "ocsp-refresh");
        timers.insert(30, "dns-query");

        let now = 150u64;
        let mut fired: Vec<&'static str> = Vec::new();

        // Drain every timer whose deadline has passed, the same shape used
        // by heavything::net::runtime at the top of the event loop.
        while let Some((deadline, _)) = timers.first_key_value() {
            if *deadline > now {
                break;
            }
            if let Some((_, label)) = timers.pop_first() {
                fired.push(label);
            }
        }

        // Two timers had deadlines <= 150: dns-query (30) and idle-tick (120).
        assert_eq!(fired, vec!["dns-query", "idle-tick"]);
        // The remaining timers must still be in ascending order.
        assert_eq!(timers.first_key_value(), Some((&300, &"pem-reload")));
        assert_eq!(timers.last_key_value(), Some((&7_200, &"ocsp-refresh")));
    }

    #[test]
    fn test_orderedmap_from_iterator() {
        let src: Vec<(i64, &'static str)> = vec![(3, "c"), (1, "a"), (2, "b")];
        let m: OrderedMap<i64, &'static str> = src.into_iter().collect();
        assert_eq!(m.len(), 3);
        let keys: Vec<i64> = m.keys().copied().collect();
        assert_eq!(keys, vec![1, 2, 3]);
    }

    #[test]
    fn test_orderedmap_extend() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(1, 100);
        m.extend([(2, 200), (3, 300)]);
        let keys: Vec<i64> = m.keys().copied().collect();
        assert_eq!(keys, vec![1, 2, 3]);
        assert_eq!(m.get(&2), Some(&200));
        assert_eq!(m.get(&3), Some(&300));
    }

    #[test]
    fn test_orderedmap_owned_into_iterator_ordered() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(3, 30);
        m.insert(1, 10);
        m.insert(2, 20);
        let collected: Vec<(i64, u32)> = m.into_iter().collect();
        assert_eq!(collected, vec![(1, 10), (2, 20), (3, 30)]);
    }

    #[test]
    fn test_orderedmap_ref_into_iterator() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(2, 20);
        m.insert(1, 10);
        let mut collected: Vec<(i64, u32)> = Vec::new();
        for (k, v) in &m {
            collected.push((*k, *v));
        }
        assert_eq!(collected, vec![(1, 10), (2, 20)]);
    }

    #[test]
    fn test_orderedmap_ref_mut_into_iterator() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(2, 20);
        m.insert(1, 10);
        for (_, v) in &mut m {
            *v += 1;
        }
        assert_eq!(m.get(&1), Some(&11));
        assert_eq!(m.get(&2), Some(&21));
    }

    #[test]
    fn test_orderedmap_clone_is_independent() {
        let mut m: OrderedMap<i64, u32> = OrderedMap::new();
        m.insert(1, 10);
        let mut c = m.clone();
        c.insert(2, 20);
        assert_eq!(m.len(), 1);
        assert_eq!(c.len(), 2);
        assert_eq!(m.get(&2), None);
        assert_eq!(c.get(&1), Some(&10));
    }

    #[test]
    fn test_orderedmap_with_unsigned_keys() {
        // The FASM `unsignedmap` variant collapses into `OrderedMap<u64, V>`
        // without requiring any separate type.
        let mut m: OrderedMap<u64, u32> = OrderedMap::new();
        m.insert(0, 0);
        m.insert(u64::MAX, 999);
        m.insert(1, 1);
        assert_eq!(m.first_key_value(), Some((&0, &0)));
        assert_eq!(m.last_key_value(), Some((&u64::MAX, &999)));
    }
}
