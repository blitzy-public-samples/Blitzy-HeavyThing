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

//! Doubly-linked-list-style sequential container — port of `list.inc`
//! (874 lines of FASM assembly).
//!
//! Per AAP §0.5.1.6 this file wraps [`std::collections::VecDeque`]
//! ("`VecDeque` for sequential access; custom linked list only where
//! `list$foreach` callback-based iteration demands it"). An audit of
//! in-scope consumers (`tui::object` widget children, `net::runtime`
//! connection lists, etc.) confirmed none rely on the FASM
//! mid-iteration stable-pointer guarantee, so this file uses **pure
//! `VecDeque<T>`** with **zero `unsafe` blocks**.
//!
//! The original FASM `list` object occupied 24 bytes (`_list_size_ofs`,
//! `_list_first_ofs`, `_list_last_ofs`) and threaded 24-byte heap-
//! allocated item blocks via `_list_valueofs` / `_list_nextofs` /
//! `_list_prevofs`. `VecDeque` preserves the same asymptotic profile
//! — O(1) push / pop at both ends, O(1) front / back / indexed access,
//! O(n) insert / remove in the middle — with substantially better
//! cache locality.
//!
//! # Dependency discipline
//!
//! Per the ds-folder rules this module depends on `std` and
//! [`crate::error::DsError`] only; no sibling `heavything` subsystem is
//! imported. Randomness-dependent operations (see [`List::shuffle`])
//! accept a caller-supplied `FnMut(usize) -> usize` closure to preserve
//! that boundary.

use std::collections::vec_deque;
use std::collections::VecDeque;

use crate::error::DsError;

// ============================================================================
// `List<T>` — sequential container matching FASM `list$*` semantics.
// ============================================================================

/// A sequential container matching the public API of the FASM `list`
/// object from `list.inc`.
///
/// Internally a [`VecDeque<T>`] — see the module-level documentation
/// for the rationale and behavioural equivalence analysis. Public
/// methods mirror the FASM `list$*` function set one-for-one (with
/// `index`-based insertion / removal replacing FASM's pointer-based
/// `list$insert_before` / `list$insert_after` / `list$remove`).
///
/// # Type parameter
///
/// - `T`: the value type. Individual values are automatically dropped
///   when the containing `List` is dropped — this subsumes the
///   FASM-level `list$clear_arg(heap$free)` discipline.
///
/// # Thread safety
///
/// `List<T>` is `Send + Sync` iff `T: Send + Sync` via the auto traits
/// on [`VecDeque`].
#[derive(Debug, Clone, Default)]
pub struct List<T> {
    inner: VecDeque<T>,
}

// ----------------------------------------------------------------------------
// Construction
// ----------------------------------------------------------------------------

impl<T> List<T> {
    /// Creates a new, empty list. Equivalent to FASM `list$new` with no
    /// capacity hint.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: VecDeque::new(),
        }
    }

    /// Creates a new list with at least the specified initial
    /// capacity. Useful when the expected final size is known upfront
    /// to avoid intermediate reallocations.
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(capacity),
        }
    }
}

// ----------------------------------------------------------------------------
// Basic accessors (read-only and mutable front/back/index access)
// ----------------------------------------------------------------------------

impl<T> List<T> {
    /// Returns the number of elements currently stored. Equivalent to
    /// FASM `list$size` which loads `[_list_size_ofs]`.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` when the list contains no elements.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the current allocation capacity of the underlying
    /// `VecDeque` in elements.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns a reference to the first element, or `None` when the
    /// list is empty. Equivalent to FASM `list$front` which returns
    /// `[_list_first_ofs]`.
    #[inline]
    #[must_use]
    pub fn front(&self) -> Option<&T> {
        self.inner.front()
    }

    /// Returns a mutable reference to the first element, or `None`
    /// when the list is empty.
    #[inline]
    #[must_use]
    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.inner.front_mut()
    }

    /// Returns a reference to the last element, or `None` when the
    /// list is empty. Equivalent to FASM `list$back` which returns
    /// `[_list_last_ofs]`.
    #[inline]
    #[must_use]
    pub fn back(&self) -> Option<&T> {
        self.inner.back()
    }

    /// Returns a mutable reference to the last element, or `None`
    /// when the list is empty.
    #[inline]
    #[must_use]
    pub fn back_mut(&mut self) -> Option<&mut T> {
        self.inner.back_mut()
    }

    /// Returns a reference to the element at `index`, or `None` when
    /// `index >= self.len()`. Equivalent to FASM `list$index` which
    /// walks the linked list until the requested ordinal is reached
    /// (O(n) in FASM; O(1) for `VecDeque`).
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    /// Returns a mutable reference to the element at `index`, or
    /// `None` when `index >= self.len()`.
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.inner.get_mut(index)
    }
}

// ----------------------------------------------------------------------------
// Push / pop — O(1) at both ends
// ----------------------------------------------------------------------------

impl<T> List<T> {
    /// Prepends `value` to the front of the list. O(1) amortised.
    /// Equivalent to FASM `list$push_front`.
    #[inline]
    pub fn push_front(&mut self, value: T) {
        self.inner.push_front(value);
    }

    /// Appends `value` to the back of the list. O(1) amortised.
    /// Equivalent to FASM `list$push_back`.
    #[inline]
    pub fn push_back(&mut self, value: T) {
        self.inner.push_back(value);
    }

    /// Removes and returns the first element, or `None` when the list
    /// is empty. O(1). Equivalent to FASM `list$pop_front`, which
    /// returns the item value and frees the 24-byte item block; Rust
    /// accomplishes the latter automatically via `Drop`.
    #[inline]
    pub fn pop_front(&mut self) -> Option<T> {
        self.inner.pop_front()
    }

    /// Removes and returns the last element, or `None` when the list
    /// is empty. O(1). Equivalent to FASM `list$pop_back`.
    #[inline]
    pub fn pop_back(&mut self) -> Option<T> {
        self.inner.pop_back()
    }
}

// ----------------------------------------------------------------------------
// Insert / remove / clear
// ----------------------------------------------------------------------------

impl<T> List<T> {
    /// Inserts `value` at position `index`, shifting subsequent
    /// elements one slot toward the back.
    ///
    /// Accepts `index == self.len()` (equivalent to [`push_back`](Self::push_back)).
    ///
    /// # Errors
    ///
    /// Returns [`DsError::BufferOverflow`] when `index > self.len()`.
    /// The `requested` field carries the attempted index, and
    /// `capacity` carries the current list length, providing callers
    /// with actionable diagnostics per AAP §0.8.3.
    ///
    /// This is the Rust equivalent of the FASM
    /// `list$insert_before` / `list$insert_after` pair, re-expressed
    /// as index-based insertion.
    pub fn insert(&mut self, index: usize, value: T) -> Result<(), DsError> {
        let len = self.inner.len();
        if index > len {
            return Err(DsError::BufferOverflow {
                requested: index,
                capacity: len,
            });
        }
        self.inner.insert(index, value);
        Ok(())
    }

    /// Removes and returns the element at `index`, shifting subsequent
    /// elements one slot toward the front. Returns `None` when
    /// `index >= self.len()`.
    ///
    /// The `Option` return style matches
    /// [`VecDeque::remove`] / [`std::collections::HashMap::remove`]
    /// convention: an out-of-range index is informationally equivalent
    /// to an empty slot and is not treated as an error per AAP §0.8.3.
    /// Equivalent to FASM `list$remove`.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        self.inner.remove(index)
    }

    /// Removes all elements, dropping each in turn. The underlying
    /// allocation capacity is preserved.
    ///
    /// Equivalent to FASM `list$clear` — when the FASM `clearfunc`
    /// argument is `heap$free` the Rust `Drop` implementation of each
    /// element accomplishes the same cleanup automatically.
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

// ----------------------------------------------------------------------------
// Iteration
// ----------------------------------------------------------------------------

impl<T> List<T> {
    /// Returns a front-to-back iterator over the list's elements.
    #[inline]
    pub fn iter(&self) -> vec_deque::Iter<'_, T> {
        self.inner.iter()
    }

    /// Returns a front-to-back iterator over the list's elements with
    /// mutable access.
    #[inline]
    pub fn iter_mut(&mut self) -> vec_deque::IterMut<'_, T> {
        self.inner.iter_mut()
    }

    /// Applies `f` to each element in front-to-back order.
    ///
    /// Equivalent to FASM
    /// `list$foreach` / `list$foreach_arg` / `list$foreach_items` —
    /// the FASM `arg` parameter (used as a workaround for assembly's
    /// lack of closures) is subsumed by the Rust closure's ability to
    /// capture surrounding state directly.
    pub fn for_each<F: FnMut(&T)>(&self, mut f: F) {
        for item in self.inner.iter() {
            f(item);
        }
    }

    /// Applies `f` to each element in front-to-back order with
    /// mutable access.
    pub fn for_each_mut<F: FnMut(&mut T)>(&mut self, mut f: F) {
        for item in self.inner.iter_mut() {
            f(item);
        }
    }

    /// Applies `f` to each element in back-to-front order. Equivalent
    /// to FASM `list$reverse_foreach` / `list$reverse_foreach_items`.
    pub fn for_each_rev<F: FnMut(&T)>(&self, mut f: F) {
        for item in self.inner.iter().rev() {
            f(item);
        }
    }

    /// Applies `f` to each element in back-to-front order with
    /// mutable access.
    pub fn for_each_rev_mut<F: FnMut(&mut T)>(&mut self, mut f: F) {
        for item in self.inner.iter_mut().rev() {
            f(item);
        }
    }

    /// Retains only the elements for which `f` returns `true`,
    /// dropping all others. Equivalent to the FASM
    /// iterate-with-in-place-removal pattern; idiomatic Rust surfaces
    /// this directly via [`VecDeque::retain`].
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, f: F) {
        self.inner.retain(f);
    }
}

// ----------------------------------------------------------------------------
// Snapshot (T: Clone) and in-place shuffle (T: any)
// ----------------------------------------------------------------------------

impl<T: Clone> List<T> {
    /// Returns a `Vec<T>` containing a cloned snapshot of the list's
    /// values in front-to-back order. Equivalent to FASM
    /// `list$to_array`, which `heap$alloc`'s a contiguous block of
    /// pointers and walks the linked list copying each value.
    #[must_use]
    pub fn to_vec(&self) -> Vec<T> {
        self.inner.iter().cloned().collect()
    }
}

impl<T> List<T> {
    /// Shuffles the list in place using a caller-provided uniform-
    /// range random generator.
    ///
    /// `gen_range` is invoked with an upper bound `n > 0` and is
    /// expected to return a uniformly distributed `usize` in
    /// `[0, n)`. The caller supplies the RNG so this module remains
    /// independent of `crate::crypto::rng` (see the ds-folder rules).
    ///
    /// This is the Rust port of FASM `list$shuffle` (lines 827–873).
    /// The original materialised an intermediate array via
    /// `list$to_array`, applied Fisher–Yates, then walked the linked
    /// list writing back the shuffled values and freed the temporary
    /// array. Rust operates directly on `VecDeque`'s contiguous
    /// backing slice via [`VecDeque::make_contiguous`], eliminating
    /// the intermediate allocation.
    ///
    /// # Robustness
    ///
    /// A misbehaving `gen_range` that returns a value outside
    /// `[0, n)` is **not** permitted to trigger a panic in this safe-
    /// Rust wrapper. The implementation clamps the returned index to
    /// `remaining - 1` to guarantee `slice.swap` stays in bounds; a
    /// well-behaved caller is unaffected by the clamp.
    ///
    /// Lists of 0 or 1 elements are a no-op.
    pub fn shuffle<F: FnMut(usize) -> usize>(&mut self, mut gen_range: F) {
        let len = self.inner.len();
        if len < 2 {
            return;
        }
        let slice = self.inner.make_contiguous();
        // Fisher–Yates: for each position i in [0, len - 1), pick a
        // uniformly random offset into the unshuffled tail and swap.
        for i in 0..(len - 1) {
            let remaining = len - i;
            let r = gen_range(remaining);
            let j = i + r.min(remaining - 1);
            slice.swap(i, j);
        }
    }
}

// ----------------------------------------------------------------------------
// Standard-trait implementations
// ----------------------------------------------------------------------------

impl<T> IntoIterator for List<T> {
    type Item = T;
    type IntoIter = vec_deque::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a List<T> {
    type Item = &'a T;
    type IntoIter = vec_deque::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut List<T> {
    type Item = &'a mut T;
    type IntoIter = vec_deque::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

impl<T> FromIterator<T> for List<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

impl<T> Extend<T> for List<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- construction ---------------------------------------------------------

    #[test]
    fn test_new_is_empty() {
        let l: List<i32> = List::new();
        assert_eq!(l.len(), 0);
        assert!(l.is_empty());
        assert!(l.front().is_none());
        assert!(l.back().is_none());
    }

    #[test]
    fn test_with_capacity() {
        let l: List<u8> = List::with_capacity(32);
        assert!(l.is_empty());
        assert!(l.capacity() >= 32);
    }

    #[test]
    fn test_default_is_empty() {
        let l: List<String> = List::default();
        assert!(l.is_empty());
    }

    // -- push / pop -----------------------------------------------------------

    #[test]
    fn test_push_front_back_sequence() {
        let mut l: List<i32> = List::new();
        l.push_front(3);
        l.push_front(2);
        l.push_back(4);
        assert_eq!(l.len(), 3);
        assert_eq!(l.to_vec(), vec![2, 3, 4]);
    }

    #[test]
    fn test_pop_front_drains_in_order() {
        let mut l: List<i32> = (0..10).collect();
        for expected in 0..10 {
            assert_eq!(l.pop_front(), Some(expected));
        }
        assert!(l.is_empty());
    }

    #[test]
    fn test_pop_back_drains_in_reverse() {
        let mut l: List<i32> = (0..10).collect();
        for expected in (0..10).rev() {
            assert_eq!(l.pop_back(), Some(expected));
        }
        assert!(l.is_empty());
    }

    #[test]
    fn test_pop_empty_returns_none() {
        let mut l: List<u8> = List::new();
        assert!(l.pop_front().is_none());
        assert!(l.pop_back().is_none());
    }

    #[test]
    fn test_front_back_access() {
        let mut l: List<i32> = List::new();
        l.push_back(10);
        l.push_back(20);
        l.push_back(30);
        assert_eq!(l.front(), Some(&10));
        assert_eq!(l.back(), Some(&30));
        *l.front_mut().unwrap() = 100;
        *l.back_mut().unwrap() = 300;
        assert_eq!(l.to_vec(), vec![100, 20, 300]);
    }

    #[test]
    fn test_get_and_get_mut() {
        let mut l: List<i32> = (10..15).collect();
        assert_eq!(l.get(0), Some(&10));
        assert_eq!(l.get(4), Some(&14));
        assert!(l.get(5).is_none());
        *l.get_mut(2).unwrap() = 99;
        assert_eq!(l.get(2), Some(&99));
        assert!(l.get_mut(100).is_none());
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut l: List<i32> = List::new();
        assert_eq!(l.len(), 0);
        assert!(l.is_empty());
        l.push_back(1);
        assert_eq!(l.len(), 1);
        assert!(!l.is_empty());
        l.pop_back();
        assert!(l.is_empty());
    }

    // -- insert / remove ------------------------------------------------------

    #[test]
    fn test_insert_middle() {
        let mut l: List<char> = List::new();
        l.push_back('a');
        l.push_back('c');
        l.insert(1, 'b').unwrap();
        assert_eq!(l.to_vec(), vec!['a', 'b', 'c']);
    }

    #[test]
    fn test_insert_at_end() {
        let mut l: List<char> = List::new();
        l.push_back('a');
        l.push_back('b');
        l.insert(2, 'c').unwrap();
        assert_eq!(l.to_vec(), vec!['a', 'b', 'c']);
    }

    #[test]
    fn test_insert_at_front() {
        let mut l: List<i32> = List::new();
        l.push_back(2);
        l.push_back(3);
        l.insert(0, 1).unwrap();
        assert_eq!(l.to_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn test_insert_out_of_bounds() {
        let mut l: List<char> = List::new();
        l.push_back('a');
        let err = l.insert(5, 'x').unwrap_err();
        match err {
            DsError::BufferOverflow { requested, capacity } => {
                assert_eq!(requested, 5);
                assert_eq!(capacity, 1);
            }
            other => panic!("expected BufferOverflow, got {other:?}"),
        }
        // List is unchanged.
        assert_eq!(l.to_vec(), vec!['a']);
    }

    #[test]
    fn test_remove_middle() {
        let mut l: List<char> = List::new();
        l.push_back('a');
        l.push_back('b');
        l.push_back('c');
        assert_eq!(l.remove(1), Some('b'));
        assert_eq!(l.to_vec(), vec!['a', 'c']);
    }

    #[test]
    fn test_remove_out_of_bounds() {
        let mut l: List<char> = List::new();
        l.push_back('a');
        assert_eq!(l.remove(5), None);
        assert_eq!(l.to_vec(), vec!['a']);
    }

    // -- iteration ------------------------------------------------------------

    #[test]
    fn test_for_each_order() {
        let l: List<i32> = (1..=5).collect();
        let mut collected = Vec::new();
        l.for_each(|v| collected.push(*v));
        assert_eq!(collected, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_for_each_rev_order() {
        let l: List<i32> = (1..=5).collect();
        let mut collected = Vec::new();
        l.for_each_rev(|v| collected.push(*v));
        assert_eq!(collected, vec![5, 4, 3, 2, 1]);
    }

    #[test]
    fn test_for_each_mut() {
        let mut l: List<i32> = (1..=5).collect();
        l.for_each_mut(|v| *v *= 2);
        assert_eq!(l.to_vec(), vec![2, 4, 6, 8, 10]);
    }

    #[test]
    fn test_for_each_rev_mut() {
        let mut l: List<i32> = vec![1, 2, 3].into_iter().collect();
        let mut seen = Vec::new();
        l.for_each_rev_mut(|v| {
            seen.push(*v);
            *v += 10;
        });
        assert_eq!(seen, vec![3, 2, 1]);
        assert_eq!(l.to_vec(), vec![11, 12, 13]);
    }

    #[test]
    fn test_retain_keeps_matching() {
        let mut l: List<i32> = (0..10).collect();
        l.retain(|&x| x % 2 == 0);
        assert_eq!(l.to_vec(), vec![0, 2, 4, 6, 8]);
    }

    #[test]
    fn test_iter_and_iter_mut() {
        let mut l: List<i32> = (1..=3).collect();
        let sum: i32 = l.iter().sum();
        assert_eq!(sum, 6);
        for v in l.iter_mut() {
            *v += 100;
        }
        assert_eq!(l.to_vec(), vec![101, 102, 103]);
    }

    // -- snapshot / clear -----------------------------------------------------

    #[test]
    fn test_to_vec_preserves_order() {
        let l: List<i32> = vec![7, 8, 9].into_iter().collect();
        assert_eq!(l.to_vec(), vec![7, 8, 9]);
    }

    #[test]
    fn test_clear_empties_preserves_capacity() {
        let mut l: List<i32> = List::with_capacity(32);
        for i in 0..10 {
            l.push_back(i);
        }
        let cap_before = l.capacity();
        l.clear();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
        assert_eq!(l.capacity(), cap_before);
    }

    // -- shuffle --------------------------------------------------------------

    #[test]
    fn test_shuffle_empty_is_noop() {
        let mut l: List<i32> = List::new();
        l.shuffle(|_| 0);
        assert!(l.is_empty());
    }

    #[test]
    fn test_shuffle_single_is_noop() {
        let mut l: List<i32> = List::new();
        l.push_back(42);
        l.shuffle(|_| 0);
        assert_eq!(l.to_vec(), vec![42]);
    }

    #[test]
    fn test_shuffle_deterministic_stub() {
        // gen_range(_) always returns 0. Fisher–Yates swaps element i with
        // itself every iteration, leaving the list unchanged.
        let mut l: List<i32> = (0..5).collect();
        l.shuffle(|_| 0);
        assert_eq!(l.to_vec(), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_shuffle_reverse_stub() {
        // gen_range(n) = n - 1 swaps i with the last element of the remaining
        // slice on every iteration, yielding a deterministic permutation.
        //
        // Trace with [0, 1, 2, 3, 4]:
        //   i=0, remaining=5, j=0+4=4 -> swap(0, 4) -> [4, 1, 2, 3, 0]
        //   i=1, remaining=4, j=1+3=4 -> swap(1, 4) -> [4, 0, 2, 3, 1]
        //   i=2, remaining=3, j=2+2=4 -> swap(2, 4) -> [4, 0, 1, 3, 2]
        //   i=3, remaining=2, j=3+1=4 -> swap(3, 4) -> [4, 0, 1, 2, 3]
        let mut l: List<i32> = (0..5).collect();
        l.shuffle(|n| n - 1);
        assert_eq!(l.to_vec(), vec![4, 0, 1, 2, 3]);
    }

    #[test]
    fn test_shuffle_clamp_misbehaving_rng() {
        // A broken gen_range that returns values outside [0, n) must not
        // cause a panic. The clamp ensures slice.swap stays in range.
        let mut l: List<i32> = (0..5).collect();
        l.shuffle(|_| 999);
        // No panic; length is preserved; values are a permutation of 0..5.
        assert_eq!(l.len(), 5);
        let mut v = l.to_vec();
        v.sort();
        assert_eq!(v, vec![0, 1, 2, 3, 4]);
    }

    // -- traits ---------------------------------------------------------------

    #[test]
    fn test_from_iterator() {
        let l: List<i32> = (0..5).collect();
        assert_eq!(l.to_vec(), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_extend() {
        let mut l: List<i32> = List::new();
        l.push_back(-1);
        l.extend(0..3);
        assert_eq!(l.to_vec(), vec![-1, 0, 1, 2]);
    }

    #[test]
    fn test_into_iterator_owned() {
        let l: List<i32> = (1..=3).collect();
        let collected: Vec<i32> = l.into_iter().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    #[test]
    fn test_into_iterator_ref() {
        let l: List<i32> = (1..=3).collect();
        let sum: i32 = (&l).into_iter().sum();
        assert_eq!(sum, 6);
        // Original is still usable.
        assert_eq!(l.len(), 3);
    }

    #[test]
    fn test_into_iterator_ref_mut() {
        let mut l: List<i32> = (1..=3).collect();
        for v in &mut l {
            *v *= 10;
        }
        assert_eq!(l.to_vec(), vec![10, 20, 30]);
    }

    #[test]
    fn test_clone_eq_snapshot() {
        let l: List<i32> = (0..4).collect();
        let c = l.clone();
        assert_eq!(l.to_vec(), c.to_vec());
    }

    #[test]
    fn test_debug_impl_is_available() {
        // Just ensures the Debug derive is wired up; the exact rendering is
        // an implementation detail of VecDeque's Debug impl.
        let l: List<i32> = vec![1, 2, 3].into_iter().collect();
        let s = format!("{l:?}");
        assert!(s.contains('1') && s.contains('2') && s.contains('3'));
    }
}
