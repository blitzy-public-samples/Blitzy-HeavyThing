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

//! Integration tests for the `heavything::ds` subsystem.
//!
//! These tests exercise the public API surface of the data-structures
//! subsystem from an external-consumer perspective (the `tests/` directory
//! produces a separate compilation unit that links against the `heavything`
//! library as if it were any other downstream crate). Collectively they
//! cover all six required in-scope features of the DS checkpoint:
//!
//! * `Buffer` — capacity defaults, append growth, `clear` capacity
//!   preservation, and a 10 MiB stress write.
//! * `StringMap` — CRUD, duplicate-key overwrite, safe empty-map
//!   operations, and 10_000-entry retrieval.
//! * `OrderedMap` — sorted iteration, range query, and post-removal
//!   order preservation (the invariants required by the epoll timer
//!   AVL walk per AAP §0.5.1.6).
//! * `List` — bidirectional push/pop, `for_each` callback semantics,
//!   and safe empty-list pop.
//! * `memfuncs` — slice `copy` parity with `slice::copy_from_slice`,
//!   `fill` byte coverage, and equal / differing slice comparisons.
//! * `DsError` — `BufferOverflow { requested, capacity }` and
//!   `KeyNotFound` variant construction plus `Display` output.
//!
//! Tests use the fluent
//! `match result { Err(DsError::BufferOverflow { .. }) => { ... }
//!  other => panic!("expected BufferOverflow, got {other:?}") }`
//! destructuring pattern because `DsError` does not derive `PartialEq`
//! (see the type definition at `src/error.rs`).

#![allow(clippy::unwrap_used)]

use heavything::ds::memfuncs;
use heavything::ds::{Buffer, List, OrderedMap, StringMap};
use heavything::error::DsError;

// ============================================================================
// Buffer tests (Issues 6–10)
// ============================================================================

#[test]
fn test_buffer_new_has_default_capacity() {
    let buf = Buffer::new();
    // AAP §0.5.1.6 — `Buffer::new()` starts with the `buffer.inc`
    // default of at least 256 bytes.
    assert!(
        buf.capacity() >= 256,
        "Buffer::new() should have capacity >= 256, got {}",
        buf.capacity()
    );
    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
}

#[test]
fn test_buffer_append_bytes_grows_length() {
    let mut buf = Buffer::new();
    buf.extend_from_slice(b"hello");
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.as_slice(), b"hello");

    buf.extend_from_slice(b", world");
    assert_eq!(buf.len(), 12);
    assert_eq!(buf.as_slice(), b"hello, world");

    // Single-byte `push` must also advance the length by one.
    buf.push(b'!');
    assert_eq!(buf.len(), 13);
    assert_eq!(buf.as_slice(), b"hello, world!");
}

#[test]
fn test_buffer_grows_past_initial_capacity() {
    // Start with a small capacity; writing more than that must trigger
    // Vec's growth strategy without panic or data loss.
    let mut buf = Buffer::with_capacity(4);
    let initial_capacity = buf.capacity();
    assert!(initial_capacity >= 4);

    // Write 256 bytes — far past the initial 4 bytes.
    let payload: Vec<u8> = (0..256u32).map(|i| (i & 0xFF) as u8).collect();
    buf.extend_from_slice(&payload);

    assert_eq!(buf.len(), 256);
    assert!(
        buf.capacity() >= 256,
        "capacity should grow to >= 256 after writing 256 bytes, got {}",
        buf.capacity()
    );
    // The data written must match the source exactly.
    assert_eq!(buf.as_slice(), payload.as_slice());
}

#[test]
fn test_buffer_clear_resets_length_but_keeps_capacity() {
    let mut buf = Buffer::new();
    buf.extend_from_slice(&[0xAA; 1024]);
    assert_eq!(buf.len(), 1024);

    let capacity_before_clear = buf.capacity();
    assert!(capacity_before_clear >= 1024);

    buf.clear();

    // Length is zeroed.
    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
    // Capacity is preserved (matches `Vec::clear` semantics, AAP §0.5.1.6).
    assert_eq!(
        buf.capacity(),
        capacity_before_clear,
        "clear() must not free the backing allocation"
    );
}

#[test]
fn test_buffer_large_write_10mb() {
    // Stress test: 10 MiB in-memory write. Exercises Vec growth across
    // many reallocations and proves Buffer can hold realistic HTTP
    // request-body sizes (AAP §0.5.1.6 / webserver.inc maxrequest = 64 MiB).
    const CHUNK: [u8; 1024] = [0x5Au8; 1024];
    const ITERS: usize = 10 * 1024; // 10 MiB / 1 KiB per chunk.

    let mut buf = Buffer::new();
    for _ in 0..ITERS {
        buf.extend_from_slice(&CHUNK);
    }

    let expected_len = ITERS * CHUNK.len();
    assert_eq!(buf.len(), expected_len);
    assert_eq!(buf.len(), 10 * 1024 * 1024);

    // Spot-check first, middle, and last bytes to rule out data
    // corruption across the reallocation boundary.
    assert_eq!(buf.as_slice()[0], 0x5A);
    assert_eq!(buf.as_slice()[5 * 1024 * 1024], 0x5A);
    assert_eq!(buf.as_slice()[expected_len - 1], 0x5A);
}

// ============================================================================
// StringMap tests (Issues 11–14)
// ============================================================================

#[test]
fn test_stringmap_insert_get_remove() {
    let mut map: StringMap<u32> = StringMap::new();
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);

    // Insert three entries; first insert of a key returns None.
    assert_eq!(map.insert("alpha".to_string(), 1), None);
    assert_eq!(map.insert("beta".to_string(), 2), None);
    assert_eq!(map.insert("gamma".to_string(), 3), None);
    assert_eq!(map.len(), 3);
    assert!(!map.is_empty());

    // Get returns borrowed references to the stored values.
    assert_eq!(map.get("alpha"), Some(&1));
    assert_eq!(map.get("beta"), Some(&2));
    assert_eq!(map.get("gamma"), Some(&3));
    assert_eq!(map.get("missing"), None);

    assert!(map.contains_key("alpha"));
    assert!(!map.contains_key("missing"));

    // Remove returns the old value.
    assert_eq!(map.remove("beta"), Some(2));
    assert_eq!(map.len(), 2);
    assert_eq!(map.get("beta"), None);

    // Removing a missing key returns None (no panic).
    assert_eq!(map.remove("missing"), None);
}

#[test]
fn test_stringmap_duplicate_key_overwrites() {
    let mut map: StringMap<&'static str> = StringMap::new();
    assert_eq!(map.insert("key".to_string(), "first"), None);
    assert_eq!(map.get("key"), Some(&"first"));

    // Re-inserting the same key must return the previous value and
    // overwrite in place. Length must NOT grow.
    assert_eq!(map.insert("key".to_string(), "second"), Some("first"));
    assert_eq!(map.len(), 1);
    assert_eq!(map.get("key"), Some(&"second"));

    // Third overwrite returns the second value, preserving the chain.
    assert_eq!(map.insert("key".to_string(), "third"), Some("second"));
    assert_eq!(map.get("key"), Some(&"third"));
    assert_eq!(map.len(), 1);
}

#[test]
fn test_stringmap_empty_operations() {
    // Fresh empty map: get / remove / contains_key / iter must all be
    // safe (no panic, no crash) per AAP §0.8.3 "no-panic" discipline.
    let mut map: StringMap<i64> = StringMap::new();
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
    assert_eq!(map.get("anything"), None);
    assert_eq!(map.get(""), None);
    assert!(!map.contains_key("foo"));
    assert_eq!(map.remove("foo"), None);

    // Iterating an empty map yields zero items.
    let collected: Vec<(&String, &i64)> = map.iter().collect();
    assert!(collected.is_empty());

    // `get_required` on an empty map must return the `KeyNotFound`
    // variant (verified via match because `DsError` lacks `PartialEq`).
    match map.get_required("bar") {
        Err(DsError::KeyNotFound) => {}
        other => panic!("expected KeyNotFound, got {other:?}"),
    }

    // `clear` on an empty map is a safe no-op.
    map.clear();
    assert!(map.is_empty());
}

#[test]
fn test_stringmap_10k_entries_retrieval() {
    // Scale test: insert 10_000 entries and verify 100% retrieval.
    // Exercises HashMap bucket distribution and rehash triggers —
    // catches any hash-quality or key-lifetime regressions.
    let mut map: StringMap<u32> = StringMap::with_capacity(10_000);
    for i in 0u32..10_000 {
        let key = format!("key_{i:05}");
        assert_eq!(map.insert(key, i), None);
    }
    assert_eq!(map.len(), 10_000);

    // Every key must be retrievable.
    for i in 0u32..10_000 {
        let key = format!("key_{i:05}");
        assert_eq!(map.get(&key), Some(&i), "missing key_{i:05}");
    }

    // A few negative lookups outside the inserted range.
    assert_eq!(map.get("key_99999"), None);
    assert_eq!(map.get("nonexistent"), None);
}

// ============================================================================
// OrderedMap tests (Issues 15–17)
// ============================================================================

#[test]
fn test_ordered_map_sorted_iteration() {
    // Insert keys in scrambled order; `iter()` must yield them in
    // ascending key order — the core invariant required by the epoll
    // timer AVL walk (AAP §0.5.1.6 / epoll.inc dispatch).
    let mut map: OrderedMap<i32, &'static str> = OrderedMap::new();
    map.insert(5, "five");
    map.insert(1, "one");
    map.insert(4, "four");
    map.insert(2, "two");
    map.insert(3, "three");

    let keys: Vec<i32> = map.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![1, 2, 3, 4, 5]);

    let values: Vec<&'static str> = map.iter().map(|(_, v)| *v).collect();
    assert_eq!(values, vec!["one", "two", "three", "four", "five"]);

    // `first_key_value` / `last_key_value` reflect the sorted order.
    assert_eq!(map.first_key_value(), Some((&1, &"one")));
    assert_eq!(map.last_key_value(), Some((&5, &"five")));
}

#[test]
fn test_ordered_map_range_query() {
    // `range` must return the contiguous subset between the bounds,
    // also in sorted order.
    let mut map: OrderedMap<i32, i32> = OrderedMap::new();
    for i in (0..=50).step_by(10) {
        // inserts 0, 10, 20, 30, 40, 50.
        map.insert(i, i * 2);
    }

    // Inclusive range `20..=40` should contain three entries:
    // (20, 40), (30, 60), (40, 80).
    let subset: Vec<(i32, i32)> = map.range(20..=40).map(|(k, v)| (*k, *v)).collect();
    assert_eq!(subset, vec![(20, 40), (30, 60), (40, 80)]);

    // Half-open range `10..40` should contain 10, 20, 30 only.
    let half_open: Vec<i32> = map.range(10..40).map(|(k, _)| *k).collect();
    assert_eq!(half_open, vec![10, 20, 30]);

    // Range with no intersecting entries must yield an empty iterator.
    let empty: Vec<i32> = map.range(100..200).map(|(k, _)| *k).collect();
    assert!(empty.is_empty());
}

#[test]
fn test_ordered_map_remove_preserves_order() {
    // After removing interior and edge keys, remaining iteration must
    // still be strictly ascending — no AVL / BTreeMap regressions.
    let mut map: OrderedMap<u32, u32> = OrderedMap::new();
    for i in 1u32..=10 {
        map.insert(i, i * 100);
    }
    assert_eq!(map.len(), 10);

    // Remove an interior key.
    assert_eq!(map.remove(&5), Some(500));
    // Remove both edge keys (current min and max).
    assert_eq!(map.remove(&1), Some(100));
    assert_eq!(map.remove(&10), Some(1_000));
    // Removing a non-existent key returns None (no panic).
    assert_eq!(map.remove(&99), None);

    assert_eq!(map.len(), 7);

    // The remaining keys must still be in ascending order.
    let keys: Vec<u32> = map.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, vec![2, 3, 4, 6, 7, 8, 9]);

    // `first_key_value` / `last_key_value` are updated correctly.
    assert_eq!(map.first_key_value(), Some((&2, &200)));
    assert_eq!(map.last_key_value(), Some((&9, &900)));
}

// ============================================================================
// List tests (Issues 18–20)
// ============================================================================

#[test]
fn test_list_push_pop_front_back() {
    let mut list: List<i32> = List::new();
    assert!(list.is_empty());
    assert_eq!(list.len(), 0);

    // Build the deque `[3, 1, 2, 4]`:
    //   push_back(1)  -> [1]
    //   push_back(2)  -> [1, 2]
    //   push_front(3) -> [3, 1, 2]
    //   push_back(4)  -> [3, 1, 2, 4]
    list.push_back(1);
    list.push_back(2);
    list.push_front(3);
    list.push_back(4);

    assert_eq!(list.len(), 4);
    assert!(!list.is_empty());
    assert_eq!(list.front(), Some(&3));
    assert_eq!(list.back(), Some(&4));

    // Pop from both ends — deque ordering must be preserved.
    assert_eq!(list.pop_front(), Some(3));
    assert_eq!(list.pop_back(), Some(4));
    assert_eq!(list.len(), 2);
    assert_eq!(list.front(), Some(&1));
    assert_eq!(list.back(), Some(&2));

    // Drain the rest.
    assert_eq!(list.pop_front(), Some(1));
    assert_eq!(list.pop_back(), Some(2));
    assert!(list.is_empty());
}

#[test]
fn test_list_foreach_callback_semantics() {
    // `for_each` must visit every element in forward order — preserves
    // the assembly `list$foreach` behavior (AAP §0.5.1.6).
    let mut list: List<u32> = List::new();
    for i in 1u32..=5 {
        list.push_back(i);
    }

    // Forward iteration summing values.
    let mut sum = 0u32;
    list.for_each(|value| sum += *value);
    assert_eq!(sum, 1 + 2 + 3 + 4 + 5);

    // Forward iteration collecting values in visit order.
    let mut visited = Vec::new();
    list.for_each(|value| visited.push(*value));
    assert_eq!(visited, vec![1, 2, 3, 4, 5]);

    // Reverse iteration yields values in descending order.
    let mut rev_visited = Vec::new();
    list.for_each_rev(|value| rev_visited.push(*value));
    assert_eq!(rev_visited, vec![5, 4, 3, 2, 1]);

    // Mutable `for_each_mut` doubles every value in place.
    list.for_each_mut(|value| *value *= 2);
    let final_visit: Vec<u32> = list.iter().copied().collect();
    assert_eq!(final_visit, vec![2, 4, 6, 8, 10]);
}

#[test]
fn test_list_empty_pop_returns_none() {
    let mut list: List<&'static str> = List::new();

    // Both ends safely return None without panic.
    assert_eq!(list.pop_front(), None);
    assert_eq!(list.pop_back(), None);
    assert!(list.is_empty());
    assert_eq!(list.len(), 0);

    // `front` / `back` / `get` on an empty list also return None.
    assert_eq!(list.front(), None);
    assert_eq!(list.back(), None);
    assert_eq!(list.get(0), None);

    // After pushing and draining, subsequent pops are still None.
    list.push_back("sole");
    assert_eq!(list.pop_front(), Some("sole"));
    assert_eq!(list.pop_front(), None);
    assert_eq!(list.pop_back(), None);
}

// ============================================================================
// memfuncs tests (Issues 21–24)
// ============================================================================

#[test]
fn test_memfuncs_copy_matches_slice_copy_from_slice() {
    // Behavioral parity: `memfuncs::copy` must produce the same byte
    // sequence as `slice::copy_from_slice` for identical inputs.
    let src: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];
    let mut via_memfuncs = [0u8; 16];
    let mut via_std = [0u8; 16];

    memfuncs::copy(&mut via_memfuncs, &src).unwrap();
    via_std.copy_from_slice(&src);

    assert_eq!(via_memfuncs, via_std);
    assert_eq!(via_memfuncs, src);

    // Partial copy: src shorter than dst must still succeed when the
    // caller narrows `dst` to the exact source length.
    let short_src = b"ABC";
    let mut partial_dst = [0u8; 8];
    memfuncs::copy(&mut partial_dst[..3], short_src).unwrap();
    assert_eq!(&partial_dst[..3], b"ABC");
    assert_eq!(&partial_dst[3..], &[0u8; 5]);

    // Overflow: src longer than dst must return `BufferOverflow`
    // with the exact requested / capacity lengths (AAP §0.8.3).
    let big = [0xABu8; 10];
    let mut small = [0u8; 4];
    match memfuncs::copy(&mut small, &big) {
        Err(DsError::BufferOverflow { requested, capacity }) => {
            assert_eq!(requested, 10);
            assert_eq!(capacity, 4);
        }
        other => panic!("expected BufferOverflow, got {other:?}"),
    }
}

#[test]
fn test_memfuncs_fill_sets_every_byte() {
    // Fill with a non-zero value must stamp every byte identically.
    let mut buf = [0u8; 32];
    memfuncs::fill(&mut buf, 0xA5);
    for (i, byte) in buf.iter().enumerate() {
        assert_eq!(*byte, 0xA5, "byte {i} not filled");
    }

    // Zeroing a previously-filled buffer works too.
    memfuncs::fill(&mut buf, 0x00);
    assert!(buf.iter().all(|&b| b == 0));

    // Empty slice is a no-op (no panic, no effect).
    let mut empty: [u8; 0] = [];
    memfuncs::fill(&mut empty, 0xFF);
    assert_eq!(empty.len(), 0);

    // The generic bound `T: Copy` admits non-byte types as well.
    let mut words = [0u32; 4];
    memfuncs::fill(&mut words, 0xDEAD_BEEF);
    assert_eq!(words, [0xDEAD_BEEF; 4]);
}

#[test]
fn test_memfuncs_compare_equal_slices() {
    // Byte-identical buffers compare as equal.
    let a = b"equal_payload_0123456789";
    let b = b"equal_payload_0123456789";
    assert!(memfuncs::eq(a, b));
    assert_eq!(memfuncs::cmp(a, b), std::cmp::Ordering::Equal);

    // The constant-time variant agrees on equal inputs.
    assert!(memfuncs::constant_time_eq(a, b));

    // Empty slices compare as equal.
    let empty_a: &[u8] = &[];
    let empty_b: &[u8] = &[];
    assert!(memfuncs::eq(empty_a, empty_b));
    assert_eq!(memfuncs::cmp(empty_a, empty_b), std::cmp::Ordering::Equal);

    // Non-byte types work via the generic bound.
    let xs = [1i32, 2, 3, 4];
    let ys = [1i32, 2, 3, 4];
    assert!(memfuncs::eq(&xs, &ys));
    assert_eq!(memfuncs::cmp(&xs, &ys), std::cmp::Ordering::Equal);
}

#[test]
fn test_memfuncs_compare_differing_slices() {
    // Buffers that differ in any byte are reported unequal.
    let a = b"hello-world";
    let b = b"hello-WORLD";
    assert!(!memfuncs::eq(a, b));
    assert_ne!(memfuncs::cmp(a, b), std::cmp::Ordering::Equal);

    // Lowercase 'w' (0x77) is greater than uppercase 'W' (0x57).
    assert_eq!(memfuncs::cmp(a, b), std::cmp::Ordering::Greater);
    assert_eq!(memfuncs::cmp(b, a), std::cmp::Ordering::Less);

    // Different lengths: shorter slice is Less than a longer slice
    // whose prefix matches.
    let short = b"abc";
    let long = b"abcd";
    assert!(!memfuncs::eq(short, long));
    assert_eq!(memfuncs::cmp(short, long), std::cmp::Ordering::Less);
    assert_eq!(memfuncs::cmp(long, short), std::cmp::Ordering::Greater);

    // `constant_time_eq` agrees with `eq` on the false case.
    assert!(!memfuncs::constant_time_eq(a, b));
    assert!(!memfuncs::constant_time_eq(short, long));
}

// ============================================================================
// DsError tests (Issues 25–26)
// ============================================================================

#[test]
fn test_ds_error_buffer_overflow_variant() {
    // Construct the struct variant with explicit named field values.
    let err = DsError::BufferOverflow {
        requested: 512,
        capacity: 256,
    };

    // Display output must contain both numeric values (per the
    // thiserror template
    // `"buffer overflow: requested {requested}, capacity {capacity}"`).
    let rendered = err.to_string();
    assert!(
        rendered.contains("512"),
        "Display missing requested=512 in {rendered:?}"
    );
    assert!(
        rendered.contains("256"),
        "Display missing capacity=256 in {rendered:?}"
    );
    assert!(
        rendered.contains("buffer overflow"),
        "Display missing literal prefix in {rendered:?}"
    );

    // Debug must at least print the variant name.
    let debug_rendered = format!("{err:?}");
    assert!(
        debug_rendered.contains("BufferOverflow"),
        "Debug missing BufferOverflow in {debug_rendered:?}"
    );

    // Destructure back out — `DsError` lacks `PartialEq`, so we
    // pattern-match rather than `assert_eq!`.
    match err {
        DsError::BufferOverflow { requested, capacity } => {
            assert_eq!(requested, 512);
            assert_eq!(capacity, 256);
        }
        other => panic!("expected BufferOverflow, got {other:?}"),
    }
}

#[test]
fn test_ds_error_key_not_found_variant() {
    let err = DsError::KeyNotFound;

    // Display produces exactly the literal configured in `#[error(...)]`.
    assert_eq!(err.to_string(), "map key not found");

    // Debug prints the unit-variant name.
    let debug_rendered = format!("{err:?}");
    assert!(
        debug_rendered.contains("KeyNotFound"),
        "Debug missing KeyNotFound in {debug_rendered:?}"
    );

    // Pattern matching discriminates the unit variant.
    match err {
        DsError::KeyNotFound => {}
        other => panic!("expected KeyNotFound, got {other:?}"),
    }

    // The `std::error::Error` trait chain is reachable; leaf-level
    // `DsError` variants have no underlying source.
    use std::error::Error;
    let source = DsError::KeyNotFound.source();
    assert!(source.is_none(), "KeyNotFound should not have a source");
}
