// HeavyThing Rust port — JSON parsing and serialization.
//
// Original assembly source:
//   json.inc — Copyright © 2015 2 Ton Digital.
//   Homepage: https://2ton.com.au/
//   Author: Jeff Marrison <jeff@2ton.com.au>
//
// This Rust translation is licensed under the GNU General Public License v3.0
// or later, preserving the original upstream license terms.
//
// This file is part of the HeavyThing Rust library.
//
// HeavyThing is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// HeavyThing is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with HeavyThing. If not, see <http://www.gnu.org/licenses/>.

//! JSON parsing and serialization.
//!
//! Port of the FASM `json.inc` module (1,639 lines). Per AAP §0.5.1.7 and
//! §0.8.9 ("std collections where semantically equivalent"), this file is
//! a thin idiomatic wrapper around the battle-tested [`serde_json`] crate
//! rather than a line-for-line reimplementation of the hand-rolled parser.
//!
//! # FASM ↔ Rust mapping
//!
//! The original assembly module represented every JSON node with a fixed
//! 24-byte tagged struct:
//!
//! ```text
//! struct json_object {
//!     name:     *string,   // +0  — key name (if this node is inside an object)
//!     type:     u32,       // +8  — 0 = value, 1 = array, 2 = object
//!     _padding: u32,       // +12
//!     union { value: *string, contents: *{list|stringmap} }, // +16
//! };
//! ```
//!
//! The Rust idiom is [`serde_json::Value`], an enum-tagged union whose
//! cases (`Null`, `Bool`, `Number`, `String`, `Array`, `Object`) subsume
//! every shape the FASM struct could express. This file re-exports
//! `serde_json::Value` as [`JsonValue`] and surfaces three numeric
//! constants ([`JSON_VALUE`], [`JSON_ARRAY`], [`JSON_OBJECT`]) identical
//! to the FASM `json_value`/`json_array`/`json_object` equates, so
//! downstream consumers (primarily the `hnwatch` binary crate parsing the
//! Hacker News API per AAP §0.3.1.3 / §0.9.3) keep FASM-style traversal
//! semantics.
//!
//! # Constructor API parity
//!
//! FASM exposed two constructor variants for every value kind:
//!
//! * `json$newvalue`       — deep-copies its string argument.
//! * `json$newvalue_nocopy`— takes ownership of its argument.
//!
//! In Rust this distinction is expressed via the standard borrow/ownership
//! split: [`from_str`] accepts `&str` and copies, [`from_string`] accepts
//! `String` and moves ownership. The behavior is byte-identical on the
//! resulting JSON value because `serde_json::Value::String` wraps an owned
//! `String` either way.
//!
//! # Error policy
//!
//! Every fallible operation returns [`Result<T, UtilError>`] with the
//! [`UtilError::Json`] variant carrying the message string produced by
//! `serde_json::Error::to_string()`. This matches the crate-wide error
//! policy established by [`crate::error`] and lets callers propagate with
//! the `?` operator without juggling a third-party error type at module
//! boundaries.
//!
//! # Traversal safety
//!
//! FASM traversal was pointer arithmetic on the tagged struct. Rust
//! traversal (`get`, `at`, `array_len`, `object_len`) always returns
//! `Option`/`0` for non-matching types — it never panics. This is
//! behaviorally identical to the FASM helpers, which would `ret` with
//! a zeroed register on a type mismatch.
//!
//! # Consumers
//!
//! * `hnwatch::hnmodel` — Hacker News API JSON decoding.
//! * `net::http::client` — HTTP request/response body handling when
//!   callers opt in to JSON bodies.

use serde_json::Value;

use crate::error::UtilError;

// ---------------------------------------------------------------------------
// Type alias and FASM-compat constants
// ---------------------------------------------------------------------------

/// The canonical JSON value type.
///
/// Alias for [`serde_json::Value`] — a tagged union semantically identical
/// to FASM's 24-byte `json_object` struct but with compile-time-enforced
/// exhaustive matching. Exposed as an alias (not a newtype) so that the
/// rich serde ecosystem (conversions, macros, `#[derive(Deserialize)]`)
/// remains directly usable from consumer crates.
pub type JsonValue = Value;

/// FASM `json_value = 0` — scalar node (null, bool, number, or string).
///
/// Returned by [`type_of`] for any [`Value::Null`], [`Value::Bool`],
/// [`Value::Number`], or [`Value::String`] node. Preserves the FASM
/// `json.inc` line 29 equate so consumers that previously switched on
/// the type field retain identical control flow.
pub const JSON_VALUE: u32 = 0;

/// FASM `json_array = 1` — ordered array node.
///
/// Returned by [`type_of`] for [`Value::Array`] nodes. Preserves the
/// FASM `json.inc` line 30 equate.
pub const JSON_ARRAY: u32 = 1;

/// FASM `json_object = 2` — keyed map node.
///
/// Returned by [`type_of`] for [`Value::Object`] nodes. Preserves the
/// FASM `json.inc` line 31 equate.
pub const JSON_OBJECT: u32 = 2;

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a JSON document from raw bytes.
///
/// Matches the FASM `json$parse` entry point. The input is expected to be
/// UTF-8; serde_json will return a syntax error if non-UTF-8 bytes appear
/// inside string literals, matching the original parser's behavior.
///
/// # Errors
///
/// Returns [`UtilError::Json`] wrapping the parser's error message on
/// any malformed input.
pub fn parse(bytes: &[u8]) -> Result<JsonValue, UtilError> {
    serde_json::from_slice::<JsonValue>(bytes).map_err(|e| UtilError::Json(e.to_string()))
}

/// Parse a JSON document from a `&str`.
///
/// Matches the FASM `json$parse_str` entry point. Preferred over [`parse`]
/// when the caller already holds a `&str`, since it avoids a redundant
/// UTF-8 validation pass that `from_slice` would perform.
///
/// # Errors
///
/// Returns [`UtilError::Json`] wrapping the parser's error message on
/// any malformed input.
pub fn parse_str(s: &str) -> Result<JsonValue, UtilError> {
    serde_json::from_str::<JsonValue>(s).map_err(|e| UtilError::Json(e.to_string()))
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize a JSON value to a byte vector (compact form, no line breaks).
///
/// Matches the FASM `json$tostring` byte-level output shape: no whitespace
/// between tokens, no trailing newline.
///
/// # Errors
///
/// Returns [`UtilError::Json`] if serialization fails. In practice this
/// only occurs for values that cannot be represented in JSON, such as
/// maps keyed by non-string types (impossible via this module's public
/// constructors but reachable if a caller mutates `JsonValue` directly).
pub fn to_bytes(v: &JsonValue) -> Result<Vec<u8>, UtilError> {
    serde_json::to_vec(v).map_err(|e| UtilError::Json(e.to_string()))
}

/// Serialize a JSON value to a `String` (compact form, no line breaks).
///
/// See [`to_bytes`] for the underlying byte shape; this function returns
/// a `String` whose bytes match what [`to_bytes`] would produce.
///
/// # Errors
///
/// Returns [`UtilError::Json`] on the same conditions documented for
/// [`to_bytes`].
pub fn to_string(v: &JsonValue) -> Result<String, UtilError> {
    serde_json::to_string(v).map_err(|e| UtilError::Json(e.to_string()))
}

/// Serialize a JSON value to a pretty-printed `String` (2-space indent).
///
/// Provided for API parity with callers that want human-readable output.
/// The FASM module did not expose a pretty-printer directly; this is a
/// convenience consistent with `serde_json`'s own split.
///
/// # Errors
///
/// Returns [`UtilError::Json`] on the same conditions documented for
/// [`to_bytes`].
pub fn to_string_pretty(v: &JsonValue) -> Result<String, UtilError> {
    serde_json::to_string_pretty(v).map_err(|e| UtilError::Json(e.to_string()))
}

// ---------------------------------------------------------------------------
// FASM-style traversal
// ---------------------------------------------------------------------------

/// Return the FASM-style type tag of a JSON value.
///
/// Mirrors FASM `json$type` / the `json_type_ofs` field read. The return
/// value is one of the [`JSON_VALUE`], [`JSON_ARRAY`], or [`JSON_OBJECT`]
/// constants.
///
/// | `JsonValue` variant                                           | Returned |
/// |---------------------------------------------------------------|----------|
/// | `Null` / `Bool` / `Number` / `String`                         | [`JSON_VALUE`]  |
/// | `Array(_)`                                                    | [`JSON_ARRAY`]  |
/// | `Object(_)`                                                   | [`JSON_OBJECT`] |
#[must_use]
pub fn type_of(v: &JsonValue) -> u32 {
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => JSON_VALUE,
        Value::Array(_) => JSON_ARRAY,
        Value::Object(_) => JSON_OBJECT,
    }
}

/// Object accessor: look up a key inside an object-typed value.
///
/// Returns `Some(&JsonValue)` when `v` is a [`Value::Object`] containing
/// `key`, and `None` in all other cases (non-object value, key absent).
/// Never panics — matches the FASM `stringmap$find` helper's behavior
/// of returning `rax == 0` on a miss.
#[must_use]
pub fn get<'a>(v: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    v.as_object()?.get(key)
}

/// Array accessor: fetch the element at `idx`.
///
/// Returns `Some(&JsonValue)` when `v` is a [`Value::Array`] and `idx`
/// is in bounds, and `None` in all other cases. Never panics — matches
/// the FASM `list$at` helper's out-of-bounds behavior.
#[must_use]
pub fn at(v: &JsonValue, idx: usize) -> Option<&JsonValue> {
    v.as_array()?.get(idx)
}

/// Array length helper.
///
/// Returns the number of elements when `v` is a [`Value::Array`], and
/// `0` for any other variant. This lenient behavior matches the FASM
/// `list$length` helper's zeroed-register return on a non-list handle.
#[must_use]
pub fn array_len(v: &JsonValue) -> usize {
    v.as_array().map(Vec::len).unwrap_or(0)
}

/// Object size helper.
///
/// Returns the number of keys when `v` is a [`Value::Object`], and `0`
/// for any other variant. Matches FASM `stringmap$size` semantics on a
/// non-map input.
#[must_use]
pub fn object_len(v: &JsonValue) -> usize {
    v.as_object().map(serde_json::Map::len).unwrap_or(0)
}

/// Collect the keys of an object-typed value into a `Vec<String>`.
///
/// Returns an empty `Vec` when `v` is not a [`Value::Object`]. The key
/// order is implementation-defined (serde_json preserves insertion order
/// when the `preserve_order` feature is enabled, otherwise BTreeMap
/// alphabetical order); callers must not rely on either ordering.
#[must_use]
pub fn object_keys(v: &JsonValue) -> Vec<String> {
    v.as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Scalar coercion
// ---------------------------------------------------------------------------

/// Coerce to a string slice.
///
/// Returns `Some(&str)` when `v` is a [`Value::String`] and `None`
/// otherwise (including for `Value::Number`, which is intentionally
/// kept numeric).
#[must_use]
pub fn as_str(v: &JsonValue) -> Option<&str> {
    v.as_str()
}

/// Coerce to an owned `String`, returning an empty `String` if the
/// value is not a string.
///
/// The "lossy" in the name signals that non-string inputs are silently
/// collapsed to `""`; callers needing strict behavior should use
/// [`as_str`] and handle `None` explicitly. This helper exists because
/// `hnwatch` frequently formats optional text fields without wanting
/// to thread `Option` through display code.
#[must_use]
pub fn as_string_lossy(v: &JsonValue) -> String {
    v.as_str().unwrap_or("").to_owned()
}

/// Coerce to `u64`.
///
/// Returns `Some(u64)` when `v` is a [`Value::Number`] that fits in
/// `u64`, and `None` otherwise. Note that integer-valued JSON literals
/// whose value is negative will round-trip through `as_i64` but return
/// `None` here, which matches `serde_json::Value::as_u64`.
#[must_use]
pub fn as_u64(v: &JsonValue) -> Option<u64> {
    v.as_u64()
}

/// Coerce to `i64`.
///
/// Returns `Some(i64)` when `v` is a [`Value::Number`] that fits in
/// `i64`, and `None` otherwise.
#[must_use]
pub fn as_i64(v: &JsonValue) -> Option<i64> {
    v.as_i64()
}

/// Coerce to `f64`.
///
/// Returns `Some(f64)` for any [`Value::Number`] (serde_json widens
/// integer literals to `f64` automatically), and `None` otherwise. Note
/// that NaN and infinity are never representable in JSON, so the
/// returned `f64` is always a finite number.
#[must_use]
pub fn as_f64(v: &JsonValue) -> Option<f64> {
    v.as_f64()
}

/// Coerce to `bool`.
///
/// Returns `Some(bool)` when `v` is a [`Value::Bool`], and `None`
/// otherwise. This is strict: non-zero numbers are **not** truthy,
/// matching `serde_json::Value::as_bool`.
#[must_use]
pub fn as_bool(v: &JsonValue) -> Option<bool> {
    v.as_bool()
}

/// Return `true` when the value is JSON `null`.
///
/// Equivalent to `matches!(v, Value::Null)`. Provided for API parity
/// with FASM's `json$isnull` helper.
#[must_use]
pub fn is_null(v: &JsonValue) -> bool {
    v.is_null()
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Construct a JSON `null`.
///
/// Mirrors the FASM `json$newnull`-style usage: produce a bare scalar
/// that can be appended into an array or object.
#[must_use]
pub fn null() -> JsonValue {
    Value::Null
}

/// Construct a JSON boolean scalar.
///
/// Equivalent to `Value::Bool(b)` but keeps the construction API
/// grouped in this module for callers that prefer the function form.
#[must_use]
pub fn from_bool(b: bool) -> JsonValue {
    Value::Bool(b)
}

/// Construct a JSON string scalar from a borrowed `&str` (copies).
///
/// Matches the FASM `json$newvalue` constructor behavior: the input is
/// duplicated so the caller retains ownership of their original buffer.
/// Use [`from_string`] when you want move semantics.
#[must_use]
pub fn from_str(s: &str) -> JsonValue {
    Value::String(s.to_owned())
}

/// Construct a JSON string scalar from an owned `String` (move).
///
/// Matches the FASM `json$newvalue_nocopy` constructor behavior: the
/// argument's ownership is transferred into the returned value without
/// an intermediate copy. Preferred when the caller built the string
/// via `format!`, concatenation, or `to_owned` and does not need it
/// afterwards.
#[must_use]
pub fn from_string(s: String) -> JsonValue {
    Value::String(s)
}

/// Construct a JSON integer scalar from an `i64`.
///
/// Infallible: every `i64` fits into a `serde_json::Number`.
#[must_use]
pub fn from_i64(n: i64) -> JsonValue {
    Value::from(n)
}

/// Construct a JSON integer scalar from a `u64`.
///
/// Infallible: every `u64` fits into a `serde_json::Number`.
#[must_use]
pub fn from_u64(n: u64) -> JsonValue {
    Value::from(n)
}

/// Construct a JSON number scalar from an `f64`.
///
/// JSON cannot represent NaN or infinity, so such inputs are lowered
/// to [`Value::Null`] rather than producing a value that would later
/// fail to serialize. This follows the convention established by
/// `serde_json::Number::from_f64`.
#[must_use]
pub fn from_f64(f: f64) -> JsonValue {
    serde_json::Number::from_f64(f)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// Construct an empty JSON array (`[]`).
///
/// Mirrors the FASM `json$newarray` / `json$newarray_nocopy`
/// constructors after the internal list has been allocated but before
/// any child has been appended.
#[must_use]
pub fn empty_array() -> JsonValue {
    Value::Array(Vec::new())
}

/// Construct an empty JSON object (`{}`).
///
/// Mirrors the FASM `json$newobject` / `json$newobject_nocopy`
/// constructors after the internal stringmap has been allocated but
/// before any key has been inserted.
#[must_use]
pub fn empty_object() -> JsonValue {
    Value::Object(serde_json::Map::new())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Parsing an object preserves key lookup semantics and reports
    /// [`JSON_OBJECT`] from [`type_of`].
    #[test]
    fn parse_object() {
        let v = parse_str(r#"{"a":1,"b":"two"}"#).expect("parse");
        assert_eq!(type_of(&v), JSON_OBJECT);
        assert_eq!(object_len(&v), 2);
        assert_eq!(as_u64(get(&v, "a").expect("key a")), Some(1));
        assert_eq!(as_str(get(&v, "b").expect("key b")), Some("two"));
        assert!(get(&v, "missing").is_none());
    }

    /// Parsing an array preserves positional access semantics and
    /// reports [`JSON_ARRAY`] from [`type_of`].
    #[test]
    fn parse_array() {
        let v = parse_str("[1, 2, 3]").expect("parse");
        assert_eq!(type_of(&v), JSON_ARRAY);
        assert_eq!(array_len(&v), 3);
        assert_eq!(as_u64(at(&v, 0).expect("idx 0")), Some(1));
        assert_eq!(as_u64(at(&v, 1).expect("idx 1")), Some(2));
        assert_eq!(as_u64(at(&v, 2).expect("idx 2")), Some(3));
        assert!(at(&v, 3).is_none());
    }

    /// Parsing a bare scalar reports [`JSON_VALUE`] from [`type_of`]
    /// and coerces through every numeric accessor.
    #[test]
    fn parse_scalar_reports_value_kind() {
        let v = parse_str("42").expect("parse");
        assert_eq!(type_of(&v), JSON_VALUE);
        assert_eq!(as_u64(&v), Some(42));
        assert_eq!(as_i64(&v), Some(42));
        assert_eq!(as_f64(&v), Some(42.0));
    }

    /// `parse_bytes` should round-trip identical input as `parse_str`.
    #[test]
    fn parse_accepts_bytes() {
        let v = parse(b"{\"k\":1}").expect("parse bytes");
        assert_eq!(as_u64(get(&v, "k").expect("key")), Some(1));
    }

    /// Full parse → serialize → reparse round trip preserves the
    /// logical value. Tests every Value variant in one input.
    #[test]
    fn roundtrip_compact() {
        let src = r#"{"k":[true,null,3.14,"s",-1]}"#;
        let v = parse_str(src).expect("parse");
        let s = to_string(&v).expect("serialize");
        let v2 = parse_str(&s).expect("reparse");
        assert_eq!(v, v2);
    }

    /// Pretty serialization should produce a longer output than compact
    /// but parse back to the same logical value.
    #[test]
    fn roundtrip_pretty() {
        let src = r#"{"k":[1,2]}"#;
        let v = parse_str(src).expect("parse");
        let pretty = to_string_pretty(&v).expect("pretty");
        let compact = to_string(&v).expect("compact");
        assert!(pretty.len() >= compact.len());
        assert_eq!(parse_str(&pretty).expect("reparse"), v);
    }

    /// `to_bytes` should produce the same content as `to_string`.
    #[test]
    fn to_bytes_matches_to_string() {
        let v = parse_str(r#"{"a":1}"#).expect("parse");
        let bytes = to_bytes(&v).expect("to_bytes");
        let text = to_string(&v).expect("to_string");
        assert_eq!(bytes, text.as_bytes());
    }

    /// Malformed input returns [`UtilError::Json`] — never panics.
    #[test]
    fn invalid_returns_error() {
        let result = parse_str("{invalid");
        assert!(matches!(result, Err(UtilError::Json(_))));
    }

    /// Traversal helpers on non-matching types return `None`/`0` rather
    /// than panic. This validates the FASM lenient-dispatch behavior.
    #[test]
    fn traversal_on_non_matching_types() {
        let scalar = parse_str("1").expect("parse");
        assert!(get(&scalar, "x").is_none());
        assert!(at(&scalar, 0).is_none());
        assert_eq!(array_len(&scalar), 0);
        assert_eq!(object_len(&scalar), 0);
        assert!(object_keys(&scalar).is_empty());

        let arr = parse_str("[1,2]").expect("parse");
        assert!(get(&arr, "x").is_none());
        assert_eq!(object_len(&arr), 0);
        assert!(object_keys(&arr).is_empty());

        let obj = parse_str(r#"{"k":1}"#).expect("parse");
        assert!(at(&obj, 0).is_none());
        assert_eq!(array_len(&obj), 0);
    }

    /// Coercion helpers on non-matching types return `None` — never
    /// panic. Matches FASM zeroed-register semantics.
    #[test]
    fn coercions_on_non_matching_types() {
        let s = parse_str(r#""hello""#).expect("parse");
        assert_eq!(as_str(&s), Some("hello"));
        assert!(as_u64(&s).is_none());
        assert!(as_i64(&s).is_none());
        assert!(as_f64(&s).is_none());
        assert!(as_bool(&s).is_none());

        let n = parse_str("-7").expect("parse");
        assert!(as_str(&n).is_none());
        assert_eq!(as_i64(&n), Some(-7));
        assert!(as_u64(&n).is_none()); // negative → no u64
        assert_eq!(as_f64(&n), Some(-7.0));
        assert!(as_bool(&n).is_none());

        let b = parse_str("true").expect("parse");
        assert_eq!(as_bool(&b), Some(true));
        assert!(as_u64(&b).is_none());
    }

    /// `as_string_lossy` returns empty string for non-string values.
    #[test]
    fn as_string_lossy_collapses_non_strings() {
        assert_eq!(as_string_lossy(&parse_str(r#""abc""#).expect("parse")), "abc");
        assert_eq!(as_string_lossy(&parse_str("1").expect("parse")), "");
        assert_eq!(as_string_lossy(&parse_str("null").expect("parse")), "");
        assert_eq!(as_string_lossy(&parse_str("[]").expect("parse")), "");
    }

    /// [`is_null`] detects null scalars and rejects every other variant.
    #[test]
    fn is_null_detects_null_only() {
        assert!(is_null(&parse_str("null").expect("parse")));
        assert!(!is_null(&parse_str("0").expect("parse")));
        assert!(!is_null(&parse_str("false").expect("parse")));
        assert!(!is_null(&parse_str(r#""""#).expect("parse")));
        assert!(!is_null(&parse_str("[]").expect("parse")));
        assert!(!is_null(&parse_str("{}").expect("parse")));
    }

    /// Construction helpers produce the expected serialized shapes.
    #[test]
    fn construct_and_serialize() {
        assert_eq!(to_string(&null()).expect("ser"), "null");
        assert_eq!(to_string(&from_bool(true)).expect("ser"), "true");
        assert_eq!(to_string(&from_bool(false)).expect("ser"), "false");
        assert_eq!(to_string(&from_i64(-5)).expect("ser"), "-5");
        assert_eq!(to_string(&from_u64(99)).expect("ser"), "99");
        assert_eq!(to_string(&from_f64(1.5)).expect("ser"), "1.5");
        assert_eq!(to_string(&from_str("hello")).expect("ser"), r#""hello""#);
        assert_eq!(
            to_string(&from_string(String::from("world"))).expect("ser"),
            r#""world""#
        );
        assert_eq!(to_string(&empty_array()).expect("ser"), "[]");
        assert_eq!(to_string(&empty_object()).expect("ser"), "{}");
    }

    /// Non-finite floats collapse to JSON null (serde_json policy).
    #[test]
    fn from_f64_rejects_non_finite() {
        assert!(is_null(&from_f64(f64::NAN)));
        assert!(is_null(&from_f64(f64::INFINITY)));
        assert!(is_null(&from_f64(f64::NEG_INFINITY)));
        // Finite values do survive.
        assert!(!is_null(&from_f64(0.0)));
        assert!(!is_null(&from_f64(-1.5)));
    }

    /// `from_str` (copy) and `from_string` (move) produce equal values.
    #[test]
    fn from_str_and_from_string_produce_equal_values() {
        let a = from_str("x");
        let b = from_string(String::from("x"));
        assert_eq!(a, b);
    }

    /// FASM-style compatibility constants match the original equates.
    #[test]
    fn fasm_constants_match() {
        assert_eq!(JSON_VALUE, 0);
        assert_eq!(JSON_ARRAY, 1);
        assert_eq!(JSON_OBJECT, 2);
    }

    /// `type_of` returns the right tag for every Value variant.
    #[test]
    fn type_of_covers_every_variant() {
        assert_eq!(type_of(&null()), JSON_VALUE);
        assert_eq!(type_of(&from_bool(true)), JSON_VALUE);
        assert_eq!(type_of(&from_i64(0)), JSON_VALUE);
        assert_eq!(type_of(&from_f64(1.0)), JSON_VALUE);
        assert_eq!(type_of(&from_str("")), JSON_VALUE);
        assert_eq!(type_of(&empty_array()), JSON_ARRAY);
        assert_eq!(type_of(&empty_object()), JSON_OBJECT);
    }

    /// `object_keys` returns every key present, and nothing else.
    #[test]
    fn object_keys_enumerates_entries() {
        let v = parse_str(r#"{"a":1,"b":2,"c":3}"#).expect("parse");
        let mut keys = object_keys(&v);
        keys.sort();
        assert_eq!(keys, vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]);
    }

    /// Hacker News-ish example exercising the shapes `hnwatch` would
    /// encounter. Validates end-to-end behavior at the consumer boundary.
    #[test]
    fn hacker_news_like_payload() {
        let raw = r#"{
            "by": "pg",
            "descendants": 42,
            "id": 1,
            "kids": [10, 20, 30],
            "score": 100,
            "title": "Hello",
            "type": "story",
            "url": "https://example.com/"
        }"#;
        let v = parse_str(raw).expect("parse HN JSON");
        assert_eq!(type_of(&v), JSON_OBJECT);
        assert_eq!(as_str(get(&v, "by").expect("by")), Some("pg"));
        assert_eq!(as_u64(get(&v, "descendants").expect("descendants")), Some(42));
        let kids = get(&v, "kids").expect("kids");
        assert_eq!(type_of(kids), JSON_ARRAY);
        assert_eq!(array_len(kids), 3);
        assert_eq!(as_u64(at(kids, 0).expect("kids[0]")), Some(10));
        assert_eq!(as_str(get(&v, "url").expect("url")), Some("https://example.com/"));
    }
}
