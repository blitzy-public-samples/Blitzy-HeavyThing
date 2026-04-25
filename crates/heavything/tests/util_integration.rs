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

//! Integration tests for the `heavything::util` subsystem.
//!
//! These tests exercise the public API surface of the utility subsystem
//! from an external-consumer perspective (the `tests/` directory produces
//! a separate compilation unit that links against the `heavything` library
//! as if it were any downstream crate). Per AAP §0.3.1.2 they verify
//! "integration test for util subsystem (zlib round-trip, base64
//! round-trip, JSON round-trip)" for the four submodules called out in
//! the QA report:
//!
//! | Section | Submodule       | Purpose                                                    | Test Count |
//! |---------|-----------------|------------------------------------------------------------|-----------|
//! | 1       | `util::zlib`    | zlib / gzip / raw-deflate round-trip, magic bytes, empty   | 6         |
//! | 2       | `util::base64`  | RFC 4648 §10 vectors, line-break wrapping, tolerant decode | 7         |
//! | 3       | `util::json`    | parse/serialize round-trip, traversal, constructors        | 6         |
//! | 4       | `util::crc`     | IEEE 802.3 check value, streaming parity, extension        | 3         |
//! | 5       | `error::UtilError` | Variant construction + Display formatting               | 2         |
//!
//! ## Why these specific scenarios?
//!
//! The FASM `zlib_deflate.inc` (4,805 lines), `zlib_inflate.inc` (2,656),
//! `base64_latin1.inc`, `json.inc` (1,639), and `crc.inc` modules were
//! all replaced by thin wrappers over `flate2`, `base64`, `serde_json`,
//! and `crc32fast` respectively (per AAP §0.5.1.7). The contract these
//! wrappers MUST honor is byte-for-byte parity with the FASM baseline
//! for the standard test vectors (RFC 4648 §10 for base64, the universal
//! `0xCBF43926` check value for CRC-32, RFC 1950/1951/1952 framing for
//! zlib/gzip/deflate). These tests assert exactly those invariants.
//!
//! ## Error variant matching pattern
//!
//! `UtilError` does NOT derive `PartialEq` (see `src/error.rs` line 397
//! — it carries `String` payloads from upstream crates). Tests use
//! `match` patterns to verify variant identity rather than `==`,
//! consistent with the established `ds_integration.rs` idiom.

#![allow(clippy::unwrap_used)]

use heavything::error::UtilError;
use heavything::util::{base64 as b64, crc, json, zlib};

// ============================================================================
// Section 1: util::zlib — zlib / gzip / raw-deflate round-trip (6 tests)
// ============================================================================

#[test]
fn test_zlib_round_trip_compressible_payload() {
    // The repeated pangram is highly compressible because the same
    // word boundaries recur ten times. Round-trip MUST recover the
    // exact input bytes (zlib is lossless) and the compressed form
    // MUST be strictly smaller than the input.
    let input = b"The quick brown fox jumps over the lazy dog.".repeat(10);
    let compressed = zlib::zlib_compress(&input).expect("zlib_compress");
    assert!(
        compressed.len() < input.len(),
        "expected compression: input={} compressed={}",
        input.len(),
        compressed.len()
    );
    let decompressed = zlib::zlib_decompress(&compressed).expect("zlib_decompress");
    assert_eq!(decompressed, input);
}

#[test]
fn test_zlib_header_method_byte_is_deflate() {
    // RFC 1950 §2.2: the zlib header is two bytes; the low nibble of
    // byte 0 MUST be 0x08 (CM = "deflate"). Validating the method
    // nibble (rather than the exact byte pair) is portable across
    // compression levels because the FLG byte varies with FLEVEL.
    let compressed = zlib::zlib_compress(b"header check").expect("compress");
    assert_eq!(
        compressed[0] & 0x0f,
        0x08,
        "zlib CM nibble must be 0x08 (deflate); got 0x{:02x}",
        compressed[0]
    );
}

#[test]
fn test_gzip_round_trip_with_magic_bytes() {
    // RFC 1952 §2.3.1 mandates the gzip magic bytes 0x1f 0x8b at the
    // file's very start, followed by the compression method byte
    // (0x08 for deflate). The Rust port MUST emit identical magic
    // bytes for HTTP `Content-Encoding: gzip` interoperability.
    let input = b"hello world from heavything";
    let compressed = zlib::gzip_compress(input).expect("gzip_compress");
    assert_eq!(
        &compressed[..2],
        &[0x1f, 0x8b],
        "gzip magic bytes must be ID1=0x1f, ID2=0x8b"
    );
    assert_eq!(compressed[2], 0x08, "gzip CM byte must be 0x08 (deflate)");
    let decompressed = zlib::gzip_decompress(&compressed).expect("gzip_decompress");
    assert_eq!(decompressed.as_slice(), input);
}

#[test]
fn test_deflate_raw_round_trip_compressible() {
    // RFC 1951 (raw deflate) emits NO header and NO trailer — used
    // by SSH transport compression (per AAP §0.5.1.4 / `ssh.inc`
    // notes). Round-trip identity MUST hold.
    let input = b"abc abc abc abc abc abc abc abc abc abc abc".repeat(20);
    let compressed = zlib::deflate_compress(&input).expect("deflate_compress");
    assert!(
        compressed.len() < input.len(),
        "expected compression: input={} compressed={}",
        input.len(),
        compressed.len()
    );
    let decompressed = zlib::deflate_decompress(&compressed).expect("deflate_decompress");
    assert_eq!(decompressed, input);
}

#[test]
fn test_zlib_empty_input_handles_gracefully() {
    // Empty inputs are an edge case for compressors. The FASM
    // baseline produces minimal, valid output for empty input across
    // all three format families; the Rust port MUST do the same and
    // round-trip back to an empty byte vector.
    let empty: &[u8] = b"";

    let zlib_empty = zlib::zlib_compress(empty).expect("zlib empty compress");
    assert!(
        zlib_empty.len() >= 2,
        "zlib output of empty input must include 2-byte header, got {} bytes",
        zlib_empty.len()
    );
    let zlib_decoded = zlib::zlib_decompress(&zlib_empty).expect("zlib empty decompress");
    assert_eq!(zlib_decoded, empty);

    let gzip_empty = zlib::gzip_compress(empty).expect("gzip empty compress");
    assert!(
        gzip_empty.len() >= 10,
        "gzip output of empty input must include 10-byte header, got {} bytes",
        gzip_empty.len()
    );
    let gzip_decoded = zlib::gzip_decompress(&gzip_empty).expect("gzip empty decompress");
    assert_eq!(gzip_decoded, empty);

    let deflate_empty = zlib::deflate_compress(empty).expect("deflate empty compress");
    let deflate_decoded = zlib::deflate_decompress(&deflate_empty).expect("deflate empty decompress");
    assert_eq!(deflate_decoded, empty);
}

#[test]
fn test_zlib_alias_deflate_inflate_match_canonical_path() {
    // Per the API adaptation registry (zlib.rs lines 354–389), the
    // `deflate` / `inflate` aliases are `pub use` re-exports of
    // `zlib_compress` / `zlib_decompress`. They MUST produce
    // byte-identical output for identical input — not merely
    // semantically equivalent — because `pub use` re-exports share
    // the same function pointer. Verify both directions.
    let input = b"alias parity check";
    let canonical = zlib::zlib_compress(input).expect("canonical");
    let aliased = zlib::deflate(input).expect("aliased");
    assert_eq!(canonical, aliased, "deflate alias must match zlib_compress");

    // Inverse direction: inflate alias decompresses the canonical
    // output identically to zlib_decompress.
    let canonical_decoded = zlib::zlib_decompress(&canonical).expect("canonical decode");
    let aliased_decoded = zlib::inflate(&canonical).expect("aliased decode");
    assert_eq!(
        canonical_decoded, aliased_decoded,
        "inflate alias must match zlib_decompress"
    );
    assert_eq!(canonical_decoded.as_slice(), input);
}

// ============================================================================
// Section 2: util::base64 — RFC 4648 vectors, line-break wrapping, tolerant decode (7 tests)
// ============================================================================

#[test]
fn test_base64_rfc4648_encode_vectors() {
    // RFC 4648 §10: the canonical base64 encoding test vectors. These
    // are the same vectors every conforming implementation in the
    // world produces. Any deviation would indicate a broken alphabet
    // or padding rule.
    assert_eq!(b64::encode(b""), "");
    assert_eq!(b64::encode(b"f"), "Zg==");
    assert_eq!(b64::encode(b"fo"), "Zm8=");
    assert_eq!(b64::encode(b"foo"), "Zm9v");
    assert_eq!(b64::encode(b"foob"), "Zm9vYg==");
    assert_eq!(b64::encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(b64::encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn test_base64_rfc4648_decode_vectors() {
    // Inverse direction of test_base64_rfc4648_encode_vectors. Every
    // padded encoding from RFC 4648 §10 MUST decode back to its
    // exact original byte sequence.
    assert_eq!(b64::decode(b"").expect("decode empty"), b"");
    assert_eq!(b64::decode(b"Zg==").expect("decode f"), b"f");
    assert_eq!(b64::decode(b"Zm8=").expect("decode fo"), b"fo");
    assert_eq!(b64::decode(b"Zm9v").expect("decode foo"), b"foo");
    assert_eq!(b64::decode(b"Zm9vYg==").expect("decode foob"), b"foob");
    assert_eq!(b64::decode(b"Zm9vYmE=").expect("decode fooba"), b"fooba");
    assert_eq!(b64::decode(b"Zm9vYmFy").expect("decode foobar"), b"foobar");
}

#[test]
fn test_base64_round_trip_arbitrary_payload() {
    // Round-trip a payload with all 256 possible byte values (in
    // permuted order) plus a trailing odd-length tail to exercise
    // padding logic. Identity MUST hold.
    let mut input: Vec<u8> = (0u8..=255).collect();
    input.extend_from_slice(b"\x00\x01\x02"); // odd tail to trigger 1-byte padding
    let encoded = b64::encode(&input);
    let decoded = b64::decode(encoded.as_bytes()).expect("decode round-trip");
    assert_eq!(decoded, input);
}

#[test]
fn test_base64_encode_no_pad_omits_equals() {
    // `encode_no_pad` MUST produce strictly-no-padding output —
    // canonical base64url-style encoding. Trailing `=` characters
    // would indicate a wrong engine selection.
    assert_eq!(b64::encode_no_pad(b"f"), "Zg");
    assert_eq!(b64::encode_no_pad(b"fo"), "Zm8");
    assert_eq!(b64::encode_no_pad(b"foo"), "Zm9v"); // no padding needed for length%3==0
    assert!(
        !b64::encode_no_pad(b"hello").contains('='),
        "encode_no_pad must never contain '='"
    );
}

#[test]
fn test_base64_encode_with_linebreaks_inserts_crlf_at_76() {
    // Verifies the CRLF-every-76-chars wrapping behavior controlled
    // by `BASE64_LINEBREAKS = true` and `BASE64_MAXLINE = 76`. We
    // use 60 input bytes which encode to 80 base64 characters,
    // forcing exactly one CRLF separator to appear at column 76.
    let input: Vec<u8> = (0u8..60).collect();
    let raw = b64::encode(&input);
    let wrapped = b64::encode_with_linebreaks(&input);

    // The wrapped form MUST contain at least one CRLF.
    assert!(
        wrapped.contains("\r\n"),
        "encode_with_linebreaks must insert CRLF for >76-char output: got {wrapped:?}"
    );
    // The wrapped form is NEVER the same string as the unwrapped one
    // when wrapping triggers.
    assert_ne!(raw, wrapped);
    // After stripping CRLF, the wrapped form MUST equal the raw form.
    let unwrapped: String = wrapped.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    assert_eq!(unwrapped, raw);

    // Direct invocation of `apply_linebreaks` with max_line=0 MUST
    // return a clone (no wrapping).
    let cloned = b64::apply_linebreaks(&raw, 0);
    assert_eq!(cloned, raw);
}

#[test]
fn test_base64_decode_tolerant_strips_whitespace() {
    // `decode_tolerant` MUST accept input with embedded `\r`, `\n`,
    // `\t`, and space characters and produce the same result as
    // `decode` against the cleaned input. This is the path PEM
    // certificate decoding takes inside `crypto::x509`.
    let pem_like = "Zm9v\r\nYmFy\r\n"; // "foobar" wrapped with CRLF
    let strict_input = "Zm9vYmFy";
    let tolerant_decoded = b64::decode_tolerant(pem_like).expect("decode_tolerant");
    let strict_decoded = b64::decode_str(strict_input).expect("decode_str");
    assert_eq!(tolerant_decoded, strict_decoded);
    assert_eq!(tolerant_decoded, b"foobar");

    // Tabs and spaces also stripped.
    let mixed_ws = " Zm9v \tYmFy ";
    let mixed_decoded = b64::decode_tolerant(mixed_ws).expect("decode_tolerant mixed ws");
    assert_eq!(mixed_decoded, b"foobar");
}

#[test]
fn test_base64_decode_invalid_returns_util_error_base64_variant() {
    // Strict `decode` rejects whitespace and out-of-alphabet bytes.
    // We verify the error variant via match because `UtilError`
    // does not derive `PartialEq`.
    let invalid = b"!!notbase64!!";
    let result = b64::decode(invalid);
    match result {
        Err(UtilError::Base64(_)) => { /* expected */ }
        Err(other) => panic!("expected UtilError::Base64, got {other:?}"),
        Ok(bytes) => panic!("expected error, got Ok({bytes:?})"),
    }
}

// ============================================================================
// Section 3: util::json — parse/serialize round-trip, traversal, constructors (6 tests)
// ============================================================================

#[test]
fn test_json_parse_str_round_trip_value_equivalence() {
    // Round-trip parse → serialize → reparse MUST produce a
    // semantically equivalent JsonValue. We use VALUE equality
    // (which serde_json::Value implements) rather than STRING
    // equality because, per json.rs lines 277–278, serde_json
    // (without the `preserve_order` feature) reorders object keys
    // into BTreeMap (alphabetical) order during serialization.
    // The contract from AAP §0.5.1.7 is round-trip *value* parity,
    // not byte parity for object-typed input.
    let original_str = r#"{"name":"alice","age":30,"admin":true,"data":null,"tags":["x","y"]}"#;
    let parsed = json::parse_str(original_str).expect("parse_str");
    let serialized = json::to_string(&parsed).expect("to_string");
    let reparsed = json::parse_str(&serialized).expect("re-parse");
    assert_eq!(parsed, reparsed, "JSON round-trip must preserve value equality");

    // Compact form has no whitespace — verify by absence of common
    // whitespace tokens. This pins down `to_string` as the compact
    // serializer (vs. `to_string_pretty`).
    assert!(!serialized.contains('\n'), "compact form must have no newline");
    assert!(
        !serialized.contains(": "),
        "compact form must have no `: ` separator"
    );

    // Bytes form MUST be the UTF-8 encoding of the String form.
    let bytes = json::to_bytes(&parsed).expect("to_bytes");
    assert_eq!(bytes.as_slice(), serialized.as_bytes());

    // Array-of-arrays input has no key-order ambiguity, so for THAT
    // shape we CAN assert exact textual round-trip identity.
    let array_input = r#"[1,2,[3,4],[[5]],null,true,false]"#;
    let array_parsed = json::parse_str(array_input).expect("parse arr");
    let array_round = json::to_string(&array_parsed).expect("ser arr");
    assert_eq!(array_round, array_input);
}

#[test]
fn test_json_constructor_and_type_of_dispatch() {
    // The `type_of` function MUST classify every JsonValue into one
    // of the three FASM-equivalent categories per the table in
    // json.rs lines 218–222. Each constructor is exercised so that
    // changes to either side surface immediately.
    assert_eq!(json::type_of(&json::null()), json::JSON_VALUE);
    assert_eq!(json::type_of(&json::from_bool(true)), json::JSON_VALUE);
    assert_eq!(json::type_of(&json::from_str("hi")), json::JSON_VALUE);
    assert_eq!(json::type_of(&json::from_string("hi".into())), json::JSON_VALUE);
    assert_eq!(json::type_of(&json::from_i64(-42)), json::JSON_VALUE);
    assert_eq!(json::type_of(&json::from_u64(42)), json::JSON_VALUE);
    // Use 1.5 (an exact binary fraction) to avoid `clippy::approx_constant`
    // false-positive on values that look like π / e.
    assert_eq!(json::type_of(&json::from_f64(1.5)), json::JSON_VALUE);
    assert_eq!(json::type_of(&json::empty_array()), json::JSON_ARRAY);
    assert_eq!(json::type_of(&json::empty_object()), json::JSON_OBJECT);

    // Specific tag values must be `0`, `1`, `2` per FASM `json.inc`
    // lines 29-31.
    assert_eq!(json::JSON_VALUE, 0);
    assert_eq!(json::JSON_ARRAY, 1);
    assert_eq!(json::JSON_OBJECT, 2);
}

#[test]
fn test_json_object_get_and_array_at_traversal_safety() {
    // Verifies the FASM-style traversal helpers — `get` for object
    // key lookup, `at` for array index lookup. Both MUST return
    // `None` for type mismatches and out-of-range accesses without
    // panicking, matching the FASM helpers' zeroed-register return
    // (json.rs lines 234-251).
    let obj = json::parse_str(r#"{"a":1,"b":[10,20,30],"c":null}"#).expect("parse");

    // Successful object key lookup.
    let a_val = json::get(&obj, "a").expect("a present");
    assert_eq!(json::as_i64(a_val), Some(1));

    // Missing key returns None (not panic).
    assert!(json::get(&obj, "missing").is_none());

    // get on non-object value returns None.
    let scalar = json::from_i64(7);
    assert!(json::get(&scalar, "anything").is_none());

    // Array index access.
    let arr = json::get(&obj, "b").expect("b present");
    let elem1 = json::at(arr, 1).expect("idx 1");
    assert_eq!(json::as_i64(elem1), Some(20));

    // Out-of-bounds returns None.
    assert!(json::at(arr, 99).is_none());

    // at on non-array returns None.
    assert!(json::at(&scalar, 0).is_none());

    // is_null detects the null variant.
    let c_val = json::get(&obj, "c").expect("c present");
    assert!(json::is_null(c_val));
    assert!(!json::is_null(a_val));
}

#[test]
fn test_json_array_len_object_len_object_keys_lenient_returns() {
    // `array_len` and `object_len` MUST return `0` (not panic) for
    // non-matching types. `object_keys` MUST return an empty `Vec`
    // for non-object values.
    let arr = json::parse_str("[1,2,3,4,5]").expect("array");
    let obj = json::parse_str(r#"{"x":1,"y":2,"z":3}"#).expect("object");
    let scalar = json::from_str("scalar");

    assert_eq!(json::array_len(&arr), 5);
    assert_eq!(json::array_len(&obj), 0); // lenient: object → 0
    assert_eq!(json::array_len(&scalar), 0); // lenient: scalar → 0

    assert_eq!(json::object_len(&obj), 3);
    assert_eq!(json::object_len(&arr), 0); // lenient: array → 0
    assert_eq!(json::object_len(&scalar), 0); // lenient: scalar → 0

    let mut keys = json::object_keys(&obj);
    keys.sort(); // serde_json key order is implementation-defined
    assert_eq!(keys, vec!["x".to_string(), "y".to_string(), "z".to_string()]);

    // object_keys on non-object returns empty Vec.
    let empty_keys = json::object_keys(&arr);
    assert!(empty_keys.is_empty(), "object_keys on array must be empty");
}

#[test]
fn test_json_pretty_print_contains_indent_and_newlines() {
    // `to_string_pretty` produces 2-space indented multi-line JSON.
    // The pretty form MUST differ from the compact form for any
    // non-empty composite value, and MUST contain newline + 2-space
    // indent sequences as evidence of pretty formatting.
    let value = json::parse_str(r#"{"k":[1,2]}"#).expect("parse");
    let compact = json::to_string(&value).expect("compact");
    let pretty = json::to_string_pretty(&value).expect("pretty");
    assert_ne!(
        compact, pretty,
        "pretty MUST differ from compact for non-trivial JSON"
    );
    assert!(
        pretty.contains('\n'),
        "pretty form must contain newline; got {pretty:?}"
    );
    assert!(
        pretty.contains("  "),
        "pretty form must contain 2-space indent; got {pretty:?}"
    );

    // Pretty output MUST round-trip back to the same JSON value.
    let reparsed = json::parse_str(&pretty).expect("reparse pretty");
    assert_eq!(json::to_string(&reparsed).expect("reserialize"), compact);
}

#[test]
fn test_json_invalid_input_returns_util_error_json_variant() {
    // Malformed JSON MUST produce `UtilError::Json` (not panic).
    // Verify via `match` since `UtilError` does not derive `PartialEq`.
    let bad = "{this is not valid json";
    let result = json::parse_str(bad);
    match result {
        Err(UtilError::Json(_)) => { /* expected */ }
        Err(other) => panic!("expected UtilError::Json, got {other:?}"),
        Ok(value) => panic!("expected parse error, got Ok({value:?})"),
    }

    // Truncated array also fails.
    let truncated = "[1,2,3,";
    match json::parse(truncated.as_bytes()) {
        Err(UtilError::Json(_)) => { /* expected */ }
        Err(other) => panic!("expected UtilError::Json, got {other:?}"),
        Ok(value) => panic!("expected parse error, got Ok({value:?})"),
    }
}

// ============================================================================
// Section 4: util::crc — IEEE 802.3 check value, streaming parity, extension (3 tests)
// ============================================================================

#[test]
fn test_crc32_universal_check_value_for_123456789() {
    // The string "123456789" produces CRC-32 = 0xCBF43926 under the
    // IEEE 802.3 polynomial — universal across every conforming
    // CRC-32 implementation in the world (gzip, PNG, Ethernet, ZIP,
    // etc.). Both the free-function and `crc32_oneshot` MUST produce
    // this exact value.
    assert_eq!(crc::crc32(0, b"123456789"), 0xCBF43926);
    assert_eq!(crc::crc32_oneshot(b"123456789"), 0xCBF43926);

    // Empty buffer with seed 0 must remain 0.
    assert_eq!(crc::crc32_oneshot(b""), 0);
    assert_eq!(crc::crc32(0, b""), 0);
}

#[test]
fn test_crc32_streaming_struct_matches_oneshot() {
    // The `Crc32` streaming struct MUST produce the same final CRC
    // as `crc32_oneshot` when fed the same payload split across
    // arbitrary chunk boundaries. This invariant lets I/O chains
    // accumulate per-packet CRCs without buffering the full payload.
    let payload = b"The quick brown fox jumps over the lazy dog.";
    let oneshot = crc::crc32_oneshot(payload);

    // Single chunk
    let mut c = crc::Crc32::new();
    c.update(payload);
    assert_eq!(c.finalize(), oneshot);

    // Two chunks at byte boundary 22.
    let mut c2 = crc::Crc32::new();
    c2.update(&payload[..22]);
    c2.update(&payload[22..]);
    assert_eq!(c2.finalize(), oneshot);

    // Many one-byte chunks — exercises every internal byte-feed path.
    let mut c3 = crc::Crc32::new();
    for byte in payload.iter() {
        c3.update(std::slice::from_ref(byte));
    }
    assert_eq!(c3.finalize(), oneshot);

    // `peek` MUST agree with `finalize` after the same bytes were fed.
    let mut c4 = crc::Crc32::new();
    c4.update(payload);
    let peeked = c4.peek();
    assert_eq!(peeked, oneshot);
    assert_eq!(c4.finalize(), oneshot);
}

#[test]
fn test_crc32_running_accumulator_extends_correctly() {
    // FASM-parity: passing the previous return value as `accum` in
    // a subsequent call MUST extend the computation so that
    // `crc32(0, AB)` equals `crc32(crc32(0, A), B)` for any split.
    // This invariant is load-bearing for `gzip` footer computation
    // and PNG chunk CRC chaining.
    let full = b"hello, world! this is a CRC chaining test";
    let one_pass = crc::crc32(0, full);
    let split = full.len() / 3;

    let part_a = &full[..split];
    let part_b = &full[split..2 * split];
    let part_c = &full[2 * split..];

    let after_a = crc::crc32(0, part_a);
    let after_b = crc::crc32(after_a, part_b);
    let after_c = crc::crc32(after_b, part_c);
    assert_eq!(
        after_c, one_pass,
        "running accumulator must yield single-pass result"
    );

    // Resuming from a saved accumulator via `Crc32::new_with_accum`
    // produces an identical chain.
    let mut staged = crc::Crc32::new();
    staged.update(part_a);
    let saved_accum = staged.peek();
    let resumed = crc::Crc32::new_with_accum(saved_accum);
    let mut tail = resumed;
    tail.update(part_b);
    tail.update(part_c);
    assert_eq!(tail.finalize(), one_pass);
}

// ============================================================================
// Section 5: error::UtilError — variant construction + Display (2 tests)
// ============================================================================

#[test]
fn test_util_error_variant_construction_and_display_prefixes() {
    // `UtilError` defines seven variants (error.rs lines 397–426);
    // each Display impl carries a stable user-facing prefix that
    // we lock down here so accidental rewordings would surface
    // as test failures.

    let zlib_err = UtilError::Zlib("bad header".to_string());
    assert!(
        zlib_err.to_string().starts_with("zlib failure:"),
        "Zlib display prefix: got {zlib_err}"
    );

    let b64_err = UtilError::Base64("bad pad".to_string());
    assert!(
        b64_err.to_string().starts_with("base64 decode failure:"),
        "Base64 display prefix: got {b64_err}"
    );

    let json_err = UtilError::Json("syntax error".to_string());
    assert!(
        json_err.to_string().starts_with("JSON parse failure:"),
        "Json display prefix: got {json_err}"
    );

    let mmap_err = UtilError::Mmap("ENOMEM".to_string());
    assert!(
        mmap_err.to_string().starts_with("mmap failure:"),
        "Mmap display prefix: got {mmap_err}"
    );

    let syslog_err = UtilError::Syslog("connect refused".to_string());
    assert!(
        syslog_err.to_string().starts_with("syslog failure:"),
        "Syslog display prefix: got {syslog_err}"
    );

    let crc_err = UtilError::CrcMismatch;
    assert_eq!(
        crc_err.to_string(),
        "CRC mismatch",
        "CrcMismatch carries no payload; Display is fixed string"
    );

    // The Io variant is reachable via `#[from] std::io::Error`; we
    // construct it the idiomatic way and verify the prefix.
    let io_err: UtilError = std::io::Error::new(std::io::ErrorKind::NotFound, "missing").into();
    assert!(
        io_err.to_string().starts_with("file I/O error:"),
        "Io display prefix: got {io_err}"
    );

    // Variant matching pattern (UtilError lacks PartialEq). This
    // confirms each constructor produces the expected enum
    // discriminant.
    match UtilError::Zlib("x".into()) {
        UtilError::Zlib(_) => {}
        other => panic!("expected Zlib, got {other:?}"),
    }
    match UtilError::Base64("x".into()) {
        UtilError::Base64(_) => {}
        other => panic!("expected Base64, got {other:?}"),
    }
    match UtilError::Json("x".into()) {
        UtilError::Json(_) => {}
        other => panic!("expected Json, got {other:?}"),
    }
    match UtilError::CrcMismatch {
        UtilError::CrcMismatch => {}
        other => panic!("expected CrcMismatch, got {other:?}"),
    }
}

#[test]
fn test_util_error_io_from_conversion_round_trip() {
    // The `From<std::io::Error>` impl for `UtilError` (via
    // `#[from]` on the Io variant in error.rs line 413) allows
    // ergonomic `?` propagation of filesystem errors. We exercise
    // it both via `.into()` and via the function-call form to
    // pin down both spellings.
    let original_kind = std::io::ErrorKind::PermissionDenied;
    let io_err = std::io::Error::new(original_kind, "denied");

    // Method-call form
    let util_err: UtilError = io_err.into();
    match &util_err {
        UtilError::Io(inner) => {
            assert_eq!(inner.kind(), original_kind);
        }
        other => panic!("expected UtilError::Io, got {other:?}"),
    }

    // Function-call form
    let io_err2 = std::io::Error::new(std::io::ErrorKind::TimedOut, "slow");
    let util_err2 = UtilError::from(io_err2);
    match util_err2 {
        UtilError::Io(inner) => {
            assert_eq!(inner.kind(), std::io::ErrorKind::TimedOut);
        }
        other => panic!("expected UtilError::Io, got {other:?}"),
    }
}
