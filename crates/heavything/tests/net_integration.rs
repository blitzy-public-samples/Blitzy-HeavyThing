
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

//! Integration tests for the `heavything::net` subsystem.
//!
//! These tests exercise the public API surface of the networking
//! subsystem from an external-consumer perspective (the `tests/`
//! directory produces a separate compilation unit that links against
//! the `heavything` library as if it were any downstream crate). Per
//! AAP §0.3.1.2 they constitute the "integration test for net
//! subsystem (live TCP + DNS + HTTP)" deliverable, and they implement
//! the formal Gate 4 (live real-world TLS artifact) and Gate 5 (live
//! API contract) named tests called out in QA Checkpoint 7's Phase 3.
//!
//! ## Test catalog
//!
//! | Section | Subject                                            | Tests | Live? |
//! |---------|----------------------------------------------------|-------|-------|
//! | 1       | Byte-frozen protocol-string + numeric constants    | 2     | no    |
//! | 2       | URL parsing (HTTP / HTTPS / invalid)               | 2     | no    |
//! | 3       | Blacklist add / contains / TTL / unknown           | 2     | no    |
//! | 4       | Runtime build + block_on round-trip                | 2     | no    |
//! | 5       | DNS lookup_host (localhost + literal + invalid TLD)| 3     | mixed |
//! | 6       | TCP echo on ephemeral port                         | 1     | no    |
//! | 7       | IoChain `Send + Sync + 'static` compile-check      | 1     | no    |
//! | 8       | HTTP server localhost round-trip                   | 1     | yes   |
//! | 9       | Live TLS handshake vs `www.rust-lang.org` (Gate 4) | 1     | yes   |
//! | 10      | Live HN API maxitem (Gate 5)                       | 1     | yes   |
//! | 11      | NetError variants Display formatting               | 6     | no    |
//! |         | **Total**                                          | **22**|       |
//!
//! ## Live-test gating
//!
//! Per AAP §0.8.4 ("live network tests are gated by environment
//! variables ... so they do not run in offline CI but are runnable for
//! Gate 1 verification") the four sections that perform real network
//! I/O — Section 5 (invalid-TLD failure path), Section 8 (localhost
//! HTTP), Section 9 (live TLS to `www.rust-lang.org`), and Section 10
//! (live HN API call) — are gated on the
//! `HEAVYTHING_LIVE_TESTS=1` environment variable. When the variable
//! is unset (the default in CI) the gated tests early-return after
//! emitting a one-line stderr notice, which is the same idiom used by
//! `tests/ffi_boundary.rs` for its TTY-gated and privilege-gated
//! tests.
//!
//! Sections that touch the *loopback* interface only (Section 6 TCP
//! echo, Section 5 `localhost` lookup) do **not** require the gate
//! because they cannot leak across hosts and are safe in any
//! environment that allows AF_INET on `127.0.0.1`.
//!
//! ## Why `IoChain::Send + Sync + 'static`?
//!
//! AAP §0.4.3 mandates that the `IoChain` trait — the Rust analogue
//! of the FASM 7-method virtual table at `io.inc:74–146` — have those
//! three bounds so chains can be moved across tokio task boundaries
//! and shared between worker threads. The fact that `Arc<dyn IoChain>`
//! satisfies these bounds is verified at compile time by Section 7's
//! `assert_send_sync_static::<dyn IoChain>()` helper. If anyone
//! removes a bound, this test file fails to compile, blocking the
//! merge.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::any::Any;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use heavything::config;
use heavything::error::{HttpError, NetError, SshError, TlsError};
use heavything::net::ssh::server::{SSH_IDENT, SSH_IDENT_BLACKLISTED};
use heavything::net::{
    blacklist, build_runtime, check_ulimit, link, url, Blacklist, BoxFuture, IoBase, IoChain,
    IoLinks, Url,
};

// ============================================================================
// Live-test gating helper (mirrors `ffi_boundary::live_tests_enabled`).
// ============================================================================

/// Returns `true` when `HEAVYTHING_LIVE_TESTS=1` is set in the
/// environment. Gated tests early-return when this is `false` so the
/// suite remains hermetic in CI.
fn live_tests_enabled() -> bool {
    matches!(
        std::env::var("HEAVYTHING_LIVE_TESTS").ok().as_deref(),
        Some("1")
    )
}

// ============================================================================
// Section 1: Byte-frozen protocol-string + numeric constants (2 tests)
// ============================================================================

#[test]
fn test_byte_frozen_constants_match_aap_specification() {
    // The `heavything::config` constants below are part of the
    // observable behavior of the FASM library. Per AAP §0.5.2.3 and
    // §0.7.1.1 each value is **required** to match the FASM
    // `ht_defaults.inc` baseline byte-for-byte. The QA checkpoint 7
    // report verified these via a custom probe; this test enshrines
    // them in the integration suite so any regression is caught by
    // `cargo test --test net_integration`.

    // EPOLL_MINFDS: the soft-limit floor enforced by `runtime::
    // check_ulimit` (FASM `epoll.inc:1160`). Exit code 97 is produced
    // when the post-`setrlimit` value falls below this floor.
    assert_eq!(
        config::EPOLL_MINFDS,
        4_096,
        "EPOLL_MINFDS must remain 4096 to preserve FASM ulimit behavior"
    );

    // EPOLL_READSIZE: 32 KiB per-connection read buffer (FASM
    // `epoll.inc:5` `epoll_readsize`).
    assert_eq!(
        config::EPOLL_READSIZE,
        32_768,
        "EPOLL_READSIZE must remain 32768 to preserve FASM read-buffer sizing"
    );

    // DNS_TIMEOUT_MSECS: 10-second async DNS resolution timeout
    // (AAP §0.5.1.4 `epoll_dns.inc` translation).
    assert_eq!(
        config::DNS_TIMEOUT_MSECS,
        10_000,
        "DNS_TIMEOUT_MSECS must remain 10s to preserve FASM async-DNS timeout"
    );

    // HSTS_HEADER_VALUE: emitted by `webserver.inc` HTTP/TLS responses
    // when `webserver_hsts = 1` (AAP §0.1.1 implicit requirements).
    // Byte-identical preservation is mandated by the prompt.
    assert_eq!(
        config::HSTS_HEADER_VALUE,
        "max-age=31536000; includeSubDomains",
        "HSTS_HEADER_VALUE must remain byte-identical for security parity"
    );
    assert_eq!(config::HSTS_HEADER_VALUE.len(), 35);

    // SSH_IDENT_STRING: the textual identification line; `ssh.inc:48`
    // sends `"SSH-2.0-HeavyThing\r\n"`. Listed in the user prompt as
    // an explicit example of preserved behavior.
    assert_eq!(
        config::SSH_IDENT_STRING,
        "SSH-2.0-HeavyThing",
        "SSH_IDENT_STRING must remain byte-identical for OpenSSH interop"
    );
    assert_eq!(config::SSH_IDENT_STRING.len(), 18);

    // The wire-frame versions (live in `ssh::server`) include the
    // CR-LF terminator; verify they are exactly 20 bytes (the
    // `SSH_IDENT_LEN` constant).
    assert_eq!(SSH_IDENT, b"SSH-2.0-HeavyThing\r\n");
    assert_eq!(SSH_IDENT.len(), 20);
    assert_eq!(SSH_IDENT_BLACKLISTED, b"SSH-2.0-HeavyThing (blacklisted)\r\n");
    assert_eq!(SSH_IDENT_BLACKLISTED.len(), 34);
}

#[test]
fn test_byte_frozen_tls_and_ssh_timing_constants() {
    // Eight canonical timer integration points per AAP §0.7.1.1 and
    // §0.7.2. Each constant is expressed as either seconds or
    // milliseconds depending on the spawn helper consuming it. Values
    // are captured here so a single integration assertion enforces
    // FASM parity for all timers — a future regression in any single
    // value will fail this test rather than silently drift.

    assert_eq!(
        config::TLS_PEM_REFRESH_INTERVAL,
        3_600,
        "TLS PEM hot-reload must run every 3600s (AAP §0.7.2.5)"
    );
    assert_eq!(
        config::TLS_SERVER_SESSIONCACHE,
        3_600,
        "TLS session cache TTL must remain 3600s (AAP §0.7.2.4)"
    );
    assert_eq!(
        config::X509_OCSP_REFRESH,
        7_200_000,
        "OCSP refresh interval must remain 7200s = 7200000ms (AAP §0.7.2)"
    );
    assert_eq!(
        config::X509_OCSP_RETRY,
        300_000,
        "OCSP retry interval must remain 300s = 300000ms (AAP §0.7.2)"
    );
    assert_eq!(
        config::TLS_BLACKLIST,
        86_400,
        "TLS IP blacklist TTL must remain 86400s (AAP §0.6.1)"
    );
    assert_eq!(
        config::SSH_BLACKLIST,
        86_400,
        "SSH IP blacklist TTL must remain 86400s (AAP §0.7.2)"
    );
    // The two share the same numeric value but live in independent
    // constants so their semantics can diverge without breaking the
    // other; tie that assumption down explicitly.
    assert_eq!(config::TLS_BLACKLIST, config::SSH_BLACKLIST);
}

// ============================================================================
// Section 2: URL parsing (HTTP / HTTPS / invalid) (2 tests)
// ============================================================================

#[test]
fn test_url_parse_http_https_basic_inputs() {
    // Plain HTTP with explicit port preserves every component.
    let u = Url::parse("http://example.com:8080/path?q=1#frag").expect("parse http");
    assert_eq!(u.protocol(), "http");
    assert_eq!(u.host(), "example.com");
    assert_eq!(u.port(), 8080);
    assert_eq!(u.effective_port(), 8080);
    assert!(
        u.path().contains("/path") || u.file().contains("/path"),
        "URL should preserve the request path component"
    );
    assert_eq!(u.query(), "q=1");

    // HTTPS without an explicit port uses the registered default,
    // which `effective_port` derives from the protocol per
    // `url.inc:effective_port`.
    let u = Url::parse("https://www.rust-lang.org/").expect("parse https");
    assert_eq!(u.protocol(), "https");
    assert_eq!(u.host(), "www.rust-lang.org");
    assert_eq!(u.effective_port(), 443);

    // Plain HTTP without explicit port → 80.
    let u = Url::parse("http://example.com/").expect("parse http no-port");
    assert_eq!(u.effective_port(), 80);

    // `Url::new` produces a default-initialised URL; the public
    // constructor is part of the published surface.
    let _ = Url::new();
}

#[test]
fn test_url_parse_invalid_returns_url_error() {
    // Empty input is rejected. The exact UrlError variant is an
    // implementation detail; we use a `match` rather than `==` because
    // `UrlError` does not derive `PartialEq` (it carries `String`
    // payloads from upstream `url::ParseError` conversions). This
    // pattern matches the `ds_integration` and `util_integration`
    // idioms.
    match Url::parse("") {
        Err(_) => {}
        Ok(u) => panic!("empty input must error, got {:?}", u.host()),
    }

    // url::encode round-trips every printable ASCII character that is
    // not in the unreserved set per RFC 3986 §2.3. The space → "%20"
    // mapping is the canonical baseline test.
    let encoded = url::encode("hello world");
    assert!(
        encoded.contains("%20") || encoded.contains('+'),
        "space must be percent- or plus-encoded; got {encoded}"
    );

    // url::decode reverses encode for any string we just produced,
    // matching FASM `url$decode` which is the inverse of `url$encode`.
    let decoded = url::decode(&encoded).expect("decode round-trip");
    assert_eq!(decoded, "hello world");
}

// ============================================================================
// Section 3: Blacklist add / contains / TTL / unknown (2 tests)
// ============================================================================

#[test]
fn test_blacklist_insert_contains_and_unknown() {
    // `Blacklist::new` returns an Arc — same pattern as FASM
    // `blacklist$new`. A 60-second default expiry mirrors the
    // FASM convention; the per-insert TTL overrides it.
    let bl = Blacklist::new(Duration::from_secs(60));

    let v4 = blacklist::key_from_ipv4(Ipv4Addr::new(192, 0, 2, 1));
    let v6 = blacklist::key_from_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    assert_eq!(bl.len(), 0);
    assert!(bl.is_empty());

    bl.insert(v4, Duration::from_secs(300));
    bl.insert(v6, Duration::from_secs(300));

    assert!(bl.contains(v4));
    assert!(bl.contains(v6));
    assert_eq!(bl.len(), 2);
    assert!(!bl.is_empty());

    // Unknown key is reported as not blacklisted.
    let unknown = blacklist::key_from_ipv4(Ipv4Addr::new(198, 51, 100, 1));
    assert!(!bl.contains(unknown));

    // Removal is observable.
    bl.remove(v4);
    assert!(!bl.contains(v4));
    assert!(bl.contains(v6));

    // `clear` empties the table.
    bl.clear();
    assert!(bl.is_empty());
}

#[test]
fn test_blacklist_ttl_zero_expires_eagerly() {
    // A zero-duration TTL inserts an entry that is immediately
    // expired. `contains` performs lazy expiry on lookup, so the
    // first observation reports `false`. Validates the FASM
    // `blacklist.inc` lazy-expiry semantics that the Rust port
    // preserves.
    let bl = Blacklist::new(Duration::from_secs(60));
    let key = blacklist::key_from_socket_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 9999)));

    bl.insert(key, Duration::from_secs(0));

    // Either the lazy-expiry path returns `false` immediately, or the
    // entry is observed once and then expires — either is correct.
    // The strict invariant we test is that within a measurable delay
    // the entry stops being reported as contained.
    std::thread::sleep(Duration::from_millis(20));
    assert!(
        !bl.contains(key),
        "zero-TTL entry must expire on lookup within 20ms"
    );

    // The 86400s value used by TLS/SSH is itself a Duration —
    // exercise the constructor with the canonical AAP value to
    // confirm no overflow or panic on the value used in production.
    let bl_long = Blacklist::new(Duration::from_secs(config::SSH_BLACKLIST));
    assert!(bl_long.is_empty());
}

// ============================================================================
// Section 4: Runtime build + block_on round-trip (2 tests)
// ============================================================================

#[test]
fn test_runtime_build_and_block_on_simple_future() {
    // `build_runtime` wraps `tokio::runtime::Builder::new_multi_thread
    // ().enable_all().build()`. Driving a trivial future to completion
    // proves the runtime is fully wired and not just constructable.
    let rt = build_runtime().expect("build_runtime");
    let answer = rt.block_on(async { 1u32 + 2 });
    assert_eq!(answer, 3);

    // Sanity-check that an `async` task that yields can also complete
    // — this exercises the scheduler and the I/O driver init path.
    let bigger = rt.block_on(async {
        tokio::task::yield_now().await;
        42_i64
    });
    assert_eq!(bigger, 42);
}

#[test]
fn test_check_ulimit_reports_a_typed_result() {
    // `check_ulimit` returns `Result<(), InitError>`. We do not
    // assert `Ok(())` because CI containers can legitimately have
    // limits below 4096 (sandbox-imposed). The point of this test is
    // that the function returns a typed result without panicking and
    // does not misbehave on platforms where `getrlimit` succeeds.
    let result = check_ulimit();
    match result {
        Ok(()) => {
            // Host has at least EPOLL_MINFDS file descriptors — the
            // expected path on production-grade Linux.
        }
        Err(_) => {
            // Sandboxed CI: `setrlimit` could not raise to
            // EPOLL_MINFDS. This is also a valid observation.
            eprintln!(
                "[net_integration] check_ulimit returned Err — host \
                 RLIMIT_NOFILE soft/hard < {}; this is expected in \
                 some sandboxed CI environments",
                config::EPOLL_MINFDS
            );
        }
    }
}

// ============================================================================
// Section 5: DNS lookup_host (localhost + literal + invalid TLD) (3 tests)
// ============================================================================

#[test]
fn test_dns_lookup_host_localhost() {
    // `localhost` MUST resolve via the kernel's nsswitch chain even
    // when no nameservers are reachable, because `nss_files` short-
    // circuits to `127.0.0.1` / `::1` from `/etc/hosts`. This is the
    // safest live test that does not require external connectivity.
    let rt = build_runtime().expect("build_runtime");
    let addrs = rt
        .block_on(heavything::net::dns::lookup_host("localhost", 80))
        .expect("localhost must resolve via /etc/hosts");
    assert!(
        !addrs.is_empty(),
        "localhost must resolve to at least one socket"
    );
    let any_loopback = addrs.iter().any(|a| match a.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    });
    assert!(
        any_loopback,
        "at least one localhost address must be a loopback IP, got {addrs:?}"
    );
    // Port must be carried through verbatim per FASM
    // `epoll_dns.inc`'s socket-address construction.
    for a in &addrs {
        assert_eq!(a.port(), 80);
    }
}

#[test]
fn test_dns_lookup_host_ip_literal() {
    // An IPv4 literal MUST be honored without contacting any
    // nameserver. The Rust port wraps `tokio::net::lookup_host` which
    // performs this short-circuit; the test verifies the wrapper
    // does not regress that behavior.
    let rt = build_runtime().expect("build_runtime");
    let addrs = rt
        .block_on(heavything::net::dns::lookup_host("127.0.0.1", 4242))
        .expect("IPv4 literal must always succeed");
    assert!(addrs
        .iter()
        .any(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) && a.port() == 4242));

    // Same for IPv6 literal.
    let addrs = rt
        .block_on(heavything::net::dns::lookup_host("::1", 4242))
        .expect("IPv6 literal must always succeed");
    assert!(addrs
        .iter()
        .any(|a| a.ip() == IpAddr::V6(Ipv6Addr::LOCALHOST) && a.port() == 4242));
}

#[test]
fn test_dns_lookup_host_invalid_tld_errors_gated() {
    // Real DNS failure required — gated.
    if !live_tests_enabled() {
        eprintln!(
            "[net_integration] skipping test_dns_lookup_host_invalid_tld_errors_gated \
             (set HEAVYTHING_LIVE_TESTS=1 to run live DNS tests)"
        );
        return;
    }

    let rt = build_runtime().expect("build_runtime");
    // The `.invalid` TLD is reserved by RFC 6761 §6.4 specifically to
    // produce NXDOMAIN. Resolution MUST fail, but it MUST fail with a
    // typed `NetError` rather than a panic.
    let result = rt.block_on(heavything::net::dns::lookup_host(
        "nonexistent-host-do-not-resolve.invalid",
        80,
    ));
    match result {
        Ok(addrs) => panic!(
            "RFC 6761 .invalid TLD must not resolve, got {addrs:?}"
        ),
        Err(NetError::Dns(_)) | Err(NetError::DnsTimeout) | Err(NetError::Io(_)) => {}
        Err(other) => panic!("expected DNS-class error, got {other}"),
    }
}

// ============================================================================
// Section 6: TCP echo on ephemeral port (1 test)
// ============================================================================

#[test]
fn test_tcp_echo_round_trip_on_loopback() {
    // Bind a tokio listener on an ephemeral loopback port, accept
    // exactly one connection, echo the payload back. The client side
    // sends 1 KiB of pseudo-random bytes and verifies the reply is
    // byte-identical. This exercises the same epoll/mio/tokio path
    // that the WebServer uses without depending on any HTTP framing.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let rt = build_runtime().expect("build_runtime");

    rt.block_on(async {
        let listener = TcpListener::bind(("127.0.0.1", 0u16))
            .await
            .expect("bind ephemeral");
        let local = listener.local_addr().expect("local_addr");

        // Server task: accept, echo, close.
        let server = tokio::spawn(async move {
            let (mut sock, _peer) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 1024];
            let n = sock.read_exact(&mut buf).await.expect("read_exact");
            assert_eq!(n, 1024);
            sock.write_all(&buf).await.expect("write_all");
            sock.flush().await.expect("flush");
        });

        // Client side: connect, send, read back, compare.
        let mut payload = [0u8; 1024];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = ((i * 31 + 7) & 0xff) as u8;
        }
        let mut client = TcpStream::connect(local).await.expect("connect");
        // `apply_stream_defaults` is the FASM `epoll$set_socketopts`
        // analogue — applied here to ensure the helper integrates with
        // a freshly accepted connection without panicking. It returns
        // `std::io::Result<()>` so we `.expect()` consistent with the
        // rest of this test's idiom.
        heavything::net::runtime::apply_stream_defaults(&client)
            .expect("apply_stream_defaults");
        client.write_all(&payload).await.expect("client write");
        client.flush().await.expect("client flush");
        let mut reply = [0u8; 1024];
        client.read_exact(&mut reply).await.expect("client read");
        assert_eq!(reply, payload, "echo round-trip must be byte-identical");

        server.await.expect("server task");
    });
}

// ============================================================================
// Section 7: IoChain `Send + Sync + 'static` compile-check (1 test)
// ============================================================================

/// Compile-time helper — moves a `T: Send + Sync + 'static` value into
/// itself. If `T` does not satisfy the bounds the call site fails to
/// compile. Used below to enforce the AAP §0.4.3 `IoChain` bounds at
/// integration-test build time.
fn assert_send_sync_static<T: Send + Sync + 'static + ?Sized>() {}

#[test]
fn test_iochain_trait_object_is_send_sync_static() {
    // Static type-level enforcement: `dyn IoChain` MUST be
    // `Send + Sync + 'static`. An `Arc<dyn IoChain>` is the canonical
    // FASM `io$parent` / `io$child` analogue and travels across
    // tokio task boundaries.
    assert_send_sync_static::<dyn IoChain>();
    assert_send_sync_static::<Arc<dyn IoChain>>();
    assert_send_sync_static::<IoBase>();
    assert_send_sync_static::<IoLinks>();

    // `BoxFuture<T>` is the trait's return type for every async
    // method; verify it is `Send` (the bound is in its definition).
    fn _bf_send<T: Send + 'static>() -> BoxFuture<T> {
        Box::pin(async move {
            // No-op — we only need the type to compile.
            unreachable!("compile-check helper")
        })
    }
    let _: fn() -> BoxFuture<()> = _bf_send::<()>;

    // Build a tiny chain (parent + child) using `IoBase` and `link`,
    // exercising the public `link` helper. The chain is trivially
    // dropped, which fires `Drop` on `IoLinks` and confirms there is
    // no panic in the destructor path.
    let parent: Arc<dyn IoChain> = IoBase::new();
    let child: Arc<dyn IoChain> = IoBase::new();
    link(&parent, child);
}

// ============================================================================
// Section 8: HTTP server localhost round-trip (1 test, live-gated)
// ============================================================================

#[test]
fn test_http_server_localhost_round_trip_gated() {
    // The HTTP server's `handle_connection` driver is a fully wired
    // pipeline (FASM `webserver$new_listener` → `epoll$run`). This
    // test binds an ephemeral loopback listener, drives a single
    // request through `handle_connection`, and asserts the response
    // begins with `HTTP/1.1`. It is gated on
    // `HEAVYTHING_LIVE_TESTS=1` because Phase 5/6 of the server
    // pipeline performs filesystem stat/open syscalls (sandbox
    // resolution + index-file lookup) that some restrictive sandboxes
    // forbid.
    if !live_tests_enabled() {
        eprintln!(
            "[net_integration] skipping test_http_server_localhost_round_trip_gated \
             (set HEAVYTHING_LIVE_TESTS=1 to run; this test exercises \
              the WebServer dispatch pipeline against a loopback listener)"
        );
        return;
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let rt = build_runtime().expect("build_runtime");
    rt.block_on(async {
        let listener = TcpListener::bind(("127.0.0.1", 0u16))
            .await
            .expect("bind");
        let local = listener.local_addr().expect("local_addr");

        // The server side: spawn a handler that uses the
        // `WebServer` chain end-to-end via `handle_connection`.
        let cfg = heavything::net::http::server::WebServerConfig::new_config();
        let cfg_for_task = Arc::clone(&cfg);
        let server_task = tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.expect("accept");
            // `handle_connection` returns when the chain closes.
            let _ = heavything::net::http::server::handle_connection(sock, peer, cfg_for_task)
                .await;
        });

        // The entire client interaction is wrapped in a hard 15s
        // timeout so the test cannot deadlock the suite if the server
        // pipeline (e.g., a stage-5/6 filesystem operation) blocks
        // beyond what a healthy round-trip should require. The wrap
        // also insulates the test from environments without a
        // configured sandbox/document root.
        let reply = tokio::time::timeout(Duration::from_secs(15), async {
            let mut client = TcpStream::connect(local).await.expect("connect");
            client
                .write_all(b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
                .await
                .expect("client write");
            client.flush().await.expect("client flush");

            // Read with bounded single-shot reads instead of
            // `read_to_end`, which would block on the server's
            // close-of-write semantics. We stop as soon as we have
            // enough bytes to assert the `HTTP/1.1 ` prefix (the
            // byte-identical `HTTP_1_1_PREFIX` constant exposed by
            // `webserver.inc:webserver_http_version`).
            let mut reply: Vec<u8> = Vec::with_capacity(1024);
            let mut buf = [0u8; 256];
            while reply.len() < 64 {
                match client.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => reply.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            let _ = client.shutdown().await;
            reply
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "test_http_server_localhost_round_trip_gated: client \
                 round-trip did not complete within 15s; the WebServer \
                 pipeline may be blocked on stage-5/6 filesystem syscalls \
                 (sandbox/index-file resolution) absent a configured \
                 document root in this environment"
            )
        });

        let preamble = String::from_utf8_lossy(&reply[..reply.len().min(64)]);
        assert!(
            preamble.starts_with("HTTP/1.1 "),
            "server response must start with `HTTP/1.1 `, got {:?}",
            preamble
        );

        // Best-effort wait for the server task to terminate.
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    });
}

// ============================================================================
// Section 9: Live TLS handshake vs `www.rust-lang.org` (Gate 4) (1 test)
// ============================================================================

#[test]
fn test_live_tls_handshake_vs_rust_lang_org() {
    // **Gate 4 named real-world artifact.** The HeavyThing port must
    // perform a complete TLS handshake against a live, public host
    // using the `webpki-roots` Mozilla CA bundle and the rustls
    // default cipher suites. The successful response is HTTP/1.1 (200
    // / 301 / 302 / etc.) — we accept any 1xx–5xx well-formed status
    // line because the upstream may rotate redirects; the point is
    // that the handshake completes and the application protocol is
    // intact.
    if !live_tests_enabled() {
        eprintln!(
            "[net_integration] skipping test_live_tls_handshake_vs_rust_lang_org \
             (set HEAVYTHING_LIVE_TESTS=1 to run live Gate 4 TLS test \
              against www.rust-lang.org:443)"
        );
        return;
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let rt = build_runtime().expect("build_runtime");
    rt.block_on(async {
        // Resolve the public host via our DNS module (exercises the
        // tokio resolver under live conditions).
        let mut addrs = heavything::net::dns::lookup_host("www.rust-lang.org", 443)
            .await
            .expect("DNS lookup must succeed for Gate 4");
        // Prefer IPv4 to dodge IPv6-disabled CI hosts; fall back to
        // whatever the resolver returned.
        addrs.sort_by_key(|a| !matches!(a.ip(), IpAddr::V4(_)));
        let target = *addrs.first().expect("at least one address");
        let tcp = match tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(target))
            .await
        {
            Ok(Ok(stream)) => stream,
            other => panic!("TCP connect to {target} failed: {other:?}"),
        };

        let client = heavything::net::tls::TlsClient::new("www.rust-lang.org")
            .expect("TlsClient::new");
        let mut tls = match tokio::time::timeout(Duration::from_secs(20), client.connect(tcp)).await
        {
            Ok(Ok(stream)) => stream,
            other => panic!("TLS handshake against www.rust-lang.org failed: {other:?}"),
        };

        // Application data: minimal HTTP/1.1 GET with explicit Host.
        // We do NOT depend on the body content — the test asserts the
        // handshake completed and the application-layer status line is
        // well-formed.
        let req = b"GET / HTTP/1.1\r\nHost: www.rust-lang.org\r\nConnection: close\r\nUser-Agent: heavything-integration/1.0\r\n\r\n";
        tls.write_all(req).await.expect("TLS write");
        tls.flush().await.expect("TLS flush");

        let mut response = Vec::with_capacity(2048);
        // Bound the read to keep the test quick; 8 KiB is plenty for
        // the status line + early headers.
        let mut buf = [0u8; 1024];
        let mut total = 0usize;
        while total < 8192 {
            match tokio::time::timeout(Duration::from_secs(15), tls.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    response.extend_from_slice(&buf[..n]);
                    total += n;
                    if response.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Ok(Err(e)) => panic!("TLS read failed: {e}"),
                Err(_) => break,
            }
        }

        assert!(
            !response.is_empty(),
            "TLS handshake completed but no application-layer bytes were received"
        );
        let head = String::from_utf8_lossy(&response[..response.len().min(64)]);
        assert!(
            head.starts_with("HTTP/1.1 ") || head.starts_with("HTTP/1.0 "),
            "expected HTTP/1.x status line; got {head:?}"
        );
    });
}

// ============================================================================
// Section 10: Live HN API maxitem (Gate 5) (1 test)
// ============================================================================

#[test]
fn test_live_hn_api_maxitem() {
    // **Gate 5 API contract verification.** Validates that the HTTPS
    // pipeline can call the public Hacker News Firebase REST API,
    // which is what the in-scope `hnwatch` binary will eventually
    // depend on. The endpoint `https://hacker-news.firebaseio.com/v0
    // /maxitem.json` returns a single integer (the largest item ID).
    if !live_tests_enabled() {
        eprintln!(
            "[net_integration] skipping test_live_hn_api_maxitem \
             (set HEAVYTHING_LIVE_TESTS=1 to run live Gate 5 HN API test)"
        );
        return;
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let rt = build_runtime().expect("build_runtime");
    rt.block_on(async {
        let mut addrs = heavything::net::dns::lookup_host("hacker-news.firebaseio.com", 443)
            .await
            .expect("DNS lookup hacker-news.firebaseio.com");
        addrs.sort_by_key(|a| !matches!(a.ip(), IpAddr::V4(_)));
        let target = *addrs.first().expect("at least one address");
        let tcp = match tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(target))
            .await
        {
            Ok(Ok(stream)) => stream,
            other => panic!("TCP connect to {target} failed: {other:?}"),
        };

        let client = heavything::net::tls::TlsClient::new("hacker-news.firebaseio.com")
            .expect("TlsClient::new");
        let mut tls = match tokio::time::timeout(Duration::from_secs(20), client.connect(tcp)).await
        {
            Ok(Ok(stream)) => stream,
            other => panic!("TLS handshake against hacker-news.firebaseio.com failed: {other:?}"),
        };

        let req = b"GET /v0/maxitem.json HTTP/1.1\r\nHost: hacker-news.firebaseio.com\r\nConnection: close\r\nUser-Agent: heavything-integration/1.0\r\n\r\n";
        tls.write_all(req).await.expect("HTTPS write");
        tls.flush().await.expect("HTTPS flush");

        let mut response = Vec::with_capacity(4096);
        let mut buf = [0u8; 2048];
        loop {
            match tokio::time::timeout(Duration::from_secs(20), tls.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > 16 * 1024 {
                        break;
                    }
                }
                Ok(Err(e)) => panic!("HTTPS read failed: {e}"),
                Err(_) => break,
            }
        }

        let text = String::from_utf8_lossy(&response);
        assert!(
            text.starts_with("HTTP/1.1 200")
                || text.starts_with("HTTP/1.0 200")
                || text.contains(" 200 "),
            "expected HTTP/1.x 200 response; got first 64 bytes: {:?}",
            &text.chars().take(64).collect::<String>()
        );

        // Parse out the response body — everything after the first
        // `\r\n\r\n` separator. The body is a JSON integer, e.g.
        // `47911456`.
        let split_pos = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("HTTP/1.x response must contain header/body separator");
        let body = &response[split_pos + 4..];
        let body_text = String::from_utf8_lossy(body);
        // The body may be chunked; if so the first line is the chunk
        // size in hex followed by `\r\n` and then the integer body.
        // Either way the integer ID must be parseable from somewhere
        // in the body.
        let trimmed = body_text.trim();
        let candidate = trimmed
            .split(|c: char| c.is_whitespace() || c == '\r' || c == '\n')
            .map(|s| s.trim_matches(|c: char| !c.is_ascii_digit()))
            .find(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or("");
        let id: u64 = u64::from_str(candidate).unwrap_or(0);
        assert!(
            id > 1_000_000,
            "maxitem ID must be a positive integer well above 1M; got {id} \
             (raw body: {:?})",
            &body_text.chars().take(80).collect::<String>()
        );
    });
}

// ============================================================================
// Section 11: NetError variants Display formatting (6 tests)
// ============================================================================

#[test]
fn test_neterror_io_display_formatting() {
    // `NetError::Io` wraps `std::io::Error` via `#[from]`. Display
    // output must include both the prefix and the inner message.
    let inner = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer closed");
    let err = NetError::Io(inner);
    let s = err.to_string();
    assert!(s.starts_with("network I/O failure"));
    assert!(s.contains("peer closed"), "expected inner message: {s}");
}

#[test]
fn test_neterror_dns_variants_display() {
    let timeout = NetError::DnsTimeout;
    assert_eq!(timeout.to_string(), "DNS lookup timed out");

    let dns = NetError::Dns("SERVFAIL".to_string());
    assert_eq!(dns.to_string(), "DNS lookup failed: SERVFAIL");
}

#[test]
fn test_tls_error_variants_display() {
    let handshake = TlsError::Handshake("bad alert".to_string());
    assert_eq!(handshake.to_string(), "TLS handshake failed: bad alert");

    let pem = TlsError::Pem("missing END CERTIFICATE".to_string());
    assert_eq!(pem.to_string(), "PEM parse failed: missing END CERTIFICATE");

    let ocsp = TlsError::Ocsp("HTTP 503".to_string());
    assert_eq!(ocsp.to_string(), "OCSP failure: HTTP 503");

    let cache = TlsError::SessionCache("AES decrypt".to_string());
    assert_eq!(cache.to_string(), "session cache failure: AES decrypt");

    // `TlsError → NetError` round-trip via `#[from]` preserves the
    // Display output: the outer `NetError::Tls(_)` wraps the inner
    // `TlsError` and the formatter chains them.
    let net: NetError = handshake.into();
    let s = net.to_string();
    assert!(s.starts_with("TLS error: "));
    assert!(s.contains("TLS handshake failed: bad alert"));
}

#[test]
fn test_ssh_error_variants_display() {
    let kex = SshError::KeyExchange("group too small".to_string());
    assert_eq!(kex.to_string(), "SSH key exchange failed: group too small");

    let auth = SshError::Auth;
    assert_eq!(auth.to_string(), "SSH authentication failed");

    let cipher = SshError::Cipher;
    assert_eq!(cipher.to_string(), "SSH cipher/HMAC failure");

    let comp = SshError::Compression("inflate failed".to_string());
    assert_eq!(comp.to_string(), "SSH compression failure: inflate failed");

    let host = SshError::HostKeys("/etc/ssh missing".to_string());
    assert_eq!(host.to_string(), "missing host keys: /etc/ssh missing");

    // Round-trip via `From`.
    let net: NetError = auth.into();
    assert!(net.to_string().starts_with("SSH error: "));
}

#[test]
fn test_http_error_variants_display() {
    // `HttpError::Parse` is the only variant we exhaustively assert on
    // here; the Display chain via `NetError::Http(_)` is what we test
    // for the other variants.
    let parse = HttpError::Parse("bad request line".to_string());
    assert_eq!(parse.to_string(), "HTTP parse failure: bad request line");

    let net: NetError = parse.into();
    let s = net.to_string();
    assert!(s.starts_with("HTTP error: "));
    assert!(s.contains("HTTP parse failure: bad request line"));
}

#[test]
fn test_url_error_can_be_constructed_and_displayed() {
    // `Url::parse` is the canonical way to surface a `UrlError`. We
    // already exercised the error path in Section 2; this test
    // additionally verifies the Display output is non-empty and
    // forwards through Debug for diagnostic-stream use.
    let result = Url::parse("");
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("empty input must error"),
    };
    let display = format!("{err}");
    assert!(
        !display.is_empty(),
        "UrlError Display output must not be empty"
    );
    // `UrlError` derives Debug; smoke-test the impl is reachable.
    let debug = format!("{err:?}");
    assert!(!debug.is_empty());

    // Ensure `UrlError` can be sent across the typical
    // `?`-propagation surface — the trait bounds are checked at
    // compile time below.
    fn _propagate(_e: &dyn std::error::Error) {}
    _propagate(&err);

    // The `Url::user` accessor is `pub` per AAP §0.5.1.4 and is part
    // of the published surface. Exercise it on a default-initialised
    // URL: a fresh URL has no user payload attached, so the
    // accessor returns `None`. This pins down the public contract.
    let u = Url::new();
    let user: Option<&Arc<dyn Any + Send + Sync>> = u.user();
    assert!(user.is_none(), "default Url must have no user payload");

    // Construct an unrelated socket-shutdown enum to exercise the
    // standard library's IpAddr / SocketAddr types we already imported
    // at the top — keeps the imports honestly used and gives us a
    // smoke-test that those types format correctly.
    let _ = format!("{:?}", Shutdown::Both);
    let _ = format!("{:?}", IpAddr::V4(Ipv4Addr::LOCALHOST));
}
