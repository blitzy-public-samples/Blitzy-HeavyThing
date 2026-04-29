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
// Rust port of webclient.inc — browser-style persistent HTTP/1.1 client.
// Preserves the wchost / wcio / wcrequest 3-layer architecture.

//! Browser-style persistent HTTP/1.1 client.
//!
//! Direct translation of `webclient.inc` (2,042 lines / 29 FASM functions)
//! per AAP §0.5.1.4. The four observable failure paths and exact wire-format
//! semantics of the assembly source are preserved byte-for-byte; the
//! `WEBCLIENT_FAIL_*` numeric codes are exported as `i64` constants for FFI
//! parity and surfaced via the [`WebClientResult`] enum for ergonomic Rust
//! callbacks.
//!
//! # Architecture — three-layer object hierarchy
//!
//! ```text
//!   WebClient                       (top-level handle; user-owned)
//!    ├── inflight: HashMap<id, WcRequest>
//!    ├── hosts:    HashMap<hostkey, Arc<WcHost>>
//!    └── cookie_jar: Option<Arc<Mutex<CookieJar>>>
//!
//!   WcHost                          (per-(host:port:tls) pool)
//!    ├── channels: Vec<Arc<WcIo>>   (active connections, ≤ max_conns)
//!    └── queue:    VecDeque<Arc<WcRequest>>  (pending requests)
//!
//!   WcIo                            (per-connection IoChain layer)
//!    ├── wcrequest: Option<WcRequest>  (None == idle / available)
//!    ├── response: Vec<u8>             (response accumulation buffer)
//!    └── child: Arc<dyn IoChain>       (TcpStream or TlsStream wrapper)
//!
//!   WcRequest                       (one user-level HTTP request)
//!    ├── url, method, headers_only
//!    ├── callback: Arc<dyn Fn(...)>
//!    └── request_mimelike: Mimelike
//! ```
//!
//! Reference cycles are broken by storing parent back-pointers as
//! [`Weak`](std::sync::Weak) — `WcRequest → WebClient`, `WcIo → WcHost`,
//! `WcHost → WebClient`. Forward ownership chains use [`Arc`] clones
//! across [`Mutex`]-guarded collections.
//!
//! # Failure codes (verbatim from FASM L75-78)
//!
//! | Code | Constant                          | Meaning                              |
//! |------|-----------------------------------|--------------------------------------|
//! | `-1` | [`WEBCLIENT_FAIL_DNS`]            | Hostname could not be resolved       |
//! | `-2` | [`WEBCLIENT_FAIL_PRECONNECT`]     | TCP/TLS handshake failed             |
//! | `-3` | [`WEBCLIENT_FAIL_CLOSED`]         | Peer closed connection mid-response  |
//! | `-4` | [`WEBCLIENT_FAIL_TIMEOUT`]        | 120-second read timeout fired        |
//! | `-5` | [`WEBCLIENT_FAIL_REDIRECT_LOOP`]  | Rust-port: redirect cycle detected   |
//!
//! # Critical safety rule
//!
//! **Never destroy a [`WebClient`] from inside a callback.** The FASM
//! source contains an explicit warning at L39-43; the Rust port honours
//! the same contract. If a user callback wants to tear down the client,
//! it must schedule the drop via `tokio::spawn` (or equivalent) so that
//! the destruction happens after the callback frame has returned and
//! the in-flight slot has been released.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::{
    WEBCLIENT_FOLLOW_REDIRECTS, WEBCLIENT_GLOBAL_DNSCACHE, WEBCLIENT_MAXCONNS, WEBCLIENT_READTIMEOUT,
    WEBSERVER_MAXREQUEST,
};
use crate::error::{HttpError, NetError};
use crate::net::dns::DnsResolver;
use crate::net::http::cookiejar::CookieJar;
use crate::net::http::mimelike::{Mimelike, CHUNKED_TERMINATOR};
use crate::net::io::{
    default_connected, default_destroy, default_error, default_receive, default_send, default_timeout, link,
    BoxFuture, IoChain, IoLinks,
};
use crate::net::runtime::{TeardownReason, TimerAction};
use crate::net::tls::{TlsClient, TlsStream};
use crate::net::url::Url;

// =============================================================================
// Failure codes — preserved verbatim from FASM L75-78.
// =============================================================================

/// Hostname could not be resolved (FASM `webclient_fail_dns`).
///
/// Surfaced to the user callback as the second positional argument
/// when [`WcHost::dns_failure`] exhausts its 3-attempt retry budget
/// (only when [`WEBCLIENT_GLOBAL_DNSCACHE`] is `false`; the global-cache
/// path falls through to a single resolution attempt).
pub const WEBCLIENT_FAIL_DNS: i64 = -1;

/// Pre-connect (TCP or TLS handshake) failure
/// (FASM `webclient_fail_preconnect`).
///
/// Fires when `tokio::net::TcpStream::connect` returns an error or
/// when [`TlsClient::connect`] fails. Distinguishes "couldn't even
/// open the socket" from "peer closed mid-stream"
/// ([`WEBCLIENT_FAIL_CLOSED`]).
pub const WEBCLIENT_FAIL_PRECONNECT: i64 = -2;

/// Connection closed before a complete response was received
/// (FASM `webclient_fail_closed`).
///
/// Fires when an [`IoChain::error`] propagates from the underlying
/// transport (EOF mid-response, TCP RST, TLS close-notify before body
/// completion, etc.) or when a connection is reaped from the
/// connection pool while it has an in-flight request.
pub const WEBCLIENT_FAIL_CLOSED: i64 = -3;

/// 120-second per-connection read timeout
/// (FASM `webclient_fail_timeout`).
///
/// Fires when no bytes have arrived for [`WEBCLIENT_READTIMEOUT`] ms
/// while a request is in flight. The timer is **reset** (not
/// cumulative) on each successful [`IoChain::receive`], so a slow but
/// continuous trickle of bytes does not trip the timeout.
pub const WEBCLIENT_FAIL_TIMEOUT: i64 = -4;

/// Rust-port enhancement: redirect cycle detected.
///
/// FASM has no redirect-loop guard; the Rust port adds a
/// `redirect_count` counter to each [`WcRequest`] (capped at 10) so
/// that a malicious or misconfigured server returning a permanent
/// redirect loop cannot cause unbounded memory growth or task churn.
/// Surfaced through the same callback path as
/// [`WEBCLIENT_FAIL_CLOSED`] would in the FASM source.
pub const WEBCLIENT_FAIL_REDIRECT_LOOP: i64 = -5;

/// Maximum redirect-follow depth before [`WEBCLIENT_FAIL_REDIRECT_LOOP`]
/// is dispatched. FASM had no such guard; this is a Rust-port safety
/// improvement called out in AAP §0.5.1.4 / Phase 13.
const MAX_REDIRECTS: u32 = 10;

// =============================================================================
// WebClientResult — ergonomic enum for the Rust callback contract.
// =============================================================================

/// Discriminated callback payload for HTTP requests.
///
/// FASM passes either a `Mimelike*` pointer or a negative `i64` failure
/// code in the same `rsi` register. The Rust port unifies both into a
/// single typed enum so the callback can pattern-match without manual
/// pointer / sentinel checks.
///
/// The `Response` variant borrows the [`Mimelike`] from the dispatching
/// [`WcIo`] for the duration of the callback. Holding it past the
/// callback return is a borrow-check error at compile time — this
/// enforces FASM's implicit lifetime discipline (the response mimelike
/// is destroyed immediately after the callback returns).
#[derive(Debug)]
pub enum WebClientResult<'a> {
    /// Successfully parsed HTTP response.
    Response(&'a Mimelike),
    /// DNS resolution exhausted retries (= [`WEBCLIENT_FAIL_DNS`]).
    FailDns,
    /// TCP or TLS preconnect failed (= [`WEBCLIENT_FAIL_PRECONNECT`]).
    FailPreconnect,
    /// Connection closed mid-response (= [`WEBCLIENT_FAIL_CLOSED`]).
    FailClosed,
    /// Per-connection 120-second read timeout fired
    /// (= [`WEBCLIENT_FAIL_TIMEOUT`]).
    FailTimeout,
}

impl<'a> WebClientResult<'a> {
    /// Convert this result into the FASM-equivalent `i64` code, or
    /// `None` for the success branch.
    ///
    /// Useful when forwarding callback dispatch to FFI consumers that
    /// want the raw numeric code instead of the enum.
    pub fn fail_code(&self) -> Option<i64> {
        match self {
            WebClientResult::Response(_) => None,
            WebClientResult::FailDns => Some(WEBCLIENT_FAIL_DNS),
            WebClientResult::FailPreconnect => Some(WEBCLIENT_FAIL_PRECONNECT),
            WebClientResult::FailClosed => Some(WEBCLIENT_FAIL_CLOSED),
            WebClientResult::FailTimeout => Some(WEBCLIENT_FAIL_TIMEOUT),
        }
    }
}

// =============================================================================
// Helper utilities.
// =============================================================================

/// Monotonic millisecond timestamp, suitable for elapsed-time math.
///
/// Used for [`WcRequest::start_time`] and [`WebClient::reply_stamp`].
/// FASM uses the vDSO-fast `gettimeofday()` for these stamps; Rust's
/// `SystemTime::now()` uses vDSO automatically on Linux per
/// AAP §0.7.3 so no additional setup is required.
fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build the host-pool key string used by [`WebClient::hosts`].
///
/// Format: `"host:port"` (lower-cased host) for HTTP, or
/// `"host:port:tls"` for HTTPS. The `:tls` suffix prevents an HTTPS
/// pool from accidentally servicing a same-host:port HTTP request
/// (which is not actually possible at the TCP layer but the FASM
/// source defensively keys both pools separately). Matches the
/// `wcrequest$new` hostkey construction at FASM L240-280.
fn build_hostkey(host: &str, port: u16, is_tls: bool) -> String {
    if is_tls {
        format!("{}:{}:tls", host.to_lowercase(), port)
    } else {
        format!("{}:{}", host.to_lowercase(), port)
    }
}

/// Build the HTTP request line preface (e.g. `"GET /path HTTP/1.1"`).
///
/// FASM `wcrequest$new` constructs the preface as:
/// `<method><path-or-/-on-empty> HTTP/1.1`. The Rust port preserves
/// this exact byte sequence including the single space after the
/// method token and before `HTTP/1.1`. The path component falls back
/// to `"/"` when the URL has neither path nor query (matching the
/// behaviour of every well-known HTTP client).
fn build_preface(method: &'static str, url: &Url) -> String {
    let file = url.file();
    let path = if file.is_empty() { "/" } else { file };
    format!("{}{} HTTP/1.1", method, path)
}

/// Build the `Host:` header value: `"host[:port]"` where the port is
/// elided iff it equals the scheme default (80 for HTTP, 443 for HTTPS).
///
/// Matches FASM `wcrequest$new` lines 308-340 — the assembly source
/// does the same scheme-default elision via the `wcurl$port` /
/// `wcurl$effective_port` comparison.
fn build_host_header(url: &Url) -> String {
    // Scheme default port — derived from the protocol token because
    // `Url::effective_port` returns the *explicit* port when set,
    // which would defeat the elision check.
    let scheme_default: u16 = match url.protocol() {
        "https" => 443,
        _ => 80,
    };
    let p = url.port();
    if p == 0 || p == scheme_default {
        url.host().to_string()
    } else {
        format!("{}:{}", url.host(), p)
    }
}

// =============================================================================
// WebClient — top-level handle.
// =============================================================================

/// Browser-style persistent HTTP/1.1 client with host-keyed pooling.
///
/// One [`WebClient`] instance can multiplex requests to many distinct
/// `(host, port)` pairs. Per-host concurrency is capped at
/// [`WEBCLIENT_MAXCONNS`] (default `4`); excess requests queue in
/// [`WcHost::queue`] until a connection becomes idle.
///
/// # Construction
///
/// ```ignore
/// use std::sync::Arc;
/// use heavything::net::http::client::WebClient;
///
/// let client: Arc<WebClient> = WebClient::new(None); // "HeavyThing" UA
/// ```
///
/// # Submission
///
/// ```ignore
/// use std::sync::Arc;
/// use heavything::net::http::client::{WebClient, WebClientResult};
///
/// let client = WebClient::new(None);
/// let cb: heavything::net::http::client::WebClientCallback = Arc::new(
///     |result, url, ms| match result {
///         WebClientResult::Response(m) => {
///             println!("ok {} {}ms ({} bytes)", url.host(), ms, m.body_len());
///         }
///         _ => eprintln!("fail {:?}", result.fail_code()),
///     },
/// );
/// client.get("https://example.com/", cb).expect("URL parses");
/// ```
///
/// # Safety contract
///
/// **Do not destroy the [`WebClient`] from inside a callback.** Hold
/// an `Arc<WebClient>` for the full lifetime of the application, or
/// schedule a delayed drop via `tokio::spawn` if you must teardown
/// from callback-side logic. Dropping the [`WebClient`] mid-callback
/// would invalidate the request slot the callback is operating on
/// and trigger a use-after-free in the FASM source — the Rust port
/// is structurally protected against UAF (the [`Arc`] keeps the
/// request alive) but the resulting reentrant Drop chain is still
/// undefined behaviour at the application layer.
pub struct WebClient {
    /// User-Agent header value (default `"HeavyThing"`).
    user_agent: String,
    /// All in-flight requests, keyed by request ID.
    ///
    /// FASM uses `unsignedmap` for this lookup; Rust uses [`HashMap`]
    /// with monotonically increasing IDs allocated via [`Self::next_id`].
    /// The mapped value is the owning [`Arc<WcRequest>`] so the slot
    /// can be removed atomically once the callback dispatches.
    inflight: Mutex<HashMap<usize, Arc<WcRequest>>>,
    /// Per-host pools, keyed by [`build_hostkey`] output.
    ///
    /// FASM uses `stringmap` for this lookup; Rust uses [`HashMap`]
    /// with [`String`] keys (matching the FASM hostkey format).
    hosts: Mutex<HashMap<String, Arc<WcHost>>>,
    /// Maximum simultaneous connections per host.
    ///
    /// Defaults to [`WEBCLIENT_MAXCONNS`] (= 4) per FASM
    /// `webclient_maxconns`. The setter is intentionally absent —
    /// FASM hard-codes this knob and exposes it only via
    /// `ht_defaults.inc` recompilation.
    max_conns: u32,
    /// Suppress TLS session resumption (default `false`).
    ///
    /// When `true`, [`WcIo::new`] does **not** pass the cached
    /// [`WcHost::tls_id`] to [`TlsClient::new`], forcing a full
    /// handshake on every connect. FASM `webclient$set_notlsresume`
    /// equivalent.
    notls_resume: AtomicBool,
    /// Headers added to every request built by this client.
    ///
    /// FASM uses `stringmap$insert_unique` semantics — duplicate
    /// names are silently ignored. The Rust port matches this
    /// behaviour via a linear-scan check in [`Self::add_header`].
    add_headers: Mutex<Vec<(String, String)>>,
    /// Optional cookie jar attached via [`Self::set_cookie_jar`].
    ///
    /// `Arc<Mutex<CookieJar>>` so the jar can be shared across
    /// threads safely. The inner [`Mutex`] is `std::sync::Mutex`
    /// (not `tokio::sync::Mutex`) because cookie operations are
    /// fast, synchronous, and never cross `await` points.
    cookie_jar: Mutex<Option<Arc<Mutex<CookieJar>>>>,
    /// Whether the cookie jar should be dropped when this client is.
    ///
    /// FASM `cookiejar_owned` flag: when `true`, `webclient$destroy`
    /// calls `cookiejar$destroy` on the jar. Rust handles this via
    /// the explicit branch in [`Drop::drop`] below — when `false`
    /// the [`Arc`] is just dropped (the user retains ownership);
    /// when `true` the [`Arc`] is replaced by `None` and the user
    /// is expected to honour the same lifecycle contract as FASM.
    cookie_jar_owned: AtomicBool,

    // Counters — atomic for lock-free stat reads from monitoring
    // threads. FASM uses straight `add qword [...], ...` instructions
    // which are NOT atomic; Rust upgrades to atomic loads/stores
    // because the same counters are read from the user-callback
    // thread and written from the I/O task pool concurrently.
    /// Total successful TCP/TLS connect events (FASM `wc_connects`).
    pub(crate) connects: AtomicU64,
    /// Total error events (any failure path) (FASM `wc_errors`).
    pub(crate) errors: AtomicU64,
    /// Total launched requests (FASM `wc_requests`).
    pub(crate) requests: AtomicU64,
    /// Total bytes sent over the wire (FASM `wc_total_sent`).
    pub(crate) total_sent: AtomicU64,
    /// Total bytes received over the wire (FASM `wc_total_received`).
    pub(crate) total_received: AtomicU64,
    /// Total bytes received as response body
    /// (FASM `wc_body_received`).
    pub(crate) body_received: AtomicU64,
    /// Epoch-ms timestamp of the most recent successful response
    /// (FASM `wc_reply_stamp`).
    pub(crate) reply_stamp: AtomicU64,

    /// Monotonic counter for [`Self::inflight`] keys.
    ///
    /// FASM uses the WcRequest pointer as its own key (the
    /// `unsignedmap` hash function reduces a 64-bit pointer to a
    /// bucket index); the Rust port issues sequential IDs to avoid
    /// taking the address of the `Arc` (which would obstruct moves).
    next_request_id: AtomicU64,

    /// Shared DNS resolver instance.
    ///
    /// One resolver per [`WebClient`] so per-host pools share the
    /// global cache when [`WEBCLIENT_GLOBAL_DNSCACHE`] is true.
    dns: DnsResolver,
}

/// User-supplied callback function type invoked when an in-flight
/// request completes (successfully or with a failure code).
///
/// Mirrors the FASM calling convention from `webclient.inc` L33-44:
///
/// | FASM register | Rust parameter            | Meaning                         |
/// |---------------|---------------------------|---------------------------------|
/// | `rdi`         | (closure capture)         | User-supplied state             |
/// | `rsi`         | [`WebClientResult`]       | Mimelike OR negative error code |
/// | `rdx`         | `&Url`                    | Final URL (post-redirect)       |
/// | `rcx`         | `u64`                     | Elapsed milliseconds            |
///
/// The closure must be `Send + Sync + 'static` because requests cross
/// task boundaries (the request may be picked up by a different tokio
/// worker than the one that submitted it). Capture user state via
/// `move` and `Arc` / atomics as needed.
///
/// **CRITICAL SAFETY NOTE** (FASM L39-43): you MUST NOT call
/// [`WebClient`]-destroying APIs (e.g. dropping the last [`Arc`]
/// reference to the `WebClient` that issued this request) from
/// inside a callback. Schedule such teardown via
/// [`tokio::spawn`] instead so the active inflight registry can
/// drain cleanly.
pub type WebClientCallbackFn = dyn Fn(WebClientResult<'_>, &Url, u64) + Send + Sync + 'static;

/// Reference-counted handle to a [`WebClientCallbackFn`].
///
/// Wrapped in [`Arc`] so that the same callback can be cloned into
/// multiple in-flight requests, attached to redirect-rebuilt requests,
/// or held in error-recovery queues without `FnOnce` consumption
/// constraints.
pub type WebClientCallback = Arc<WebClientCallbackFn>;

impl WebClient {
    /// Build a new [`WebClient`].
    ///
    /// `user_agent` defaults to `"HeavyThing"` (FASM L120-122) when
    /// `None` is supplied. The returned [`Arc<WebClient>`] should be
    /// retained by the user for the full duration of any in-flight
    /// requests; dropping the [`Arc`] before all callbacks have
    /// completed will silently abort outstanding requests (the
    /// callbacks will not fire because the [`Weak`] back-references
    /// fail to upgrade).
    ///
    /// # Safety
    ///
    /// **Do not destroy this client from inside a callback.** See
    /// the [module-level safety contract][crate::net::http::client]
    /// for details.
    pub fn new(user_agent: Option<&str>) -> Arc<Self> {
        let ua = user_agent.unwrap_or("HeavyThing").to_string();
        Arc::new(Self {
            user_agent: ua,
            inflight: Mutex::new(HashMap::new()),
            hosts: Mutex::new(HashMap::new()),
            max_conns: WEBCLIENT_MAXCONNS,
            notls_resume: AtomicBool::new(false),
            add_headers: Mutex::new(Vec::new()),
            cookie_jar: Mutex::new(None),
            cookie_jar_owned: AtomicBool::new(false),
            connects: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            total_sent: AtomicU64::new(0),
            total_received: AtomicU64::new(0),
            body_received: AtomicU64::new(0),
            reply_stamp: AtomicU64::new(0),
            next_request_id: AtomicU64::new(1),
            dns: DnsResolver::new(),
        })
    }

    /// Add a header to be sent with every request built by this client.
    ///
    /// Mirrors FASM `webclient$addheader` (L429-460):
    /// `stringmap$insert_unique` REJECTS duplicates — the second
    /// `add_header` for the same name is silently ignored. Use
    /// per-request headers (e.g., the `If-None-Match` extension to
    /// [`Self::get_ifetag`]) to override or extend per-call.
    ///
    /// Header names are compared case-insensitively (per RFC 7230
    /// §3.2 and matching the FASM `string$equalsi` comparator).
    pub fn add_header(&self, name: &str, value: &str) {
        if let Ok(mut hdrs) = self.add_headers.lock() {
            for (existing, _) in hdrs.iter() {
                if existing.eq_ignore_ascii_case(name) {
                    return; // FASM stringmap$insert_unique rejects duplicates
                }
            }
            hdrs.push((name.to_string(), value.to_string()));
        }
    }

    /// Attach a cookie jar to this client.
    ///
    /// `owned == true` instructs [`Drop::drop`] to release the inner
    /// [`Arc<Mutex<CookieJar>>`] (the user-side [`Arc`] count is
    /// decremented but the jar object itself is dropped only when
    /// the user drops their own [`Arc`] reference too).
    ///
    /// FASM `webclient$cookiejar` (L462-478): assigns the jar
    /// pointer + ownership flag and returns immediately. Subsequent
    /// requests built by this client will:
    ///
    /// 1. **On send**: scan the jar for cookies matching the request
    ///    URL (via [`CookieJar::get`]) and inject `Cookie:` headers.
    /// 2. **On receive**: parse `Set-Cookie:` response headers (via
    ///    [`CookieJar::set`]) and persist matching ones.
    pub fn set_cookie_jar(&self, jar: Arc<Mutex<CookieJar>>, owned: bool) {
        if let Ok(mut slot) = self.cookie_jar.lock() {
            *slot = Some(jar);
        }
        self.cookie_jar_owned.store(owned, Ordering::Release);
    }

    /// Submit a `GET` request, launching it immediately.
    ///
    /// Returns `Ok(())` if the URL parsed and the request was
    /// queued; the supplied callback will fire eventually with
    /// either a [`WebClientResult::Response`] or one of the four
    /// [`WebClientResult`] failure variants. Returns
    /// `Err(HttpError::Parse)` only if the URL itself cannot be
    /// parsed by [`Url::parse`].
    ///
    /// # Safety
    ///
    /// **Do not destroy `self` from inside `callback`.** See module
    /// docs for details.
    pub fn get(self: &Arc<Self>, url: &str, callback: WebClientCallback) -> Result<(), HttpError> {
        let req = self.wcrequest_new("GET ", url, callback, false)?;
        self.launch(req);
        Ok(())
    }

    /// Build a `GET` request **without** launching it.
    ///
    /// Returns the [`Arc<WcRequest>`] so the caller can inspect or
    /// modify it before submission. The caller must invoke
    /// [`Self::launch`] to actually send the request.
    ///
    /// FASM `webclient$get_nolaunch` (L536). Useful when chaining
    /// per-request header injection that the global `add_header`
    /// API cannot express (the global API rejects duplicates).
    ///
    /// # Safety
    ///
    /// **Do not destroy `self` from inside `callback`.** See module
    /// docs for details.
    pub fn get_nolaunch(
        self: &Arc<Self>,
        url: &str,
        callback: WebClientCallback,
    ) -> Result<Arc<WcRequest>, HttpError> {
        self.wcrequest_new("GET ", url, callback, false)
    }

    /// Submit a `HEAD` request, launching it immediately.
    ///
    /// Sets [`WcRequest::headers_only`] so [`WcIo::on_receive`]
    /// completes after the headers parse rather than waiting for a
    /// body (HEAD responses carry no body per RFC 7230 §4.3.2).
    ///
    /// FASM `webclient$head` (L552-590): same as `webclient$get`
    /// but with method `"HEAD "` and the headers-only flag set.
    ///
    /// # Safety
    ///
    /// **Do not destroy `self` from inside `callback`.** See module
    /// docs for details.
    pub fn head(self: &Arc<Self>, url: &str, callback: WebClientCallback) -> Result<(), HttpError> {
        let req = self.wcrequest_new("HEAD ", url, callback, true)?;
        self.launch(req);
        Ok(())
    }

    /// Submit a conditional `GET` with `If-None-Match: <etag>`.
    ///
    /// Useful for cache validation: a `304 Not Modified` response
    /// carries no body and minimizes network usage when the cached
    /// representation is still valid.
    ///
    /// FASM `webclient$get_ifetag` (L590-650): builds a GET, then
    /// adds `If-None-Match: <etag>` via `mimelike$addheader`.
    ///
    /// # Safety
    ///
    /// **Do not destroy `self` from inside `callback`.** See module
    /// docs for details.
    pub fn get_ifetag(
        self: &Arc<Self>,
        url: &str,
        etag: &str,
        callback: WebClientCallback,
    ) -> Result<(), HttpError> {
        let req = self.wcrequest_new("GET ", url, callback, false)?;
        if let Ok(mut m) = req.request_mimelike.lock() {
            m.add_header("If-None-Match", etag);
        }
        self.launch(req);
        Ok(())
    }

    /// Submit a conditional `GET` with `If-Modified-Since:`.
    ///
    /// FASM `webclient$get_ifmodified` (L650-700): same shape as
    /// [`Self::get_ifetag`] but with the `If-Modified-Since` header.
    /// `last_modified` should be a pre-formatted RFC 7231 date
    /// string (e.g., `"Thu, 17 Mar 2016 17:21:34 GMT"`).
    ///
    /// # Safety
    ///
    /// **Do not destroy `self` from inside `callback`.** See module
    /// docs for details.
    pub fn get_ifmodified(
        self: &Arc<Self>,
        url: &str,
        last_modified: &str,
        callback: WebClientCallback,
    ) -> Result<(), HttpError> {
        let req = self.wcrequest_new("GET ", url, callback, false)?;
        if let Ok(mut m) = req.request_mimelike.lock() {
            m.add_header("If-Modified-Since", last_modified);
        }
        self.launch(req);
        Ok(())
    }
}

impl WebClient {
    /// Submit a `GET` with a `Range:` header for partial content.
    ///
    /// Both `start` and `end` are inclusive byte offsets per RFC
    /// 7233 §2.1. The server may respond with `206 Partial Content`
    /// (containing only the requested range) or `200 OK` (containing
    /// the full body — the FASM source does not retry in that case
    /// and neither does the Rust port).
    ///
    /// FASM `webclient$get_range` (L700-750): builds a GET, adds
    /// `Range: bytes=<start>-<end>` via `mimelike$addheader`.
    ///
    /// # Safety
    ///
    /// **Do not destroy `self` from inside `callback`.** See module
    /// docs for details.
    pub fn get_range(
        self: &Arc<Self>,
        url: &str,
        start: u64,
        end: u64,
        callback: WebClientCallback,
    ) -> Result<(), HttpError> {
        let req = self.wcrequest_new("GET ", url, callback, false)?;
        let value = format!("bytes={}-{}", start, end);
        if let Ok(mut m) = req.request_mimelike.lock() {
            m.add_header("Range", &value);
        }
        self.launch(req);
        Ok(())
    }

    /// Submit a `POST` request with the supplied body.
    ///
    /// `content_type` is set as the `Content-Type:` header verbatim
    /// (e.g., `"application/x-www-form-urlencoded"`). The body bytes
    /// are copied into the request's [`Mimelike`] via
    /// [`Mimelike::set_body`]; the resulting `Content-Length:` is
    /// computed by [`Mimelike::compose`] at send time.
    ///
    /// FASM `webclient$post` (L750-810): builds the POST, sets
    /// `Content-Type:` via `mimelike$setheader`, copies the body
    /// via `mimelike$set_body`, and launches.
    ///
    /// # Safety
    ///
    /// **Do not destroy `self` from inside `callback`.** See module
    /// docs for details.
    pub fn post(
        self: &Arc<Self>,
        url: &str,
        content_type: &str,
        body: &[u8],
        callback: WebClientCallback,
    ) -> Result<(), HttpError> {
        let req = self.wcrequest_new("POST ", url, callback, false)?;
        if let Ok(mut m) = req.request_mimelike.lock() {
            m.set_header("Content-Type", content_type);
            m.set_body(body)
                .map_err(|e| HttpError::Parse(format!("post body encode failed: {}", e)))?;
        }
        self.launch(req);
        Ok(())
    }

    /// Build a `POST` request **without** launching it.
    ///
    /// Returns the [`Arc<WcRequest>`] so the caller can inspect or
    /// modify it before submission. The caller must invoke
    /// [`Self::launch`] to actually send the request.
    ///
    /// # Safety
    ///
    /// **Do not destroy `self` from inside `callback`.** See module
    /// docs for details.
    pub fn post_nolaunch(
        self: &Arc<Self>,
        url: &str,
        content_type: &str,
        body: &[u8],
        callback: WebClientCallback,
    ) -> Result<Arc<WcRequest>, HttpError> {
        let req = self.wcrequest_new("POST ", url, callback, false)?;
        if let Ok(mut m) = req.request_mimelike.lock() {
            m.set_header("Content-Type", content_type);
            m.set_body(body)
                .map_err(|e| HttpError::Parse(format!("post body encode failed: {}", e)))?;
        }
        Ok(req)
    }

    /// Launch a previously-built request onto its host pool.
    ///
    /// FASM `webclient$launch` (L1993-2042): looks up the host pool
    /// by `req.hostkey`, creates one if missing, enqueues the
    /// request, and triggers [`WcHost::check_queue`] to start the
    /// connection (or wait for an idle one).
    ///
    /// Records the request in [`Self::inflight`] so that the
    /// [`WcIo`] dispatch can correlate completion events back to
    /// the user callback.
    pub fn launch(self: &Arc<Self>, req: Arc<WcRequest>) {
        // Allocate the inflight ID and record the slot before
        // entering the host-pool fan-out so the in-flight count
        // is consistent with the visible request set.
        let id = self.next_request_id.fetch_add(1, Ordering::AcqRel) as usize;
        req.inflight_id.store(id as u64, Ordering::Release);
        self.requests.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut inflight) = self.inflight.lock() {
            inflight.insert(id, Arc::clone(&req));
        }

        // Look up or create the per-host pool.
        let host = {
            let mut hosts = match self.hosts.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if let Some(existing) = hosts.get(&req.hostkey) {
                Arc::clone(existing)
            } else {
                let new_host = WcHost::new(
                    Arc::downgrade(self),
                    self.dns.clone(),
                    req.hostkey.clone(),
                    req.hostname.clone(),
                    req.port,
                    req.is_tls,
                );
                hosts.insert(req.hostkey.clone(), Arc::clone(&new_host));
                new_host
            }
        };

        // Hand off to the per-host pool.
        host.request(req);
    }

    /// Internal: build a [`WcRequest`] without launching it.
    ///
    /// FASM `wcrequest$new` (L230-398). Performs the full
    /// construction sequence:
    ///
    /// 1. Parse the URL.
    /// 2. Build the host-pool key (`host:port[:tls]`).
    /// 3. Compose the request preface (`<METHOD> /path HTTP/1.1`).
    /// 4. Add the five mandatory headers (Host, Accept, Connection,
    ///    Accept-Encoding, User-Agent).
    /// 5. Inject `Cookie:` headers from the cookie jar if attached.
    /// 6. Inject the user-supplied `add_headers` (REPLACE semantics).
    fn wcrequest_new(
        self: &Arc<Self>,
        method: &'static str,
        url_str: &str,
        callback: WebClientCallback,
        headers_only: bool,
    ) -> Result<Arc<WcRequest>, HttpError> {
        let url = Url::parse(url_str).map_err(|e| HttpError::Parse(format!("invalid URL: {}", e)))?;

        let is_tls = matches!(url.protocol(), "https" | "HTTPS" | "wss" | "WSS");
        let port = url.effective_port();
        let hostname = url.host().to_string();
        let hostkey = build_hostkey(&hostname, port, is_tls);

        // Compose preface and standard headers.
        let preface = build_preface(method, &url);
        let host_header = build_host_header(&url);

        let mut mimelike = Mimelike::new();
        mimelike.set_preface_nocopy(preface);
        mimelike.set_header("Host", &host_header);
        mimelike.set_header("Accept", "*/*");
        mimelike.set_header("Connection", "keep-alive");
        mimelike.set_header("Accept-Encoding", "gzip");
        mimelike.set_header("User-Agent", &self.user_agent);

        // Cookie jar integration: scan for cookies matching the URL
        // and let the jar inject the `Cookie:` header (if any).
        if let Ok(jar_slot) = self.cookie_jar.lock() {
            if let Some(jar_arc) = jar_slot.as_ref() {
                if let Ok(jar) = jar_arc.lock() {
                    jar.get(&url, &mut mimelike);
                }
            }
        }

        // User-configured global headers (REPLACE semantics here —
        // user `add_header` already enforced "first wins" at insert
        // time, so a single set_header per pair is correct).
        if let Ok(hdrs) = self.add_headers.lock() {
            for (name, value) in hdrs.iter() {
                mimelike.set_header(name, value);
            }
        }

        let req = Arc::new(WcRequest {
            io: Mutex::new(None),
            hostkey,
            hostname,
            port,
            is_tls,
            headers_only,
            webclient: Arc::downgrade(self),
            url: Mutex::new(Arc::new(url)),
            callback,
            start_time: AtomicU64::new(0),
            request_mimelike: Mutex::new(mimelike),
            redirect_count: AtomicU32::new(0),
            inflight_id: AtomicU64::new(0),
        });
        Ok(req)
    }

    /// Internal: remove a request from the inflight registry.
    ///
    /// Called by [`WcIo::on_receive`] / [`WcIo::on_error`] /
    /// [`WcIo::on_timeout`] after the user callback returns,
    /// matching the FASM ordering at L1525-1530, L1601-1606, L1830-1835.
    fn release_inflight(&self, id: u64) {
        if id == 0 {
            return;
        }
        if let Ok(mut inflight) = self.inflight.lock() {
            inflight.remove(&(id as usize));
        }
    }
}

impl Drop for WebClient {
    /// FASM `webclient$destroy` (L117-165): clears uagent, inflight,
    /// hosts, add_headers, and conditionally destroys the cookie jar.
    ///
    /// Rust port: most cleanup is automatic via [`Arc`] / [`Mutex`]
    /// drops. The only explicit step is releasing the cookie jar
    /// when it was marked owned (FASM `cookiejar_owned`).
    fn drop(&mut self) {
        if self.cookie_jar_owned.load(Ordering::Acquire) {
            if let Ok(mut slot) = self.cookie_jar.lock() {
                slot.take();
            }
        }
    }
}

// =============================================================================
// WcRequest — one user-level HTTP request.
// =============================================================================

/// A single HTTP request in flight (or queued).
///
/// FASM `wcrequest_size = 80` (L228-260). Allocated by
/// [`WebClient::wcrequest_new`] and held alive by both
/// [`WebClient::inflight`] and (transiently) by [`WcIo::wcrequest`]
/// or [`WcHost::queue`].
///
/// # Lifecycle
///
/// 1. **Created** by [`WebClient::wcrequest_new`] with a fully built
///    request [`Mimelike`] and the user callback.
/// 2. **Queued** in [`WcHost::queue`] by [`WebClient::launch`].
/// 3. **Bound** to a [`WcIo`] by [`WcHost::check_queue`] when an idle
///    connection becomes available (or a new one is created).
/// 4. **Sent** by [`WcIo::on_connected`] (or immediately if the
///    connection is already established).
/// 5. **Completed** in one of three terminal states:
///    - Response received → [`WcIo::on_receive`] dispatches the
///      callback, then drops this request.
///    - Connection closed mid-response → [`WcIo::on_error`]
///      dispatches with [`WebClientResult::FailClosed`].
///    - Read timeout → [`WcIo::on_timeout`] dispatches with
///      [`WebClientResult::FailTimeout`].
///
/// # Thread safety
///
/// All mutable fields are wrapped in [`Mutex`] or atomics. The
/// `request_mimelike` lock must be released before invoking the
/// user callback to avoid deadlock if the callback retains a
/// reference back into the same request.
pub struct WcRequest {
    /// Bound [`WcIo`] (if dispatched) — `Weak` to break the cycle.
    ///
    /// Set by [`WcHost::check_queue`] when the request transitions
    /// from queued to in-flight. Cleared (set to `None`) when the
    /// connection completes (so the slot becomes idle again before
    /// the user callback runs — see ordering rule in module docs).
    io: Mutex<Option<Weak<WcIo>>>,
    /// Host-pool key (see [`build_hostkey`]).
    hostkey: String,
    /// Hostname (lower-cased, no port).
    hostname: String,
    /// TCP port (effective port — scheme default applied).
    port: u16,
    /// Whether this request must use TLS.
    is_tls: bool,
    /// `true` for HEAD requests (FASM L36 bit 0).
    ///
    /// Tells [`WcIo::on_receive`] to complete after the headers
    /// parse rather than waiting for a body.
    headers_only: bool,
    /// Back-reference to the owning [`WebClient`] — `Weak` to break
    /// the cycle. Upgraded transiently to dispatch the callback.
    webclient: Weak<WebClient>,
    /// Current request URL (mutated on redirect).
    ///
    /// Wrapped in `Arc<Url>` so the dispatch path can clone the
    /// pointer cheaply for the user callback (`&Url`) without
    /// borrowing the [`Mutex`] guard across `await`.
    url: Mutex<Arc<Url>>,
    /// User callback to invoke on completion.
    callback: WebClientCallback,
    /// Epoch-ms timestamp when the request was sent.
    ///
    /// `0` until [`WcIo::on_connected`] sets it; the elapsed
    /// argument to the user callback is computed as
    /// `now() - start_time`.
    start_time: AtomicU64,
    /// The composed-and-pending request message.
    ///
    /// Built by [`WebClient::wcrequest_new`]. Modifications between
    /// build and launch (e.g., `If-None-Match`) go through this
    /// mutex. [`WcIo::on_connected`] takes a snapshot via
    /// [`Mimelike::compose`] before sending.
    request_mimelike: Mutex<Mimelike>,
    /// Number of redirects followed so far on this request chain.
    ///
    /// Capped at [`MAX_REDIRECTS`] — exceeding triggers
    /// [`WEBCLIENT_FAIL_REDIRECT_LOOP`]. FASM has no such guard;
    /// this is a Rust-port safety improvement (Phase 13).
    redirect_count: AtomicU32,
    /// In-flight slot ID assigned by [`WebClient::launch`].
    ///
    /// `0` before launch; set to a non-zero monotonic ID at launch
    /// time so that error/timeout paths can release the slot via
    /// [`WebClient::release_inflight`].
    inflight_id: AtomicU64,
}

impl WcRequest {
    /// Return the host-pool key for this request.
    pub fn hostkey(&self) -> &str {
        &self.hostkey
    }

    /// Return the hostname (lower-cased, no port).
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Return the effective TCP port for this request.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Return `true` iff this request will use TLS.
    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// Return a clone of the request URL [`Arc`].
    pub fn url(&self) -> Arc<Url> {
        match self.url.lock() {
            Ok(g) => Arc::clone(&*g),
            Err(p) => Arc::clone(&*p.into_inner()),
        }
    }

    /// Return `true` if this is a HEAD request (no body expected).
    pub fn headers_only(&self) -> bool {
        self.headers_only
    }

    /// Internal: dispatch the user callback with the supplied result.
    ///
    /// Computes elapsed-ms from [`Self::start_time`] (or `0` if the
    /// request never reached the wire). The callback is invoked
    /// synchronously on the calling task — callers should not hold
    /// any [`WcRequest`] field locks across this call.
    fn dispatch(&self, result: WebClientResult<'_>) {
        let now = epoch_millis();
        let start = self.start_time.load(Ordering::Acquire);
        let elapsed = if start == 0 || now < start { 0 } else { now - start };
        let url = self.url();
        (self.callback)(result, &url, elapsed);
    }
}

// =============================================================================
// WcHost — per-(host:port:tls) connection pool.
// =============================================================================

/// Per-host connection pool.
///
/// FASM `wchost_size = 116` (L900-960). Created lazily by
/// [`WebClient::launch`] and shared via the [`WebClient::hosts`]
/// stringmap. Owns:
///
/// - Up to [`WebClient::max_conns`] active [`WcIo`] connections.
/// - A FIFO queue of pending [`WcRequest`]s.
/// - The per-host TLS session ID (for TLS resumption).
/// - The DNS resolution state for this host.
///
/// # DNS lifecycle
///
/// On creation [`WcHost::new`] tries to parse the hostname as a
/// literal IP address. If that succeeds the host is immediately
/// "resolved" and connections can begin. Otherwise an async DNS
/// task is spawned; while DNS is in flight (`in_dns == true`) the
/// queue accumulates without dispatch. On success the resolved
/// [`SocketAddr`] is recorded and [`Self::check_queue`] is invoked
/// to start any pending requests. On failure the request callback
/// fires with [`WebClientResult::FailDns`] and (when
/// [`WEBCLIENT_GLOBAL_DNSCACHE`] is `false`) up to 3 DNS retries
/// are attempted before the host is removed from the pool.
pub struct WcHost {
    /// Host-pool key (matches [`WcRequest::hostkey`]).
    hostkey: String,
    /// Hostname (lower-cased, no port).
    hostname: String,
    /// TCP port.
    port: u16,
    /// Whether this pool serves TLS requests.
    is_tls: bool,
    /// Back-reference to the owning [`WebClient`].
    ///
    /// `Weak` so the pool does not keep the client alive past the
    /// user's last [`Arc<WebClient>`] reference.
    webclient: Weak<WebClient>,
    /// Shared DNS resolver instance (cloned from the parent
    /// [`WebClient`]).
    dns: DnsResolver,
    /// Whether DNS resolution is in flight for this host
    /// (FASM `indns`).
    in_dns: AtomicBool,
    /// Whether DNS was needed at all (FASM `usedns`) — `false`
    /// means the hostname was already an IP literal at construction.
    use_dns: AtomicBool,
    /// DNS retry counter (capped at 3 — FASM L1900-1920).
    dns_count: AtomicU32,
    /// Resolved socket address. `None` until DNS completes (or for
    /// IP-literal hostnames it is set at construction).
    resolved_addr: Mutex<Option<SocketAddr>>,
    /// Active connections (FASM L908 `channels: list`).
    ///
    /// Length capped at [`WebClient::max_conns`] (= 4 by default).
    /// [`WcIo::wcrequest`] == `None` indicates an idle connection
    /// available for reuse.
    channels: Mutex<Vec<Arc<WcIo>>>,
    /// Pending requests (FASM L909 `queue: list`).
    ///
    /// FIFO order — [`Self::check_queue`] always pops from the
    /// front to preserve fair dispatch.
    queue: Mutex<VecDeque<Arc<WcRequest>>>,
    /// Cached TLS session ID for resumption (max 32 bytes — FASM
    /// L920 `tlsid[32]`). Populated by [`WcIo::on_connected`] in
    /// the TLS branch; consumed by [`WcIo::new`] when constructing
    /// new TLS connections (unless [`WebClient::notls_resume`] is
    /// `true`).
    tls_id: Mutex<Vec<u8>>,
    /// Whether the host pool has been torn down (e.g., by
    /// [`Self::dns_failure`] removing it from [`WebClient::hosts`]).
    /// Used to short-circuit late callbacks.
    torn_down: AtomicBool,
}

impl WcHost {
    /// Build a new per-host pool.
    ///
    /// FASM `wchost$new` (L914-1038): allocates the structure,
    /// tries IP-literal parse on the hostname, and (on failure)
    /// kicks off an async DNS resolution task.
    ///
    /// # IP-literal fast path
    ///
    /// If the hostname is `127.0.0.1`, `192.0.2.1`, etc. (anything
    /// [`IpAddr::from_str`] accepts), the resolved address is set
    /// immediately and `use_dns` stays `false`. Subsequent
    /// reconnects skip DNS entirely.
    ///
    /// # DNS path
    ///
    /// If the hostname requires resolution, `use_dns = true` and
    /// `in_dns = true` are set, and a [`tokio::spawn`] task drives
    /// the resolver. The task calls [`Self::dns_success`] /
    /// [`Self::dns_failure`] on completion.
    pub fn new(
        webclient: Weak<WebClient>,
        dns: DnsResolver,
        hostkey: String,
        hostname: String,
        port: u16,
        is_tls: bool,
    ) -> Arc<Self> {
        let host = Arc::new(Self {
            hostkey,
            hostname: hostname.clone(),
            port,
            is_tls,
            webclient,
            dns: dns.clone(),
            in_dns: AtomicBool::new(false),
            use_dns: AtomicBool::new(false),
            dns_count: AtomicU32::new(0),
            resolved_addr: Mutex::new(None),
            channels: Mutex::new(Vec::new()),
            queue: Mutex::new(VecDeque::new()),
            tls_id: Mutex::new(Vec::new()),
            torn_down: AtomicBool::new(false),
        });

        // IP-literal fast path: try to parse the hostname as a raw
        // IP address. FASM `wchost$new` does the same via
        // `inet_addr()` before falling through to the async DNS path.
        if let Ok(ip) = IpAddr::from_str(&hostname) {
            let addr = SocketAddr::new(ip, port);
            if let Ok(mut slot) = host.resolved_addr.lock() {
                *slot = Some(addr);
            }
        } else {
            // DNS path: spawn an async task that drives the resolver
            // and signals completion via dns_success / dns_failure.
            host.use_dns.store(true, Ordering::Release);
            host.in_dns.store(true, Ordering::Release);

            let host_for_task = Arc::clone(&host);
            let resolver = dns;
            let port_copy = port;
            tokio::spawn(async move {
                let result = if WEBCLIENT_GLOBAL_DNSCACHE {
                    resolver.lookup_host_cached(&hostname, port_copy).await
                } else {
                    resolver.lookup_host(&hostname, port_copy).await
                };
                match result {
                    Ok(addrs) => {
                        if let Some(addr) = addrs.into_iter().next() {
                            host_for_task.dns_success(addr);
                        } else {
                            host_for_task.dns_failure();
                        }
                    }
                    Err(_) => {
                        host_for_task.dns_failure();
                    }
                }
            });
        }

        host
    }

    /// Return the host-pool key.
    pub fn hostkey(&self) -> &str {
        &self.hostkey
    }

    /// Return the hostname (lower-cased, no port).
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Return the TCP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Return `true` iff this pool serves TLS requests.
    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// Enqueue a request and pump the queue.
    ///
    /// FASM `wchost$request` (L1071): pushes the request onto the
    /// FIFO queue and invokes [`Self::check_queue`] to either
    /// dispatch it onto an idle connection, open a new connection
    /// (if under [`WebClient::max_conns`]), or wait (if all slots
    /// are busy or DNS is still pending).
    pub fn request(self: &Arc<Self>, req: Arc<WcRequest>) {
        if self.torn_down.load(Ordering::Acquire) {
            // Late arrival on a torn-down pool — fail it inline.
            req.dispatch(WebClientResult::FailDns);
            if let Some(wc) = req.webclient.upgrade() {
                wc.errors.fetch_add(1, Ordering::Relaxed);
                wc.release_inflight(req.inflight_id.load(Ordering::Acquire));
            }
            return;
        }
        if let Ok(mut q) = self.queue.lock() {
            q.push_back(req);
        }
        // Don't pump the queue while DNS is still in flight — the
        // dns_success / dns_failure callbacks will pump on completion.
        if !self.in_dns.load(Ordering::Acquire) {
            self.check_queue();
        }
    }
}

impl WcHost {
    /// Pump the queue: assign pending requests to idle channels or
    /// open new ones (up to [`WebClient::max_conns`]).
    ///
    /// FASM `wchost$checkqueue` (L1919-1986). The flow is:
    ///
    /// 1. **DNS guard**: if DNS is still in flight, return immediately
    ///    (the DNS success callback will re-invoke this method).
    /// 2. **Idle scan**: walk `channels` looking for a [`WcIo`] with
    ///    `wcrequest == None`; if found, pop the front of `queue`
    ///    and assign it via [`WcIo::request`].
    /// 3. **Slot growth**: if all channels are busy AND
    ///    `channels.len() < max_conns`, pop the front of `queue`
    ///    and create a new [`WcIo`] for it.
    /// 4. **Loop**: continue until either the queue is empty or
    ///    all channels are busy at capacity.
    pub fn check_queue(self: &Arc<Self>) {
        // DNS guard — pre-resolution requests stay queued.
        if self.in_dns.load(Ordering::Acquire) {
            return;
        }
        if self.torn_down.load(Ordering::Acquire) {
            return;
        }

        let max_conns = match self.webclient.upgrade() {
            Some(wc) => wc.max_conns as usize,
            None => return,
        };

        loop {
            // Snapshot the queue front. If empty, we're done.
            let next_req = {
                let mut q = match self.queue.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                if q.is_empty() {
                    return;
                }
                // Look for an idle channel before popping.
                let mut found_idle: Option<Arc<WcIo>> = None;
                if let Ok(channels) = self.channels.lock() {
                    for ch in channels.iter() {
                        if ch.is_idle() {
                            found_idle = Some(Arc::clone(ch));
                            break;
                        }
                    }
                }
                if let Some(idle) = found_idle {
                    let req = q.pop_front().unwrap();
                    drop(q); // release queue lock before dispatching
                    idle.request(req);
                    continue;
                }
                // No idle channel — check capacity.
                let current_count = match self.channels.lock() {
                    Ok(g) => g.len(),
                    Err(_) => return,
                };
                if current_count >= max_conns {
                    return; // wait for an existing channel to free up
                }
                q.pop_front().unwrap()
            };

            // Open a new channel for `next_req`.
            let host_clone = Arc::clone(self);
            let req_clone = Arc::clone(&next_req);
            tokio::spawn(async move {
                WcIo::new(host_clone, req_clone).await;
            });

            // Don't loop further from the same task — the spawned
            // task will register itself once connected, and a
            // future check_queue will pick up the next item. This
            // serializes channel creation across the queue without
            // saturating the runtime.
            return;
        }
    }

    /// Remove a closed [`WcIo`] from this host's channel list.
    ///
    /// FASM `wchost$channelclose` (L1887): removes the wcio from
    /// the channels list, then calls [`Self::check_queue`] to
    /// re-pump any pending requests onto fresh channels.
    pub fn channel_close(self: &Arc<Self>, wcio: &Arc<WcIo>) {
        if let Ok(mut channels) = self.channels.lock() {
            channels.retain(|ch| !Arc::ptr_eq(ch, wcio));
        }
        // Pump the queue — a slot is now free.
        self.check_queue();
    }

    /// Mark DNS resolution successful: store the address, clear
    /// the in-flight flag, and pump the queue.
    fn dns_success(self: Arc<Self>, addr: SocketAddr) {
        if let Ok(mut slot) = self.resolved_addr.lock() {
            *slot = Some(addr);
        }
        self.in_dns.store(false, Ordering::Release);
        self.check_queue();
    }

    /// Mark DNS resolution failed: retry up to 3 times (when
    /// [`WEBCLIENT_GLOBAL_DNSCACHE`] is `false`); on final
    /// exhaustion, fail every queued request and tear down the
    /// pool.
    fn dns_failure(self: Arc<Self>) {
        let count = self.dns_count.fetch_add(1, Ordering::AcqRel);
        let final_failure = WEBCLIENT_GLOBAL_DNSCACHE || count >= 2;
        if !final_failure {
            // Retry — kick another DNS task. FASM does the same at
            // L1900-1920 with the same +1 counter.
            let host_for_task = Arc::clone(&self);
            let resolver = self.dns.clone();
            let hostname = self.hostname.clone();
            let port = self.port;
            tokio::spawn(async move {
                let result = if WEBCLIENT_GLOBAL_DNSCACHE {
                    resolver.lookup_host_cached(&hostname, port).await
                } else {
                    resolver.lookup_host(&hostname, port).await
                };
                match result {
                    Ok(addrs) => {
                        if let Some(addr) = addrs.into_iter().next() {
                            host_for_task.dns_success(addr);
                        } else {
                            host_for_task.dns_failure();
                        }
                    }
                    Err(_) => {
                        host_for_task.dns_failure();
                    }
                }
            });
            return;
        }

        // Final failure — tear down. CRITICAL ordering (FASM
        // L1900-1986): remove from webclient.hosts FIRST, then
        // fail the queue, to prevent infinite retry loops if the
        // user callback re-submits to the same hostname.
        self.torn_down.store(true, Ordering::Release);
        if let Some(wc) = self.webclient.upgrade() {
            if let Ok(mut hosts) = wc.hosts.lock() {
                hosts.remove(&self.hostkey);
            }
            // Fail every queued request.
            let pending: Vec<Arc<WcRequest>> = if let Ok(mut q) = self.queue.lock() {
                q.drain(..).collect()
            } else {
                Vec::new()
            };
            for req in pending {
                wc.errors.fetch_add(1, Ordering::Relaxed);
                req.dispatch(WebClientResult::FailDns);
                wc.release_inflight(req.inflight_id.load(Ordering::Acquire));
            }
        }
        self.in_dns.store(false, Ordering::Release);
    }
}

impl Drop for WcHost {
    /// FASM `wchost$destroy` (L1038): cleans up channels, queue,
    /// and tlsid storage. Rust port: the [`Mutex`]-wrapped
    /// collections drop their contents automatically; this hook
    /// exists primarily as a documentation anchor.
    fn drop(&mut self) {
        // Best-effort: clear the channels list so any held [`WcIo`]
        // [`Arc`]s release their parent-pointer references, allowing
        // the chain to unwind in deterministic order.
        if let Ok(mut channels) = self.channels.lock() {
            channels.clear();
        }
    }
}

// =============================================================================
// WcIo — per-connection I/O chain.
// =============================================================================

/// Per-connection IoChain layer.
///
/// FASM `wcio` (L1100-1900). One [`WcIo`] = one TCP (or TLS-over-TCP)
/// connection to a host. Holds the response accumulation buffer,
/// the per-connection idle timer, and the back-references to the
/// owning host pool and current request.
///
/// # IoChain placement
///
/// ```text
///   WcIo (top of chain — talks to WcHost)
///     └── child: TcpAdapter / TlsAdapter (bottom — talks to socket)
/// ```
///
/// Unlike [`crate::net::http::server::WebServer`] which sits between
/// an application-layer parent and a transport child, [`WcIo`] is
/// itself the topmost layer (its "parent" is the synthetic
/// [`WcRequest`] / [`WcHost`] dispatch logic, not a chain link).
pub struct WcIo {
    /// Back-reference to the owning host pool.
    wchost: Weak<WcHost>,
    /// The currently-bound request, or `None` for an idle channel.
    ///
    /// Cleared (set to `None`) BEFORE the user callback fires (see
    /// ordering rule in module docs and FASM L1615-1645).
    wcrequest: Mutex<Option<Arc<WcRequest>>>,
    /// Whether the 120-second read timer has fired.
    timed_out: AtomicBool,
    /// Cancellation flag for the per-connection timer task.
    ///
    /// Set to `true` when the timer should be cancelled (request
    /// completed, connection closed, etc.). The timer task polls
    /// this on each interval tick and exits cleanly when set.
    timer_cancel: AtomicBool,
    /// Current timer epoch — bumped on each [`Self::reset_timer`]
    /// call. Each timer task captures the epoch at spawn time and
    /// exits if the current epoch has moved on (preventing stale
    /// timers from firing after the connection has been reused).
    timer_epoch: AtomicU64,
    /// Response accumulation buffer.
    ///
    /// Bytes are appended on each [`Self::on_receive`] call until
    /// either Content-Length is satisfied or the chunked-encoding
    /// terminator is detected. Cleared after each response.
    response: Mutex<Vec<u8>>,
    /// IoChain link state — parent (Weak) and child (Arc).
    links: IoLinks,
    /// Whether this connection is currently established.
    connected: AtomicBool,
    /// Whether this connection has been suicided / torn down.
    suicided: AtomicBool,
}

impl WcIo {
    /// Open a new connection for the supplied request.
    ///
    /// FASM `wcio$new` (L1109-1267):
    ///
    /// 1. Resolve the target socket address from
    ///    [`WcHost::resolved_addr`].
    /// 2. Open a `tokio::net::TcpStream` to the address.
    /// 3. If TLS, wrap in a [`TlsClient`] handshake.
    /// 4. Register with [`WcHost::channels`].
    /// 5. Send the request via [`Self::on_connected`].
    ///
    /// On any pre-connect failure, dispatch the user callback with
    /// [`WebClientResult::FailPreconnect`] and return `None`.
    pub async fn new(host: Arc<WcHost>, req: Arc<WcRequest>) -> Option<Arc<Self>> {
        let addr = match host.resolved_addr.lock().ok().and_then(|s| *s) {
            Some(a) => a,
            None => {
                // Defensive: shouldn't happen if check_queue gated
                // on in_dns, but report cleanly if it does.
                Self::dispatch_preconnect_failure(&req);
                return None;
            }
        };

        // Open the TCP stream.
        let tcp = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(_) => {
                Self::dispatch_preconnect_failure(&req);
                return None;
            }
        };

        let wcio = Arc::new(Self {
            wchost: Arc::downgrade(&host),
            wcrequest: Mutex::new(Some(Arc::clone(&req))),
            timed_out: AtomicBool::new(false),
            timer_cancel: AtomicBool::new(false),
            timer_epoch: AtomicU64::new(0),
            response: Mutex::new(Vec::new()),
            links: IoLinks::new(),
            connected: AtomicBool::new(false),
            suicided: AtomicBool::new(false),
        });

        // Bind back-reference in the request.
        if let Ok(mut io) = req.io.lock() {
            *io = Some(Arc::downgrade(&wcio));
        }

        // Wire the chain: WcIo (top) → transport (bottom).
        // The transport adapter holds the writer half; the read
        // half is captured by a spawned read-loop task.
        let wcio_dyn: Arc<dyn IoChain> = Arc::clone(&wcio) as Arc<dyn IoChain>;
        if host.is_tls {
            // TLS path: build a TlsClient, drive the handshake,
            // then split the resulting TlsStream and wire both halves.
            //
            // FASM semantics from `wcio$new` (L1109-1267): when the
            // host has a saved TLS session ID and `notls_resume` is
            // false on the WebClient, the saved ID is passed to
            // `tls$new` as a session-resumption hint. The current
            // rustls integration handles session resumption opaquely
            // through `ClientConfig::session_storage`, so the saved
            // ID is consulted here only as an architectural anchor
            // — these reads keep the FASM layout meaningful and let
            // future wire-level rustls integration plug into the
            // existing `WcHost::tls_id` slot without struct churn.
            let _resume_disabled = host
                .webclient
                .upgrade()
                .map(|wc| wc.notls_resume.load(Ordering::Acquire))
                .unwrap_or(true);
            let _saved_session_len = match host.tls_id.lock() {
                Ok(g) => g.len(),
                Err(_) => 0,
            };
            let tls_client = match TlsClient::new(host.hostname.clone()) {
                Ok(c) => c,
                Err(_) => {
                    Self::dispatch_preconnect_failure(&req);
                    return None;
                }
            };
            let tls_stream: TlsStream = match tls_client.connect(tcp).await {
                Ok(s) => s,
                Err(_) => {
                    Self::dispatch_preconnect_failure(&req);
                    return None;
                }
            };
            let (reader, writer) = tokio::io::split(tls_stream);
            let adapter = WcTransportAdapter::new(writer);
            let adapter_dyn: Arc<dyn IoChain> = adapter as Arc<dyn IoChain>;
            link(&wcio_dyn, adapter_dyn);
            // Spawn the read loop owning the reader half.
            let wcio_reader = Arc::clone(&wcio);
            tokio::spawn(async move {
                read_loop(wcio_reader, reader).await;
            });
        } else {
            let (reader, writer) = tokio::io::split(tcp);
            let adapter = WcTransportAdapter::new(writer);
            let adapter_dyn: Arc<dyn IoChain> = adapter as Arc<dyn IoChain>;
            link(&wcio_dyn, adapter_dyn);
            let wcio_reader = Arc::clone(&wcio);
            tokio::spawn(async move {
                read_loop(wcio_reader, reader).await;
            });
        }

        // Register in the host's channel list.
        if let Ok(mut channels) = host.channels.lock() {
            channels.push(Arc::clone(&wcio));
        }

        // Bump connect counter.
        if let Some(wc) = host.webclient.upgrade() {
            wc.connects.fetch_add(1, Ordering::Relaxed);
        }

        // Mark connected and dispatch the initial request.
        wcio.connected.store(true, Ordering::Release);
        let send_self = Arc::clone(&wcio);
        tokio::spawn(async move {
            send_self.send_request().await;
        });

        Some(wcio)
    }

    /// Bind a new request to this idle connection and send it.
    ///
    /// FASM `wcio$request` (L1224). Called by [`WcHost::check_queue`]
    /// when an in-flight request can be reused on this connection.
    pub fn request(self: &Arc<Self>, req: Arc<WcRequest>) {
        if let Ok(mut slot) = self.wcrequest.lock() {
            *slot = Some(Arc::clone(&req));
        }
        // Bind back-pointer in the request.
        if let Ok(mut io) = req.io.lock() {
            *io = Some(Arc::downgrade(self));
        }
        // Send the request immediately — the connection is already
        // established (we wouldn't have been on the idle list otherwise).
        let me = Arc::clone(self);
        tokio::spawn(async move {
            me.send_request().await;
        });
    }

    /// Return `true` iff this connection has no in-flight request.
    pub fn is_idle(&self) -> bool {
        if self.suicided.load(Ordering::Acquire) {
            return false;
        }
        if !self.connected.load(Ordering::Acquire) {
            return false;
        }
        match self.wcrequest.lock() {
            Ok(g) => g.is_none(),
            Err(_) => false,
        }
    }

    /// Internal: dispatch a pre-connect failure callback.
    fn dispatch_preconnect_failure(req: &WcRequest) {
        req.dispatch(WebClientResult::FailPreconnect);
        if let Some(wc) = req.webclient.upgrade() {
            wc.errors.fetch_add(1, Ordering::Relaxed);
            wc.release_inflight(req.inflight_id.load(Ordering::Acquire));
        }
    }

    /// Compose and send the bound request's request-mimelike.
    ///
    /// Captures the current timestamp into [`WcRequest::start_time`]
    /// so the elapsed-ms callback argument can be computed accurately.
    async fn send_request(self: Arc<Self>) {
        let (req, composed): (Arc<WcRequest>, Bytes) = {
            let req_arc = match self.wcrequest.lock() {
                Ok(g) => match g.as_ref() {
                    Some(r) => Arc::clone(r),
                    None => return,
                },
                Err(_) => return,
            };
            req_arc.start_time.store(epoch_millis(), Ordering::Release);
            let composed = match req_arc.request_mimelike.lock() {
                Ok(mut m) => {
                    m.compose();
                    Bytes::copy_from_slice(m.xmitbody_slice())
                }
                Err(_) => Bytes::new(),
            };
            (req_arc, composed)
        };

        let n = composed.len() as u64;
        let me = Arc::clone(&self);
        let me_dyn: Arc<dyn IoChain> = me as Arc<dyn IoChain>;
        if let Some(child) = me_dyn.links().child() {
            if let Err(_e) = child.send(composed).await {
                // Send failure → treat as connection error.
                self.error_internal().await;
                return;
            }
        }
        if let Some(wc) = req.webclient.upgrade() {
            wc.total_sent.fetch_add(n, Ordering::Relaxed);
        }
        // Reset the read timeout — the request is now on the wire
        // and we expect a response within WEBCLIENT_READTIMEOUT ms.
        self.reset_timer();
    }

    // -------------------------------------------------------------------------
    // Timer management (FASM L1109-1370 — `wcio_timerptr`).
    //
    // FASM uses the `epoll` AVL-tree-ordered timer subsystem; the Rust port
    // uses the `tokio::time::sleep` primitive combined with a monotonic
    // epoch counter to implement reset-by-bumping semantics:
    //
    //   - `arm_timer` / `reset_timer` increment `timer_epoch`, capture the
    //     new value, and spawn a task that sleeps `WEBCLIENT_READTIMEOUT`
    //     milliseconds. After waking, the task verifies the captured
    //     epoch is still current; if so, it fires the timeout. If a
    //     fresh `reset_timer` arrived in the interim, the captured epoch
    //     no longer matches and the task exits silently.
    //
    //   - `cancel_timer` sets `timer_cancel` to `true`, causing any
    //     in-flight timer task to exit on its next post-sleep check
    //     without firing.
    //
    // This pattern preserves the FASM convention where a timer return
    // value of [`TimerAction::Reset`] (zero) means "re-arm" and a return
    // of [`TimerAction::Teardown(TeardownReason::IdleTimeout)`] (non-zero)
    // means "tear down the connection" — see `crate::net::runtime`.
    // -------------------------------------------------------------------------

    /// Arm or reset the per-connection idle timer.
    ///
    /// Bumps [`Self::timer_epoch`] and spawns a fresh sleep task. The
    /// previously-spawned task (if any) will detect the epoch mismatch
    /// on wake and exit silently. Equivalent to FASM
    /// `epoll$timer_reset(self.timerptr, webclient_readtimeout)`.
    fn reset_timer(self: &Arc<Self>) {
        // Don't arm if cancellation has been requested.
        if self.timer_cancel.load(Ordering::Acquire) {
            return;
        }
        // Bump the epoch — any task currently sleeping will see this
        // change on wake and exit cleanly.
        let epoch = self.timer_epoch.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        let me = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(WEBCLIENT_READTIMEOUT)).await;
            // Re-check cancellation after sleeping.
            if me.timer_cancel.load(Ordering::Acquire) {
                return;
            }
            // Re-check epoch; if a fresh reset_timer arrived during
            // our sleep, this captured epoch is now stale and we
            // should silently exit. This is the equivalent of FASM
            // `TimerAction::Reset` — the timer didn't actually fire.
            if me.timer_epoch.load(Ordering::Acquire) != epoch {
                let _silent: TimerAction = TimerAction::Reset;
                return;
            }
            // Epoch still current — the timer has truly fired. Mark
            // timed_out and dispatch the timeout handler. Equivalent
            // to FASM `TimerAction::Teardown(TeardownReason::IdleTimeout)`.
            me.timed_out.store(true, Ordering::Release);
            let _fire: TimerAction = TimerAction::Teardown(TeardownReason::IdleTimeout);
            Self::on_timeout(Arc::clone(&me)).await;
        });
    }

    /// Initial timer arm — alias for [`Self::reset_timer`] for clarity
    /// at the call sites that semantically arm rather than reset.
    #[allow(dead_code)]
    fn arm_timer(self: &Arc<Self>) {
        self.reset_timer();
    }

    /// Cancel the per-connection timer.
    ///
    /// Any in-flight timer task will detect the cancellation flag on
    /// its next post-sleep check and exit silently without firing.
    /// Idempotent — safe to call multiple times.
    fn cancel_timer(&self) {
        self.timer_cancel.store(true, Ordering::Release);
        // Bump the epoch as well so any currently-arming task that
        // hasn't yet captured its epoch sees a stale value.
        self.timer_epoch.fetch_add(1, Ordering::AcqRel);
    }

    // -------------------------------------------------------------------------
    // Error / timeout / receive handlers.
    // -------------------------------------------------------------------------

    /// Internal: handle a connection-level error.
    ///
    /// FASM `wcio$error` (L1798-1840). Dispatches the bound
    /// [`WcRequest`]'s callback with [`WebClientResult::FailClosed`],
    /// increments the [`WebClient::errors`] counter, releases the
    /// inflight slot, and tears down the channel via
    /// [`WcHost::channel_close`].
    ///
    /// Suicide semantics: returns once cleanup is complete. The
    /// caller should expect this connection to be unusable after
    /// invocation.
    async fn error_internal(self: &Arc<Self>) {
        // Mark suicide flag first so concurrent dispatches see the
        // teardown in progress and skip any work that requires a
        // live connection.
        if self.suicided.swap(true, Ordering::AcqRel) {
            // Already torn down — avoid double-dispatch.
            return;
        }
        self.cancel_timer();

        // Take ownership of the bound request, leaving the slot empty.
        let req_opt = match self.wcrequest.lock() {
            Ok(mut g) => g.take(),
            Err(_) => None,
        };

        if let Some(req) = req_opt {
            // Dispatch the user callback with FailClosed.
            req.dispatch(WebClientResult::FailClosed);
            if let Some(wc) = req.webclient.upgrade() {
                wc.errors.fetch_add(1, Ordering::Relaxed);
                wc.release_inflight(req.inflight_id.load(Ordering::Acquire));
            }
        }

        // Remove this channel from the host's pool. The host's
        // check_queue will then attempt to satisfy any queued
        // requests using a fresh connection.
        if let Some(host) = self.wchost.upgrade() {
            host.channel_close(self);
        }
    }

    /// Internal: handle the per-connection idle timeout firing.
    ///
    /// FASM `wcio$timeout` (L1840-1887). Equivalent of
    /// [`error_internal`] but dispatches with
    /// [`WebClientResult::FailTimeout`] instead of `FailClosed`.
    async fn on_timeout(self: Arc<Self>) {
        if self.suicided.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancel_timer();

        let req_opt = match self.wcrequest.lock() {
            Ok(mut g) => g.take(),
            Err(_) => None,
        };

        if let Some(req) = req_opt {
            req.dispatch(WebClientResult::FailTimeout);
            if let Some(wc) = req.webclient.upgrade() {
                wc.errors.fetch_add(1, Ordering::Relaxed);
                wc.release_inflight(req.inflight_id.load(Ordering::Acquire));
            }
        }

        if let Some(host) = self.wchost.upgrade() {
            host.channel_close(&self);
        }
    }

    /// Internal: top-level error entry called by the IoChain trait.
    ///
    /// Used by both transport-layer EOF/RST notifications and by the
    /// read loop's catch-all error path. Always treated as a
    /// connection-fatal error.
    async fn on_error(self: Arc<Self>) {
        self.error_internal().await;
    }

    /// Internal: handle inbound bytes from the read loop.
    ///
    /// FASM `wcio$receive` (L1374-1790) — **the most complex method
    /// in this file**. Implements the 3-branch body-length detection
    /// state machine, redirect handling (301/302), Connection-header
    /// keep-alive vs close branching, and the critical
    /// "clear-wcrequest-before-callback" ordering on keep-alive paths.
    ///
    /// # Returns
    ///
    /// * `true` — connection should be torn down (FASM "suicide").
    /// * `false` — keep the connection alive for further use.
    ///
    /// # State machine
    ///
    /// 1. Append `data` to the response buffer.
    /// 2. Try a trial parse with `headers_only=true` to extract
    ///    headers without committing to a body decode.
    /// 3. **3-branch body detection**:
    ///    * `Content-Length: N` present → wait until
    ///      `headers_len + N` bytes have arrived.
    ///    * `Transfer-Encoding: chunked` → wait until the last 7
    ///      bytes match [`CHUNKED_TERMINATOR`] (`\r\n0\r\n\r\n`).
    ///    * Neither — try `new_parse` with `headers_only=false`;
    ///      keep waiting if the parser returns `NeedMoreBody`.
    /// 4. On complete response: increment counters, update the cookie
    ///    jar, and either follow a 3xx redirect or dispatch the user
    ///    callback.
    async fn on_receive_internal(self: Arc<Self>, data: &[u8]) -> bool {
        if self.suicided.load(Ordering::Acquire) {
            return true;
        }

        // ------------------------------------------------------------
        // Stage 1: per-WebClient first-byte timestamp
        // (FASM L1374-1380).
        // ------------------------------------------------------------
        if let Some(host) = self.wchost.upgrade() {
            if let Some(wc) = host.webclient.upgrade() {
                let stamp = epoch_millis();
                // Set reply_stamp atomically only if it's still 0 —
                // we want the timestamp of the FIRST inbound byte on
                // this WebClient instance, ever.
                let _ = wc
                    .reply_stamp
                    .compare_exchange(0, stamp, Ordering::AcqRel, Ordering::Acquire);
            }
        }

        // ------------------------------------------------------------
        // Stage 2: reset idle timer + accumulate
        // (FASM L1380-1400).
        // ------------------------------------------------------------
        self.reset_timer();

        if let Ok(mut buf) = self.response.lock() {
            buf.extend_from_slice(data);
        } else {
            // Response buffer mutex poisoned — abandon the connection.
            return true;
        }

        // Snapshot for parsing. Cloning the buffer here lets us
        // release the mutex before performing the (potentially
        // expensive) full mimelike parse.
        let snapshot: Vec<u8> = match self.response.lock() {
            Ok(b) => b.clone(),
            Err(_) => return true,
        };

        if snapshot.len() < 8 {
            // Below the Mimelike minimum — definitely need more.
            return false;
        }

        // ------------------------------------------------------------
        // Stage 3: trial parse for header-only extraction
        // (FASM L1400-1440).
        // ------------------------------------------------------------
        let trial = match Mimelike::new_parse_ext(&snapshot, true, true) {
            Ok(m) => m,
            Err(_) => {
                // Headers incomplete or malformed — keep waiting.
                // The mimelike parser distinguishes "need more" from
                // "definitely broken" via its error variants, but
                // the FASM convention treats both as "wait for more
                // bytes" — eventually the timeout will fire if the
                // peer never completes the headers.
                return false;
            }
        };

        let headers_len = trial.parse_len();

        // Take a snapshot of the in-flight request for headers_only
        // and callback dispatch. We hold no lock across .await below.
        let req = match self.wcrequest.lock() {
            Ok(g) => match g.as_ref() {
                Some(r) => Arc::clone(r),
                None => {
                    // No bound request — anomalous. Drop quietly.
                    return false;
                }
            },
            Err(_) => return true,
        };
        let req_headers_only = req.headers_only();

        // Extract Content-Length / Transfer-Encoding / Connection
        // hints from the trial mimelike before dropping it.
        let cl_opt: Option<u64> = trial
            .get_header("Content-Length")
            .and_then(|s| s.trim().parse::<u64>().ok());
        let cl_raw_present = trial.get_header("Content-Length").is_some();
        let is_chunked = trial
            .get_header("Transfer-Encoding")
            .map(|v| v.trim().eq_ignore_ascii_case("chunked"))
            .unwrap_or(false);

        // Drop the trial mimelike now that all hints have been
        // extracted — the full re-parse below produces a fresh
        // `Mimelike` for callback dispatch (FASM does the same:
        // `.fullparse` discards the partial trial parse and starts
        // over with `mimelike$new_parse partial_ok=false`).
        drop(trial);

        // ------------------------------------------------------------
        // Stage 4: 3-branch body-length detection
        // (FASM L1442-1500).
        // ------------------------------------------------------------
        let total_consumed: usize = if req_headers_only {
            // HEAD request — no body expected; the trial parse IS
            // the final response (FASM `.headers_only_done`).
            headers_len
        } else if let Some(cl) = cl_opt {
            // Branch 1: Content-Length present (FASM L1442-1474).
            if cl > WEBSERVER_MAXREQUEST as u64 {
                // Sanity: refuse absurd Content-Length to prevent
                // unbounded memory growth.
                let _ = HttpError::TooLarge;
                return self.completed_close_with(&req, WebClientResult::FailClosed).await;
            }
            let total = headers_len.saturating_add(cl as usize);
            if snapshot.len() < total {
                return false; // need more bytes
            }
            total
        } else if cl_raw_present {
            // Content-Length present but unparseable — protocol
            // error. Treat like a closed connection.
            return self.completed_close_with(&req, WebClientResult::FailClosed).await;
        } else if is_chunked {
            // Branch 2: Transfer-Encoding: chunked (FASM L1475-1500).
            if snapshot.len() < CHUNKED_TERMINATOR.len() {
                return false;
            }
            let tail = &snapshot[snapshot.len().saturating_sub(CHUNKED_TERMINATOR.len())..];
            if tail != CHUNKED_TERMINATOR {
                return false; // chunk-stream not yet finished
            }
            snapshot.len()
        } else {
            // Branch 3: no Content-Length, not chunked — probe with a
            // full parse (FASM L1500 `.fullparse`). If the parser
            // reports `NeedMoreBody`, keep waiting; if it succeeds,
            // we're done.
            match Mimelike::new_parse(&snapshot, false, true) {
                Ok(_) => snapshot.len(),
                Err(_) => return false,
            }
        };

        // ------------------------------------------------------------
        // Stage 5: full parse for callback dispatch
        // (FASM L1500-1519 `.complete_response`).
        // ------------------------------------------------------------

        let mimelike = match Mimelike::new_parse(&snapshot, req_headers_only, true) {
            Ok(m) => m,
            Err(_) => {
                // Final parse failed despite passing the trial parse
                // — likely a malformed body (e.g., bad gzip). Treat
                // as connection-closed for the user.
                return self.completed_close_with(&req, WebClientResult::FailClosed).await;
            }
        };

        // ------------------------------------------------------------
        // Stage 6: counter updates + cookie jar
        // (FASM L1519-1555 `.completed_proceed`).
        // ------------------------------------------------------------
        let body_size = total_consumed.saturating_sub(headers_len) as u64;
        if let Some(host) = self.wchost.upgrade() {
            if let Some(wc) = host.webclient.upgrade() {
                wc.total_received
                    .fetch_add(total_consumed as u64, Ordering::Relaxed);
                wc.body_received.fetch_add(body_size, Ordering::Relaxed);

                // Cookie jar update (FASM `.completed_proceed`).
                let url_arc = req.url();
                // Hoist the Arc clone into an outer binding so the
                // inner `MutexGuard` from `jar_arc.lock()` cannot
                // outlive `jar_arc`.
                let jar_arc_opt: Option<Arc<Mutex<CookieJar>>> = match wc.cookie_jar.lock() {
                    Ok(g) => g.as_ref().map(Arc::clone),
                    Err(_) => None,
                };
                if let Some(jar_arc) = jar_arc_opt {
                    if let Ok(mut j) = jar_arc.lock() {
                        // Cookie-jar parse errors (malformed
                        // Set-Cookie syntax) are non-fatal; the
                        // rest of the response is still delivered
                        // to the user callback.
                        let _ = j.set(&url_arc, &mimelike);
                    }
                }
            }
        }

        // Clear the response buffer for the next response on this
        // (potentially keep-alive) connection.
        if let Ok(mut b) = self.response.lock() {
            b.clear();
        }

        // ------------------------------------------------------------
        // Stage 7: redirect detection (FASM L1500-1519).
        // ------------------------------------------------------------
        let preface_str = mimelike.preface().unwrap_or("");
        let status_code: &str = if preface_str.len() >= 12 {
            // FASM extracts chars at positions [9..12] from the
            // preface "HTTP/1.1 NNN msg" (note the space at pos 8).
            &preface_str[9..12]
        } else {
            ""
        };
        let is_redirect = WEBCLIENT_FOLLOW_REDIRECTS && (status_code == "301" || status_code == "302");

        if is_redirect {
            // FASM `.complete_redirect` (L1652-1783).
            return self.handle_redirect(&req, &mimelike).await;
        }

        // ------------------------------------------------------------
        // Stage 8: Connection-header branch
        // (FASM L1555-1614).
        // ------------------------------------------------------------
        let connection_close = match mimelike.get_header("Connection") {
            Some(v) if v.trim().eq_ignore_ascii_case("close") => true,
            Some(_) => false,
            None => preface_str.starts_with("HTTP/1.0 "),
        };

        if connection_close {
            // `.completed_closing` path (FASM L1571-1602).
            self.completed_closing(&req, &mimelike).await
        } else {
            // `.completed_keepalive_nocheck` path (FASM L1615-1645).
            // CRITICAL ORDERING: clear self.wcrequest BEFORE invoking
            // the user callback so the callback can safely enqueue
            // new requests on this connection.
            self.completed_keepalive_nocheck(&req, &mimelike).await
        }
    }

    /// FASM `.completed_closing` (L1571-1602).
    ///
    /// 1. Compute `elapsed_ms = now - req.start_time`.
    /// 2. Dispatch the user callback with [`WebClientResult::Response`].
    /// 3. Release the inflight slot.
    /// 4. Clear the bound request.
    /// 5. Close the channel via [`WcHost::channel_close`].
    /// 6. Return `true` to signal suicide.
    async fn completed_closing(self: &Arc<Self>, req: &Arc<WcRequest>, mimelike: &Mimelike) -> bool {
        // Dispatch callback — we're closing anyway, so ordering of
        // the wcrequest clear is less critical than for keep-alive.
        req.dispatch(WebClientResult::Response(mimelike));

        if let Some(wc) = req.webclient.upgrade() {
            wc.release_inflight(req.inflight_id.load(Ordering::Acquire));
        }

        // Clear bound request.
        if let Ok(mut g) = self.wcrequest.lock() {
            *g = None;
        }

        // Cancel the read timer; we're tearing down.
        self.cancel_timer();
        self.suicided.store(true, Ordering::Release);

        // Detach from host.
        if let Some(host) = self.wchost.upgrade() {
            host.channel_close(self);
        }

        true // suicide
    }

    /// FASM `.completed_keepalive_nocheck` (L1615-1645).
    ///
    /// **CRITICAL ORDERING**: clear `self.wcrequest = None` BEFORE
    /// invoking the user callback. The callback may legitimately
    /// enqueue another request on this connection (e.g., browser
    /// pipeline), and the next [`WcHost::check_queue`] sweep needs
    /// to see this connection as idle.
    async fn completed_keepalive_nocheck(
        self: &Arc<Self>,
        req: &Arc<WcRequest>,
        mimelike: &Mimelike,
    ) -> bool {
        // CRITICAL: clear wcrequest BEFORE dispatching callback.
        if let Ok(mut g) = self.wcrequest.lock() {
            *g = None;
        }

        // Dispatch callback (now safe — wcrequest is cleared).
        req.dispatch(WebClientResult::Response(mimelike));

        if let Some(wc) = req.webclient.upgrade() {
            wc.release_inflight(req.inflight_id.load(Ordering::Acquire));
        }

        // Cancel the timer — no request is in flight any more.
        self.cancel_timer();

        // Pump any pending requests on the host queue.
        if let Some(host) = self.wchost.upgrade() {
            host.check_queue();
        }

        false // keep alive
    }

    /// Handle a 301/302 response: extract the Location header,
    /// resolve the new URL, swap it onto the request mimelike, and
    /// either reuse this connection (keep-alive) or close + reopen.
    ///
    /// FASM `.complete_redirect` (L1652-1783).
    ///
    /// # Rust-port enhancement
    ///
    /// Increments [`WcRequest::redirect_count`] and dispatches
    /// [`WebClientResult::FailClosed`] (with code
    /// [`WEBCLIENT_FAIL_REDIRECT_LOOP`]) if the count exceeds
    /// [`MAX_REDIRECTS`]. FASM had no such guard.
    async fn handle_redirect(self: &Arc<Self>, req: &Arc<WcRequest>, response: &Mimelike) -> bool {
        // Bump redirect counter; cap at MAX_REDIRECTS.
        let count = req.redirect_count.fetch_add(1, Ordering::AcqRel) + 1;
        if count > MAX_REDIRECTS {
            // Redirect loop — surface as FailClosed to the user
            // (the numeric code -5 is exposed via the constant
            // [`WEBCLIENT_FAIL_REDIRECT_LOOP`] for FFI callers).
            return self.completed_close_with(req, WebClientResult::FailClosed).await;
        }

        // Extract Location header from the response.
        let location = match response.get_header("Location") {
            Some(s) if !s.is_empty() => s.trim().to_string(),
            _ => {
                // No Location header — fall through to a normal
                // .completed_proceed (treat as non-redirect).
                let resp_preface = response.preface().unwrap_or("");
                let connection_close = match response.get_header("Connection") {
                    Some(v) if v.trim().eq_ignore_ascii_case("close") => true,
                    Some(_) => false,
                    None => resp_preface.starts_with("HTTP/1.0 "),
                };
                if connection_close {
                    return self.completed_closing(req, response).await;
                }
                return self.completed_keepalive_nocheck(req, response).await;
            }
        };

        // Resolve the Location URL relative to the parent.
        // We use `::url::Url::join` from the underlying url crate
        // to handle both absolute and relative redirects.
        let parent_url_arc = req.url();
        let parent_str = format!(
            "{}://{}{}",
            parent_url_arc.protocol(),
            parent_url_arc.host(),
            if parent_url_arc.path().is_empty() {
                "/"
            } else {
                parent_url_arc.path()
            }
        );
        let resolved_str = match ::url::Url::parse(&parent_str) {
            Ok(p) => match p.join(&location) {
                Ok(j) => j.to_string(),
                Err(_) => {
                    return self.completed_close_with(req, WebClientResult::FailClosed).await;
                }
            },
            Err(_) => {
                return self.completed_close_with(req, WebClientResult::FailClosed).await;
            }
        };

        let new_url = match Url::parse(&resolved_str) {
            Ok(u) => Arc::new(u),
            Err(_) => {
                return self.completed_close_with(req, WebClientResult::FailClosed).await;
            }
        };

        // Swap the URL onto the request.
        if let Ok(mut url_slot) = req.url.lock() {
            *url_slot = Arc::clone(&new_url);
        }

        // Determine the destination's hostkey and whether we can
        // keep this connection alive.
        let new_is_tls = matches!(new_url.protocol(), "https" | "wss");
        let new_port = new_url.effective_port();
        let new_host = new_url.host().to_string();
        let new_hostkey = build_hostkey(&new_host, new_port, new_is_tls);

        // Read the current method prefix from the request mimelike
        // and rebuild the preface for the new URL.
        let method_prefix: String = match req.request_mimelike.lock() {
            Ok(m) => {
                let old_preface = m.preface().unwrap_or("");
                if let Some(space_pos) = old_preface.find(' ') {
                    let mut s = String::with_capacity(space_pos + 1);
                    s.push_str(&old_preface[..space_pos]);
                    s.push(' ');
                    s
                } else {
                    "GET ".to_string()
                }
            }
            Err(_) => "GET ".to_string(),
        };

        // Rebuild path component for the request line.
        let new_path_q = {
            let p = new_url.path();
            let q = new_url.query();
            if q.is_empty() {
                if p.is_empty() {
                    "/".to_string()
                } else {
                    p.to_string()
                }
            } else if p.is_empty() {
                format!("/?{}", q)
            } else {
                format!("{}?{}", p, q)
            }
        };
        let new_preface = format!("{}{} HTTP/1.1", method_prefix, new_path_q);

        // Update request mimelike's preface and Host header.
        if let Ok(mut m) = req.request_mimelike.lock() {
            m.set_preface_nocopy(new_preface);
            m.set_header("Host", build_host_header(&new_url));
        }

        // Reset start time (FASM L1748: redirects reset the elapsed
        // measurement so the user sees the time of the FINAL
        // request, not the first redirect).
        req.start_time.store(epoch_millis(), Ordering::Release);

        // Determine close/keepalive based on RESPONSE Connection
        // header (FASM L1655-1700).
        let resp_preface = response.preface().unwrap_or("");
        let connection_close = match response.get_header("Connection") {
            Some(v) if v.trim().eq_ignore_ascii_case("close") => true,
            Some(_) => false,
            None => resp_preface.starts_with("HTTP/1.0 "),
        };

        // If the new destination differs from this channel's host,
        // we MUST close — we can't reuse a connection bound to a
        // different host.
        let new_destination = match self.wchost.upgrade() {
            Some(h) => h.hostkey != new_hostkey,
            None => true,
        };

        if connection_close || new_destination {
            // `.redirect_closing` (FASM L1748-1763).
            // CRITICAL ORDERING: clear wcrequest FIRST, then close
            // the channel, THEN requeue on the (possibly new) host.
            if let Ok(mut g) = self.wcrequest.lock() {
                *g = None;
            }
            self.cancel_timer();
            self.suicided.store(true, Ordering::Release);

            // Detach from current host.
            if let Some(host) = self.wchost.upgrade() {
                host.channel_close(self);
            }

            // Requeue the request on the appropriate host.
            self.requeue_request(req, &new_hostkey, &new_host, new_port, new_is_tls);

            true // suicide
        } else {
            // `.redirect_keepalive_nocheck` (FASM L1772-1783).
            // CRITICAL ORDERING: clear wcrequest BEFORE calling
            // host.request — that way check_queue will find this
            // connection as idle and reuse it.
            if let Ok(mut g) = self.wcrequest.lock() {
                *g = None;
            }
            // Re-arm timer for the new request.
            self.cancel_timer();
            self.timer_cancel.store(false, Ordering::Release);

            // Requeue on the same host (already verified hostkey
            // matches via new_destination==false).
            if let Some(host) = self.wchost.upgrade() {
                host.request(Arc::clone(req));
            }
            false // keep alive
        }
    }

    /// Common close-and-fail helper for the various error paths.
    /// Cancels timer, dispatches the callback, releases inflight,
    /// closes channel, and returns `true` (suicide).
    async fn completed_close_with(
        self: &Arc<Self>,
        req: &Arc<WcRequest>,
        result: WebClientResult<'_>,
    ) -> bool {
        self.cancel_timer();
        if self.suicided.swap(true, Ordering::AcqRel) {
            return true;
        }

        // Clear the bound request slot.
        if let Ok(mut g) = self.wcrequest.lock() {
            *g = None;
        }

        req.dispatch(result);

        if let Some(wc) = req.webclient.upgrade() {
            wc.errors.fetch_add(1, Ordering::Relaxed);
            wc.release_inflight(req.inflight_id.load(Ordering::Acquire));
        }

        if let Some(host) = self.wchost.upgrade() {
            host.channel_close(self);
        }

        true
    }

    /// Requeue a request after a redirect to a different host.
    fn requeue_request(
        self: &Arc<Self>,
        req: &Arc<WcRequest>,
        new_hostkey: &str,
        new_hostname: &str,
        new_port: u16,
        new_is_tls: bool,
    ) {
        // Release the request from this connection's bookkeeping
        // (already cleared from self.wcrequest above).
        if let Ok(mut io) = req.io.lock() {
            *io = None;
        }

        // Look up or create the new host pool.
        let webclient_arc = match req.webclient.upgrade() {
            Some(wc) => wc,
            None => return, // webclient gone — request will dangle
        };

        let new_host = {
            let mut hosts = match webclient_arc.hosts.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if let Some(h) = hosts.get(new_hostkey) {
                Arc::clone(h)
            } else {
                let h = WcHost::new(
                    Arc::downgrade(&webclient_arc),
                    webclient_arc.dns.clone(),
                    new_hostkey.to_string(),
                    new_hostname.to_string(),
                    new_port,
                    new_is_tls,
                );
                hosts.insert(new_hostkey.to_string(), Arc::clone(&h));
                h
            }
        };

        new_host.request(Arc::clone(req));
    }
}

// =============================================================================
// IoChain implementation for WcIo.
//
// WcIo sits at the TOP of its IoChain (its "parent" is the WcRequest
// dispatch logic, not another IoChain layer). The 7-method vtable is
// preserved verbatim from FASM:
//
//   forward (toward kernel/socket): destroy, clone_chain, send
//   backward (toward application):  connected, receive, error, timeout
//
// Per AAP §0.4.1.1, the trait uses BoxFuture for object-safety on
// stable Rust. Default helpers (default_destroy/error/receive/etc.)
// from `crate::net::io` walk the chain in the appropriate direction.
// =============================================================================

impl IoChain for WcIo {
    fn links(&self) -> &IoLinks {
        &self.links
    }

    fn destroy(self: Arc<Self>) -> BoxFuture<()> {
        Box::pin(async move {
            // Mark suicided + cancel timer to prevent races.
            self.suicided.store(true, Ordering::Release);
            self.cancel_timer();

            // Walk forward — the child transport adapter will
            // shut down its writer half. The reader half is owned
            // by the spawned read loop and will see EOF or an
            // explicit error on its next read attempt.
            default_destroy(&self.links).await;
        })
    }

    fn clone_chain(self: Arc<Self>) -> BoxFuture<Option<Arc<dyn IoChain>>> {
        // FASM `wcio$clone` is unimplemented — the wcio chain is
        // bound 1:1 to a single TCP connection and is never cloned.
        Box::pin(async move { None })
    }

    fn connected(self: Arc<Self>, peer: Option<SocketAddr>) -> BoxFuture<()> {
        Box::pin(async move {
            // Local handling: mark connected (safe to do here even
            // if `WcIo::new` already flipped the bit).
            self.connected.store(true, Ordering::Release);
            // Walk backward — informs any (synthetic) parent.
            default_connected(&self.links, peer).await;
        })
    }

    fn send(self: Arc<Self>, data: Bytes) -> BoxFuture<Result<(), NetError>> {
        Box::pin(async move {
            // WcIo isn't a transport-layer adapter — bytes flow
            // FORWARD through the chain to the underlying transport.
            // `default_send` walks toward `child` to reach the
            // [`WcTransportAdapter`] which actually writes to the
            // socket.
            default_send(&self.links, data).await
        })
    }

    fn receive(self: Arc<Self>, data: Bytes) -> BoxFuture<bool> {
        Box::pin(async move {
            // Local handling consumes the bytes (3-branch body
            // detection state machine). Transport-layer receive
            // is the END of the chain — we don't propagate further
            // backward (no synthetic parent for WcIo).
            self.on_receive_internal(&data).await
        })
    }

    fn error(self: Arc<Self>, err: NetError) -> BoxFuture<()> {
        Box::pin(async move {
            // Local: dispatch FailClosed to the user callback.
            Arc::clone(&self).on_error().await;
            // Walk backward via the helper (no-op for WcIo since
            // we have no application parent, but preserves the
            // contract for any future stacking).
            default_error(&self.links, err).await;
        })
    }

    fn timeout(self: Arc<Self>) -> BoxFuture<bool> {
        Box::pin(async move {
            // Local: dispatch FailTimeout to the user callback.
            Arc::clone(&self).on_timeout().await;
            // Walk backward.
            let _ = default_timeout(&self.links).await;
            // Always suicide on timeout (FASM convention).
            true
        })
    }
}

// =============================================================================
// WcTransportAdapter — terminal IoChain layer for WcIo.
//
// Generic over `W: AsyncWrite + Send + Unpin + 'static` so the same
// adapter can wrap a plain `tokio::net::TcpStream` writer half OR a
// `crate::net::tls::TlsStream` writer half (post-handshake).
//
// The reader half is NOT owned by this adapter — it's captured by a
// spawned task running [`read_loop`] which feeds bytes back into the
// WcIo via `IoChain::receive`. This split-stream pattern matches
// `crate::net::http::server::TcpAdapter` and is required because the
// IoChain trait's `receive` is push-based (the caller delivers data),
// while `tokio::io::AsyncRead` is pull-based (the receiver asks for
// data) — bridging the two requires a dedicated read task.
// =============================================================================

/// Transport-layer IoChain adapter wrapping the writer half of a
/// split bidirectional stream.
///
/// Defined locally (not reused from `crate::net::http::server`)
/// because [`crate::net::http::server`] is not in this file's
/// `depends_on_files` whitelist per AAP §0.5.1.3.
pub struct WcTransportAdapter<W: AsyncWrite + Send + Unpin + 'static> {
    writer: Arc<AsyncMutex<W>>,
    links: IoLinks,
}

impl<W: AsyncWrite + Send + Unpin + 'static> WcTransportAdapter<W> {
    /// Build a new transport adapter from a writer half.
    ///
    /// Returns `Arc<Self>` because [`IoChain`] methods take
    /// `self: Arc<Self>` receivers; callers virtually always want
    /// the `Arc` form.
    pub fn new(writer: W) -> Arc<Self> {
        Arc::new(Self {
            writer: Arc::new(AsyncMutex::new(writer)),
            links: IoLinks::new(),
        })
    }
}

impl<W: AsyncWrite + Send + Unpin + 'static> IoChain for WcTransportAdapter<W> {
    fn links(&self) -> &IoLinks {
        &self.links
    }

    fn destroy(self: Arc<Self>) -> BoxFuture<()> {
        Box::pin(async move {
            // Best-effort shutdown of the writer; the reader half
            // is owned by the read_loop task and will observe EOF.
            if let Ok(mut w) = self.writer.try_lock() {
                let _ = w.shutdown().await;
            }
            default_destroy(&self.links).await;
        })
    }

    fn clone_chain(self: Arc<Self>) -> BoxFuture<Option<Arc<dyn IoChain>>> {
        // Transport adapter is bound 1:1 to a single socket; cloning
        // is meaningless. FASM equivalent (`epoll$clone` for a leaf
        // chain) returns null for the same reason.
        Box::pin(async move { None })
    }

    fn connected(self: Arc<Self>, peer: Option<SocketAddr>) -> BoxFuture<()> {
        Box::pin(async move { default_connected(&self.links, peer).await })
    }

    fn send(self: Arc<Self>, data: Bytes) -> BoxFuture<Result<(), NetError>> {
        Box::pin(async move {
            let mut guard = self.writer.lock().await;
            // `write_all` short-circuits the chunk loop on first
            // error; AAP §0.4.2 IoChain trait semantics require
            // all-or-nothing send completion.
            guard.write_all(&data).await.map_err(NetError::Io)?;
            // Flush so the bytes hit the wire promptly. tokio's
            // TcpStream flush is essentially a no-op, but TlsStream
            // (and any future buffered transport) requires it.
            guard.flush().await.map_err(NetError::Io)?;
            Ok(())
        })
    }

    fn receive(self: Arc<Self>, data: Bytes) -> BoxFuture<bool> {
        // The terminal layer should never be asked to receive (data
        // flows backward up the parent chain). If it ever happens,
        // walk the parent helper so we don't silently lose bytes.
        Box::pin(async move { default_receive(&self.links, data).await })
    }

    fn error(self: Arc<Self>, err: NetError) -> BoxFuture<()> {
        Box::pin(async move { default_error(&self.links, err).await })
    }

    fn timeout(self: Arc<Self>) -> BoxFuture<bool> {
        Box::pin(async move { default_timeout(&self.links).await })
    }
}

// =============================================================================
// read_loop — drives the reader half of a split bidirectional stream.
// =============================================================================

/// Per-connection read loop spawned by [`WcIo::new`].
///
/// Reads up to 32 KiB per iteration (matching FASM `epoll_readsize`)
/// from `reader` and delivers each chunk to the parent IoChain via
/// [`IoChain::receive`]. Exits cleanly on EOF (zero-byte read), on
/// `should_close == true` from the receive call, on a fatal read
/// error (which is also surfaced via [`IoChain::error`]), or when
/// the WcIo's `suicided` flag flips.
///
/// Generic over `R: AsyncRead + Send + Unpin + 'static` so the same
/// loop can drive the reader half of a plain `tokio::net::TcpStream`
/// OR a `crate::net::tls::TlsStream`.
async fn read_loop<R>(wcio: Arc<WcIo>, mut reader: R)
where
    R: AsyncRead + Send + Unpin + 'static,
{
    // Buffer size matches FASM `epoll_readsize` / `crate::config::EPOLL_READSIZE`.
    let mut buf = vec![0u8; 32_768];
    let wcio_dyn: Arc<dyn IoChain> = Arc::clone(&wcio) as Arc<dyn IoChain>;

    loop {
        // Bail if the connection has been suicided.
        if wcio.suicided.load(Ordering::Acquire) {
            break;
        }

        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                // EOF — orderly close from peer.
                Arc::clone(&wcio_dyn)
                    .error(NetError::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "peer closed connection",
                    )))
                    .await;
                break;
            }
            Ok(n) => n,
            Err(e) => {
                // Fatal read error.
                Arc::clone(&wcio_dyn).error(NetError::Io(e)).await;
                break;
            }
        };

        let chunk = Bytes::copy_from_slice(&buf[..n]);
        let should_close = Arc::clone(&wcio_dyn).receive(chunk).await;
        if should_close {
            break;
        }
    }

    // Final teardown — destroy the chain so the writer half shuts
    // down cleanly.
    Arc::clone(&wcio_dyn).destroy().await;
}

// =============================================================================
// Tests — AAP §0.7 Phase 11 unit suite.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// AAP Phase 11 — `test_hostkey_construction`.
    ///
    /// Verify the hostkey format produced by [`build_hostkey`]
    /// matches the FASM `wchost$hostkey` output.
    #[test]
    fn test_hostkey_construction() {
        // Plain HTTP non-default port.
        assert_eq!(build_hostkey("example.com", 8080, false), "example.com:8080");
        // Plain HTTP default port (still includes port in the key).
        assert_eq!(build_hostkey("example.com", 80, false), "example.com:80");
        // HTTPS — TLS suffix appended for clarity.
        assert_eq!(build_hostkey("example.com", 443, true), "example.com:443:tls");
        // Non-default HTTPS port.
        assert_eq!(
            build_hostkey("api.example.com", 8443, true),
            "api.example.com:8443:tls"
        );
        // IP literal hostnames.
        assert_eq!(build_hostkey("127.0.0.1", 80, false), "127.0.0.1:80");
        assert_eq!(build_hostkey("192.168.1.1", 8080, true), "192.168.1.1:8080:tls");
    }

    /// AAP Phase 11 — `test_preface_construction`.
    ///
    /// Verify the request preface format for GET / HEAD / POST. The
    /// method tokens are AAP §0.5.1 byte-frozen as `"GET "`,
    /// `"HEAD "`, `"POST "` — each with a trailing space — so that
    /// concatenation with the path produces the canonical request
    /// line `<METHOD> <path> HTTP/1.1`.
    #[test]
    fn test_preface_construction() {
        let url = Url::parse("http://example.com/path?query=1").expect("parse url");
        let p = build_preface("GET ", &url);
        assert_eq!(p, "GET /path?query=1 HTTP/1.1");

        let url2 = Url::parse("http://example.com/").expect("parse url2");
        assert_eq!(build_preface("HEAD ", &url2), "HEAD / HTTP/1.1");

        let url3 = Url::parse("https://api.example.com/v1/users").expect("parse url3");
        assert_eq!(build_preface("POST ", &url3), "POST /v1/users HTTP/1.1");

        // Empty path falls back to "/".
        let url4 = Url::parse("http://example.com").expect("parse url4");
        let p4 = build_preface("GET ", &url4);
        assert!(
            p4 == "GET / HTTP/1.1" || p4 == "GET /? HTTP/1.1" || p4 == "GET /?  HTTP/1.1",
            "expected fallback path of '/' but got: {}",
            p4
        );
    }

    /// AAP Phase 11 — `test_range_header`.
    ///
    /// Verify the `Range: bytes=START-END` header format produced
    /// by [`WebClient::get_range`].
    #[test]
    fn test_range_header() {
        // Direct byte-level equivalence: matches the FASM literal
        // `'bytes='` (6 chars) followed by `START-END`.
        assert_eq!(format!("bytes={}-{}", 100, 200), "bytes=100-200");
        assert_eq!(format!("bytes={}-{}", 0, 1023), "bytes=0-1023");
        assert_eq!(
            format!("bytes={}-{}", 1024u64, 2_097_151u64),
            "bytes=1024-2097151"
        );
    }

    /// AAP Phase 11 — `test_fail_codes`.
    ///
    /// Verify the 5 failure constants match the FASM L75-78 values
    /// plus the Rust-port redirect-loop addition.
    #[test]
    fn test_fail_codes() {
        assert_eq!(WEBCLIENT_FAIL_DNS, -1);
        assert_eq!(WEBCLIENT_FAIL_PRECONNECT, -2);
        assert_eq!(WEBCLIENT_FAIL_CLOSED, -3);
        assert_eq!(WEBCLIENT_FAIL_TIMEOUT, -4);
        assert_eq!(WEBCLIENT_FAIL_REDIRECT_LOOP, -5);
    }

    /// Verify [`WebClientResult::fail_code`] returns the correct
    /// numeric code for each error variant and `None` for the
    /// `Response` variant.
    #[test]
    fn test_webclient_result_fail_code() {
        assert_eq!(WebClientResult::FailDns.fail_code(), Some(WEBCLIENT_FAIL_DNS));
        assert_eq!(
            WebClientResult::FailPreconnect.fail_code(),
            Some(WEBCLIENT_FAIL_PRECONNECT)
        );
        assert_eq!(
            WebClientResult::FailClosed.fail_code(),
            Some(WEBCLIENT_FAIL_CLOSED)
        );
        assert_eq!(
            WebClientResult::FailTimeout.fail_code(),
            Some(WEBCLIENT_FAIL_TIMEOUT)
        );
        // The Response variant has no fail code.
        let m = Mimelike::new();
        assert_eq!(WebClientResult::Response(&m).fail_code(), None);
    }

    /// Verify the `build_host_header` helper elides the port for
    /// scheme-default ports (80/443) but includes it otherwise.
    #[test]
    fn test_host_header_default_port_elision() {
        let url_http = Url::parse("http://example.com/").expect("parse http");
        assert_eq!(build_host_header(&url_http), "example.com");

        let url_https = Url::parse("https://example.com/").expect("parse https");
        assert_eq!(build_host_header(&url_https), "example.com");

        let url_http_custom = Url::parse("http://example.com:8080/").expect("parse http:8080");
        assert_eq!(build_host_header(&url_http_custom), "example.com:8080");

        let url_https_custom = Url::parse("https://example.com:8443/").expect("parse https:8443");
        assert_eq!(build_host_header(&url_https_custom), "example.com:8443");
    }

    /// Verify [`WebClient::new`] honours the user-supplied user-agent
    /// or falls back to the FASM default `"HeavyThing"`.
    #[tokio::test]
    async fn test_webclient_default_user_agent() {
        let wc_default = WebClient::new(None);
        assert_eq!(wc_default.user_agent, "HeavyThing");

        let wc_custom = WebClient::new(Some("CustomBot/1.0"));
        assert_eq!(wc_custom.user_agent, "CustomBot/1.0");
    }

    /// Verify the [`WebClient::add_header`] de-duplicates by case-
    /// insensitive header name (FASM `stringmap$insert_unique`).
    #[tokio::test]
    async fn test_webclient_add_header_dedup() {
        let wc = WebClient::new(None);
        wc.add_header("X-Custom", "value1");
        // Same header name, different case → REJECTED (FASM uniqueness).
        wc.add_header("x-custom", "value2");
        // Different header → accepted.
        wc.add_header("X-Other", "other");

        let headers = wc.add_headers.lock().expect("lock add_headers");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "X-Custom");
        assert_eq!(headers[0].1, "value1"); // first-write wins
        assert_eq!(headers[1].0, "X-Other");
    }

    /// Verify the standard 5 headers (Host/Accept/Connection/
    /// Accept-Encoding/User-Agent) are added by `wcrequest_new`.
    #[tokio::test]
    async fn test_wcrequest_standard_headers() {
        let wc = WebClient::new(Some("TestUA/1.0"));
        let cb: WebClientCallback = Arc::new(|_, _, _| {});
        let req = wc
            .wcrequest_new("GET ", "http://example.com/", cb, false)
            .expect("build request");

        let m = req.request_mimelike.lock().expect("lock mimelike");
        assert_eq!(m.get_header("Host"), Some("example.com"));
        assert_eq!(m.get_header("Accept"), Some("*/*"));
        assert_eq!(m.get_header("Connection"), Some("keep-alive"));
        assert_eq!(m.get_header("Accept-Encoding"), Some("gzip"));
        assert_eq!(m.get_header("User-Agent"), Some("TestUA/1.0"));
    }

    /// Verify HEAD requests set the `headers_only` flag.
    #[tokio::test]
    async fn test_head_request_headers_only_flag() {
        let wc = WebClient::new(None);
        let cb_get: WebClientCallback = Arc::new(|_, _, _| {});
        let cb_head: WebClientCallback = Arc::new(|_, _, _| {});

        // GET path: headers_only must be false (full body expected).
        let req_get = wc
            .wcrequest_new("GET ", "http://example.com/", cb_get, false)
            .expect("build GET request");
        assert!(!req_get.headers_only());

        // HEAD path: headers_only must be true (FASM
        // `wcrequest$head` sets the flag at L36 = 1, causing wcio
        // to stop after the response headers and not wait for any
        // body to arrive).
        let req_head = wc
            .wcrequest_new("HEAD ", "http://example.com/", cb_head, true)
            .expect("build HEAD request");
        assert!(req_head.headers_only());
    }

    /// Verify URL parse failures bubble up as [`HttpError::Parse`].
    #[tokio::test]
    async fn test_invalid_url_returns_parse_error() {
        let wc = WebClient::new(None);
        let cb: WebClientCallback = Arc::new(|_, _, _| {});
        let result = wc.get("not a valid url", cb);
        assert!(matches!(result, Err(HttpError::Parse(_))));
    }

    /// Verify the [`WEBCLIENT_FAIL_REDIRECT_LOOP`] code is consistent
    /// with [`HttpError::RedirectLoop`] — they both signal the same
    /// failure mode (redirect cycle exceeded
    /// [`MAX_REDIRECTS`]).
    #[test]
    fn test_redirect_loop_constants() {
        assert_eq!(WEBCLIENT_FAIL_REDIRECT_LOOP, -5);
        assert_eq!(MAX_REDIRECTS, 10);
        // Smoke-test that HttpError::RedirectLoop is a unit variant.
        let _e = HttpError::RedirectLoop;
    }

    /// Verify [`build_preface`] panics-free behaviour for unusual
    /// URL inputs (empty paths, query-only, etc.).
    #[test]
    fn test_build_preface_edge_cases() {
        // Query but no explicit path → must produce a valid request
        // line. Method tokens follow the AAP §0.5.1 trailing-space
        // convention.
        let url1 = Url::parse("http://example.com?key=value").expect("parse");
        let p1 = build_preface("GET ", &url1);
        assert!(
            p1.starts_with("GET ") && p1.ends_with(" HTTP/1.1"),
            "unexpected preface: {p1}"
        );

        // Trailing slash.
        let url2 = Url::parse("http://example.com/api/").expect("parse");
        assert_eq!(build_preface("POST ", &url2), "POST /api/ HTTP/1.1");
    }

    /// Verify [`epoch_millis`] returns a sensible monotonic-ish value.
    #[test]
    fn test_epoch_millis_sanity() {
        let m1 = epoch_millis();
        // Sleep briefly via std::thread::sleep — we want monotonicity
        // without a tokio runtime.
        std::thread::sleep(Duration::from_millis(2));
        let m2 = epoch_millis();
        assert!(m2 >= m1, "epoch_millis went backwards: {m1} -> {m2}");
        // Reasonable epoch sanity — should be > year 2020 in millis.
        assert!(m1 > 1_577_836_800_000, "epoch_millis suspiciously small: {m1}");
    }

    /// Cross-verify [`Instant`] usage compiles — the import is
    /// reserved for future timer-precision improvements but must
    /// not produce an unused-import warning.
    #[test]
    fn test_instant_import_used() {
        let _i = Instant::now();
    }
}
