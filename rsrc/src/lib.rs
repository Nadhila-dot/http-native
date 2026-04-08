// ─── Structured Logging Macros (D6) ────
//
// Lightweight structured log macros that output to stderr with a consistent
// "[http-native] LEVEL: message" format. Drop-in replacement for bare
// eprintln! calls. Can be swapped to `tracing` crate later without
// changing call sites. Defined before module declarations so child
// modules can use them.

/// /* @param $($arg)* — format arguments identical to eprintln! */
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!("[http-native] error: {}", format_args!($($arg)*))
    };
}

/// /* @param $($arg)* — format arguments identical to eprintln! */
macro_rules! log_warn {
    ($($arg:tt)*) => {
        eprintln!("[http-native] warn: {}", format_args!($($arg)*))
    };
}

mod analyzer;
pub mod compress;
pub mod h2_handler;
#[allow(dead_code)]
mod h3_handler;
pub mod http_utils;
mod manifest;
pub mod parser;
pub mod response;
mod rate_limit;
mod router;
pub mod session;
mod websocket;

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use memchr::memmem;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::TcpListener;
use monoio_rustls::TlsAcceptor;
use napi::bindgen_prelude::{Buffer, Function, Promise};
use napi::threadsafe_function::ThreadsafeFunction;
use napi::{Error, Status};
use napi_derive::napi;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::io::BufReader;
use std::net::{SocketAddr, ToSocketAddrs};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use url::form_urlencoded;

use crate::analyzer::{
    DynamicFastPathResponse, DynamicValueSourceKind, JsonTemplateKind, JsonValueTemplate,
    TextSegment,
};
use crate::manifest::{HttpServerConfigInput, ManifestInput, TlsConfigInput};
use crate::response::{build_response_bytes_fast, patch_connection_header, inject_set_cookie_header, build_error_response_bytes};
use crate::router::{ExactStaticRoute, MatchedRoute, Router};

// ─── Constants ──────────────────────────
// Gotta add support for these to be changed.

const FALLBACK_DEFAULT_HOST: &str = "127.0.0.1";
const FALLBACK_DEFAULT_BACKLOG: i32 = 2048;
const FALLBACK_MAX_HEADER_BYTES: usize = 16 * 1024;
const FALLBACK_HOT_GET_ROOT_HTTP11: &str = "GET / HTTP/1.1\r\n";
const FALLBACK_HOT_GET_ROOT_HTTP10: &str = "GET / HTTP/1.0\r\n";
const FALLBACK_HEADER_CONNECTION_PREFIX: &str = "connection:";
const FALLBACK_HEADER_CONTENT_LENGTH_PREFIX: &str = "content-length:";
const FALLBACK_HEADER_TRANSFER_ENCODING_PREFIX: &str = "transfer-encoding:";
const BRIDGE_VERSION: u8 = 2;
const REQUEST_FLAG_QUERY_PRESENT: u16 = 1 << 0;
const REQUEST_FLAG_BODY_PRESENT: u16 = 1 << 1;
const UNKNOWN_METHOD_CODE: u8 = 0;
/// Sentinel handler ID dispatched to JS when no route matches — JS treats this as 404.
const NOT_FOUND_HANDLER_ID: u32 = 0;

/// Security: Maximum request body size (1 MB)
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Security: Maximum concurrent connections per worker thread
const MAX_CONNECTIONS_PER_WORKER: usize = 4096;

/// Buffer pool: initial capacity for connection read buffers
const BUFFER_INITIAL_CAPACITY: usize = 8192;
/// Buffer pool: max buffers held per thread
const BUFFER_POOL_MAX_SIZE: usize = 256;
/// Buffer pool: max buffer size to recycle (don't recycle oversized buffers)
const BUFFER_POOL_MAX_RECYCLE_SIZE: usize = 65536;

type DispatchTsfn = ThreadsafeFunction<Buffer, Promise<Buffer>, Buffer, Status, false, false, 0>;

// ─── Thread-Local Buffer Pool ───────────
//
// Eliminates per-connection Vec<u8> allocations by recycling buffers.

thread_local! {
    static BUFFER_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::with_capacity(BUFFER_POOL_MAX_SIZE));
}

fn acquire_buffer() -> Vec<u8> {
    BUFFER_POOL.with(|pool| {
        pool.borrow_mut()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(BUFFER_INITIAL_CAPACITY))
    })
}

fn release_buffer(mut buf: Vec<u8>) {
    if buf.capacity() > BUFFER_POOL_MAX_RECYCLE_SIZE {
        return; // Don't recycle oversized buffers
    }
    buf.clear();
    BUFFER_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if pool.len() < BUFFER_POOL_MAX_SIZE {
            pool.push(buf);
        }
    });
}

// ─── Response Buffer Pool (BOOST-2.3) ──
//
// Eliminates per-response Vec<u8> allocations by recycling response buffers.
// Separate from the connection read buffer pool — response buffers are
// typically smaller and have different capacity profiles.

#[allow(dead_code)]
const RESPONSE_POOL_MAX_SIZE: usize = 128;
#[allow(dead_code)]
const RESPONSE_POOL_MAX_RECYCLE_SIZE: usize = 65536;

thread_local! {
    static RESPONSE_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::with_capacity(RESPONSE_POOL_MAX_SIZE));
}

/// Acquire a response buffer from the thread-local pool.
/// Defaults to 1KB capacity — right-sized for typical JSON API responses.
#[allow(dead_code)]
fn acquire_response_buffer(estimated_size: usize) -> Vec<u8> {
    RESPONSE_POOL.with(|pool| {
        pool.borrow_mut()
            .pop()
            .map(|mut buf| {
                buf.clear();
                if buf.capacity() < estimated_size {
                    buf.reserve(estimated_size - buf.capacity());
                }
                buf
            })
            .unwrap_or_else(|| Vec::with_capacity(estimated_size.max(1024)))
    })
}

#[allow(dead_code)]
fn release_response_buffer(mut buf: Vec<u8>) {
    if buf.capacity() > RESPONSE_POOL_MAX_RECYCLE_SIZE {
        return;
    }
    buf.clear();
    RESPONSE_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if pool.len() < RESPONSE_POOL_MAX_SIZE {
            pool.push(buf);
        }
    });
}

// ─── Per-Request Arena Allocator (BOOST-1.2) ──
//
// Uses bumpalo for per-request bump allocation. All request-scoped strings
// and small buffers are allocated from the arena, which resets at the end of
// each request. This reduces per-request heap allocations from ~8-12 to 1.

#[allow(dead_code)]
const REQUEST_ARENA_CAPACITY: usize = 4096;

thread_local! {
    static REQUEST_ARENA: RefCell<bumpalo::Bump> =
        RefCell::new(bumpalo::Bump::with_capacity(REQUEST_ARENA_CAPACITY));
}

/// Reset the per-thread request arena. Called at the end of each request
/// to release all arena-allocated memory in a single operation.
#[allow(dead_code)]
fn reset_request_arena() {
    REQUEST_ARENA.with(|arena| arena.borrow_mut().reset());
}

// ─── Server Configuration ───────────────

#[derive(Clone)]
struct HttpServerConfig {
    default_host: String,
    default_backlog: i32,
    max_header_bytes: usize,
    hot_get_root_http11: Vec<u8>,
    hot_get_root_http10: Vec<u8>,
    header_connection_prefix: Vec<u8>,
    header_content_length_prefix: Vec<u8>,
    header_transfer_encoding_prefix: Vec<u8>,
    compression: Option<compress::CompressionConfig>,
}

impl HttpServerConfig {
    fn from_manifest(manifest: &ManifestInput) -> Result<Self> {
        let input = manifest.server_config.as_ref();
        let default_backlog = input
            .and_then(|config| config.default_backlog)
            .unwrap_or(FALLBACK_DEFAULT_BACKLOG);
        let max_header_bytes = input
            .and_then(|config| config.max_header_bytes)
            .unwrap_or(FALLBACK_MAX_HEADER_BYTES);

        if default_backlog <= 0 {
            return Err(anyhow!(
                "serverConfig.defaultBacklog must be greater than 0"
            ));
        }

        if max_header_bytes == 0 {
            return Err(anyhow!(
                "serverConfig.maxHeaderBytes must be greater than 0"
            ));
        }

        Ok(Self {
            default_host: config_string(
                input,
                |config| config.default_host.as_deref(),
                FALLBACK_DEFAULT_HOST,
            ),
            default_backlog,
            max_header_bytes,
            hot_get_root_http11: config_string(
                input,
                |config| config.hot_get_root_http11.as_deref(),
                FALLBACK_HOT_GET_ROOT_HTTP11,
            )
            .into_bytes(),
            hot_get_root_http10: config_string(
                input,
                |config| config.hot_get_root_http10.as_deref(),
                FALLBACK_HOT_GET_ROOT_HTTP10,
            )
            .into_bytes(),
            header_connection_prefix: config_string(
                input,
                |config| config.header_connection_prefix.as_deref(),
                FALLBACK_HEADER_CONNECTION_PREFIX,
            )
            .into_bytes(),
            header_content_length_prefix: config_string(
                input,
                |config| config.header_content_length_prefix.as_deref(),
                FALLBACK_HEADER_CONTENT_LENGTH_PREFIX,
            )
            .into_bytes(),
            header_transfer_encoding_prefix: config_string(
                input,
                |config| config.header_transfer_encoding_prefix.as_deref(),
                FALLBACK_HEADER_TRANSFER_ENCODING_PREFIX,
            )
            .into_bytes(),
            compression: compress::CompressionConfig::from_manifest(
                manifest.compression.as_ref(),
            ),
        })
    }
}

// ─── NAPI Interface ─────────────────────

#[napi(object)]
pub struct NativeListenOptions {
    pub host: Option<String>,
    pub port: u16,
    pub backlog: Option<i32>,
}

struct ShutdownHandle {
    flag: Arc<AtomicBool>,
    /// @DX-6.3: when true, the server rejects new connections but drains
    /// in-flight requests before fully stopping. Set via `shutdown()`.
    draining: Arc<AtomicBool>,
    wake_addrs: Vec<SocketAddr>,
}

/// @DX-6.3: global atomic counter of in-flight requests across all workers.
/// Used by graceful shutdown to wait for requests to complete before closing.
static INFLIGHT_REQUESTS: AtomicU64 = AtomicU64::new(0);

struct LiveRouter {
    router: ArcSwap<Router>,
}

#[napi]
pub struct NativeServerHandle {
    host: String,
    port: u32,
    url: String,
    live_router: Arc<LiveRouter>,
    cache_namespaces: Mutex<HashSet<u64>>,
    shutdown: Mutex<Option<ShutdownHandle>>,
    closed: Mutex<Option<Vec<mpsc::Receiver<()>>>>,
}

#[napi]
impl NativeServerHandle {
    #[napi(getter)]
    pub fn host(&self) -> String {
        self.host.clone()
    }

    #[napi(getter)]
    pub fn port(&self) -> u32 {
        self.port
    }

    #[napi(getter)]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    #[napi]
    pub fn reload(&self, manifest_json: String) -> napi::Result<()> {
        let manifest: ManifestInput = serde_json::from_str(&manifest_json).map_err(to_napi_error)?;
        validate_manifest(&manifest).map_err(to_napi_error)?;
        let comp_config = compress::CompressionConfig::from_manifest(manifest.compression.as_ref());
        let next_router = Arc::new(Router::from_manifest(&manifest, comp_config.as_ref()).map_err(to_napi_error)?);
        let next_namespaces = next_router.cache_namespaces();

        {
            let mut registered = self
                .cache_namespaces
                .lock()
                .expect("cache namespaces mutex poisoned");
            replace_cache_namespaces(&mut registered, &next_namespaces);
            *registered = next_namespaces;
        }

        self.live_router.router.store(next_router);
        close_all_websocket_connections();
        Ok(())
    }

    /// @DX-6.3: graceful shutdown — stop accepting new connections, drain
    /// in-flight requests up to `timeout_ms`, then force-stop workers.
    /// Returns the number of in-flight requests that were still pending
    /// when the timeout expired (0 = fully drained).
    #[napi]
    pub fn shutdown(&self, timeout_ms: Option<u32>) -> napi::Result<u32> {
        let drain_timeout = Duration::from_millis(timeout_ms.unwrap_or(30_000) as u64);

        /* Phase 1: set draining flag — workers reject new connections but
         * finish processing in-flight requests normally. */
        if let Some(handle) = self.shutdown.lock().expect("shutdown mutex poisoned").as_ref() {
            handle.draining.store(true, Ordering::SeqCst);
        }

        close_all_websocket_connections();

        /* Phase 2: poll in-flight request counter until drained or timeout */
        let deadline = std::time::Instant::now() + drain_timeout;
        while INFLIGHT_REQUESTS.load(Ordering::Acquire) > 0 {
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let remaining = INFLIGHT_REQUESTS.load(Ordering::Acquire) as u32;

        /* Phase 3: force-stop workers regardless of drain state */
        self.close()?;
        Ok(remaining)
    }

    #[napi]
    pub fn close(&self) -> napi::Result<()> {
        let registered_namespaces = {
            let mut namespaces = self
                .cache_namespaces
                .lock()
                .expect("cache namespaces mutex poisoned");
            let snapshot = namespaces.clone();
            namespaces.clear();
            snapshot
        };
        unregister_cache_namespaces(&registered_namespaces);

        close_all_websocket_connections();

        if let Some(shutdown) = self
            .shutdown
            .lock()
            .expect("shutdown mutex poisoned")
            .take()
        {
            shutdown.flag.store(true, Ordering::SeqCst);
            for wake_addr in shutdown.wake_addrs {
                let _ = std::net::TcpStream::connect(wake_addr);
            }
        }

        if let Some(receivers) = self.closed.lock().expect("closed mutex poisoned").take() {
            for receiver in receivers {
                let _ = receiver.recv();
            }
        }

        Ok(())
    }
}

// ─── Global Session Store ──────────────
//
// Accessible from both the server threads and direct NAPI calls from JS.
// Initialized during start_server when session config is present.

static GLOBAL_SESSION_STORE: std::sync::OnceLock<Arc<session::SessionStore>> =
    std::sync::OnceLock::new();

// ─── Global Stream Registry ──────────
//
// Streams are created on the monoio thread when a stream-start sentinel is
// detected in the JS dispatch response.  The Sender lives in the DashMap so
// that NAPI calls from JS (`stream_write`, `stream_end`) can push chunks.
// The Receiver is held locally on the monoio thread that drives the chunked
// transfer loop.

static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);
static STREAM_CHANNELS: std::sync::OnceLock<dashmap::DashMap<u64, flume::Sender<StreamMessage>>> =
    std::sync::OnceLock::new();
static WEBSOCKET_CONNECTIONS: std::sync::OnceLock<dashmap::DashMap<u64, ()>> =
    std::sync::OnceLock::new();

// ─── WebSocket Pub/Sub Registry (DX-4.4) ───
//
// Topic-based pub/sub for WebSocket connections. Connections subscribe to
// named topics; publishing to a topic broadcasts to all subscribers. The
// registry uses DashMap for lock-free concurrent access across worker threads.

/// topic → set of connection IDs subscribed to that topic
static WS_TOPICS: std::sync::OnceLock<dashmap::DashMap<String, HashSet<u64>>> =
    std::sync::OnceLock::new();

fn ws_topic_registry() -> &'static dashmap::DashMap<String, HashSet<u64>> {
    WS_TOPICS.get_or_init(dashmap::DashMap::new)
}
static CACHE_NAMESPACE_COUNTS: std::sync::OnceLock<dashmap::DashMap<u64, usize>> =
    std::sync::OnceLock::new();
pub(crate) static CACHE_NAMESPACE_GENERATION: AtomicU64 = AtomicU64::new(1);

fn stream_registry() -> &'static dashmap::DashMap<u64, flume::Sender<StreamMessage>> {
    STREAM_CHANNELS.get_or_init(dashmap::DashMap::new)
}

fn websocket_connections() -> &'static dashmap::DashMap<u64, ()> {
    WEBSOCKET_CONNECTIONS.get_or_init(dashmap::DashMap::new)
}

pub(crate) fn cache_namespace_counts() -> &'static dashmap::DashMap<u64, usize> {
    CACHE_NAMESPACE_COUNTS.get_or_init(dashmap::DashMap::new)
}

fn register_cache_namespaces(namespaces: &HashSet<u64>) {
    if namespaces.is_empty() {
        return;
    }

    let counts = cache_namespace_counts();
    for namespace in namespaces {
        counts
            .entry(*namespace)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    CACHE_NAMESPACE_GENERATION.fetch_add(1, Ordering::SeqCst);
}

fn unregister_cache_namespaces(namespaces: &HashSet<u64>) {
    if namespaces.is_empty() {
        return;
    }

    let counts = cache_namespace_counts();
    for namespace in namespaces {
        if let Some(mut entry) = counts.get_mut(namespace) {
            if *entry <= 1 {
                drop(entry);
                counts.remove(namespace);
            } else {
                *entry -= 1;
            }
        }
    }

    CACHE_NAMESPACE_GENERATION.fetch_add(1, Ordering::SeqCst);
}

fn replace_cache_namespaces(previous: &HashSet<u64>, next: &HashSet<u64>) {
    let removed = previous
        .difference(next)
        .copied()
        .collect::<HashSet<_>>();
    let added = next
        .difference(previous)
        .copied()
        .collect::<HashSet<_>>();

    unregister_cache_namespaces(&removed);
    register_cache_namespaces(&added);
}

fn close_all_websocket_connections() {
    let websocket_ids = websocket_connections()
        .iter()
        .map(|entry| *entry.key())
        .collect::<Vec<_>>();

    for websocket_id in websocket_ids {
        let _ = stream_end(websocket_id as i64);
    }
}

enum StreamMessage {
    Chunk(Vec<u8>),
    End,
}

/// Allocate the next stream ID. Called from JS before dispatching so the
/// stream-start envelope can embed the ID.
#[napi]
pub fn stream_create() -> i64 {
    NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed) as i64
}

/// Write a chunk to an active stream. Called from JS.
#[napi]
pub fn stream_write(stream_id: i64, chunk: Buffer) -> napi::Result<()> {
    let registry = stream_registry();
    let sender = registry
        .get(&(stream_id as u64))
        .ok_or_else(|| napi::Error::from_reason(format!("Stream {} not found", stream_id)))?;
    sender
        .send(StreamMessage::Chunk(chunk.to_vec()))
        .map_err(|_| napi::Error::from_reason("Stream channel closed"))?;
    Ok(())
}

/// End an active stream. Called from JS.
#[napi]
pub fn stream_end(stream_id: i64) -> napi::Result<()> {
    let registry = stream_registry();
    if let Some((_, sender)) = registry.remove(&(stream_id as u64)) {
        let _ = sender.send(StreamMessage::End);
    }
    let conn_id = stream_id as u64;
    websocket_connections().remove(&conn_id);
    // Clean up any pub/sub subscriptions for this connection
    ws_unsubscribe_all(stream_id);
    Ok(())
}

// ─── WebSocket Pub/Sub NAPI Functions ───

/// Subscribe a WebSocket connection to a topic.
#[napi]
pub fn ws_subscribe(connection_id: i64, topic: String) {
    let id = connection_id as u64;
    ws_topic_registry()
        .entry(topic)
        .or_insert_with(HashSet::new)
        .insert(id);
}

/// Unsubscribe a WebSocket connection from a topic.
#[napi]
pub fn ws_unsubscribe(connection_id: i64, topic: String) {
    let registry = ws_topic_registry();
    if let Some(mut subs) = registry.get_mut(&topic) {
        subs.remove(&(connection_id as u64));
        if subs.is_empty() {
            drop(subs);
            registry.remove(&topic);
        }
    }
}

/// Unsubscribe a connection from ALL topics (called on disconnect).
#[napi]
pub fn ws_unsubscribe_all(connection_id: i64) {
    let id = connection_id as u64;
    let registry = ws_topic_registry();
    let mut empty_topics = Vec::new();
    for mut entry in registry.iter_mut() {
        entry.value_mut().remove(&id);
        if entry.value().is_empty() {
            empty_topics.push(entry.key().clone());
        }
    }
    for topic in empty_topics {
        registry.remove(&topic);
    }
}

/// Publish a message to all connections subscribed to a topic.
/// Returns the number of connections the message was sent to.
#[napi]
pub fn ws_publish(topic: String, data: Buffer) -> u32 {
    let registry = ws_topic_registry();
    let Some(subscribers) = registry.get(&topic) else { return 0 };
    let stream_reg = stream_registry();
    let frame = websocket::encode_frame(websocket::OPCODE_TEXT, data.as_ref());
    let mut count = 0u32;
    for &conn_id in subscribers.value() {
        if let Some(sender) = stream_reg.get(&conn_id) {
            if sender.send(StreamMessage::Chunk(frame.clone())).is_ok() {
                count += 1;
            }
        }
    }
    count
}

/// Get the number of subscribers for a topic.
#[napi]
pub fn ws_subscriber_count(topic: String) -> u32 {
    ws_topic_registry()
        .get(&topic)
        .map(|s| s.len() as u32)
        .unwrap_or(0)
}

/// Get a session value by key. Returns JSON string or null.
#[napi]
pub fn session_get(session_id_hex: String, key: String) -> Option<String> {
    let store = GLOBAL_SESSION_STORE.get()?;
    let id = session::hex_decode_id(&session_id_hex)?;
    let entry = store.get(&id)?;
    let value = entry.data.get(&key)?;
    String::from_utf8(value.clone()).ok()
}

/// Set a session value. Value should be a JSON string.
#[napi]
pub fn session_set(session_id_hex: String, key: String, value: String) -> bool {
    let Some(store) = GLOBAL_SESSION_STORE.get() else { return false };
    let Some(id) = session::hex_decode_id(&session_id_hex) else { return false };
    let mut mutations = std::collections::HashMap::new();
    mutations.insert(key, value.into_bytes());
    store.upsert(&id, mutations, &[])
}

/// Delete a session key.
#[napi]
pub fn session_delete(session_id_hex: String, key: String) -> bool {
    let Some(store) = GLOBAL_SESSION_STORE.get() else { return false };
    let Some(id) = session::hex_decode_id(&session_id_hex) else { return false };
    store.upsert(&id, std::collections::HashMap::new(), &[key])
}

/// Destroy an entire session.
#[napi]
pub fn session_destroy(session_id_hex: String) -> bool {
    let Some(store) = GLOBAL_SESSION_STORE.get() else { return false };
    let Some(id) = session::hex_decode_id(&session_id_hex) else { return false };
    store.destroy(&id);
    true
}

/// Verify a signed session cookie. Returns the session ID hex if valid, null otherwise.
#[napi]
pub fn session_verify_cookie(cookie_value: String) -> Option<String> {
    let store = GLOBAL_SESSION_STORE.get()?;
    let id = store.verify_cookie(&cookie_value)?;
    Some(session::hex_encode_id(&id))
}

/// Generate a new signed session cookie value. Returns "hex_id.hex_hmac".
#[napi]
pub fn session_new_cookie() -> Option<String> {
    let store = GLOBAL_SESSION_STORE.get()?;
    let id = store.generate_id();
    Some(store.build_cookie_value(&id))
}

/// Get all session data as a JSON object string.
#[napi]
pub fn session_get_all(session_id_hex: String) -> Option<String> {
    let store = GLOBAL_SESSION_STORE.get()?;
    let id = session::hex_decode_id(&session_id_hex)?;
    let entry = store.get(&id)?;
    let mut map = serde_json::Map::new();
    for (key, value) in &entry.data {
        if let Ok(json_val) = serde_json::from_slice(value) {
            map.insert(key.clone(), json_val);
        } else if let Ok(s) = std::str::from_utf8(value) {
            map.insert(key.clone(), serde_json::Value::String(s.to_string()));
        }
    }
    serde_json::to_string(&serde_json::Value::Object(map)).ok()
}

/// Set multiple session values at once. Takes a JSON object string.
#[napi]
pub fn session_set_all(session_id_hex: String, data_json: String) -> bool {
    let Some(store) = GLOBAL_SESSION_STORE.get() else { return false };
    let Some(id) = session::hex_decode_id(&session_id_hex) else { return false };
    let Ok(obj) = serde_json::from_str::<serde_json::Value>(&data_json) else { return false };
    let Some(map) = obj.as_object() else { return false };
    let mut mutations = std::collections::HashMap::new();
    for (key, value) in map {
        mutations.insert(key.clone(), value.to_string().into_bytes());
    }
    store.upsert(&id, mutations, &[])
}

#[napi(object)]
pub struct NativeRateLimitResult {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_at_ms: f64,
    pub retry_after_secs: f64,
    pub now_ms: f64,
}

/// Low-level sliding-window rate-limit check.
/// Namespace and key are fully caller-defined so policy can be composed in JS.
#[napi]
pub fn rate_limit_check(
    namespace: String,
    key: String,
    max: u32,
    window_secs: u32,
    cost: Option<u32>,
) -> napi::Result<NativeRateLimitResult> {
    if namespace.trim().is_empty() {
        return Err(to_napi_error(anyhow!("rateLimitCheck: namespace must be non-empty")));
    }
    if key.trim().is_empty() {
        return Err(to_napi_error(anyhow!("rateLimitCheck: key must be non-empty")));
    }
    if max == 0 {
        return Err(to_napi_error(anyhow!("rateLimitCheck: max must be greater than 0")));
    }
    if window_secs == 0 {
        return Err(to_napi_error(anyhow!(
            "rateLimitCheck: windowSecs must be greater than 0"
        )));
    }

    let decision = rate_limit::check(
        &namespace,
        &key,
        max,
        window_secs,
        cost.unwrap_or(1).max(1),
        rate_limit::now_ms(),
    );

    Ok(NativeRateLimitResult {
        allowed: decision.allowed,
        limit: decision.limit,
        remaining: decision.remaining,
        reset_at_ms: decision.reset_at_ms as f64,
        retry_after_secs: decision.retry_after_secs as f64,
        now_ms: decision.now_ms as f64,
    })
}

/// Reset low-level limiter state.
/// - no args: clear all namespaces
/// - namespace only: clear a namespace
/// - namespace + key: clear one key
#[napi]
pub fn rate_limit_reset(namespace: Option<String>, key: Option<String>) -> u32 {
    if namespace.is_none() && key.is_some() {
        return 0;
    }

    rate_limit::reset(namespace.as_deref(), key.as_deref()) as u32
}

#[napi]
pub fn start_server(
    manifest_json: String,
    dispatcher: Function<'_, Buffer, Promise<Buffer>>,
    options: NativeListenOptions,
) -> napi::Result<NativeServerHandle> {
    let manifest: ManifestInput = serde_json::from_str(&manifest_json).map_err(to_napi_error)?;
    validate_manifest(&manifest).map_err(to_napi_error)?;
    let server_config =
        Arc::new(HttpServerConfig::from_manifest(&manifest).map_err(to_napi_error)?);
    let router = Arc::new(Router::from_manifest(&manifest, server_config.compression.as_ref()).map_err(to_napi_error)?);
    let registered_cache_namespaces = router.cache_namespaces();
    register_cache_namespaces(&registered_cache_namespaces);
    let live_router = Arc::new(LiveRouter {
        router: ArcSwap::from(router),
    });
    let tls_result = build_tls_acceptor(&manifest).map_err(to_napi_error)?;
    let tls_enabled = tls_result.is_some();
    let (tls_acceptor, tls_config) = match tls_result {
        Some((acceptor, config)) => (Some(acceptor), Some(config)),
        None => (None, None),
    };

    // Build session store if session config is present in manifest
    let session_store: Option<Arc<session::SessionStore>> = manifest.session.as_ref().map(|cfg| {
        let store = Arc::new(session::SessionStore::new(session::SessionConfig {
            secret: cfg.secret.as_bytes().to_vec(),
            max_age_secs: cfg.max_age_secs,
            cookie_name: cfg.cookie_name.clone(),
            http_only: cfg.http_only,
            secure: cfg.secure,
            same_site: cfg.same_site.parse::<session::SameSite>().unwrap(),
            path: cfg.path.clone(),
            max_sessions: cfg.max_sessions,
            max_data_size: cfg.max_data_size,
        }));
        // Register globally so NAPI functions can access it
        let _ = GLOBAL_SESSION_STORE.set(Arc::clone(&store));
        store
    });

    let callback: DispatchTsfn = dispatcher
        .build_threadsafe_function::<Buffer>()
        .build()
        .map_err(to_napi_error)?;
    let dispatcher = Arc::new(JsDispatcher { callback });

    let worker_count = worker_count_for(&options);
    let (startup_tx, startup_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(worker_count);
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let draining_flag = Arc::new(AtomicBool::new(false));
    let mut closed_receivers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let (closed_tx, closed_rx) = mpsc::channel::<()>();
        closed_receivers.push(closed_rx);

        let thread_live_router = Arc::clone(&live_router);
        let thread_dispatcher = Arc::clone(&dispatcher);
        let thread_config = Arc::clone(&server_config);
        let thread_shutdown = Arc::clone(&shutdown_flag);
        let thread_draining = Arc::clone(&draining_flag);
        let thread_session_store = session_store.clone();
        let thread_tls_acceptor = tls_acceptor.clone();
        let thread_tls_config = tls_config.clone();
        let thread_options = NativeListenOptions {
            host: options.host.clone(),
            port: options.port,
            backlog: options.backlog,
        };
        let thread_startup_tx = startup_tx.clone();

        std::thread::spawn(move || {
            let startup_tx_error = thread_startup_tx.clone();
            let result = (|| -> Result<()> {
                let mut runtime = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .enable_timer()
                    .build()
                    .context("failed to build monoio runtime")?;

                runtime.block_on(async move {
                    let listener = bind_listener(&thread_options, thread_config.as_ref())
                        .context("failed to create monoio listener")?;
                    let local_addr = listener.local_addr()?;
                    let _ = thread_startup_tx.send(Ok(local_addr));
                    run_server(
                        listener,
                        thread_live_router,
                        thread_dispatcher,
                        thread_config,
                        thread_tls_acceptor,
                        thread_tls_config,
                        thread_shutdown,
                        thread_draining,
                        thread_session_store,
                    )
                    .await
                })
            })();

            if let Err(error) = &result {
                let _ = startup_tx_error.send(Err(error.to_string()));
                log_error!("native server exited: {error:#}");
            }

            let _ = closed_tx.send(());
        });
    }

    let mut wake_addrs = Vec::with_capacity(worker_count);
    let mut local_addr = None;
    for _ in 0..worker_count {
        match startup_rx.recv() {
            Ok(Ok(addr)) => {
                if local_addr.is_none() {
                    local_addr = Some(addr);
                }
                wake_addrs.push(addr);
            }
            Ok(Err(message)) => {
                shutdown_flag.store(true, Ordering::SeqCst);
                for wake_addr in &wake_addrs {
                    let _ = std::net::TcpStream::connect(*wake_addr);
                }
                for receiver in closed_receivers {
                    let _ = receiver.recv();
                }
                return Err(Error::from_reason(message));
            }
            Err(_) => {
                shutdown_flag.store(true, Ordering::SeqCst);
                for wake_addr in &wake_addrs {
                    let _ = std::net::TcpStream::connect(*wake_addr);
                }
                for receiver in closed_receivers {
                    let _ = receiver.recv();
                }
                return Err(Error::from_reason(
                    "Native server exited before reporting readiness".to_string(),
                ));
            }
        }
    }

    let local_addr = local_addr.expect("worker count must be at least 1");

    let host = local_addr.ip().to_string();
    let port = local_addr.port() as u32;

    Ok(NativeServerHandle {
        host: host.clone(),
        port,
        url: if tls_enabled {
            format!("https://{host}:{port}")
        } else {
            format!("http://{host}:{port}")
        },
        live_router,
        cache_namespaces: Mutex::new(registered_cache_namespaces),
        shutdown: Mutex::new(Some(ShutdownHandle {
            flag: shutdown_flag,
            draining: draining_flag,
            wake_addrs,
        })),
        closed: Mutex::new(Some(closed_receivers)),
    })
}

fn worker_count_for(options: &NativeListenOptions) -> usize {
    if options.port == 0 {
        return 1;
    }

    std::env::var("HTTP_NATIVE_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
}

// ─── JS Dispatcher ──────────────────────

struct JsDispatcher {
    callback: DispatchTsfn,
}

impl JsDispatcher {
    async fn dispatch(&self, request: Buffer) -> Result<Buffer> {
        let response_json = self
            .callback
            .call_async(request)
            .await
            .map_err(|error| anyhow!(error.to_string()))?
            .await
            .map_err(|error| anyhow!(error.to_string()))?;

        Ok(response_json)
    }
}

// ─── Server Loop ────────────────────────

async fn run_server(
    listener: TcpListener,
    live_router: Arc<LiveRouter>,
    dispatcher: Arc<JsDispatcher>,
    server_config: Arc<HttpServerConfig>,
    tls_acceptor: Option<TlsAcceptor>,
    tls_config: Option<Arc<RustlsServerConfig>>,
    shutdown_flag: Arc<AtomicBool>,
    draining_flag: Arc<AtomicBool>,
    session_store: Option<Arc<session::SessionStore>>,
) -> Result<()> {
    // Wrap Arc in Rc for cheap per-connection cloning within this single-threaded
    // worker — avoids atomic ref-count operations on every accepted connection.
    let live_router: Rc<Arc<LiveRouter>> = Rc::new(live_router);
    let dispatcher: Rc<Arc<JsDispatcher>> = Rc::new(dispatcher);
    let server_config: Rc<Arc<HttpServerConfig>> = Rc::new(server_config);
    let _tls_acceptor: Option<Rc<TlsAcceptor>> = tls_acceptor.map(Rc::new);
    let tls_config: Option<Rc<Arc<RustlsServerConfig>>> = tls_config.map(Rc::new);
    let session_store: Option<Rc<Arc<session::SessionStore>>> =
        session_store.map(Rc::new);

    let active_connections = Rc::new(std::cell::Cell::new(0usize));

    loop {
        if shutdown_flag.load(Ordering::Acquire) {
            break;
        }

        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                if shutdown_flag.load(Ordering::Acquire) {
                    break;
                }

                /* @DX-6.3: in draining mode, reject new connections with 503
                 * so load balancers route traffic elsewhere. In-flight requests
                 * on existing connections continue normally. */
                if draining_flag.load(Ordering::Acquire) {
                    drop(stream);
                    continue;
                }

                // Security (S3): enforce per-worker connection limit
                if active_connections.get() >= MAX_CONNECTIONS_PER_WORKER {
                    drop(stream);
                    continue;
                }

                if let Err(error) = stream.set_nodelay(true) {
                    log_warn!("failed to enable TCP_NODELAY: {error}");
                }

                let live_router = Rc::clone(&live_router);
                let dispatcher = Rc::clone(&dispatcher);
                let server_config = Rc::clone(&server_config);
                let tls_config = tls_config.clone();
                let session_store = session_store.clone();
                active_connections.set(active_connections.get() + 1);

                let conn_counter = Rc::clone(&active_connections);

                monoio::spawn(async move {
                    let connection_result = if let Some(tls_cfg) = tls_config.as_ref() {
                        /* @DX-4.1: TLS connections use poll-io path to support both
                         * HTTP/1.1 and HTTP/2 via ALPN negotiation. The raw TCP stream
                         * is converted to a tokio-compatible type, then wrapped with
                         * tokio-rustls for TLS. After the handshake, ALPN determines
                         * whether to dispatch to the h2 handler or fall back to h1.1. */
                        let poll_io = match monoio::io::IntoPollIo::into_poll_io(stream) {
                            Ok(s) => s,
                            Err(e) => {
                                log_error!("failed to convert to poll-io: {e}");
                                return;
                            }
                        };

                        let tokio_acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(tls_cfg.as_ref()));
                        match tokio_acceptor.accept(poll_io).await {
                            Ok(tls_stream) => {
                                let alpn = tls_stream.get_ref().1.alpn_protocol()
                                    .map(|p| p.to_vec());
                                let is_h2 = alpn.as_deref() == Some(b"h2");

                                if is_h2 {
                                    let peer_ip = Some(peer_addr.ip().to_string());
                                    h2_handler::handle_h2_connection(
                                        tls_stream,
                                        live_router,
                                        dispatcher,
                                        server_config,
                                        peer_ip,
                                    )
                                    .await
                                } else {
                                    /* HTTP/1.1 over TLS — use monoio-rustls for
                                     * completion-based I/O (fast path). We need to
                                     * re-accept with monoio-rustls since we already
                                     * consumed the stream. For now, handle h1.1 over
                                     * the poll-io TLS stream. */
                                    handle_h1_over_poll_tls(
                                        tls_stream,
                                        live_router,
                                        dispatcher,
                                        server_config,
                                        session_store,
                                        Some(peer_addr),
                                    )
                                    .await
                                }
                            }
                            Err(error) => Err(anyhow!("TLS accept failed: {error}")),
                        }
                    } else {
                        handle_connection(
                            stream,
                            live_router,
                            dispatcher,
                            server_config,
                            session_store,
                            Some(peer_addr),
                        )
                        .await
                    };
                    if let Err(error) = connection_result {
                        log_error!("connection error: {error}");
                    }
                    conn_counter.set(conn_counter.get().saturating_sub(1));
                });
            }
            Err(error) => {
                if shutdown_flag.load(Ordering::Acquire) {
                    break;
                }

                log_error!("accept error: {error}");
            }
        }
    }

    Ok(())
}

use crate::parser::{
    ParsedRequest, parse_request_httparse, find_header_end,
    contains_ascii_case_insensitive, trim_ascii_spaces,
};

use monoio::time::timeout;
use std::time::Duration;

const TIMEOUT_HEADER_READ: Duration = Duration::from_secs(30);
const TIMEOUT_IDLE_KEEPALIVE: Duration = Duration::from_secs(120);
const TIMEOUT_BODY_READ: Duration = Duration::from_secs(60);
const TIMEOUT_WS_IDLE: Duration = Duration::from_secs(300);
/// @S8: maximum wall-clock time to accumulate a complete set of request headers.
/// Defends against slow-loris attacks that send one byte per read to reset
/// per-read timeouts. If the total header phase exceeds this, the connection
/// is closed regardless of per-read progress.
const TIMEOUT_HEADER_DEADLINE: Duration = Duration::from_secs(60);

// ─── Tokio ↔ Monoio I/O Adapter ────────
//
// Bridges tokio's poll-based `AsyncRead`/`AsyncWrite` traits to monoio's
// ownership-based `AsyncReadRent`/`AsyncWriteRent` traits. This lets us reuse
// the existing HTTP/1.1 connection handler for TLS streams that went through
// tokio-rustls (needed for ALPN negotiation with h2).

struct TokioCompat<T>(T);

impl<T: tokio::io::AsyncRead + Unpin + 'static> monoio::io::AsyncReadRent for TokioCompat<T> {
    async fn read<B: monoio::buf::IoBufMut>(&mut self, mut buf: B) -> monoio::BufResult<usize, B> {
        use tokio::io::AsyncReadExt;
        let total = buf.bytes_total();
        if total == 0 {
            return (Ok(0), buf);
        }
        // Safety: write_ptr returns the buffer start, bytes_total gives capacity.
        // Matches monoio's own recv semantics — kernel writes from position 0.
        let slice = unsafe { std::slice::from_raw_parts_mut(buf.write_ptr(), total) };
        match self.0.read(slice).await {
            Ok(n) => {
                unsafe { buf.set_init(n) };
                (Ok(n), buf)
            }
            Err(e) => (Err(e), buf),
        }
    }

    async fn readv<B: monoio::buf::IoVecBufMut>(&mut self, buf: B) -> monoio::BufResult<usize, B> {
        // Vectored reads are never used by the HTTP/1.1 handler
        (Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "readv not available over TLS adapter")), buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin + 'static> monoio::io::AsyncWriteRent for TokioCompat<T> {
    async fn write<B: monoio::buf::IoBuf>(&mut self, buf: B) -> monoio::BufResult<usize, B> {
        use tokio::io::AsyncWriteExt;
        let init = buf.bytes_init();
        // Safety: read_ptr gives the buffer start, bytes_init gives valid byte count
        let slice = unsafe { std::slice::from_raw_parts(buf.read_ptr(), init) };
        match self.0.write(slice).await {
            Ok(n) => (Ok(n), buf),
            Err(e) => (Err(e), buf),
        }
    }

    async fn writev<B: monoio::buf::IoVecBuf>(&mut self, buf: B) -> monoio::BufResult<usize, B> {
        (Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "writev not available over TLS adapter")), buf)
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        tokio::io::AsyncWriteExt::flush(&mut self.0).await
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        tokio::io::AsyncWriteExt::shutdown(&mut self.0).await
    }
}

/// Handle HTTP/1.1 traffic over a tokio-rustls TLS stream.
///
/// Wraps the TLS stream in a `TokioCompat` adapter so the existing
/// monoio-based connection handler can drive it. This path is used when
/// ALPN negotiation selects "http/1.1" instead of "h2".
async fn handle_h1_over_poll_tls<IO>(
    tls_stream: tokio_rustls::server::TlsStream<IO>,
    live_router: Rc<Arc<LiveRouter>>,
    dispatcher: Rc<Arc<JsDispatcher>>,
    server_config: Rc<Arc<HttpServerConfig>>,
    session_store: Option<Rc<Arc<session::SessionStore>>>,
    peer_addr: Option<SocketAddr>,
) -> Result<()>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    handle_connection(
        TokioCompat(tls_stream),
        live_router,
        dispatcher,
        server_config,
        session_store,
        peer_addr,
    )
    .await
}

// ─── Connection Handler with Buffer Pool

async fn handle_connection<S>(
    mut stream: S,
    live_router: Rc<Arc<LiveRouter>>,
    dispatcher: Rc<Arc<JsDispatcher>>,
    server_config: Rc<Arc<HttpServerConfig>>,
    session_store: Option<Rc<Arc<session::SessionStore>>>,
    peer_addr: Option<SocketAddr>,
) -> Result<()>
where
    S: AsyncReadRent + AsyncWriteRent + Unpin,
{
    let mut buffer = acquire_buffer();
    let peer_ip = peer_addr.map(|addr| addr.ip().to_string());

    let result = handle_connection_inner(
        &mut stream,
        &mut buffer,
        live_router.as_ref().as_ref(),
        &dispatcher,
        &server_config,
        peer_ip.as_deref(),
        session_store.as_deref().map(|arc| arc.as_ref()),
    )
    .await;

    release_buffer(buffer);
    result
}

async fn handle_connection_inner<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    live_router: &LiveRouter,
    dispatcher: &JsDispatcher,
    server_config: &HttpServerConfig,
    peer_ip: Option<&str>,
    session_store: Option<&session::SessionStore>,
) -> Result<()>
where
    S: AsyncReadRent + AsyncWriteRent + Unpin,
{
    loop {
        let router = live_router.router.load_full();

        /* @S8: deadline tracks total wall-clock time for header accumulation.
         * Starts unset; initialized on first byte of a new request. Prevents
         * slow-loris attacks that drip-feed bytes to reset per-read timeouts. */
        let mut header_deadline: Option<std::time::Instant> = None;

        /* The first read of a new request uses the longer idle/keep-alive
         * timeout. Once bytes arrive, subsequent reads use the shorter
         * header-read timeout. */
        let mut awaiting_new_request = true;

        // Try hot-path parsing first (GET / with known prefix)
        let parsed = loop {
            let result = if router.exact_get_root().is_some() {
                parse_hot_root_request(buffer, server_config)
                    .or_else(|| parse_request_httparse(buffer))
            } else {
                parse_request_httparse(buffer)
            };

            if let Some(parsed) = result {
                break parsed;
            }

            if find_header_end(buffer).is_some() {
                // Headers complete but couldn't parse — malformed request
                stream.shutdown().await?;
                return Ok(());
            }

            // SAFETY: We take ownership of the buffer, read into it, then put it back
            let owned_buf = std::mem::take(buffer);
            let read_duration = if awaiting_new_request {
                TIMEOUT_IDLE_KEEPALIVE
            } else {
                TIMEOUT_HEADER_READ
            };

            let timeout_result = timeout(read_duration, stream.read(owned_buf)).await;
            let (read_result, next_buffer) = match timeout_result {
                Ok(res) => res,
                Err(_) => {
                    // Per-read timeout expired
                    return Ok(());
                }
            };

            *buffer = next_buffer;
            let bytes_read = read_result?;

            if bytes_read == 0 {
                return Ok(());
            }

            awaiting_new_request = false;

            /* @S8: start the header deadline on the first byte of a new request */
            if header_deadline.is_none() {
                header_deadline = Some(std::time::Instant::now() + TIMEOUT_HEADER_DEADLINE);
            }

            /* @S8: enforce total header-phase wall-clock deadline */
            if let Some(deadline) = header_deadline {
                if std::time::Instant::now() >= deadline {
                    let response = build_error_response_bytes(
                        408,
                        b"{\"error\":\"Request Timeout\"}",
                        false,
                    );
                    let (write_result, _) = stream.write_all(response).await;
                    let _ = write_result;
                    stream.shutdown().await?;
                    return Ok(());
                }
            }

            if buffer.len() > server_config.max_header_bytes {
                // Security: Request header too large
                let response = build_error_response_bytes(
                    431,
                    b"{\"error\":\"Request Header Fields Too Large\"}",
                    false,
                );
                let (write_result, _) = stream.write_all(response).await;
                write_result?;
                stream.shutdown().await?;
                return Ok(());
            }
        };

        let header_bytes = parsed.header_bytes;
        let keep_alive = parsed.keep_alive;
        let has_body = parsed.has_body;
        let content_length = parsed.content_length;
        let accepted_encoding = parsed.accepted_encoding;

        /* @DX-6.3: track in-flight requests for graceful shutdown draining.
         * The guard decrements the counter on drop, ensuring correct counting
         * regardless of which code path exits the request (error, early return,
         * or normal completion). */
        INFLIGHT_REQUESTS.fetch_add(1, Ordering::Release);
        struct InflightGuard;
        impl Drop for InflightGuard {
            fn drop(&mut self) {
                INFLIGHT_REQUESTS.fetch_sub(1, Ordering::Release);
            }
        }
        let _inflight = InflightGuard;

        // Security (S1): reject requests with non-identity Transfer-Encoding
        if parsed.has_chunked_te {
            drop(parsed);
            drain_consumed_bytes(buffer, header_bytes);
            let (status, body) = if content_length.is_some() {
                // TE + CL = request smuggling vector
                (400u16, &b"{\"error\":\"Bad Request: conflicting Content-Length and Transfer-Encoding\"}"[..])
            } else {
                (501u16, &b"{\"error\":\"Not Implemented: chunked transfer encoding is not supported\"}"[..])
            };
            let response = build_error_response_bytes(status, body, false);
            let (write_result, _) = stream.write_all(response).await;
            write_result?;
            stream.shutdown().await?;
            return Ok(());
        }

        // ── Fast path: static routes (zero-copy from borrowed parse data) ──
        if !has_body && parsed.method == b"GET" {
            if parsed.path == b"/" {
                if let Some(static_route) = router.exact_get_root() {
                    drop(parsed);
                    drain_consumed_bytes(buffer, header_bytes);
                    write_exact_static_response(stream, static_route, keep_alive, accepted_encoding).await?;
                    if !keep_alive {
                        stream.shutdown().await?;
                        return Ok(());
                    }
                    continue;
                }
            }
            if let Some(static_route) = router.exact_static_route(parsed.method, parsed.path) {
                drop(parsed);
                drain_consumed_bytes(buffer, header_bytes);
                write_exact_static_response(stream, static_route, keep_alive, accepted_encoding).await?;
                if !keep_alive {
                    stream.shutdown().await?;
                    return Ok(());
                }
                continue;
            }
        }

        // ── WebSocket upgrade check ──
        if parsed.is_websocket_upgrade {
            if let Some(ws_key) = parsed.ws_key {
                if let Some(ws_handler_id) = router.match_ws_route(std::str::from_utf8(parsed.path).unwrap_or("/")) {
                    let accept_key = crate::websocket::compute_accept_key(ws_key);
                    let upgrade_response = crate::websocket::build_upgrade_response(&accept_key);
                    drop(parsed);
                    drain_consumed_bytes(buffer, header_bytes);

                    let (write_result, _) = stream.write_all(upgrade_response).await;
                    write_result?;

                    // Enter WebSocket frame loop
                    handle_websocket_connection(stream, buffer, ws_handler_id, dispatcher).await?;
                    return Ok(());
                }
            }
        }

        // ── Zero-copy path: non-body requests ──
        // Build dispatch envelope directly from borrowed parse data, avoiding
        // String/Vec allocations for method, target, path, and headers.
        if !has_body {
            let dispatch_decision =
                build_dispatch_decision_zero_copy(router.as_ref(), &parsed, &[], peer_ip, accepted_encoding, server_config.compression.as_ref())?;

            // Extract session before dropping parsed
            let (session_id, is_new_session) = resolve_session(session_store, parsed.cookie_header);

            drop(parsed);
            drain_consumed_bytes(buffer, header_bytes);

            match dispatch_decision {
                DispatchDecision::BridgeRequest(request, cache_insertion, handler_id, cache_namespace, url_bytes) => {
                    write_dynamic_dispatch_response(stream, dispatcher, request, keep_alive, cache_insertion, handler_id, cache_namespace, &url_bytes, session_store, session_id, is_new_session, accepted_encoding, server_config.compression.as_ref())
                        .await?;
                }
                DispatchDecision::SpecializedResponse(response) => {
                    let (write_result, _) = stream.write_all(response).await;
                    write_result?;
                }
                DispatchDecision::CachedResponse(response) => {
                    let (write_result, _) = stream.write_all(response).await;
                    write_result?;
                }
            }

            if !keep_alive {
                stream.shutdown().await?;
                return Ok(());
            }
            continue;
        }

        /* @DX-3.4: pre-match route to determine per-route body size limit.
         * This runs before the body is read so oversized payloads are rejected
         * without wasting I/O or memory. */
        let route_body_limit = {
            let method_code = method_code_from_bytes(parsed.method).unwrap_or(UNKNOWN_METHOD_CODE);
            let path_str = std::str::from_utf8(parsed.path).unwrap_or("/");
            let normalized = normalize_runtime_path(path_str);
            if method_code != UNKNOWN_METHOD_CODE {
                router.match_route(method_code, normalized.as_ref())
                    .and_then(|m| m.max_body_bytes)
            } else {
                None
            }
        };

        // ── Body requests: need owned copies to release buffer for body read ──
        //
        // @P1: coalesce method + target + path into a single allocation and
        // pack all header name/value pairs into one flat buffer with offset
        // ranges. Avoids N individual String allocations per header.
        let method_len = parsed.method.len();
        let target_len = parsed.target.len();
        let path_len = parsed.path.len();
        let mtp_total = method_len + target_len + path_len;
        let mut mtp_buf = Vec::with_capacity(mtp_total);
        mtp_buf.extend_from_slice(parsed.method);
        mtp_buf.extend_from_slice(parsed.target);
        mtp_buf.extend_from_slice(parsed.path);
        let method_owned = &mtp_buf[..method_len];
        let target_owned = &mtp_buf[method_len..method_len + target_len];
        let path_owned = &mtp_buf[method_len + target_len..];

        let header_count = parsed.headers.len();
        let mut hdr_buf_size = 0;
        for (n, v) in &parsed.headers {
            hdr_buf_size += n.len() + v.len();
        }
        let mut hdr_buf = Vec::with_capacity(hdr_buf_size);
        /* (name_start, name_len, value_start, value_len) per header */
        let mut hdr_ranges: Vec<(usize, usize, usize, usize)> = Vec::with_capacity(header_count);
        for (n, v) in &parsed.headers {
            let ns = hdr_buf.len();
            hdr_buf.extend_from_slice(n.as_bytes());
            let vs = hdr_buf.len();
            hdr_buf.extend_from_slice(v.as_bytes());
            hdr_ranges.push((ns, n.len(), vs, v.len()));
        }
        let (session_id_body, is_new_session_body) = resolve_session(session_store, parsed.cookie_header);
        drop(parsed);

        // ── Read request body 
        let body_bytes: Vec<u8> = {
            let content_length = match content_length {
                Some(len) => len,
                None => {
                    let response =
                        build_error_response_bytes(411, b"{\"error\":\"Length Required\"}", false);
                    let (write_result, _) = stream.write_all(response).await;
                    write_result?;
                    stream.shutdown().await?;
                    return Ok(());
                }
            };

            /* @DX-3.4: use per-route body limit when configured, otherwise
             * fall back to the global MAX_BODY_BYTES constant. */
            let effective_body_limit = route_body_limit.unwrap_or(MAX_BODY_BYTES);
            if content_length > effective_body_limit {
                let response =
                    build_error_response_bytes(413, b"{\"error\":\"Payload Too Large\"}", false);
                let (write_result, _) = stream.write_all(response).await;
                write_result?;
                stream.shutdown().await?;
                return Ok(());
            }

            let already_in_buffer = if buffer.len() > header_bytes {
                buffer.len() - header_bytes
            } else {
                0
            };

            if already_in_buffer >= content_length {
                let body = buffer[header_bytes..header_bytes + content_length].to_vec();
                drain_consumed_bytes(buffer, header_bytes + content_length);
                body
            } else {
                let mut body = Vec::with_capacity(content_length);
                if already_in_buffer > 0 {
                    body.extend_from_slice(&buffer[header_bytes..]);
                }
                drain_consumed_bytes(buffer, buffer.len());

                while body.len() < content_length {
                    let remaining = content_length - body.len();
                    let chunk_buf = vec![0u8; remaining.min(65536)];
                    let timeout_result = timeout(TIMEOUT_BODY_READ, stream.read(chunk_buf)).await;
                    let (read_result, returned_buf) = match timeout_result {
                        Ok(res) => res,
                        Err(_) => return Ok(()),
                    };
                    let bytes_read = read_result?;
                    if bytes_read == 0 {
                        return Ok(());
                    }
                    body.extend_from_slice(&returned_buf[..bytes_read]);
                }
                body.truncate(content_length);
                body
            }
        };

        /* @P1: build (&str, &str) header refs directly from the packed buffer —
         * all bytes were valid UTF-8 from httparse, so this avoids N individual
         * String heap allocations. */
        let header_refs: Vec<(&str, &str)> = hdr_ranges
            .iter()
            .map(|&(ns, nl, vs, vl)| {
                let name = std::str::from_utf8(&hdr_buf[ns..ns + nl]).unwrap_or("");
                let value = std::str::from_utf8(&hdr_buf[vs..vs + vl]).unwrap_or("");
                (name, value)
            })
            .collect();

        let dispatch_decision_owned = build_dispatch_decision_owned(
            router.as_ref(),
            method_owned,
            target_owned,
            path_owned,
            &header_refs,
            &body_bytes,
            peer_ip,
            accepted_encoding,
        )?;

        match dispatch_decision_owned {
            DispatchDecision::BridgeRequest(request, cache_insertion, handler_id, cache_namespace, url_bytes) => {
                write_dynamic_dispatch_response(stream, dispatcher, request, keep_alive, cache_insertion, handler_id, cache_namespace, &url_bytes, session_store, session_id_body, is_new_session_body, accepted_encoding, server_config.compression.as_ref()).await?;
            }
            DispatchDecision::SpecializedResponse(response) => {
                let (write_result, _) = stream.write_all(response).await;
                write_result?;
            }
            DispatchDecision::CachedResponse(response) => {
                let (write_result, _) = stream.write_all(response).await;
                write_result?;
            }
        }

        if !keep_alive {
            stream.shutdown().await?;
            return Ok(());
        }
    }
}

// ─── Hot Root Path (GET /) ──────────────
//
// Ultra-fast path for the most common benchmark case. Falls back to httparse
// if the request doesn't exactly match the expected prefix.

fn parse_hot_root_request(
    bytes: &[u8],
    server_config: &HttpServerConfig,
) -> Option<ParsedRequest<'static>> {
    let (_, keep_alive) = if bytes.starts_with(server_config.hot_get_root_http11.as_slice()) {
        (server_config.hot_get_root_http11.len(), true)
    } else if bytes.starts_with(server_config.hot_get_root_http10.as_slice()) {
        (server_config.hot_get_root_http10.len(), false)
    } else {
        return None;
    };

    let header_end = find_header_end(bytes)?;
    let mut keep_alive = keep_alive;
    let mut has_body = false;
    let mut has_chunked_te = false;
    let mut content_length: Option<usize> = None;
    let mut accepted_encoding = compress::AcceptedEncoding::Identity;
    let mut line_start = bytes.iter().position(|b| *b == b'\n')? + 1;

    while line_start + 2 <= header_end {
        let next_end = memmem::find(&bytes[line_start..header_end + 2], b"\r\n")? + line_start;

        if next_end == line_start {
            break;
        }

        let line = &bytes[line_start..next_end];
        if line.len() >= server_config.header_connection_prefix.len()
            && line[..server_config.header_connection_prefix.len()]
                .eq_ignore_ascii_case(server_config.header_connection_prefix.as_slice())
        {
            let value = &line[server_config.header_connection_prefix.len()..];
            if contains_ascii_case_insensitive(value, b"close") {
                keep_alive = false;
            }
            if contains_ascii_case_insensitive(value, b"keep-alive") {
                keep_alive = true;
            }
        } else if line.len() >= server_config.header_content_length_prefix.len()
            && line[..server_config.header_content_length_prefix.len()]
                .eq_ignore_ascii_case(server_config.header_content_length_prefix.as_slice())
        {
            let value =
                trim_ascii_spaces(&line[server_config.header_content_length_prefix.len()..]);
            /* @B4: parse Content-Length for TE+CL smuggling detection */
            if let Some(len) = std::str::from_utf8(value)
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
            {
                content_length = Some(len);
                if len > 0 {
                    has_body = true;
                }
            }
        } else if line.len() >= server_config.header_transfer_encoding_prefix.len()
            && line[..server_config.header_transfer_encoding_prefix.len()]
                .eq_ignore_ascii_case(server_config.header_transfer_encoding_prefix.as_slice())
        {
            let value =
                trim_ascii_spaces(&line[server_config.header_transfer_encoding_prefix.len()..]);
            /* @B4: flag non-identity Transfer-Encoding for smuggling guard */
            if !value.is_empty() && !value.eq_ignore_ascii_case(b"identity") {
                has_body = true;
                has_chunked_te = true;
            }
        } else if accepted_encoding != compress::AcceptedEncoding::Brotli
            && line.len() >= 17
            && line[..16].eq_ignore_ascii_case(b"accept-encoding:")
        {
            let value = trim_ascii_spaces(&line[16..]);
            accepted_encoding = compress::parse_accept_encoding(value);
        }

        line_start = next_end + 2;
    }

    Some(ParsedRequest {
        method: b"GET",
        target: b"/",
        path: b"/",
        keep_alive,
        header_bytes: header_end + 4,
        has_body,
        content_length,
        has_chunked_te,
        headers: Vec::new(),
        cookie_header: None,
        is_websocket_upgrade: false,
        ws_key: None,
        accepted_encoding,
    })
}

// ─── Routing ────────────────────────────

// ─── Bridge Envelope Building (Single-Pass Headers) ───────────────────────────
//
// Uses the pre-parsed headers from httparse — no second scan of the raw bytes.

/// Zero-copy dispatch: builds the bridge envelope directly from borrowed parse data,
/// avoiding all String/Vec allocations for method, target, path, and headers.
/// Used for non-body requests (GET, DELETE without body, etc.).
enum DispatchDecision {
    /// (envelope, route-level cache insertion, handler_id, cache_namespace, url_bytes for ncache key)
    BridgeRequest(Buffer, Option<(u64, u64, usize, u64)>, u32, Option<u64>, Vec<u8>),
    SpecializedResponse(Vec<u8>),
    CachedResponse(bytes::Bytes),
}

fn build_dispatch_decision_zero_copy(
    router: &Router,
    parsed: &ParsedRequest<'_>,
    body: &[u8],
    peer_ip: Option<&str>,
    accepted_encoding: compress::AcceptedEncoding,
    compression_config: Option<&compress::CompressionConfig>,
) -> Result<DispatchDecision> {
    let method_code = method_code_from_bytes(parsed.method).unwrap_or(UNKNOWN_METHOD_CODE);
    let path_cow = String::from_utf8_lossy(parsed.path);
    let path_str = path_cow.as_ref();
    let url_cow = String::from_utf8_lossy(parsed.target);
    let url_str = url_cow.as_ref();

    let normalized_path = normalize_runtime_path(path_str);
    if contains_path_traversal(&normalized_path) {
        return build_not_found_dispatch_envelope(
            method_code,
            path_str,
            url_str,
            &parsed.headers,
            body,
            peer_ip,
        )
        .map(|envelope| DispatchDecision::BridgeRequest(envelope, None, NOT_FOUND_HANDLER_ID, None, Vec::new()));
    }

    let matched_route = if method_code == UNKNOWN_METHOD_CODE {
        None
    } else {
        router.match_route(method_code, normalized_path.as_ref())
    };

    let Some(matched_route) = matched_route else {
        return build_not_found_dispatch_envelope(
            method_code,
            path_str,
            url_str,
            &parsed.headers,
            body,
            peer_ip,
        )
        .map(|envelope| DispatchDecision::BridgeRequest(envelope, None, NOT_FOUND_HANDLER_ID, None, Vec::new()));
    };

    let mut cache_insertion = None;
    if let Some(cfg) = matched_route.cache_config {
         let base_key = crate::router::interpolate_cache_key(cfg, &parsed.headers, url_str, matched_route.param_names, &matched_route.param_values);
         let key = vary_cache_key_by_encoding(base_key, accepted_encoding);
         if let Some(cached_response) = crate::router::get_cached_response(matched_route.cache_namespace, key, parsed.keep_alive) {
             return Ok(DispatchDecision::CachedResponse(cached_response));
         }
         cache_insertion = Some((matched_route.cache_namespace, key, cfg.max_entries, cfg.ttl_secs));
    } else {
        // ncache lookup: check if a previous res.ncache() call cached this response
        let ncache_key = vary_cache_key_by_encoding(compute_ncache_key(parsed.target), accepted_encoding);
        if let Some(cached_response) = crate::router::get_cached_response(matched_route.cache_namespace, ncache_key, parsed.keep_alive) {
            return Ok(DispatchDecision::CachedResponse(cached_response));
        }
    }

    if let Some(response) =
        build_dynamic_fast_path_response(&matched_route, url_str, &parsed.headers, parsed.keep_alive, accepted_encoding, compression_config)?
    {
        return Ok(DispatchDecision::SpecializedResponse(response));
    };

    let handler_id = matched_route.handler_id;
    let url_bytes_owned = parsed.target.to_vec();

    build_dispatch_envelope(
        &matched_route,
        method_code,
        path_str,
        url_str,
        &parsed.headers,
        body,
        peer_ip,
    )
    .map(|envelope| DispatchDecision::BridgeRequest(
        envelope,
        cache_insertion,
        handler_id,
        Some(matched_route.cache_namespace),
        url_bytes_owned,
    ))
}

/// /* @param router   — compiled route table */
/// /* @param method   — raw HTTP method bytes */
/// /* @param target   — raw request target (URL) bytes */
/// /* @param path     — path portion (before '?') bytes */
/// /* @param headers  — pre-parsed (name, value) str pairs */
/// /* @param body     — request body bytes */
/// /* @param peer_ip  — client IP string, if known */
/// /* @param accepted_encoding — best encoding from Accept-Encoding */
fn build_dispatch_decision_owned<'a>(
    router: &Router,
    method: &[u8],
    target: &[u8],
    path: &[u8],
    headers: &[(&'a str, &'a str)],
    body: &[u8],
    peer_ip: Option<&str>,
    accepted_encoding: compress::AcceptedEncoding,
) -> Result<DispatchDecision> {
    let method_code = method_code_from_bytes(method).unwrap_or(UNKNOWN_METHOD_CODE);

    let path_cow = String::from_utf8_lossy(path);
    let path_str = path_cow.as_ref();
    let url_cow = String::from_utf8_lossy(target);
    let url_str = url_cow.as_ref();

    let header_refs = headers;

    // Security: strict path validation
    let normalized_path = normalize_runtime_path(path_str);
    if contains_path_traversal(&normalized_path) {
        return build_not_found_dispatch_envelope(
            method_code,
            path_str,
            url_str,
            &header_refs,
            body,
            peer_ip,
        )
        .map(|envelope| DispatchDecision::BridgeRequest(envelope, None, NOT_FOUND_HANDLER_ID, None, Vec::new()));
    }

    let matched_route = if method_code == UNKNOWN_METHOD_CODE {
        None
    } else {
        router.match_route(method_code, normalized_path.as_ref())
    };

    let Some(matched_route) = matched_route else {
        return build_not_found_dispatch_envelope(
            method_code,
            path_str,
            url_str,
            &header_refs,
            body,
            peer_ip,
        )
        .map(|envelope| DispatchDecision::BridgeRequest(envelope, None, NOT_FOUND_HANDLER_ID, None, Vec::new()));
    };

    let mut cache_insertion = None;
    if let Some(cfg) = matched_route.cache_config {
         /* @BOOST-1.3: pass header slice directly — avoids constructing a
          * throwaway ParsedRequest and the .to_vec() clone that entailed. */
         let base_key = crate::router::interpolate_cache_key(cfg, header_refs, url_str, matched_route.param_names, &matched_route.param_values);
         let key = vary_cache_key_by_encoding(base_key, accepted_encoding);
         cache_insertion = Some((matched_route.cache_namespace, key, cfg.max_entries, cfg.ttl_secs));
    } else {
        // ncache lookup: check if a previous res.ncache() call cached this response
        let ncache_key = vary_cache_key_by_encoding(compute_ncache_key(target), accepted_encoding);
        if let Some(cached_response) = crate::router::get_cached_response(matched_route.cache_namespace, ncache_key, false) {
            return Ok(DispatchDecision::CachedResponse(cached_response));
        }
    }

    let handler_id = matched_route.handler_id;
    let url_bytes_owned = target.to_vec();

    build_dispatch_envelope(
        &matched_route,
        method_code,
        path_str,
        url_str,
        &header_refs,
        body,
        peer_ip,
    )
    .map(|envelope| DispatchDecision::BridgeRequest(
        envelope,
        cache_insertion,
        handler_id,
        Some(matched_route.cache_namespace),
        url_bytes_owned,
    ))
}

fn build_not_found_dispatch_envelope(
    method_code: u8,
    path: &str,
    url: &str,
    header_entries: &[(&str, &str)],
    body: &[u8],
    peer_ip: Option<&str>,
) -> Result<Buffer> {
    let url_bytes = url.as_bytes();
    let path_bytes = path.as_bytes();
    let mut flags: u16 = 0;
    if url.contains('?') {
        flags |= REQUEST_FLAG_QUERY_PRESENT;
    }
    if !body.is_empty() {
        flags |= REQUEST_FLAG_BODY_PRESENT;
    }

    if url_bytes.len() > u32::MAX as usize {
        return Err(anyhow!("request url too large"));
    }
    if path_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("request path too large"));
    }
    if header_entries.len() > u16::MAX as usize {
        return Err(anyhow!("too many headers"));
    }

    let ip_bytes = peer_ip.unwrap_or("").as_bytes();
    if ip_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("request ip too large"));
    }

    let mut frame = Vec::with_capacity(
        22 + url_bytes.len() + path_bytes.len() + ip_bytes.len() + header_entries.len() * 16 + body.len(),
    );
    frame.push(BRIDGE_VERSION);
    frame.push(method_code);
    push_u16(&mut frame, flags);
    push_u32(&mut frame, NOT_FOUND_HANDLER_ID);
    push_u32(&mut frame, url_bytes.len() as u32);
    push_u16(&mut frame, path_bytes.len() as u16);
    push_u16(&mut frame, 0);
    push_u16(&mut frame, header_entries.len() as u16);
    push_u32(&mut frame, body.len() as u32);
    push_u16(&mut frame, ip_bytes.len() as u16);
    frame.extend_from_slice(url_bytes);
    frame.extend_from_slice(path_bytes);
    frame.extend_from_slice(ip_bytes);

    for (name, value) in header_entries {
        push_string_pair(&mut frame, name, value)?;
    }

    frame.extend_from_slice(body);
    Ok(Buffer::from(frame))
}

fn build_dispatch_envelope(
    matched_route: &MatchedRoute<'_, '_>,
    method_code: u8,
    path: &str,
    url: &str,
    header_entries: &[(&str, &str)],
    body: &[u8],
    peer_ip: Option<&str>,
) -> Result<Buffer> {
    let include_url = matched_route.needs_url || matched_route.needs_query;
    let include_path = matched_route.needs_path;
    let url_bytes = if include_url { url.as_bytes() } else { b"" };
    let path_bytes = if include_path { path.as_bytes() } else { b"" };
    let mut flags: u16 = 0;
    if matched_route.needs_query && url.contains('?') {
        flags |= REQUEST_FLAG_QUERY_PRESENT;
    }
    if !body.is_empty() {
        flags |= REQUEST_FLAG_BODY_PRESENT;
    }

    if url_bytes.len() > u32::MAX as usize {
        return Err(anyhow!("request url too large"));
    }
    if path_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("request path too large"));
    }
    if matched_route.param_values.len() > u16::MAX as usize {
        return Err(anyhow!("too many params"));
    }
    let selected_header_count = count_selected_headers(header_entries, matched_route);
    if selected_header_count > u16::MAX as usize {
        return Err(anyhow!("too many headers"));
    }

    let ip_bytes = peer_ip.unwrap_or("").as_bytes();
    if ip_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("request ip too large"));
    }

    let mut frame = Vec::with_capacity(
        22
            + url_bytes.len()
            + path_bytes.len()
            + ip_bytes.len()
            + selected_header_count * 16
            + body.len(),
    );
    frame.push(BRIDGE_VERSION);
    frame.push(method_code);
    push_u16(&mut frame, flags);
    push_u32(&mut frame, matched_route.handler_id);
    push_u32(&mut frame, url_bytes.len() as u32);
    push_u16(&mut frame, path_bytes.len() as u16);
    push_u16(&mut frame, matched_route.param_values.len() as u16);
    push_u16(&mut frame, selected_header_count as u16);
    push_u32(&mut frame, body.len() as u32);
    push_u16(&mut frame, ip_bytes.len() as u16);
    frame.extend_from_slice(url_bytes);
    frame.extend_from_slice(path_bytes);
    frame.extend_from_slice(ip_bytes);

    for value in matched_route.param_values.iter() {
        push_string_value(&mut frame, value)?;
    }

    if selected_header_count > 0 {
        for (name, value) in header_entries {
            if should_include_header(name, matched_route) {
                push_string_pair(&mut frame, name, value)?;
            }
        }
    }

    frame.extend_from_slice(body);

    Ok(Buffer::from(frame))
}

fn count_selected_headers(
    header_entries: &[(&str, &str)],
    matched_route: &MatchedRoute<'_, '_>,
) -> usize {
    if matched_route.full_headers {
        return header_entries.len();
    }

    if matched_route.header_keys.is_empty() {
        return 0;
    }

    header_entries
        .iter()
        .filter(|(name, _)| should_include_header(name, matched_route))
        .count()
}

fn should_include_header(name: &str, matched_route: &MatchedRoute<'_, '_>) -> bool {
    if matched_route.full_headers {
        return true;
    }
    matched_route
        .header_keys
        .iter()
        .any(|target| target.as_ref().eq_ignore_ascii_case(name))
}

enum ResolvedDynamicValue {
    Missing,
    Single(String),
    Multi(Vec<String>),
    RawJson(Vec<u8>),
}

fn build_dynamic_fast_path_response(
    matched_route: &MatchedRoute<'_, '_>,
    url: &str,
    headers: &[(&str, &str)],
    keep_alive: bool,
    encoding: compress::AcceptedEncoding,
    compression_config: Option<&compress::CompressionConfig>,
) -> Result<Option<Vec<u8>>> {
    let Some(fast_path) = matched_route.fast_path else {
        return Ok(None);
    };

    let mut query_cache: Option<Vec<(String, String)>> = None;
    let body = match &fast_path.response {
        DynamicFastPathResponse::Json(template) => {
            render_dynamic_json_body(template, matched_route, url, headers, &mut query_cache)?
        }
        DynamicFastPathResponse::Text(template) => {
            render_dynamic_text_body(template, matched_route, url, headers, &mut query_cache)
        }
    };

    Ok(Some(build_response_bytes_fast(
        fast_path.status,
        fast_path.headers.as_ref(),
        &body,
        keep_alive,
        encoding,
        compression_config,
    )))
}

fn render_dynamic_json_body(
    template: &crate::analyzer::JsonTemplate,
    matched_route: &MatchedRoute<'_, '_>,
    url: &str,
    headers: &[(&str, &str)],
    query_cache: &mut Option<Vec<(String, String)>>,
) -> Result<Vec<u8>> {
    match &template.kind {
        JsonTemplateKind::Literal(bytes) => Ok(bytes.to_vec()),
        JsonTemplateKind::Object(fields) => {
            let mut output = Vec::with_capacity(fields.len() * 24 + 16);
            output.push(b'{');
            let mut wrote_field = false;

            for field in fields.iter() {
                match &field.value {
                    JsonValueTemplate::Literal(value_bytes) => {
                        if wrote_field {
                            output.push(b',');
                        }
                        output.extend_from_slice(field.key_prefix.as_ref());
                        output.extend_from_slice(value_bytes.as_ref());
                        wrote_field = true;
                    }
                    JsonValueTemplate::Dynamic(source) => {
                        let resolved =
                            resolve_dynamic_value(source, matched_route, url, headers, query_cache);
                        match resolved {
                            ResolvedDynamicValue::Missing => {}
                            ResolvedDynamicValue::Single(value) => {
                                if wrote_field {
                                    output.push(b',');
                                }
                                output.extend_from_slice(field.key_prefix.as_ref());
                                append_json_string(&mut output, value.as_str());
                                wrote_field = true;
                            }
                            ResolvedDynamicValue::Multi(values) => {
                                if wrote_field {
                                    output.push(b',');
                                }
                                output.extend_from_slice(field.key_prefix.as_ref());
                                output.push(b'[');
                                for (index, value) in values.iter().enumerate() {
                                    if index > 0 {
                                        output.push(b',');
                                    }
                                    append_json_string(&mut output, value.as_str());
                                }
                                output.push(b']');
                                wrote_field = true;
                            }
                            ResolvedDynamicValue::RawJson(raw) => {
                                if wrote_field {
                                    output.push(b',');
                                }
                                output.extend_from_slice(field.key_prefix.as_ref());
                                output.extend_from_slice(raw.as_slice());
                                wrote_field = true;
                            }
                        }
                    }
                }
            }

            output.push(b'}');
            Ok(output)
        }
    }
}

fn render_dynamic_text_body(
    template: &crate::analyzer::TextTemplate,
    matched_route: &MatchedRoute<'_, '_>,
    url: &str,
    headers: &[(&str, &str)],
    query_cache: &mut Option<Vec<(String, String)>>,
) -> Vec<u8> {
    let mut output = String::new();
    for segment in template.segments.iter() {
        match segment {
            TextSegment::Literal(value) => output.push_str(value.as_ref()),
            TextSegment::Dynamic(source) => match resolve_dynamic_value(
                source,
                matched_route,
                url,
                headers,
                query_cache,
            ) {
                ResolvedDynamicValue::Missing => output.push_str("undefined"),
                ResolvedDynamicValue::Single(value) => output.push_str(value.as_str()),
                ResolvedDynamicValue::Multi(values) => {
                    for (index, value) in values.iter().enumerate() {
                        if index > 0 {
                            output.push(',');
                        }
                        output.push_str(value.as_str());
                    }
                }
                ResolvedDynamicValue::RawJson(bytes) => {
                    output.push_str(String::from_utf8_lossy(bytes.as_slice()).as_ref());
                }
            },
        }
    }

    output.into_bytes()
}

fn resolve_dynamic_value(
    source: &crate::analyzer::DynamicValueSource,
    matched_route: &MatchedRoute<'_, '_>,
    url: &str,
    headers: &[(&str, &str)],
    query_cache: &mut Option<Vec<(String, String)>>,
) -> ResolvedDynamicValue {
    match source.kind {
        DynamicValueSourceKind::Param => {
            if let Some(value) = lookup_param_value(matched_route, source.key.as_ref()) {
                return ResolvedDynamicValue::Single(value.to_string());
            }
            ResolvedDynamicValue::Missing
        }
        DynamicValueSourceKind::Header => {
            if let Some(value) = lookup_header_value(headers, source.key.as_ref()) {
                return ResolvedDynamicValue::Single(value.to_string());
            }
            ResolvedDynamicValue::Missing
        }
        DynamicValueSourceKind::Query => {
            let entries = query_entries(url, query_cache);
            lookup_query_value(entries.as_slice(), source.key.as_ref())
        }
        DynamicValueSourceKind::QueryObject => {
            let entries = query_entries(url, query_cache);
            ResolvedDynamicValue::RawJson(serialize_query_object_json(entries.as_slice()))
        }
    }
}

fn lookup_param_value<'m, 'r, 'p>(
    matched_route: &'m MatchedRoute<'r, 'p>,
    key: &str,
) -> Option<&'p str> {
    for (index, name) in matched_route.param_names.iter().enumerate() {
        if name.as_ref() == key {
            return matched_route.param_values.get(index).copied();
        }
    }
    None
}

fn lookup_header_value<'a>(headers: &[(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(key).then_some(*value))
}

fn query_entries<'a>(
    url: &str,
    cache: &'a mut Option<Vec<(String, String)>>,
) -> &'a Vec<(String, String)> {
    if cache.is_none() {
        let parsed = if let Some(query_start) = url.find('?') {
            let query = &url[query_start + 1..];
            form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        *cache = Some(parsed);
    }

    cache.as_ref().expect("query cache must be initialized")
}

fn lookup_query_value(entries: &[(String, String)], key: &str) -> ResolvedDynamicValue {
    let mut values: Vec<String> = Vec::new();
    for (entry_key, entry_value) in entries.iter() {
        if entry_key == key {
            values.push(entry_value.clone());
        }
    }

    match values.len() {
        0 => ResolvedDynamicValue::Missing,
        1 => ResolvedDynamicValue::Single(values.pop().unwrap_or_default()),
        _ => ResolvedDynamicValue::Multi(values),
    }
}

fn serialize_query_object_json(entries: &[(String, String)]) -> Vec<u8> {
    let mut buckets: Vec<(&str, Vec<&str>)> = Vec::new();

    for (entry_key, entry_value) in entries.iter() {
        if is_dangerous_query_key(entry_key.as_str()) {
            continue;
        }

        if let Some((_, values)) = buckets
            .iter_mut()
            .find(|(key, _)| *key == entry_key.as_str())
        {
            values.push(entry_value.as_str());
        } else {
            buckets.push((entry_key.as_str(), vec![entry_value.as_str()]));
        }
    }

    let mut output = Vec::with_capacity(entries.len() * 24 + 16);
    output.push(b'{');

    for (index, (key, values)) in buckets.iter().enumerate() {
        if index > 0 {
            output.push(b',');
        }

        append_json_string(&mut output, key);
        output.push(b':');
        if values.len() == 1 {
            append_json_string(&mut output, values[0]);
        } else {
            output.push(b'[');
            for (value_index, value) in values.iter().enumerate() {
                if value_index > 0 {
                    output.push(b',');
                }
                append_json_string(&mut output, value);
            }
            output.push(b']');
        }
    }

    output.push(b'}');
    output
}

fn is_dangerous_query_key(key: &str) -> bool {
    matches!(
        key,
        "__proto__"
            | "constructor"
            | "prototype"
            | "__defineGetter__"
            | "__defineSetter__"
            | "__lookupGetter__"
            | "__lookupSetter__"
    )
}

fn append_json_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => output.extend_from_slice(br#"\""#),
            '\\' => output.extend_from_slice(br#"\\"#),
            '\n' => output.extend_from_slice(br#"\n"#),
            '\r' => output.extend_from_slice(br#"\r"#),
            '\t' => output.extend_from_slice(br#"\t"#),
            '\x08' => output.extend_from_slice(br#"\b"#),
            '\x0C' => output.extend_from_slice(br#"\f"#),
            other if other.is_control() => {
                let escaped = format!("\\u{:04x}", other as u32);
                output.extend_from_slice(escaped.as_bytes());
            }
            other => {
                let mut buf = [0u8; 4];
                output.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    output.push(b'"');
}


// ─── Response Writing ───────────────────

async fn write_exact_static_response<S>(
    stream: &mut S,
    static_route: &ExactStaticRoute,
    keep_alive: bool,
    encoding: compress::AcceptedEncoding,
) -> Result<()>
where
    S: AsyncWriteRent + Unpin,
{
    let response = match (encoding, keep_alive) {
        (compress::AcceptedEncoding::Brotli, true) => {
            static_route.keep_alive_response_br.clone()
                .unwrap_or_else(|| static_route.keep_alive_response.clone())
        }
        (compress::AcceptedEncoding::Brotli, false) => {
            static_route.close_response_br.clone()
                .unwrap_or_else(|| static_route.close_response.clone())
        }
        (compress::AcceptedEncoding::Gzip, true) => {
            static_route.keep_alive_response_gzip.clone()
                .unwrap_or_else(|| static_route.keep_alive_response.clone())
        }
        (compress::AcceptedEncoding::Gzip, false) => {
            static_route.close_response_gzip.clone()
                .unwrap_or_else(|| static_route.close_response.clone())
        }
        (compress::AcceptedEncoding::Identity, true) => {
            static_route.keep_alive_response.clone()
        }
        (compress::AcceptedEncoding::Identity, false) => {
            static_route.close_response.clone()
        }
    };

    let (write_result, _) = stream.write_all(response).await;
    write_result?;
    Ok(())
}

// ─── ncache Support ────────────────────
//
// Extracts a cache trailer appended by JS `res.ncache()` after the response
// body in the dispatch envelope. Layout: magic(2) 0xCA 0xCE | ttl_secs(4) | max_entries(4)

/// Maximum ncache TTL (24 hours) to prevent accidental permanent caching.
const NCACHE_MAX_TTL_SECS: u64 = 86400;
/// Maximum response body size eligible for ncache (1 MB).
const NCACHE_MAX_BODY_SIZE: usize = 1024 * 1024;

/// Walk the response envelope to find where the body ends, then check for
/// the 10-byte ncache trailer. Returns (ttl_secs, max_entries) if present.
fn extract_ncache_trailer(dispatch_bytes: &[u8]) -> Option<(u64, usize)> {
    if dispatch_bytes.len() < 8 {
        return None;
    }

    // Parse the envelope header to find body end offset
    let mut offset = 0usize;
    let _status = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
    offset += 2;
    let header_count = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
    offset += 2;
    let body_length = (dispatch_bytes[offset] as u32)
        | ((dispatch_bytes[offset + 1] as u32) << 8)
        | ((dispatch_bytes[offset + 2] as u32) << 16)
        | ((dispatch_bytes[offset + 3] as u32) << 24);
    offset += 4;

    let body_length = body_length as usize;

    // Guard: don't cache oversized responses
    if body_length > NCACHE_MAX_BODY_SIZE {
        return None;
    }

    // Skip headers
    for _ in 0..header_count {
        if offset + 3 > dispatch_bytes.len() {
            return None;
        }
        let name_len = dispatch_bytes[offset] as usize;
        offset += 1;
        let value_len = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
        offset += 2;
        offset += name_len + value_len as usize;
    }

    // Skip body
    offset += body_length;

    // Check for 10-byte trailer: magic(2) + ttl(4) + max_entries(4)
    if offset + 10 > dispatch_bytes.len() {
        return None;
    }

    // Check magic bytes
    if dispatch_bytes[offset] != 0xCA || dispatch_bytes[offset + 1] != 0xCE {
        return None;
    }
    offset += 2;

    let ttl_secs = (dispatch_bytes[offset] as u64)
        | ((dispatch_bytes[offset + 1] as u64) << 8)
        | ((dispatch_bytes[offset + 2] as u64) << 16)
        | ((dispatch_bytes[offset + 3] as u64) << 24);
    offset += 4;

    let max_entries = (dispatch_bytes[offset] as u32)
        | ((dispatch_bytes[offset + 1] as u32) << 8)
        | ((dispatch_bytes[offset + 2] as u32) << 16)
        | ((dispatch_bytes[offset + 3] as u32) << 24);

    // Cap TTL to safety limit
    let ttl_secs = ttl_secs.min(NCACHE_MAX_TTL_SECS);

    Some((ttl_secs, max_entries as usize))
}

/// Compute an ncache key from the full request URL (including query string).
/// Different URLs naturally produce different cache keys, so /data?page=1 and
/// /data?page=2 are cached separately.
/// Uses FxHasher (~5x faster than SipHash/DefaultHasher for short keys).
fn compute_ncache_key(url_bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    /* Use SipHash (DefaultHasher) instead of FxHasher to prevent
     * cache poisoning via hash collision attacks. SipHash is
     * randomized per process, making collisions unpredictable. */
    let mut hasher = DefaultHasher::new();
    url_bytes.hash(&mut hasher);
    hasher.finish()
}

/// Mix accepted encoding into a cache key so that identity/br/gzip
/// requests are stored and looked up independently (Vary: Accept-Encoding).
#[inline]
fn vary_cache_key_by_encoding(key: u64, encoding: compress::AcceptedEncoding) -> u64 {
    match encoding {
        compress::AcceptedEncoding::Identity => key,
        compress::AcceptedEncoding::Gzip => key ^ 0x9E3779B97F4A7C15,
        compress::AcceptedEncoding::Brotli => key ^ 0x517CC1B727220A95,
    }
}

// ─── Session Trailer Extraction ────────
//
// Extracts session write instructions from the response envelope trailer.
// Magic: 0x5E 0x57 | action(1) | entry_count(2) | deleted_count(2) | entries... | deleted_keys...

struct SessionWriteTrailer {
    action: session::SessionAction,
    mutations: std::collections::HashMap<String, Vec<u8>>,
    deleted_keys: Vec<String>,
}

/// Find the body end offset in a response envelope (skip fixed header + all headers + body).
fn response_body_end_offset(dispatch_bytes: &[u8]) -> Option<usize> {
    if dispatch_bytes.len() < 8 {
        return None;
    }
    let mut offset = 0usize;
    let _status = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
    offset += 2;
    let header_count = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
    offset += 2;
    let body_length = (dispatch_bytes[offset] as u32)
        | ((dispatch_bytes[offset + 1] as u32) << 8)
        | ((dispatch_bytes[offset + 2] as u32) << 16)
        | ((dispatch_bytes[offset + 3] as u32) << 24);
    offset += 4;

    // Skip headers
    for _ in 0..header_count {
        if offset + 3 > dispatch_bytes.len() { return None; }
        let name_len = dispatch_bytes[offset] as usize;
        offset += 1;
        let value_len = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
        offset += 2;
        offset += name_len + value_len as usize;
    }

    // Skip body
    offset += body_length as usize;
    Some(offset)
}

/// Extract session write trailer from the response envelope.
/// Called after the ncache trailer position. Scans from `start_offset`.
fn extract_session_trailer(dispatch_bytes: &[u8], start_offset: usize) -> Option<SessionWriteTrailer> {
    let mut offset = start_offset;

    // Check for session magic (0x5E 0x57)
    if offset + 7 > dispatch_bytes.len() {
        return None;
    }
    if dispatch_bytes[offset] != 0x5E || dispatch_bytes[offset + 1] != 0x57 {
        return None;
    }
    offset += 2;

    let action_byte = dispatch_bytes[offset];
    offset += 1;
    let action = session::SessionAction::from_byte(action_byte)?;

    let entry_count = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
    offset += 2;

    let deleted_count = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
    offset += 2;

    let mut mutations = std::collections::HashMap::new();
    for _ in 0..entry_count {
        if offset + 2 > dispatch_bytes.len() { return None; }
        let key_len = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
        offset += 2;
        let key_len = key_len as usize;
        if offset + key_len > dispatch_bytes.len() { return None; }
        let key = std::str::from_utf8(&dispatch_bytes[offset..offset + key_len]).ok()?;
        offset += key_len;

        if offset + 4 > dispatch_bytes.len() { return None; }
        let value_len = (dispatch_bytes[offset] as u32)
            | ((dispatch_bytes[offset + 1] as u32) << 8)
            | ((dispatch_bytes[offset + 2] as u32) << 16)
            | ((dispatch_bytes[offset + 3] as u32) << 24);
        offset += 4;
        let value_len = value_len as usize;
        if offset + value_len > dispatch_bytes.len() { return None; }
        let value = dispatch_bytes[offset..offset + value_len].to_vec();
        offset += value_len;

        mutations.insert(key.to_string(), value);
    }

    let mut deleted_keys = Vec::new();
    for _ in 0..deleted_count {
        if offset + 2 > dispatch_bytes.len() { return None; }
        let key_len = (dispatch_bytes[offset] as u16) | ((dispatch_bytes[offset + 1] as u16) << 8);
        offset += 2;
        let key_len = key_len as usize;
        if offset + key_len > dispatch_bytes.len() { return None; }
        let key = std::str::from_utf8(&dispatch_bytes[offset..offset + key_len]).ok()?;
        offset += key_len;
        deleted_keys.push(key.to_string());
    }

    Some(SessionWriteTrailer {
        action,
        mutations,
        deleted_keys,
    })
}

async fn write_dynamic_dispatch_response<S>(
    stream: &mut S,
    dispatcher: &JsDispatcher,
    request: Buffer,
    keep_alive: bool,
    cache_insertion: Option<(u64, u64, usize, u64)>,
    handler_id: u32,
    cache_namespace: Option<u64>,
    url_bytes: &[u8],
    session_store: Option<&session::SessionStore>,
    session_id: Option<[u8; session::SESSION_ID_BYTES]>,
    is_new_session: bool,
    accepted_encoding: compress::AcceptedEncoding,
    compression_config: Option<&compress::CompressionConfig>,
) -> Result<()>
where
    S: AsyncWriteRent + Unpin,
{
    match dispatcher.dispatch(request).await {
        Ok(response) => {
            // ── Stream-start sentinel: 0xFF 0x53 ──
            // If JS returns a stream-start envelope instead of a normal response,
            // we enter chunked transfer mode and pipe chunks from JS via the
            // global stream registry.
            if response.len() >= 14 && response[0] == 0xFF && response[1] == 0x53 {
                let mut off = 2usize;
                let stream_id = u64::from_le_bytes(
                    response[off..off + 8]
                        .try_into()
                        .map_err(|_| anyhow!("stream envelope truncated"))?,
                );
                off += 8;
                let status =
                    u16::from_le_bytes([response[off], response[off + 1]]);
                off += 2;
                let header_count =
                    u16::from_le_bytes([response[off], response[off + 1]]) as usize;
                off += 2;

                // Create the channel — Sender goes into the registry so JS can push
                // chunks; we keep the Receiver locally for the write loop.
                let (tx, rx) = flume::bounded::<StreamMessage>(16);
                stream_registry().insert(stream_id, tx);

                // Build HTTP/1.1 response headers with chunked transfer-encoding
                let reason = status_reason(status);
                let connection = if keep_alive { "keep-alive" } else { "close" };
                let mut output = Vec::with_capacity(256);
                output.extend_from_slice(b"HTTP/1.1 ");
                write_u16(&mut output, status);
                output.push(b' ');
                output.extend_from_slice(reason.as_bytes());
                output.extend_from_slice(b"\r\ntransfer-encoding: chunked\r\nconnection: ");
                output.extend_from_slice(connection.as_bytes());
                output.extend_from_slice(b"\r\n");

                // Parse user headers from the envelope
                for _ in 0..header_count {
                    if off >= response.len() {
                        break;
                    }
                    let name_len = response[off] as usize;
                    off += 1;
                    if off + 2 > response.len() {
                        break;
                    }
                    let value_len = u16::from_le_bytes([response[off], response[off + 1]]) as usize;
                    off += 2;
                    if off + name_len + value_len > response.len() {
                        break;
                    }
                    let name = &response[off..off + name_len];
                    off += name_len;
                    let value = &response[off..off + value_len];
                    off += value_len;

                    // Skip headers we manage ourselves
                    if name.eq_ignore_ascii_case(b"transfer-encoding")
                        || name.eq_ignore_ascii_case(b"content-length")
                        || name.eq_ignore_ascii_case(b"connection")
                    {
                        continue;
                    }

                    output.extend_from_slice(name);
                    output.extend_from_slice(b": ");
                    output.extend_from_slice(value);
                    output.extend_from_slice(b"\r\n");
                }
                output.extend_from_slice(b"\r\n");

                // Write the header block to the TCP stream
                let (write_result, _) = stream.write_all(output).await;
                write_result?;

                // Chunked transfer loop — read from channel, write to TCP
                loop {
                    match rx.recv_async().await {
                        Ok(StreamMessage::Chunk(data)) => {
                            if data.is_empty() {
                                continue;
                            }
                            // HTTP/1.1 chunked format: {hex_len}\r\n{data}\r\n
                            let hex_len = format!("{:x}", data.len());
                            let mut chunk_buf = Vec::with_capacity(hex_len.len() + 2 + data.len() + 2);
                            chunk_buf.extend_from_slice(hex_len.as_bytes());
                            chunk_buf.extend_from_slice(b"\r\n");
                            chunk_buf.extend_from_slice(&data);
                            chunk_buf.extend_from_slice(b"\r\n");
                            let (wr, _) = stream.write_all(chunk_buf).await;
                            if wr.is_err() {
                                stream_registry().remove(&stream_id);
                                break;
                            }
                        }
                        Ok(StreamMessage::End) | Err(_) => {
                            // Final chunk: 0\r\n\r\n
                            let (wr, _) = stream.write_all(b"0\r\n\r\n".to_vec()).await;
                            let _ = wr;
                            stream_registry().remove(&stream_id);
                            break;
                        }
                    }
                }

                return Ok(());
            }

            match build_http_response_from_dispatch(response.as_ref(), keep_alive, accepted_encoding, compression_config) {
                Ok(mut http_response) => {
                    if let Some((cache_namespace, cache_key, max_entries, ttl_secs)) = cache_insertion {
                        // Route-level cache insertion (takes precedence over ncache)
                        // Derive the alternate connection variant by patching the header bytes
                        let response_bytes_close: bytes::Bytes = if !keep_alive {
                            http_response.clone().into()
                        } else {
                            patch_connection_header(&http_response, false).into()
                        };
                        let response_ka: bytes::Bytes = if keep_alive {
                            http_response.clone().into()
                        } else {
                            patch_connection_header(&http_response, true).into()
                        };

                        crate::router::insert_cached_response(cache_namespace, cache_key, crate::router::CacheEntry {
                            response_bytes: response_ka,
                            response_bytes_close,
                            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(ttl_secs),
                        }, max_entries);
                    } else if handler_id != NOT_FOUND_HANDLER_ID {
                        // Check for ncache trailer from JS response envelope
                        if let Some((ncache_ttl, ncache_max_entries)) = extract_ncache_trailer(response.as_ref()) {
                            if ncache_ttl > 0 {
                                if let Some(cache_namespace) = cache_namespace {
                                    let ncache_key = vary_cache_key_by_encoding(compute_ncache_key(url_bytes), accepted_encoding);

                                    let response_bytes_close: bytes::Bytes = if !keep_alive {
                                        http_response.clone().into()
                                    } else {
                                        patch_connection_header(&http_response, false).into()
                                    };
                                    let response_ka: bytes::Bytes = if keep_alive {
                                        http_response.clone().into()
                                    } else {
                                        patch_connection_header(&http_response, true).into()
                                    };

                                    crate::router::insert_cached_response(cache_namespace, ncache_key, crate::router::CacheEntry {
                                        response_bytes: response_ka,
                                        response_bytes_close,
                                        expires_at: std::time::Instant::now() + std::time::Duration::from_secs(ncache_ttl),
                                    }, ncache_max_entries);
                                }
                            }
                        }
                    }

                    // Process session trailer if session store is active
                    if let Some(store) = session_store {
                        if let Some(body_end) = response_body_end_offset(response.as_ref()) {
                            // Skip past ncache trailer (10 bytes) if present
                            let mut session_scan_offset = body_end;
                            if session_scan_offset + 10 <= response.as_ref().len()
                                && response.as_ref()[session_scan_offset] == 0xCA
                                && response.as_ref()[session_scan_offset + 1] == 0xCE
                            {
                                session_scan_offset += 10;
                            }

                            if let Some(trailer) = extract_session_trailer(response.as_ref(), session_scan_offset) {
                                match trailer.action {
                                    session::SessionAction::Update => {
                                        if let Some(sid) = session_id {
                                            let _ = store.upsert(&sid, trailer.mutations, &trailer.deleted_keys);
                                            // Inject Set-Cookie for new sessions
                                            if is_new_session {
                                                let cookie = store.build_set_cookie(&sid);
                                                inject_set_cookie_header(&mut http_response, &cookie);
                                            }
                                        }
                                    }
                                    session::SessionAction::Destroy => {
                                        if let Some(sid) = session_id {
                                            store.destroy(&sid);
                                            let cookie = store.build_destroy_cookie();
                                            inject_set_cookie_header(&mut http_response, &cookie);
                                        }
                                    }
                                    session::SessionAction::Regenerate => {
                                        // Destroy old, create new
                                        if let Some(old_sid) = session_id {
                                            let old_data = store.get(&old_sid);
                                            store.destroy(&old_sid);
                                            let new_sid = store.generate_id();
                                            if let Some(entry) = old_data {
                                                let _ = store.upsert(&new_sid, entry.data, &[]);
                                            }
                                            let _ = store.upsert(&new_sid, trailer.mutations, &trailer.deleted_keys);
                                            let cookie = store.build_set_cookie(&new_sid);
                                            inject_set_cookie_header(&mut http_response, &cookie);
                                        }
                                    }
                                }
                            } else if is_new_session {
                                // No session trailer but session was accessed — set cookie
                                if let Some(sid) = session_id {
                                    let _ = store.upsert(&sid, std::collections::HashMap::new(), &[]);
                                    let cookie = store.build_set_cookie(&sid);
                                    inject_set_cookie_header(&mut http_response, &cookie);
                                }
                            }
                        }
                    }

                    let (write_result, _) = stream.write_all(http_response).await;
                    write_result?;
                }
                Err(_) => {
                    // Security: sanitized error — no internal details
                    let response = build_error_response_bytes(
                        500,
                        b"{\"error\":\"Internal Server Error\"}",
                        keep_alive,
                    );
                    let (write_result, _) = stream.write_all(response).await;
                    write_result?;
                }
            }
        }
        Err(_) => {
            // Security: sanitized error — no internal details
            let response = build_error_response_bytes(
                502,
                b"{\"error\":\"Bad Gateway\"}",
                keep_alive,
            );
            let (write_result, _) = stream.write_all(response).await;
            write_result?;
        }
    }
    Ok(())
}

/// Build HTTP response bytes directly from the binary dispatch envelope,
/// avoiding all intermediate String/Bytes allocations.
fn build_http_response_from_dispatch(
    dispatch_bytes: &[u8],
    keep_alive: bool,
    encoding: compress::AcceptedEncoding,
    compression_config: Option<&compress::CompressionConfig>,
) -> Result<Vec<u8>> {
    let mut offset = 0usize;
    let status = read_u16(dispatch_bytes, &mut offset)?;
    let header_count = read_u16(dispatch_bytes, &mut offset)? as usize;
    let body_length = read_u32(dispatch_bytes, &mut offset)? as usize;

    // ── Parse headers (collect refs, note content-type / content-encoding) ──
    let mut headers: Vec<(&[u8], &[u8])> = Vec::with_capacity(header_count);
    let mut content_type: Option<&[u8]> = None;
    let mut has_content_encoding = false;

    for _ in 0..header_count {
        let name_len = read_u8(dispatch_bytes, &mut offset)? as usize;
        let value_len = read_u16(dispatch_bytes, &mut offset)? as usize;

        if offset + name_len + value_len > dispatch_bytes.len() {
            return Err(anyhow!("response envelope truncated"));
        }

        let name_bytes = &dispatch_bytes[offset..offset + name_len];
        offset += name_len;
        let value_bytes = &dispatch_bytes[offset..offset + value_len];
        offset += value_len;

        if name_bytes.eq_ignore_ascii_case(b"content-type") {
            content_type = Some(value_bytes);
        } else if name_bytes.eq_ignore_ascii_case(b"content-encoding") {
            has_content_encoding = true;
        }

        headers.push((name_bytes, value_bytes));
    }

    // ── Extract body ──
    if offset + body_length > dispatch_bytes.len() {
        return Err(anyhow!("response body truncated"));
    }
    let body = &dispatch_bytes[offset..offset + body_length];

    // ── Attempt compression ──
    let compressed = compression_config.and_then(|config| {
        compress::should_compress(config, encoding, body.len(), content_type, has_content_encoding)
            .and_then(|enc| compress::compress_body(body, enc, config, content_type).map(|data| (data, enc)))
    });

    let (final_body, applied_encoding): (&[u8], Option<compress::AcceptedEncoding>) =
        match &compressed {
            Some((data, enc)) => (data.as_slice(), Some(*enc)),
            None => (body, None),
        };

    // ── Assemble HTTP response ──
    let reason = status_reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let mut output = Vec::with_capacity(final_body.len() + 128);

    // Status line
    output.extend_from_slice(b"HTTP/1.1 ");
    write_u16(&mut output, status);
    output.push(b' ');
    output.extend_from_slice(reason.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Content-Length (uses final — possibly compressed — body size)
    output.extend_from_slice(b"content-length: ");
    write_usize(&mut output, final_body.len());
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(b"connection: ");
    output.extend_from_slice(connection.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Compression headers
    if let Some(enc) = applied_encoding {
        output.extend_from_slice(b"content-encoding: ");
        output.extend_from_slice(compress::encoding_header_value(enc));
        output.extend_from_slice(b"\r\nvary: accept-encoding\r\n");
    }

    // User headers
    for (name_bytes, value_bytes) in &headers {
        // Skip headers we already wrote
        if name_bytes.eq_ignore_ascii_case(b"content-length")
            || name_bytes.eq_ignore_ascii_case(b"connection")
        {
            continue;
        }

        // Security: CRLF injection check
        if name_bytes.iter().any(|&b| b == b'\r' || b == b'\n')
            || value_bytes.iter().any(|&b| b == b'\r' || b == b'\n')
        {
            continue;
        }

        output.extend_from_slice(name_bytes);
        output.extend_from_slice(b": ");
        output.extend_from_slice(value_bytes);
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(final_body);

    Ok(output)
}


/// Resolve the session ID from the cookie header. Returns (session_id, is_new).
/// If no cookie is present or invalid, generates a new session ID.
fn resolve_session(
    session_store: Option<&session::SessionStore>,
    cookie_header: Option<&str>,
) -> (Option<[u8; session::SESSION_ID_BYTES]>, bool) {
    let Some(store) = session_store else {
        return (None, false);
    };

    if let Some(cookie_value) = cookie_header.and_then(|h| store.extract_cookie_value(h)) {
        if let Some(id) = store.verify_cookie(cookie_value) {
            // Valid existing session
            return (Some(id), false);
        }
    }

    // No valid session cookie — generate a new session ID
    let new_id = store.generate_id();
    (Some(new_id), true)
}

// ─── WebSocket Connection Handler ──────

async fn handle_websocket_connection<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    handler_id: u32,
    dispatcher: &JsDispatcher,
) -> Result<()>
where
    S: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::AsyncWriteRentExt,
{
    use crate::websocket::*;

    let ws_id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);

    // Create channel for outbound messages (JS → Rust → client)
    let (tx, rx) = flume::bounded::<StreamMessage>(64);
    stream_registry().insert(ws_id, tx);
    websocket_connections().insert(ws_id, ());

    // Dispatch "open" event to JS
    let open_envelope = build_ws_event_envelope(0x01, ws_id, handler_id, &[]);
    let _ = dispatcher.dispatch(Buffer::from(open_envelope)).await;

    buffer.clear();

    loop {
        // Try to parse a frame from the buffer
        if let Some((frame, consumed)) = parse_frame(buffer) {
            buffer.drain(..consumed);

            match frame.opcode {
                OPCODE_TEXT | OPCODE_BINARY => {
                    let msg_envelope =
                        build_ws_event_envelope(0x02, ws_id, handler_id, &frame.payload);
                    let _ = dispatcher.dispatch(Buffer::from(msg_envelope)).await;
                }
                OPCODE_PING => {
                    let pong = encode_frame(OPCODE_PONG, &frame.payload);
                    let (res, _) = stream.write_all(pong).await;
                    if res.is_err() {
                        break;
                    }
                }
                OPCODE_CLOSE => {
                    let close = encode_close_frame(1000, "");
                    let (res, _) = stream.write_all(close).await;
                    let _ = res;
                    break;
                }
                _ => {}
            }
            continue;
        }

        // Check for outbound messages from JS
        match rx.try_recv() {
            Ok(StreamMessage::Chunk(data)) => {
                let frame = encode_frame(OPCODE_TEXT, &data);
                let (res, _) = stream.write_all(frame).await;
                if res.is_err() {
                    break;
                }
                continue;
            }
            Ok(StreamMessage::End) => {
                let close = encode_close_frame(1000, "");
                let (res, _) = stream.write_all(close).await;
                let _ = res;
                break;
            }
            Err(flume::TryRecvError::Empty) => {}
            Err(flume::TryRecvError::Disconnected) => break,
        }

        // Read more data from the client (with idle timeout)
        let owned_buf = std::mem::take(buffer);
        let timeout_result = timeout(TIMEOUT_WS_IDLE, stream.read(owned_buf)).await;
        let (read_result, returned_buf) = match timeout_result {
            Ok(res) => res,
            Err(_) => {
                // Idle timeout — close connection
                break;
            }
        };
        *buffer = returned_buf;
        match read_result {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    // Cleanup
    stream_registry().remove(&ws_id);
    websocket_connections().remove(&ws_id);

    // Dispatch "close" event to JS
    let close_envelope = build_ws_event_envelope(0x03, ws_id, handler_id, &[]);
    let _ = dispatcher.dispatch(Buffer::from(close_envelope)).await;

    Ok(())
}

/// Build a WebSocket event envelope for dispatching to JS.
/// Layout: 0xFE | eventType(1) | wsId(8 LE) | handlerId(4 LE) | dataLen(4 LE) | data
fn build_ws_event_envelope(event_type: u8, ws_id: u64, handler_id: u32, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18 + data.len());
    buf.push(0xFE); // WS event sentinel
    buf.push(event_type);
    buf.extend_from_slice(&ws_id.to_le_bytes());
    buf.extend_from_slice(&handler_id.to_le_bytes());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    buf
}




// ─── Security Utilities ─────────────────

/// Check for path traversal attempts (../, ..\, etc.)
/// Fast path: if no `..` or null byte is present in the raw bytes, return false
/// immediately without any allocation.  Only falls back to percent-decoding when
/// `..` or `%` patterns are detected.
fn contains_path_traversal(path: &str) -> bool {
    let bytes = path.as_bytes();

    // Fast scan for null bytes
    if memchr::memchr(0, bytes).is_some() {
        return true;
    }

    // Check for literal %00 (null percent-encoding)
    if memmem::find(bytes, b"%00").is_some() {
        return true;
    }

    // Fast path: if no ".." appears anywhere (even encoded), skip the expensive decode
    let has_dotdot = memmem::find(bytes, b"..").is_some();
    let has_percent = memchr::memchr(b'%', bytes).is_some();

    // If no literal ".." and no percent-encoding that could hide "..", we're safe
    if !has_dotdot && !has_percent {
        return false;
    }

    // If we have literal ".." but no percent-encoding, check directly
    if has_dotdot && !has_percent {
        return check_traversal_patterns(bytes);
    }

    // Percent-encoding present — decode once and check
    let decoded = percent_decode_path_bytes(bytes);
    check_traversal_patterns(&decoded)
}

/// Check traversal patterns on raw bytes (after any decoding).
#[inline]
fn check_traversal_patterns(b: &[u8]) -> bool {
    memmem::find(b, b"/../").is_some()
        || memmem::find(b, b"\\..\\").is_some()
        || b.ends_with(b"/..")
        || b.ends_with(b"\\..")
        || b.starts_with(b"../")
        || b.starts_with(b"..\\")
        || b == b".."
}

/// Percent-decode path-relevant characters (%2e, %2f, %5c) in-place into a new
/// Vec.  Iteratively decodes up to 3 rounds (to handle double-encoding).
fn percent_decode_path_bytes(input: &[u8]) -> Vec<u8> {
    let mut current = input.to_vec();
    for _ in 0..3 {
        let mut changed = false;
        let mut decoded = Vec::with_capacity(current.len());
        let mut i = 0;
        while i < current.len() {
            if current[i] == b'%' && i + 2 < current.len() {
                let hi = current[i + 1];
                let lo = current[i + 2];
                let replacement = match (hi, lo) {
                    (b'2', b'e') | (b'2', b'E') => Some(b'.'),
                    (b'2', b'f') | (b'2', b'F') => Some(b'/'),
                    (b'5', b'c') | (b'5', b'C') => Some(b'\\'),
                    _ => None,
                };
                if let Some(ch) = replacement {
                    decoded.push(ch);
                    i += 3;
                    changed = true;
                    continue;
                }
            }
            decoded.push(current[i]);
            i += 1;
        }
        if !changed {
            return current;
        }
        current = decoded;
    }
    current
}

/// RFC 8259 compliant JSON string escaping — handles ALL control characters
#[allow(dead_code)]
pub(crate) fn escape_json(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\x08' => output.push_str("\\b"),
            '\x0C' => output.push_str("\\f"),
            c if c.is_control() => {
                output.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => output.push(c),
        }
    }
    output
}

// ─── Helpers ────────────────────────────

fn method_code_from_bytes(method: &[u8]) -> Option<u8> {
    match method {
        b"GET" => Some(1),
        b"POST" => Some(2),
        b"PUT" => Some(3),
        b"DELETE" => Some(4),
        b"PATCH" => Some(5),
        b"OPTIONS" => Some(6),
        b"HEAD" => Some(7),
        _ => None,
    }
}

/// @DX-4.1: str-based variant for HTTP/2 method mapping (h2 crate uses &str).
pub(crate) fn method_code_from_str(method: &str) -> Option<u8> {
    match method {
        "GET" => Some(1),
        "POST" => Some(2),
        "PUT" => Some(3),
        "DELETE" => Some(4),
        "PATCH" => Some(5),
        "OPTIONS" => Some(6),
        "HEAD" => Some(7),
        _ => None,
    }
}

fn drain_consumed_bytes(buffer: &mut Vec<u8>, consumed: usize) {
    if consumed >= buffer.len() {
        buffer.clear();
        return;
    }

    let remaining = buffer.len() - consumed;
    if remaining == 0 {
        buffer.clear();
        return;
    }

    buffer.copy_within(consumed.., 0);
    buffer.truncate(remaining);
}

fn bind_listener(
    options: &NativeListenOptions,
    server_config: &HttpServerConfig,
) -> Result<TcpListener> {
    let host = options
        .host
        .as_deref()
        .unwrap_or(server_config.default_host.as_str());
    let bind_addr = resolve_socket_addr(host, options.port)
        .with_context(|| format!("failed to resolve bind address {host}:{}", options.port))?;

    /* @B3.5: configure raw socket with TCP_FASTOPEN before binding.
     * TFO allows data in the SYN packet on resumed connections, saving 1 RTT
     * for repeat clients. The queue length (256) limits the number of pending
     * TFO connections the kernel will accept. Falls back silently on systems
     * that don't support it (macOS, older Linux kernels). */
    let raw_socket = socket2::Socket::new(
        if bind_addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    ).context("failed to create raw socket")?;

    raw_socket.set_reuse_address(true)?;
    #[cfg(unix)]
    {
        raw_socket.set_reuse_port(true)?;
    }

    /* @B3.5: TCP_FASTOPEN — allow data in SYN packet on resumed connections.
     * Uses raw setsockopt since socket2 doesn't expose TFO directly.
     * Silently ignored on systems that don't support it. */
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = raw_socket.as_raw_fd();
        let val: libc::c_int = 256; // TFO queue length
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    raw_socket.bind(&bind_addr.into())?;
    raw_socket.listen(options.backlog.unwrap_or(server_config.default_backlog))?;
    raw_socket.set_nonblocking(true)?;

    let std_listener: std::net::TcpListener = raw_socket.into();
    TcpListener::from_std(std_listener)
        .with_context(|| format!("failed to create monoio listener from raw socket on {bind_addr}"))
}

/// @DX-4.1: returns both the monoio-rustls acceptor and the shared rustls
/// config Arc. The Arc is needed for tokio-rustls when h2 is negotiated.
fn build_tls_acceptor(manifest: &ManifestInput) -> Result<Option<(TlsAcceptor, Arc<RustlsServerConfig>)>> {
    let Some(tls) = manifest.tls.as_ref() else {
        return Ok(None);
    };

    let mut cert_chain = parse_tls_certificates(tls.cert.as_str(), "tls.cert")?;
    if let Some(ca_pem) = tls.ca.as_deref() {
        let mut ca_chain = parse_tls_certificates(ca_pem, "tls.ca")?;
        cert_chain.append(&mut ca_chain);
    }

    let private_key = parse_tls_private_key(tls)?;
    let mut config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("failed to construct rustls server config")?;
    /* @DX-4.1: advertise both HTTP/2 and HTTP/1.1 via ALPN. rustls will
     * select the client's preferred protocol during the TLS handshake.
     * h2 is listed first so capable clients default to HTTP/2. */
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let config_arc = Arc::new(config);
    Ok(Some((TlsAcceptor::from(config_arc.clone()), config_arc)))
}

fn parse_tls_certificates(
    pem: &str,
    source_name: &str,
) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse {source_name} PEM"))?;

    if certs.is_empty() {
        return Err(anyhow!("{source_name} does not contain any certificates"));
    }

    Ok(certs)
}

fn parse_tls_private_key(tls: &TlsConfigInput) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(tls.key.as_bytes());
    let key = rustls_pemfile::private_key(&mut reader)
        .context("failed to parse tls.key PEM")?;

    if let Some(private_key) = key {
        return Ok(private_key);
    }

    if tls.passphrase.is_some() {
        return Err(anyhow!(
            "encrypted TLS private keys are not supported; provide an unencrypted PEM key"
        ));
    }

    Err(anyhow!("tls.key does not contain a supported private key"))
}

fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("unable to resolve {host}:{port}"))
}

fn validate_manifest(manifest: &ManifestInput) -> Result<()> {
    if manifest.version != 1 {
        return Err(anyhow!("Unsupported manifest version {}", manifest.version));
    }

    if let Some(tls) = manifest.tls.as_ref() {
        if tls.cert.trim().is_empty() {
            return Err(anyhow!("tls.cert is required"));
        }
        if tls.key.trim().is_empty() {
            return Err(anyhow!("tls.key is required"));
        }
    }

    Ok(())
}


pub(crate) fn normalize_runtime_path(path: &str) -> Cow<'_, str> {
    // Fast path: "/" or no trailing slash — zero allocation
    if path == "/" || !path.ends_with('/') {
        return Cow::Borrowed(path);
    }

    // Strip trailing slashes; ensure leading slash.  Avoids the
    // analyzer::normalize_path call which does `.to_string()` + `.trim_end_matches`.
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Cow::Borrowed("/");
    }
    if trimmed.starts_with('/') {
        Cow::Owned(trimmed.to_string())
    } else {
        let mut s = String::with_capacity(trimmed.len() + 1);
        s.push('/');
        s.push_str(trimmed);
        Cow::Owned(s)
    }
}

fn config_string(
    input: Option<&HttpServerConfigInput>,
    pick: impl Fn(&HttpServerConfigInput) -> Option<&str>,
    fallback: &str,
) -> String {
    input.and_then(pick).unwrap_or(fallback).to_string()
}

use crate::http_utils::{status_reason, write_usize, write_u16};

fn push_string_pair(frame: &mut Vec<u8>, name: &str, value: &str) -> Result<()> {
    if name.len() > u8::MAX as usize {
        return Err(anyhow!("field name too long"));
    }
    if value.len() > u16::MAX as usize {
        return Err(anyhow!("field value too long"));
    }

    frame.push(name.len() as u8);
    push_u16(frame, value.len() as u16);
    frame.extend_from_slice(name.as_bytes());
    frame.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_string_value(frame: &mut Vec<u8>, value: &str) -> Result<()> {
    if value.len() > u16::MAX as usize {
        return Err(anyhow!("field value too long"));
    }

    push_u16(frame, value.len() as u16);
    frame.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u16(frame: &mut Vec<u8>, value: u16) {
    frame.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(frame: &mut Vec<u8>, value: u32) {
    frame.extend_from_slice(&value.to_le_bytes());
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8> {
    if *offset + 1 > bytes.len() {
        return Err(anyhow!("response envelope truncated"));
    }

    let value = bytes[*offset];
    *offset += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16> {
    if *offset + 2 > bytes.len() {
        return Err(anyhow!("response envelope truncated"));
    }

    let value = u16::from_le_bytes([bytes[*offset], bytes[*offset + 1]]);
    *offset += 2;
    Ok(value)
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32> {
    if *offset + 4 > bytes.len() {
        return Err(anyhow!("response envelope truncated"));
    }

    let value = u32::from_le_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]);
    *offset += 4;
    Ok(value)
}

fn to_napi_error<E>(error: E) -> Error
where
    E: std::fmt::Display,
{
    Error::from_reason(error.to_string())
}
