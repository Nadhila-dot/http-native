mod analyzer;
mod manifest;
mod router;

use anyhow::{anyhow, Context, Result};
use memchr::memmem;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::{ListenerOpts, TcpListener, TcpStream};
use napi::bindgen_prelude::{Buffer, Function, Promise};
use napi::threadsafe_function::ThreadsafeFunction;
use napi::{Error, Status};
use napi_derive::napi;
use std::borrow::Cow;
use std::cell::RefCell;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use url::form_urlencoded;

use crate::analyzer::{
    DynamicFastPathResponse, DynamicValueSourceKind, JsonTemplateKind, JsonValueTemplate,
    TextSegment,
};
use crate::manifest::{HttpServerConfigInput, ManifestInput};
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
const BRIDGE_VERSION: u8 = 1;
const REQUEST_FLAG_QUERY_PRESENT: u16 = 1 << 0;
const REQUEST_FLAG_BODY_PRESENT: u16 = 1 << 1;
const UNKNOWN_METHOD_CODE: u8 = 0;
/// Sentinel handler ID dispatched to JS when no route matches — JS treats this as 404.
const NOT_FOUND_HANDLER_ID: u32 = 0;

/// Security: Maximum number of headers we allow per request
const MAX_HEADER_COUNT: usize = 64;
/// Security: Maximum URL length to prevent abuse
const MAX_URL_LENGTH: usize = 8192;
/// Security: Maximum single header value length
const MAX_HEADER_VALUE_LENGTH: usize = 8192;
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
    wake_addrs: Vec<SocketAddr>,
}

#[napi]
pub struct NativeServerHandle {
    host: String,
    port: u32,
    url: String,
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
    pub fn close(&self) -> napi::Result<()> {
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
    let router = Arc::new(Router::from_manifest(&manifest).map_err(to_napi_error)?);

    let callback: DispatchTsfn = dispatcher
        .build_threadsafe_function::<Buffer>()
        .build()
        .map_err(to_napi_error)?;
    let dispatcher = Arc::new(JsDispatcher { callback });

    let worker_count = worker_count_for(&options);
    let (startup_tx, startup_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(worker_count);
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let mut closed_receivers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let (closed_tx, closed_rx) = mpsc::channel::<()>();
        closed_receivers.push(closed_rx);

        let thread_router = Arc::clone(&router);
        let thread_dispatcher = Arc::clone(&dispatcher);
        let thread_config = Arc::clone(&server_config);
        let thread_shutdown = Arc::clone(&shutdown_flag);
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
                        thread_router,
                        thread_dispatcher,
                        thread_config,
                        thread_shutdown,
                    )
                    .await
                })
            })();

            if let Err(error) = &result {
                let _ = startup_tx_error.send(Err(error.to_string()));
                eprintln!("[http-native] native server error: {error:#}");
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
        url: format!("http://{host}:{port}"),
        shutdown: Mutex::new(Some(ShutdownHandle {
            flag: shutdown_flag,
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
    router: Arc<Router>,
    dispatcher: Arc<JsDispatcher>,
    server_config: Arc<HttpServerConfig>,
    shutdown_flag: Arc<AtomicBool>,
) -> Result<()> {
    let active_connections: std::cell::Cell<usize> = std::cell::Cell::new(0);

    loop {
        if shutdown_flag.load(Ordering::Acquire) {
            break;
        }

        match listener.accept().await {
            Ok((stream, _)) => {
                if shutdown_flag.load(Ordering::Acquire) {
                    break;
                }

                // Security (S3): enforce per-worker connection limit
                if active_connections.get() >= MAX_CONNECTIONS_PER_WORKER {
                    drop(stream);
                    continue;
                }

                if let Err(error) = stream.set_nodelay(true) {
                    eprintln!("[http-native] failed to enable TCP_NODELAY: {error}");
                }

                let router = Arc::clone(&router);
                let dispatcher = Arc::clone(&dispatcher);
                let server_config = Arc::clone(&server_config);
                active_connections.set(active_connections.get() + 1);

                // Safety: monoio is single-threaded per worker, so Cell is fine here
                let conn_counter = &active_connections as *const std::cell::Cell<usize>;

                monoio::spawn(async move {
                    if let Err(error) =
                        handle_connection(stream, router, dispatcher, server_config).await
                    {
                        eprintln!("[http-native] connection error: {error}");
                    }
                    // Safety: single-threaded — pointer is always valid while server runs
                    unsafe { &*conn_counter }.set(
                        unsafe { &*conn_counter }.get().saturating_sub(1),
                    );
                });
            }
            Err(error) => {
                if shutdown_flag.load(Ordering::Acquire) {
                    break;
                }

                eprintln!("[http-native] accept error: {error}");
            }
        }
    }

    Ok(())
}

// ─── Parsed Request (from httparse) ─────

struct ParsedRequest<'a> {
    method: &'a [u8],
    target: &'a [u8],
    path: &'a [u8],
    keep_alive: bool,
    header_bytes: usize,
    has_body: bool,
    content_length: Option<usize>,
    /// True when a non-identity Transfer-Encoding header was seen
    has_chunked_te: bool,
    /// Pre-parsed header pairs — stored once, used by both routing and bridge
    headers: Vec<(&'a str, &'a str)>,
}

use monoio::time::timeout;
use std::time::Duration;

const TIMEOUT_HEADER_READ: Duration = Duration::from_secs(30);
const TIMEOUT_IDLE_KEEPALIVE: Duration = Duration::from_secs(120);
const TIMEOUT_BODY_READ: Duration = Duration::from_secs(60);
const TIMEOUT_WRITE: Duration = Duration::from_secs(30);

// ─── Connection Handler with Buffer Pool 

async fn handle_connection(
    mut stream: TcpStream,
    router: Arc<Router>,
    dispatcher: Arc<JsDispatcher>,
    server_config: Arc<HttpServerConfig>,
) -> Result<()> {
    let mut buffer = acquire_buffer();

    let result = handle_connection_inner(
        &mut stream,
        &mut buffer,
        &router,
        &dispatcher,
        &server_config,
    )
    .await;

    release_buffer(buffer);
    result
}

async fn handle_connection_inner(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    router: &Router,
    dispatcher: &JsDispatcher,
    server_config: &HttpServerConfig,
) -> Result<()> {
    let mut is_first_request = true;

    loop {
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
            let read_duration = if is_first_request {
                TIMEOUT_HEADER_READ
            } else {
                TIMEOUT_IDLE_KEEPALIVE
            };
            
            let timeout_result = timeout(read_duration, stream.read(owned_buf)).await;
            let (read_result, next_buffer) = match timeout_result {
                Ok(res) => res,
                Err(_) => {
                    // Read timeout
                    return Ok(());
                }
            };
            
            *buffer = next_buffer;
            let bytes_read = read_result?;

            if bytes_read == 0 {
                return Ok(());
            }

            is_first_request = false;

            if buffer.len() > server_config.max_header_bytes {
                // Security: Request header too large
                let response = build_error_response_bytes(
                    431,
                    b"{\"error\":\"Request Header Fields Too Large\"}",
                    false,
                );
                let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
                if let Ok((write_result, _)) = timeout_result {
                    write_result?;
                }
                stream.shutdown().await?;
                return Ok(());
            }
        };

        let header_bytes = parsed.header_bytes;
        let keep_alive = parsed.keep_alive;
        let has_body = parsed.has_body;
        let content_length = parsed.content_length;

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
            let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
            if let Ok((write_result, _)) = timeout_result {
                write_result?;
            }
            stream.shutdown().await?;
            return Ok(());
        }

        // ── Fast path: static routes (zero-copy from borrowed parse data) ──
        if !has_body && parsed.method == b"GET" {
            if parsed.path == b"/" {
                if let Some(static_route) = router.exact_get_root() {
                    drop(parsed);
                    drain_consumed_bytes(buffer, header_bytes);
                    write_exact_static_response(stream, static_route, keep_alive).await?;
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
                write_exact_static_response(stream, static_route, keep_alive).await?;
                if !keep_alive {
                    stream.shutdown().await?;
                    return Ok(());
                }
                continue;
            }
        }

        // ── Zero-copy path: non-body requests ──
        // Build dispatch envelope directly from borrowed parse data, avoiding
        // String/Vec allocations for method, target, path, and headers.
        if !has_body {
            let dispatch_decision = build_dispatch_decision_zero_copy(router, &parsed, &[])?;
            drop(parsed);
            drain_consumed_bytes(buffer, header_bytes);

            match dispatch_decision {
                DispatchDecision::BridgeRequest(request, cache_insertion, handler_id, url_bytes) => {
                    write_dynamic_dispatch_response(stream, dispatcher, request, keep_alive, cache_insertion, handler_id, &url_bytes)
                        .await?;
                }
                DispatchDecision::SpecializedResponse(response) => {
                    let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
                    if let Ok((write_result, _)) = timeout_result {
                        write_result?;
                    }
                }
                DispatchDecision::CachedResponse(response) => {
                    let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
                    if let Ok((write_result, _)) = timeout_result {
                        write_result?;
                    }
                }
            }

            if !keep_alive {
                stream.shutdown().await?;
                return Ok(());
            }
            continue;
        }

        // ── Body requests: need owned copies to release buffer for body read ──
        let method_owned: Vec<u8> = parsed.method.to_vec();
        let target_owned: Vec<u8> = parsed.target.to_vec();
        let path_owned: Vec<u8> = parsed.path.to_vec();
        let headers_owned: Vec<(String, String)> = parsed
            .headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        drop(parsed);

        // ── Read request body 
        let body_bytes: Vec<u8> = {
            let content_length = match content_length {
                Some(len) => len,
                None => {
                    let response =
                        build_error_response_bytes(411, b"{\"error\":\"Length Required\"}", false);
                    let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
                    if let Ok((write_result, _)) = timeout_result {
                        write_result?;
                    }
                    stream.shutdown().await?;
                    return Ok(());
                }
            };

            if content_length > MAX_BODY_BYTES {
                let response =
                    build_error_response_bytes(413, b"{\"error\":\"Payload Too Large\"}", false);
                let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
                if let Ok((write_result, _)) = timeout_result {
                    write_result?;
                }
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

        let dispatch_decision_owned = build_dispatch_decision_owned(
            router,
            &method_owned,
            &target_owned,
            &path_owned,
            &headers_owned,
            &body_bytes,
        )?;

        match dispatch_decision_owned {
            DispatchDecision::BridgeRequest(request, cache_insertion, handler_id, url_bytes) => {
                write_dynamic_dispatch_response(stream, dispatcher, request, keep_alive, cache_insertion, handler_id, &url_bytes).await?;
            }
            DispatchDecision::SpecializedResponse(response) => {
                let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
                if let Ok((write_result, _)) = timeout_result {
                    write_result?;
                }
            }
            DispatchDecision::CachedResponse(response) => {
                let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
                if let Ok((write_result, _)) = timeout_result {
                    write_result?;
                }
            }
        }

        if !keep_alive {
            stream.shutdown().await?;
            return Ok(());
        }
    }
}

// ─── httparse-based Request Parsing ─────
//
// Uses the battle-tested `httparse` crate for RFC-compliant zero-copy parsing.
// Single-pass: parses headers once and stores them for reuse by both the
// router and the bridge envelope builder.

fn parse_request_httparse(bytes: &[u8]) -> Option<ParsedRequest<'_>> {
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut req = httparse::Request::new(&mut raw_headers);

    let header_len = match req.parse(bytes) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return None,
        Err(_) => return None, // Malformed — caller will handle
    };

    let method = req.method?.as_bytes();
    let target = req.path?.as_bytes();
    let version = req.version?;

    // Security: enforce URL length limit
    if target.len() > MAX_URL_LENGTH {
        return None;
    }

    // Extract path (before '?')
    let path = target.split(|b| *b == b'?').next()?;

    let mut keep_alive = version >= 1; // HTTP/1.1+ defaults to keep-alive
    let mut has_body = false;
    let mut content_length: Option<usize> = None;
    let mut has_chunked_te = false;
    let mut headers = Vec::with_capacity(req.headers.len());

    for header in req.headers.iter() {
        if header.name.is_empty() {
            break;
        }

        // Security: enforce header value length
        if header.value.len() > MAX_HEADER_VALUE_LENGTH {
            return None;
        }

        let name = header.name; // httparse gives us &str
        let value = match std::str::from_utf8(header.value) {
            Ok(v) => v,
            Err(_) => continue, // Skip non-UTF-8 headers
        };

        // Connection handling
        if name.eq_ignore_ascii_case("connection") {
            let lower = value.to_ascii_lowercase();
            if lower.contains("close") {
                keep_alive = false;
            }
            if lower.contains("keep-alive") {
                keep_alive = true;
            }
        }

        // Body detection
        if name.eq_ignore_ascii_case("content-length") {
            let trimmed = value.trim();
            if let Ok(len) = trimmed.parse::<usize>() {
                content_length = Some(len);
                if len > 0 {
                    has_body = true;
                }
            }
        }

        if name.eq_ignore_ascii_case("transfer-encoding") {
            let trimmed = value.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("identity") {
                has_body = true;
                has_chunked_te = true;
            }
        }

        headers.push((name, value));
    }

    Some(ParsedRequest {
        method,
        target,
        path,
        keep_alive,
        header_bytes: header_len,
        has_body,
        content_length,
        has_chunked_te,
        headers,
    })
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
            if value != b"0" {
                has_body = true;
            }
        } else if line.len() >= server_config.header_transfer_encoding_prefix.len()
            && line[..server_config.header_transfer_encoding_prefix.len()]
                .eq_ignore_ascii_case(server_config.header_transfer_encoding_prefix.as_slice())
        {
            let value =
                trim_ascii_spaces(&line[server_config.header_transfer_encoding_prefix.len()..]);
            if !value.is_empty() && !value.eq_ignore_ascii_case(b"identity") {
                has_body = true;
            }
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
        content_length: None,
        has_chunked_te: false,
        headers: Vec::new(),
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
    /// (envelope, route-level cache insertion, handler_id, url_bytes for ncache key)
    BridgeRequest(Buffer, Option<(u32, u64, usize, u64)>, u32, Vec<u8>),
    SpecializedResponse(Vec<u8>),
    CachedResponse(bytes::Bytes),
}

fn build_dispatch_decision_zero_copy(
    router: &Router,
    parsed: &ParsedRequest<'_>,
    body: &[u8],
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
        )
        .map(|envelope| DispatchDecision::BridgeRequest(envelope, None, NOT_FOUND_HANDLER_ID, Vec::new()));
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
        )
        .map(|envelope| DispatchDecision::BridgeRequest(envelope, None, NOT_FOUND_HANDLER_ID, Vec::new()));
    };

    let mut cache_insertion = None;
    if let Some(cfg) = matched_route.cache_config {
         let key = crate::router::interpolate_cache_key(cfg, parsed, url_str, matched_route.param_names, &matched_route.param_values);
         if let Some(cached_response) = crate::router::get_cached_response(matched_route.handler_id, key, parsed.keep_alive) {
             return Ok(DispatchDecision::CachedResponse(cached_response));
         }
         cache_insertion = Some((matched_route.handler_id, key, cfg.max_entries, cfg.ttl_secs));
    } else {
        // ncache lookup: check if a previous res.ncache() call cached this response
        let ncache_key = compute_ncache_key(matched_route.handler_id, parsed.target);
        if let Some(cached_response) = crate::router::get_cached_response(matched_route.handler_id, ncache_key, parsed.keep_alive) {
            return Ok(DispatchDecision::CachedResponse(cached_response));
        }
    }

    if let Some(response) =
        build_dynamic_fast_path_response(&matched_route, url_str, &parsed.headers, parsed.keep_alive)?
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
    )
    .map(|envelope| DispatchDecision::BridgeRequest(envelope, cache_insertion, handler_id, url_bytes_owned))
}

fn build_dispatch_decision_owned(
    router: &Router,
    method: &[u8],
    target: &[u8],
    path: &[u8],
    headers: &[(String, String)],
    body: &[u8],
) -> Result<DispatchDecision> {
    let method_code = method_code_from_bytes(method).unwrap_or(UNKNOWN_METHOD_CODE);

    let path_cow = String::from_utf8_lossy(path);
    let path_str = path_cow.as_ref();
    let url_cow = String::from_utf8_lossy(target);
    let url_str = url_cow.as_ref();

    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();

    // Security: strict path validation
    let normalized_path = normalize_runtime_path(path_str);
    if contains_path_traversal(&normalized_path) {
        return build_not_found_dispatch_envelope(
            method_code,
            path_str,
            url_str,
            &header_refs,
            body,
        )
        .map(|envelope| DispatchDecision::BridgeRequest(envelope, None, NOT_FOUND_HANDLER_ID, Vec::new()));
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
        )
        .map(|envelope| DispatchDecision::BridgeRequest(envelope, None, NOT_FOUND_HANDLER_ID, Vec::new()));
    };

    let mut cache_insertion = None;
    if let Some(cfg) = matched_route.cache_config {
         let mock_parsed = ParsedRequest {
             method,
             target,
             path,
             keep_alive: false,
             header_bytes: 0,
             has_body: true,
             content_length: None,
             has_chunked_te: false,
             headers: header_refs.clone(),
         };
         let key = crate::router::interpolate_cache_key(cfg, &mock_parsed, url_str, matched_route.param_names, &matched_route.param_values);
         cache_insertion = Some((matched_route.handler_id, key, cfg.max_entries, cfg.ttl_secs));
    } else {
        // ncache lookup: check if a previous res.ncache() call cached this response
        let ncache_key = compute_ncache_key(matched_route.handler_id, target);
        if let Some(cached_response) = crate::router::get_cached_response(matched_route.handler_id, ncache_key, false) {
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
    )
    .map(|envelope| DispatchDecision::BridgeRequest(envelope, cache_insertion, handler_id, url_bytes_owned))
}

fn build_not_found_dispatch_envelope(
    method_code: u8,
    path: &str,
    url: &str,
    header_entries: &[(&str, &str)],
    body: &[u8],
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

    let mut frame = Vec::with_capacity(
        20 + url_bytes.len() + path_bytes.len() + header_entries.len() * 16 + body.len(),
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
    frame.extend_from_slice(url_bytes);
    frame.extend_from_slice(path_bytes);

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

    let mut frame = Vec::with_capacity(
        20 + url_bytes.len() + path_bytes.len() + selected_header_count * 16 + body.len(),
    );
    frame.push(BRIDGE_VERSION);
    frame.push(method_code);
    push_u16(&mut frame, flags);
    push_u32(&mut frame, matched_route.handler_id);
    push_u32(&mut frame, url_bytes.len() as u32);
    push_u16(&mut frame, path_bytes.len() as u16);
    push_u16(&mut frame, matched_route.param_values.len() as u16);
    push_u16(&mut frame, selected_header_count as u16);
    push_u32(&mut frame, body.len() as u32); // NEW: body length
    frame.extend_from_slice(url_bytes);
    frame.extend_from_slice(path_bytes);

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

    frame.extend_from_slice(body); // NEW: body bytes at end

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

fn build_response_bytes_fast(
    status: u16,
    headers: &[(Box<str>, Box<str>)],
    body: &[u8],
    keep_alive: bool,
) -> Vec<u8> {
    let reason = status_reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let body_len = body.len();

    let mut total_size =
        9 + 3 + 1 + reason.len() + 2 + 16 + count_digits(body_len) + 2 + 12 + connection.len() + 2;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            continue;
        }
        total_size += name.len() + 2 + value.len() + 2;
    }

    total_size += 2 + body_len;

    let mut output = Vec::with_capacity(total_size);
    output.extend_from_slice(b"HTTP/1.1 ");
    write_u16(&mut output, status);
    output.push(b' ');
    output.extend_from_slice(reason.as_bytes());
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(b"content-length: ");
    write_usize(&mut output, body_len);
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(b"connection: ");
    output.extend_from_slice(connection.as_bytes());
    output.extend_from_slice(b"\r\n");

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            continue;
        }
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(body);
    output
}

// ─── Response Writing ───────────────────

async fn write_exact_static_response(
    stream: &mut TcpStream,
    static_route: &ExactStaticRoute,
    keep_alive: bool,
) -> Result<()> {
    let response = if keep_alive {
        static_route.keep_alive_response.clone()
    } else {
        static_route.close_response.clone()
    };

    let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
    if let Ok((write_result, _)) = timeout_result {
        write_result?;
    }
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

/// Compute an ncache key from handler_id + full request URL (including query string).
/// Different URLs naturally produce different cache keys, so /data?page=1 and
/// /data?page=2 are cached separately.
fn compute_ncache_key(handler_id: u32, url_bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    handler_id.hash(&mut hasher);
    url_bytes.hash(&mut hasher);
    hasher.finish()
}

async fn write_dynamic_dispatch_response(
    stream: &mut TcpStream,
    dispatcher: &JsDispatcher,
    request: Buffer,
    keep_alive: bool,
    cache_insertion: Option<(u32, u64, usize, u64)>,
    handler_id: u32,
    url_bytes: &[u8],
) -> Result<()> {
    match dispatcher.dispatch(request).await {
        Ok(response) => {
            match build_http_response_from_dispatch(response.as_ref(), keep_alive) {
                Ok(http_response) => {
                    if let Some((handler_id, cache_key, max_entries, ttl_secs)) = cache_insertion {
                        // Route-level cache insertion (takes precedence over ncache)
                        let response_bytes_close: bytes::Bytes = if !keep_alive {
                            http_response.clone().into()
                        } else {
                            build_http_response_from_dispatch(response.as_ref(), false)
                                .unwrap_or_default()
                                .into()
                        };
                        let response_ka: bytes::Bytes = if keep_alive {
                            http_response.clone().into()
                        } else {
                            build_http_response_from_dispatch(response.as_ref(), true)
                                .unwrap_or_default()
                                .into()
                        };

                        crate::router::insert_cached_response(handler_id, cache_key, crate::router::CacheEntry {
                            response_bytes: response_ka,
                            response_bytes_close,
                            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(ttl_secs),
                        }, max_entries);
                    } else if handler_id != NOT_FOUND_HANDLER_ID {
                        // Check for ncache trailer from JS response envelope
                        if let Some((ncache_ttl, ncache_max_entries)) = extract_ncache_trailer(response.as_ref()) {
                            if ncache_ttl > 0 {
                                let ncache_key = compute_ncache_key(handler_id, url_bytes);

                                let response_bytes_close: bytes::Bytes = if !keep_alive {
                                    http_response.clone().into()
                                } else {
                                    build_http_response_from_dispatch(response.as_ref(), false)
                                        .unwrap_or_default()
                                        .into()
                                };
                                let response_ka: bytes::Bytes = if keep_alive {
                                    http_response.clone().into()
                                } else {
                                    build_http_response_from_dispatch(response.as_ref(), true)
                                        .unwrap_or_default()
                                        .into()
                                };

                                crate::router::insert_cached_response(handler_id, ncache_key, crate::router::CacheEntry {
                                    response_bytes: response_ka,
                                    response_bytes_close,
                                    expires_at: std::time::Instant::now() + std::time::Duration::from_secs(ncache_ttl),
                                }, ncache_max_entries);
                            }
                        }
                    }

                    let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(http_response)).await;
                    if let Ok((write_result, _)) = timeout_result {
                        write_result?;
                    }
                }
                Err(_) => {
                    // Security: sanitized error — no internal details
                    let response = build_error_response_bytes(
                        500,
                        b"{\"error\":\"Internal Server Error\"}",
                        keep_alive,
                    );
                    let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
                    if let Ok((write_result, _)) = timeout_result {
                        write_result?;
                    }
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
            let timeout_result = timeout(TIMEOUT_WRITE, stream.write_all(response)).await;
            if let Ok((write_result, _)) = timeout_result {
                write_result?;
            }
        }
    }
    Ok(())
}

/// Build HTTP response bytes directly from the binary dispatch envelope,
/// avoiding all intermediate String/Bytes allocations.
fn build_http_response_from_dispatch(dispatch_bytes: &[u8], keep_alive: bool) -> Result<Vec<u8>> {
    let mut offset = 0usize;
    let status = read_u16(dispatch_bytes, &mut offset)?;
    let header_count = read_u16(dispatch_bytes, &mut offset)? as usize;
    let body_length = read_u32(dispatch_bytes, &mut offset)? as usize;

    let reason = status_reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };

    // Conservative estimate: framing overhead + all dispatch bytes
    let mut output = Vec::with_capacity(dispatch_bytes.len() + 128);

    // Status line
    output.extend_from_slice(b"HTTP/1.1 ");
    write_u16(&mut output, status);
    output.push(b' ');
    output.extend_from_slice(reason.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Mandatory headers
    output.extend_from_slice(b"content-length: ");
    write_usize(&mut output, body_length);
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(b"connection: ");
    output.extend_from_slice(connection.as_bytes());
    output.extend_from_slice(b"\r\n");

    // User headers — read directly from binary without String allocation
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

    // Body
    if offset + body_length > dispatch_bytes.len() {
        return Err(anyhow!("response body truncated"));
    }
    output.extend_from_slice(&dispatch_bytes[offset..offset + body_length]);

    Ok(output)
}

/// Build a simple error response without going through the JS bridge
fn build_error_response_bytes(status: u16, body: &[u8], keep_alive: bool) -> Vec<u8> {
    let reason = status_reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let body_len = body.len();

    let total_size =
        9 + 3 + 1 + reason.len() + 2 + 16 + count_digits(body_len) + 2 + 12 + connection.len() + 2 + 45 + 2 + body_len;

    let mut output = Vec::with_capacity(total_size);
    output.extend_from_slice(b"HTTP/1.1 ");
    write_u16(&mut output, status);
    output.push(b' ');
    output.extend_from_slice(reason.as_bytes());
    output.extend_from_slice(b"\r\ncontent-length: ");
    write_usize(&mut output, body_len);
    output.extend_from_slice(b"\r\nconnection: ");
    output.extend_from_slice(connection.as_bytes());
    output.extend_from_slice(b"\r\ncontent-type: application/json; charset=utf-8\r\n\r\n");
    output.extend_from_slice(body);

    output
}


// ─── Security Utilities ─────────────────

/// Check for path traversal attempts (../, ..\, etc.)
fn contains_path_traversal(path: &str) -> bool {
    if path.contains('\0') || path.contains("%00") {
        return true;
    }

    let mut decoded = path.to_string();
    for _ in 0..3 {
        let next = decoded
            .replace("%2e", ".")
            .replace("%2E", ".")
            .replace("%2f", "/")
            .replace("%2F", "/")
            .replace("%5c", "\\")
            .replace("%5C", "\\");
        if next == decoded {
            break;
        }
        decoded = next;
    }

    decoded.contains("/../")
        || decoded.contains("\\..\\")
        || decoded.ends_with("/..")
        || decoded.ends_with("\\..")
        || decoded.starts_with("../")
        || decoded.starts_with("..\\")
        || decoded == ".."
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
    let listener_opts = ListenerOpts::new()
        .reuse_addr(true)
        .reuse_port(true)
        .backlog(options.backlog.unwrap_or(server_config.default_backlog));

    TcpListener::bind_with_config(bind_addr, &listener_opts)
        .with_context(|| format!("failed to bind TCP listener on {bind_addr}"))
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

    Ok(())
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    memmem::find(bytes, b"\r\n\r\n")
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }

    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn trim_ascii_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn normalize_runtime_path(path: &str) -> Cow<'_, str> {
    if path == "/" || !path.ends_with('/') {
        return Cow::Borrowed(path);
    }

    Cow::Owned(crate::analyzer::normalize_path(path))
}

fn config_string(
    input: Option<&HttpServerConfigInput>,
    pick: impl Fn(&HttpServerConfigInput) -> Option<&str>,
    fallback: &str,
) -> String {
    input.and_then(pick).unwrap_or(fallback).to_string()
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

/// Fast integer-to-string for small values — uses stack-allocated itoa buffer
#[inline(always)]
fn write_usize(output: &mut Vec<u8>, value: usize) {
    let mut buf = itoa::Buffer::new();
    output.extend_from_slice(buf.format(value).as_bytes());
}

#[inline(always)]
fn write_u16(output: &mut Vec<u8>, value: u16) {
    let mut buf = itoa::Buffer::new();
    output.extend_from_slice(buf.format(value).as_bytes());
}

fn count_digits(mut n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut count = 0;
    while n > 0 {
        count += 1;
        n /= 10;
    }
    count
}

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
