//! HTTP/3 (QUIC) connection handler (DX-4.2).
//!
//! Runs on a dedicated tokio runtime thread since quinn requires tokio.
//! The QUIC endpoint binds to the same port as TCP (but over UDP).
//! Each HTTP/3 request dispatches through the same JS bridge as HTTP/1.1
//! and HTTP/2, maintaining full API parity.
//!
//! Architecture:
//! - Separate std::thread with tokio runtime for QUIC
//! - quinn::Endpoint accepts QUIC connections
//! - h3 crate handles HTTP/3 semantics (QPACK, stream mapping)
//! - Requests are encoded into bridge envelopes and dispatched to JS
//! - Alt-Svc header injection in HTTP/1.1 and HTTP/2 responses

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes};
use http::{Response as HttpResponse, StatusCode};
use napi::bindgen_prelude::Buffer;

use crate::compress;
use crate::parser::intern_header_name;
use crate::router::ExactStaticRoute;
use crate::{
    JsDispatcher, LiveRouter, HttpServerConfig,
    UNKNOWN_METHOD_CODE, MAX_BODY_BYTES,
    INFLIGHT_REQUESTS, method_code_from_str,
};

/// Start the HTTP/3 QUIC listener on a dedicated tokio runtime.
///
/// Spawns a background thread running a full tokio runtime, since quinn
/// requires tokio's async I/O. The QUIC endpoint binds to the same address
/// as the TCP listener but on UDP.
pub fn start_h3_listener(
    bind_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    live_router: Arc<LiveRouter>,
    dispatcher: Arc<JsDispatcher>,
    server_config: Arc<HttpServerConfig>,
) -> Result<()> {
    let quinn_server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| anyhow!("failed to create QUIC TLS config: {e}"))?
    ));

    std::thread::Builder::new()
        .name("h3-quic-runtime".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("failed to create tokio runtime for QUIC");

            rt.block_on(async move {
                if let Err(e) = run_h3_endpoint(
                    bind_addr,
                    quinn_server_config,
                    live_router,
                    dispatcher,
                    server_config,
                ).await {
                    log_error!("HTTP/3 endpoint error: {e}");
                }
            });
        })
        .map_err(|e| anyhow!("failed to spawn QUIC thread: {e}"))?;

    Ok(())
}

/// Main QUIC accept loop on the tokio runtime.
async fn run_h3_endpoint(
    bind_addr: SocketAddr,
    server_config: quinn::ServerConfig,
    live_router: Arc<LiveRouter>,
    dispatcher: Arc<JsDispatcher>,
    http_config: Arc<HttpServerConfig>,
) -> Result<()> {
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .map_err(|e| anyhow!("QUIC bind failed on {bind_addr}: {e}"))?;

    eprintln!("[http-native] HTTP/3 (QUIC) listening on {bind_addr}");

    while let Some(incoming) = endpoint.accept().await {
        let router = Arc::clone(&live_router);
        let disp = Arc::clone(&dispatcher);
        let config = Arc::clone(&http_config);

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let peer = connection.remote_address();
                    if let Err(e) = handle_h3_connection(
                        connection, router, disp, config, peer,
                    ).await {
                        log_error!("h3 connection error from {peer}: {e}");
                    }
                }
                Err(e) => {
                    log_error!("QUIC handshake error: {e}");
                }
            }
        });
    }

    Ok(())
}

/// Handle a single HTTP/3 connection (multiple streams).
async fn handle_h3_connection(
    quinn_conn: quinn::Connection,
    live_router: Arc<LiveRouter>,
    dispatcher: Arc<JsDispatcher>,
    server_config: Arc<HttpServerConfig>,
    peer_addr: SocketAddr,
) -> Result<()> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(quinn_conn))
        .await
        .map_err(|e| anyhow!("h3 handshake failed: {e}"))?;

    let peer_ip = peer_addr.ip().to_string();

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let router = live_router.router.load_full();
                let disp = Arc::clone(&dispatcher);
                let config = Arc::clone(&server_config);
                let ip = peer_ip.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_h3_request(
                        resolver, router, &disp, &config, &ip,
                    ).await {
                        log_error!("h3 stream error: {e}");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                log_error!("h3 accept error: {e}");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single HTTP/3 request via the resolver → stream pattern.
async fn handle_h3_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    router: Arc<crate::router::Router>,
    dispatcher: &JsDispatcher,
    _server_config: &HttpServerConfig,
    peer_ip: &str,
) -> Result<()> {
    INFLIGHT_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Release);
    let _guard = InflightGuard;

    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| anyhow!("h3 resolve request: {e}"))?;

    let (parts, _) = request.into_parts();

    let method_str = parts.method.as_str();
    let path_and_query = parts.uri.path_and_query();
    let path = path_and_query.map(|pq| pq.path()).unwrap_or("/");
    let full_uri = path_and_query.map(|pq| pq.as_str()).unwrap_or("/");
    let query_present = parts.uri.query().is_some();
    let method_code = method_code_from_str(method_str).unwrap_or(UNKNOWN_METHOD_CODE);

    /* Collect headers */
    let mut headers: Vec<(&str, &str)> = Vec::with_capacity(parts.headers.len());
    let mut accepted_encoding = compress::AcceptedEncoding::Identity;

    for (name, value) in parts.headers.iter() {
        let name_str = intern_header_name(name.as_str());
        if let Ok(val_str) = std::str::from_utf8(value.as_bytes()) {
            if name_str == "accept-encoding"
                && accepted_encoding != compress::AcceptedEncoding::Brotli
            {
                accepted_encoding = compress::parse_accept_encoding(val_str.as_bytes());
            }
            headers.push((name_str, val_str));
        }
    }

    /* Static route fast-path */
    if method_str == "GET" {
        if let Some(static_route) = router.exact_static_route(b"GET", path.as_bytes()) {
            return send_h3_static_response(&mut stream, static_route, accepted_encoding).await;
        }
    }

    /* Read request body from QUIC stream */
    let mut body_bytes = Vec::new();
    while let Some(chunk) = stream.recv_data().await.map_err(|e| anyhow!("h3 body: {e}"))? {
        let remaining = chunk.remaining();
        if body_bytes.len() + remaining > MAX_BODY_BYTES {
            let response = HttpResponse::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .unwrap();
            stream.send_response(response).await.map_err(|e| anyhow!("h3 send: {e}"))?;
            stream.send_data(Bytes::from_static(b"{\"error\":\"Payload Too Large\"}"))
                .await
                .map_err(|e| anyhow!("h3 send body: {e}"))?;
            stream.finish().await.map_err(|e| anyhow!("h3 finish: {e}"))?;
            return Ok(());
        }
        let mut buf = vec![0u8; remaining];
        chunk.chunk().iter().enumerate().for_each(|(i, &b)| buf[i] = b);
        body_bytes.extend_from_slice(&buf[..remaining]);
    }

    /* Route matching */
    let normalized_path = crate::normalize_runtime_path(path);
    let matched_route = if method_code != UNKNOWN_METHOD_CODE {
        router.match_route(method_code, normalized_path.as_ref())
    } else {
        None
    };

    /* Build bridge envelope — reuse the H2 envelope builder */
    let envelope = crate::h2_handler::build_h2_bridge_envelope(
        method_code,
        &headers,
        path,
        full_uri,
        &body_bytes,
        Some(peer_ip),
        query_present,
        &matched_route,
    );

    /* Dispatch to JS */
    match dispatcher.dispatch(Buffer::from(envelope)).await {
        Ok(response_buf) => {
            send_h3_response_from_bridge(&mut stream, &response_buf).await?;
        }
        Err(e) => {
            let response = HttpResponse::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(())
                .unwrap();
            stream.send_response(response).await.ok();
            stream.send_data(
                Bytes::from(format!("{{\"error\":\"Internal Server Error: {e}\"}}")),
            ).await.ok();
            stream.finish().await.ok();
        }
    }

    Ok(())
}

/// Send a pre-built static response over HTTP/3.
async fn send_h3_static_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    static_route: &ExactStaticRoute,
    encoding: compress::AcceptedEncoding,
) -> Result<()> {
    let response_bytes = match encoding {
        compress::AcceptedEncoding::Brotli => {
            static_route.keep_alive_response_br.as_ref()
                .unwrap_or(&static_route.keep_alive_response)
        }
        compress::AcceptedEncoding::Gzip => {
            static_route.keep_alive_response_gzip.as_ref()
                .unwrap_or(&static_route.keep_alive_response)
        }
        _ => &static_route.keep_alive_response,
    };

    let bytes = response_bytes.as_ref();
    if let Some(header_end) = memchr::memmem::find(bytes, b"\r\n\r\n") {
        let header_section = &bytes[..header_end];
        let body = &bytes[header_end + 4..];

        /* Parse actual status code from the HTTP/1.1 status line */
        let actual_status = header_section.split(|&b| b == b'\n')
            .next()
            .and_then(|line| {
                let line = if line.ends_with(b"\r") { &line[..line.len() - 1] } else { line };
                let parts: Vec<&[u8]> = line.splitn(3, |&b| b == b' ').collect();
                if parts.len() >= 2 {
                    std::str::from_utf8(parts[1]).ok()?.parse::<u16>().ok()
                } else {
                    None
                }
            })
            .and_then(|code| StatusCode::from_u16(code).ok())
            .unwrap_or(StatusCode::OK);

        let mut builder = HttpResponse::builder().status(actual_status);

        for line in header_section.split(|&b| b == b'\n') {
            let line = if line.ends_with(b"\r") { &line[..line.len() - 1] } else { line };
            if line.starts_with(b"HTTP/") || line.is_empty() { continue; }
            if let Some(colon) = line.iter().position(|&b| b == b':') {
                let name = &line[..colon];
                let value = &line[colon + 1..];
                let value = if value.first() == Some(&b' ') { &value[1..] } else { value };
                /* Skip h1-only headers invalid in h3 */
                if name.eq_ignore_ascii_case(b"connection")
                    || name.eq_ignore_ascii_case(b"transfer-encoding")
                    || name.eq_ignore_ascii_case(b"keep-alive")
                {
                    continue;
                }
                if let (Ok(n), Ok(v)) = (std::str::from_utf8(name), std::str::from_utf8(value)) {
                    builder = builder.header(n, v);
                }
            }
        }

        let response = builder.body(()).map_err(|e| anyhow!("h3 response: {e}"))?;
        stream.send_response(response).await.map_err(|e| anyhow!("h3 send: {e}"))?;
        if !body.is_empty() {
            stream.send_data(Bytes::copy_from_slice(body)).await
                .map_err(|e| anyhow!("h3 send body: {e}"))?;
        }
        stream.finish().await.map_err(|e| anyhow!("h3 finish: {e}"))?;
    } else {
        /* Malformed static response — missing header/body boundary. Send 500. */
        let response = HttpResponse::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(())
            .unwrap();
        stream.send_response(response).await.map_err(|e| anyhow!("h3 send: {e}"))?;
        stream.send_data(Bytes::from_static(b"{\"error\":\"Internal Server Error\"}"))
            .await.map_err(|e| anyhow!("h3 send body: {e}"))?;
        stream.finish().await.map_err(|e| anyhow!("h3 finish: {e}"))?;
    }

    Ok(())
}

/// Parse bridge response and send as HTTP/3.
async fn send_h3_response_from_bridge(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    response_buf: &[u8],
) -> Result<()> {
    if response_buf.len() < 8 {
        let response = HttpResponse::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(())
            .unwrap();
        stream.send_response(response).await.ok();
        stream.send_data(Bytes::from_static(b"{\"error\":\"Invalid bridge response\"}"))
            .await.ok();
        stream.finish().await.ok();
        return Ok(());
    }

    let status = u16::from_le_bytes([response_buf[0], response_buf[1]]);
    let header_count = u16::from_le_bytes([response_buf[2], response_buf[3]]) as usize;
    let body_len = u32::from_le_bytes([
        response_buf[4], response_buf[5], response_buf[6], response_buf[7],
    ]) as usize;

    let mut offset = 8usize;
    let mut builder = HttpResponse::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK));

    for _ in 0..header_count {
        if offset + 4 > response_buf.len() { break; }
        let name_len = u16::from_le_bytes([response_buf[offset], response_buf[offset + 1]]) as usize;
        offset += 2;
        let value_len = u16::from_le_bytes([response_buf[offset], response_buf[offset + 1]]) as usize;
        offset += 2;

        if offset + name_len + value_len > response_buf.len() { break; }

        let name = &response_buf[offset..offset + name_len];
        offset += name_len;
        let value = &response_buf[offset..offset + value_len];
        offset += value_len;

        if name.eq_ignore_ascii_case(b"connection")
            || name.eq_ignore_ascii_case(b"transfer-encoding")
        {
            continue;
        }

        if let (Ok(n), Ok(v)) = (std::str::from_utf8(name), std::str::from_utf8(value)) {
            builder = builder.header(n, v);
        }
    }

    let body = if offset + body_len <= response_buf.len() {
        &response_buf[offset..offset + body_len]
    } else if offset < response_buf.len() {
        &response_buf[offset..]
    } else {
        &[]
    };

    let response = builder.body(()).map_err(|e| anyhow!("h3 response: {e}"))?;
    stream.send_response(response).await.map_err(|e| anyhow!("h3 send: {e}"))?;
    if !body.is_empty() {
        stream.send_data(Bytes::copy_from_slice(body)).await
            .map_err(|e| anyhow!("h3 send body: {e}"))?;
    }
    stream.finish().await.map_err(|e| anyhow!("h3 finish: {e}"))?;

    Ok(())
}

/// RAII guard for decrementing in-flight request counter.
struct InflightGuard;
impl Drop for InflightGuard {
    fn drop(&mut self) {
        INFLIGHT_REQUESTS.fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}

/// Build the Alt-Svc header value advertising HTTP/3 availability.
/// Injected into HTTP/1.1 and HTTP/2 responses when HTTP/3 is enabled.
pub fn alt_svc_header(port: u16) -> String {
    format!("h3=\":{port}\"; ma=86400")
}
