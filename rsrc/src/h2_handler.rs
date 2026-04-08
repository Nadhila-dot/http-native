//! HTTP/2 connection handler (DX-4.1 / BOOST-3.1).
//!
//! Handles HTTP/2 multiplexed streams over TLS connections that negotiate
//! the "h2" ALPN protocol. Each stream dispatches through the same routing
//! and handler infrastructure as HTTP/1.1, maintaining API parity.
//!
//! Architecture:
//! - TLS handshake with ALPN negotiation selects "h2" protocol
//! - Raw TCP stream is converted to poll-io compatible wrapper
//! - tokio-rustls provides TLS over the poll-io stream
//! - h2 crate handles frame processing, HPACK compression, flow control
//! - Each HTTP/2 stream maps to a single route handler invocation
//! - Responses are sent back through the h2 send-response mechanism

use std::rc::Rc;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::server::{self, SendResponse};
use h2::RecvStream;
use http::{Request as H2Request, Response as H2Response, StatusCode};
use napi::bindgen_prelude::Buffer;
use tokio_rustls::server::TlsStream as TokioTlsStream;

use crate::compress;
use crate::parser::intern_header_name;
use crate::router::{ExactStaticRoute, Router};
use crate::{
    JsDispatcher, LiveRouter, HttpServerConfig,
    BRIDGE_VERSION, REQUEST_FLAG_QUERY_PRESENT, REQUEST_FLAG_BODY_PRESENT,
    UNKNOWN_METHOD_CODE, NOT_FOUND_HANDLER_ID, MAX_BODY_BYTES,
    INFLIGHT_REQUESTS, method_code_from_str,
};

/// Maximum concurrent streams per HTTP/2 connection.
const H2_MAX_CONCURRENT_STREAMS: u32 = 256;

/// Initial window size for HTTP/2 flow control (2 MB).
const H2_INITIAL_WINDOW_SIZE: u32 = 2 * 1024 * 1024;

/// Handle an HTTP/2 connection over a poll-io TLS stream.
///
/// Performs the h2 server handshake, then dispatches each stream through
/// the standard routing infrastructure. Multiplexed streams are handled
/// concurrently — there is no head-of-line blocking.
pub(crate) async fn handle_h2_connection<IO>(
    io: TokioTlsStream<IO>,
    live_router: Rc<Arc<LiveRouter>>,
    dispatcher: Rc<Arc<JsDispatcher>>,
    server_config: Rc<Arc<HttpServerConfig>>,
    peer_ip: Option<String>,
) -> Result<()>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    let mut h2_builder = server::Builder::new();
    h2_builder
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)
        .initial_window_size(H2_INITIAL_WINDOW_SIZE);

    let mut connection = h2_builder
        .handshake(io)
        .await
        .map_err(|e| anyhow!("h2 handshake failed: {e}"))?;

    while let Some(result) = connection.accept().await {
        let (request, respond) = result.map_err(|e| anyhow!("h2 accept error: {e}"))?;

        let router_ref = live_router.as_ref().as_ref();
        let router = router_ref.router.load_full();
        let dispatcher_ref = Rc::clone(&dispatcher);
        let config_ref = Rc::clone(&server_config);
        let peer_ip_clone = peer_ip.clone();

        /* Each HTTP/2 stream is an independent request — dispatch concurrently.
         * This eliminates head-of-line blocking that HTTP/1.1 suffers from. */
        monoio::spawn(async move {
            if let Err(e) = handle_h2_stream(
                request,
                respond,
                router,
                dispatcher_ref.as_ref().as_ref(),
                config_ref.as_ref().as_ref(),
                peer_ip_clone.as_deref(),
            )
            .await
            {
                log_error!("h2 stream error: {e}");
            }
        });
    }

    Ok(())
}

/// Handle a single HTTP/2 stream (one request → one response).
async fn handle_h2_stream(
    request: H2Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    router: Arc<Router>,
    dispatcher: &JsDispatcher,
    server_config: &HttpServerConfig,
    peer_ip: Option<&str>,
) -> Result<()> {
    INFLIGHT_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Release);
    let _guard = InflightGuard;

    let (parts, mut body_stream) = request.into_parts();

    let method_str = parts.method.as_str();
    let path_and_query = parts.uri.path_and_query();
    let path = path_and_query.map(|pq| pq.path()).unwrap_or("/");
    let full_uri = path_and_query
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let query_present = parts.uri.query().is_some();

    let method_code = method_code_from_str(method_str).unwrap_or(UNKNOWN_METHOD_CODE);

    /* Collect headers into (name, value) pairs for routing and bridge */
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

    /* Try static route fast-path first */
    if method_str == "GET" {
        if let Some(static_route) = router.exact_static_route(b"GET", path.as_bytes()) {
            return send_h2_static_response(&mut respond, static_route, accepted_encoding);
        }
    }

    /* Read body if present */
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk.map_err(|e| anyhow!("h2 body read error: {e}"))?;
        if body_bytes.len() + chunk.len() > MAX_BODY_BYTES {
            let response = H2Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false)?;
            send.send_data(Bytes::from_static(b"{\"error\":\"Payload Too Large\"}"), true)?;
            return Ok(());
        }
        body_bytes.extend_from_slice(&chunk);
        body_stream.flow_control().release_capacity(chunk.len())?;
    }

    /* Route matching */
    let normalized_path = crate::normalize_runtime_path(path);
    let matched_route = if method_code != UNKNOWN_METHOD_CODE {
        router.match_route(method_code, normalized_path.as_ref())
    } else {
        None
    };

    let _handler_id = matched_route.as_ref().map(|r| r.handler_id).unwrap_or(NOT_FOUND_HANDLER_ID);

    /* Build binary bridge envelope for JS dispatch */
    let envelope = build_h2_bridge_envelope(
        method_code,
        &headers,
        path,
        full_uri,
        &body_bytes,
        peer_ip,
        query_present,
        &matched_route,
    );

    /* Dispatch to JS and send response */
    match dispatcher.dispatch(Buffer::from(envelope)).await {
        Ok(response_buf) => {
            send_h2_response_from_bridge(&mut respond, &response_buf, server_config.compression.as_ref(), accepted_encoding)?;
        }
        Err(e) => {
            let response = H2Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false)?;
            send.send_data(
                Bytes::from(format!("{{\"error\":\"Internal Server Error: {e}\"}}")),
                true,
            )?;
        }
    }

    Ok(())
}

/// Send a pre-built static response over an HTTP/2 stream.
fn send_h2_static_response(
    respond: &mut SendResponse<Bytes>,
    static_route: &ExactStaticRoute,
    encoding: compress::AcceptedEncoding,
) -> Result<()> {
    /* Select the best pre-compressed variant */
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

    /* Parse the pre-built HTTP/1.1 response to extract status, headers, and body
     * for the h2 response. The static response format is:
     * "HTTP/1.1 200 OK\r\nheader: value\r\n...\r\n\r\nbody" */
    let bytes = response_bytes.as_ref();
    if let Some(header_end) = memchr::memmem::find(bytes, b"\r\n\r\n") {
        let header_section = &bytes[..header_end];
        let body = &bytes[header_end + 4..];

        /* Parse actual status code from the HTTP/1.1 status line */
        let actual_status = header_section.split(|&b| b == b'\n')
            .next()
            .and_then(|line| {
                let line = if line.ends_with(b"\r") { &line[..line.len() - 1] } else { line };
                // "HTTP/1.1 200 OK" → extract "200"
                let parts: Vec<&[u8]> = line.splitn(3, |&b| b == b' ').collect();
                if parts.len() >= 2 {
                    std::str::from_utf8(parts[1]).ok()?.parse::<u16>().ok()
                } else {
                    None
                }
            })
            .and_then(|code| StatusCode::from_u16(code).ok())
            .unwrap_or(StatusCode::OK);

        let mut builder = H2Response::builder().status(actual_status);

        /* Parse headers from the pre-built response */
        for line in header_section.split(|&b| b == b'\n') {
            let line = if line.ends_with(b"\r") { &line[..line.len() - 1] } else { line };
            if line.starts_with(b"HTTP/") || line.is_empty() {
                continue;
            }
            if let Some(colon) = line.iter().position(|&b| b == b':') {
                let name = &line[..colon];
                let value = &line[colon + 1..];
                let value = if value.first() == Some(&b' ') { &value[1..] } else { value };
                /* Skip connection-specific headers invalid in h2 */
                if name.eq_ignore_ascii_case(b"connection")
                    || name.eq_ignore_ascii_case(b"transfer-encoding")
                {
                    continue;
                }
                if let (Ok(n), Ok(v)) = (std::str::from_utf8(name), std::str::from_utf8(value)) {
                    builder = builder.header(n, v);
                }
            }
        }

        let response = builder.body(()).map_err(|e| anyhow!("h2 response build error: {e}"))?;
        let mut send = respond.send_response(response, body.is_empty())?;
        if !body.is_empty() {
            send.send_data(Bytes::copy_from_slice(body), true)?;
        }
    } else {
        /* Fallback: send raw body */
        let response = H2Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false)?;
        send.send_data(response_bytes.clone(), true)?;
    }

    Ok(())
}

/// Build a bridge envelope for JS dispatch from HTTP/2 request data.
/// Also used by the HTTP/3 handler for bridge envelope construction.
pub fn build_h2_bridge_envelope(
    method_code: u8,
    headers: &[(&str, &str)],
    path: &str,
    url: &str,
    body: &[u8],
    peer_ip: Option<&str>,
    query_present: bool,
    matched: &Option<crate::router::MatchedRoute<'_, '_>>,
) -> Vec<u8> {
    let handler_id = matched.as_ref().map(|m| m.handler_id).unwrap_or(NOT_FOUND_HANDLER_ID);
    let ip_str = peer_ip.unwrap_or("");

    /* Serialize matched route params as "k=v\0k=v" */
    let mut params_buf = Vec::new();
    if let Some(m) = matched.as_ref() {
        for (i, name) in m.param_names.iter().enumerate() {
            if i > 0 { params_buf.push(0); }
            params_buf.extend_from_slice(name.as_bytes());
            params_buf.push(b'=');
            if let Some(val) = m.param_values.get(i) {
                params_buf.extend_from_slice(val.as_bytes());
            }
        }
    }

    /* Serialize headers needed by bridge */
    let needed_headers = if let Some(m) = matched.as_ref() {
        if m.full_headers {
            headers.to_vec()
        } else {
            headers.iter()
                .filter(|(name, _)| m.header_keys.iter().any(|k| k.as_ref().eq_ignore_ascii_case(name)))
                .copied()
                .collect::<Vec<_>>()
        }
    } else {
        headers.to_vec()
    };

    let mut hdr_buf = Vec::new();
    for (name, value) in &needed_headers {
        if !hdr_buf.is_empty() { hdr_buf.push(0); }
        hdr_buf.extend_from_slice(name.as_bytes());
        hdr_buf.push(b':');
        hdr_buf.extend_from_slice(value.as_bytes());
    }

    let mut flags: u16 = 0;
    if query_present { flags |= REQUEST_FLAG_QUERY_PRESENT; }
    if !body.is_empty() { flags |= REQUEST_FLAG_BODY_PRESENT; }

    /* Binary envelope: version | method | flags(2) | handler_id(4) | url_len(2) | path_len(2) |
     * ip_len(2) | params_len(2) | headers_len(2) | body_len(4) | url | path | ip | params | headers | body */
    let url_bytes = url.as_bytes();
    let path_bytes = path.as_bytes();
    let ip_bytes = ip_str.as_bytes();
    let total = 1 + 1 + 2 + 4 + 2 + 2 + 2 + 2 + 2 + 4 + url_bytes.len() + path_bytes.len()
        + ip_bytes.len() + params_buf.len() + hdr_buf.len() + body.len();

    let mut buf = Vec::with_capacity(total);
    buf.push(BRIDGE_VERSION);
    buf.push(method_code);
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&handler_id.to_le_bytes());
    buf.extend_from_slice(&(url_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(ip_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(params_buf.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(hdr_buf.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(url_bytes);
    buf.extend_from_slice(path_bytes);
    buf.extend_from_slice(ip_bytes);
    buf.extend_from_slice(&params_buf);
    buf.extend_from_slice(&hdr_buf);
    buf.extend_from_slice(body);

    buf
}

/// Parse a JS bridge response envelope and send it as an HTTP/2 response.
fn send_h2_response_from_bridge(
    respond: &mut SendResponse<Bytes>,
    response_buf: &[u8],
    _compression_config: Option<&compress::CompressionConfig>,
    _accepted_encoding: compress::AcceptedEncoding,
) -> Result<()> {
    if response_buf.len() < 8 {
        let response = H2Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false)?;
        send.send_data(Bytes::from_static(b"{\"error\":\"Invalid bridge response\"}"), true)?;
        return Ok(());
    }

    /* Parse bridge response: status(2) | header_count(2) | body_len(4) | headers... | body */
    let status = u16::from_le_bytes([response_buf[0], response_buf[1]]);
    let header_count = u16::from_le_bytes([response_buf[2], response_buf[3]]) as usize;
    let body_len = u32::from_le_bytes([
        response_buf[4], response_buf[5], response_buf[6], response_buf[7],
    ]) as usize;

    let mut offset = 8usize;
    let mut builder = H2Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK));

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

        /* Skip h1-only headers invalid in h2 */
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

    let response = builder.body(()).map_err(|e| anyhow!("h2 response error: {e}"))?;
    let mut send = respond.send_response(response, body.is_empty())?;
    if !body.is_empty() {
        send.send_data(Bytes::copy_from_slice(body), true)?;
    }

    Ok(())
}

/// RAII guard for decrementing the in-flight request counter.
struct InflightGuard;
impl Drop for InflightGuard {
    fn drop(&mut self) {
        INFLIGHT_REQUESTS.fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}
