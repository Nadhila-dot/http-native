//! HTTP/1.1 request parser extracted from lib.rs (plan item R1).
//!
//! Contains the `ParsedRequest` struct, the httparse-based parser, and
//! low-level byte utilities shared between the hot-path parser and the
//! full parser.

use memchr::memmem;

use crate::compress;

// ─── Constants ────────────────────────────

/// Maximum number of headers allowed per request.
pub const MAX_HEADER_COUNT: usize = 64;
/// Maximum URL length to prevent abuse.
pub const MAX_URL_LENGTH: usize = 8192;
/// Maximum single header value length.
pub const MAX_HEADER_VALUE_LENGTH: usize = 8192;

// ─── Parsed Request ───────────────────────

/// Zero-copy parsed HTTP/1.1 request. All string slices borrow from the
/// connection read buffer and are valid until the buffer is drained.
pub struct ParsedRequest<'a> {
    pub method: &'a [u8],
    pub target: &'a [u8],
    pub path: &'a [u8],
    pub keep_alive: bool,
    pub header_bytes: usize,
    pub has_body: bool,
    pub content_length: Option<usize>,
    /// True when a non-identity Transfer-Encoding header was seen.
    pub has_chunked_te: bool,
    /// Pre-parsed header pairs — stored once, used by both routing and bridge.
    pub headers: Vec<(&'a str, &'a str)>,
    /// Raw cookie header value for session extraction.
    pub cookie_header: Option<&'a str>,
    /// True when the request contains an Upgrade: websocket header.
    pub is_websocket_upgrade: bool,
    /// The Sec-WebSocket-Key header value, if present.
    pub ws_key: Option<&'a str>,
    /// Best accepted encoding from Accept-Encoding header.
    pub accepted_encoding: compress::AcceptedEncoding,
}

// ─── httparse-based Request Parsing ───────
//
// Uses the battle-tested `httparse` crate for RFC-compliant zero-copy parsing.
// Single-pass: parses headers once and stores them for reuse by both the
// router and the bridge envelope builder.

/// Parse a raw HTTP/1.1 request from a byte buffer using httparse.
///
/// Returns `None` if the buffer is incomplete (partial headers) or if the
/// request is malformed. The caller retries after reading more data.
///
/// /* @param bytes — raw bytes from the connection read buffer */
/// /* @returns — parsed request borrowing from the buffer, or None */
pub fn parse_request_httparse(bytes: &[u8]) -> Option<ParsedRequest<'_>> {
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut req = httparse::Request::new(&mut raw_headers);

    let header_len = match req.parse(bytes) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return None,
        Err(_) => return None,
    };

    let method = req.method?.as_bytes();
    let target = req.path?.as_bytes();
    let version = req.version?;

    /* security: enforce URL length limit */
    if target.len() > MAX_URL_LENGTH {
        return None;
    }

    /* extract path (before '?') — use SIMD-accelerated memchr for the scan (@B4.1) */
    let path = match memchr::memchr(b'?', target) {
        Some(pos) => &target[..pos],
        None => target,
    };

    let mut keep_alive = version >= 1; // HTTP/1.1+ defaults to keep-alive
    let mut has_body = false;
    let mut content_length: Option<usize> = None;
    let mut has_chunked_te = false;
    let mut cookie_header: Option<&str> = None;
    let mut is_websocket_upgrade = false;
    let mut ws_key: Option<&str> = None;
    let mut accepted_encoding = compress::AcceptedEncoding::Identity;
    let mut headers = Vec::with_capacity(req.headers.len());

    for header in req.headers.iter() {
        if header.name.is_empty() {
            break;
        }

        /* security: enforce header value length */
        if header.value.len() > MAX_HEADER_VALUE_LENGTH {
            return None;
        }

        let name = intern_header_name(header.name);
        let value = match std::str::from_utf8(header.value) {
            Ok(v) => v,
            Err(_) => continue,
        };

        /* connection handling — interned names are lowercase so fast-path
         * comparisons can use pointer equality for known headers. Fall back
         * to case-insensitive for non-interned names. */
        if name.eq_ignore_ascii_case("connection") {
            let vb = value.as_bytes();
            if contains_ascii_case_insensitive(vb, b"close") {
                keep_alive = false;
            }
            if contains_ascii_case_insensitive(vb, b"keep-alive") {
                keep_alive = true;
            }
        }

        /* body detection */
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

        /* session: capture cookie header */
        if name.eq_ignore_ascii_case("cookie") {
            cookie_header = Some(value);
        }

        /* websocket: detect upgrade request */
        if name.eq_ignore_ascii_case("upgrade") {
            if value.eq_ignore_ascii_case("websocket") {
                is_websocket_upgrade = true;
            }
        }
        if name.eq_ignore_ascii_case("sec-websocket-key") {
            ws_key = Some(value);
        }

        /* compression: parse Accept-Encoding */
        if accepted_encoding != compress::AcceptedEncoding::Brotli
            && name.eq_ignore_ascii_case("accept-encoding")
        {
            accepted_encoding = compress::parse_accept_encoding(value.as_bytes());
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
        cookie_header,
        is_websocket_upgrade,
        ws_key,
        accepted_encoding,
    })
}

// ─── Byte Utilities ───────────────────────

/// Find the `\r\n\r\n` header-body boundary in a byte buffer.
///
/// /* @param bytes — raw request bytes */
/// /* @returns — byte offset of the first `\r\n` in the `\r\n\r\n` sequence */
pub fn find_header_end(bytes: &[u8]) -> Option<usize> {
    memmem::find(bytes, b"\r\n\r\n")
}

/// Check if `haystack` contains `needle` with ASCII case-insensitive comparison.
///
/// /* @param haystack — bytes to search in */
/// /* @param needle   — pattern to find (case-insensitive) */
pub fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }

    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Trim leading and trailing ASCII whitespace from a byte slice.
///
/// /* @param bytes — input byte slice */
/// /* @returns — trimmed sub-slice */
pub fn trim_ascii_spaces(bytes: &[u8]) -> &[u8] {
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

// ─── Header Name Interning (@BOOST-2.2) ─────
//
// Maps the most common HTTP header names to `&'static str` references.
// This eliminates redundant byte copies when header names flow through
// the body-request path (hdr_buf packing) and speeds up downstream
// case-insensitive comparisons (interned names are already lowercase).
//
// Strategy: branch on `raw.len()` first (single integer compare), then
// do a case-insensitive match only within that length bucket. This keeps
// the miss path cost to one branch on the length — no string comparisons
// for headers that don't match any known length.

/// /* @param raw — header name borrowed from the httparse parse buffer */
/// /* @returns — static `&str` for well-known headers, original `&str` otherwise */
pub fn intern_header_name<'a>(raw: &'a str) -> &'a str {
    match raw.len() {
        4 => {
            if raw.eq_ignore_ascii_case("host") { return "host"; }
            if raw.eq_ignore_ascii_case("date") { return "date"; }
            if raw.eq_ignore_ascii_case("vary") { return "vary"; }
            raw
        }
        6 => {
            if raw.eq_ignore_ascii_case("accept") { return "accept"; }
            if raw.eq_ignore_ascii_case("cookie") { return "cookie"; }
            if raw.eq_ignore_ascii_case("origin") { return "origin"; }
            raw
        }
        7 => {
            if raw.eq_ignore_ascii_case("referer") { return "referer"; }
            if raw.eq_ignore_ascii_case("upgrade") { return "upgrade"; }
            raw
        }
        10 => {
            if raw.eq_ignore_ascii_case("connection") { return "connection"; }
            if raw.eq_ignore_ascii_case("user-agent") { return "user-agent"; }
            raw
        }
        12 => {
            if raw.eq_ignore_ascii_case("content-type") { return "content-type"; }
            raw
        }
        13 => {
            if raw.eq_ignore_ascii_case("authorization") { return "authorization"; }
            if raw.eq_ignore_ascii_case("cache-control") { return "cache-control"; }
            if raw.eq_ignore_ascii_case("if-none-match") { return "if-none-match"; }
            raw
        }
        14 => {
            if raw.eq_ignore_ascii_case("content-length") { return "content-length"; }
            if raw.eq_ignore_ascii_case("accept-charset") { return "accept-charset"; }
            raw
        }
        15 => {
            if raw.eq_ignore_ascii_case("accept-encoding") { return "accept-encoding"; }
            if raw.eq_ignore_ascii_case("accept-language") { return "accept-language"; }
            raw
        }
        17 => {
            if raw.eq_ignore_ascii_case("transfer-encoding") { return "transfer-encoding"; }
            if raw.eq_ignore_ascii_case("if-modified-since") { return "if-modified-since"; }
            raw
        }
        19 => {
            if raw.eq_ignore_ascii_case("content-disposition") { return "content-disposition"; }
            raw
        }
        _ => raw,
    }
}
