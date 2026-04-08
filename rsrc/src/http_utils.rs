//! Shared HTTP utilities used by both the server core (lib.rs) and the router.
//!
//! Consolidates duplicated helpers that were previously defined independently
//! in lib.rs and router.rs (plan items D1, D2, R4).

use std::collections::HashMap;

// ─── Status Reason Phrases ────────────────

/// Map an HTTP status code to its standard reason phrase.
///
/// /* @param status — HTTP status code (e.g. 200, 404) */
/// /* @returns — static reason phrase string */
pub fn status_reason(status: u16) -> &'static str {
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

// ─── HTTP Response Building ───────────────

/// Build a complete HTTP/1.1 response from status, headers (HashMap), body,
/// and keep-alive flag. Used by the router for static/prebuilt responses.
///
/// /* @param status    — HTTP status code */
/// /* @param headers   — response headers as name/value pairs */
/// /* @param body      — raw response body bytes */
/// /* @param keep_alive — whether to set connection: keep-alive or close */
pub fn build_response_bytes(
    status: u16,
    headers: &HashMap<String, String>,
    body: &[u8],
    keep_alive: bool,
) -> Vec<u8> {
    let reason = status_reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let body_len = body.len();

    /* pre-calculate total size to avoid reallocation */
    let mut total_size = 9 + 3 + 1 + reason.len() + 2  // "HTTP/1.1 {status} {reason}\r\n"
        + 16 + count_digits(body_len) + 2               // "content-length: {len}\r\n"
        + 12 + connection.len() + 2;                     // "connection: {val}\r\n"

    for (name, value) in headers {
        total_size += name.len() + 2 + value.len() + 2;
    }
    total_size += 2 + body_len; // "\r\n" + body

    let mut output = Vec::with_capacity(total_size);
    output.extend_from_slice(b"HTTP/1.1 ");
    write_u16(&mut output, status);
    output.push(b' ');
    output.extend_from_slice(reason.as_bytes());
    output.extend_from_slice(b"\r\ncontent-length: ");
    write_usize(&mut output, body_len);
    output.extend_from_slice(b"\r\nconnection: ");
    output.extend_from_slice(connection.as_bytes());
    output.extend_from_slice(b"\r\n");

    for (name, value) in headers {
        /* security: skip headers with CRLF injection */
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

// ─── Integer Formatting Helpers ───────────

/// Write a usize as decimal ASCII into the output buffer.
/// Uses itoa for zero-allocation formatting.
///
/// /* @param output — target byte buffer */
/// /* @param value  — integer to format */
#[inline(always)]
pub fn write_usize(output: &mut Vec<u8>, value: usize) {
    let mut buf = itoa::Buffer::new();
    output.extend_from_slice(buf.format(value).as_bytes());
}

/// Write a u16 as decimal ASCII into the output buffer.
///
/// /* @param output — target byte buffer */
/// /* @param value  — integer to format */
#[inline(always)]
pub fn write_u16(output: &mut Vec<u8>, value: u16) {
    let mut buf = itoa::Buffer::new();
    output.extend_from_slice(buf.format(value).as_bytes());
}

/// Count the number of decimal digits in a usize value.
///
/// /* @param n — value to count digits of */
/// /* @returns — digit count (1 for n=0) */
pub fn count_digits(mut n: usize) -> usize {
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
