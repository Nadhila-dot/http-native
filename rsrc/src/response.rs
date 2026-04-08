//! Response builder utilities (plan item R2).
//!
//! Contains functions for constructing raw HTTP/1.1 response byte vectors,
//! patching connection headers, and injecting Set-Cookie headers into
//! already-built responses.

use memchr::memmem;

use crate::http_utils::{count_digits, status_reason, write_u16, write_usize};
use crate::compress;

/// Build a complete HTTP/1.1 response with optional compression.
///
/// Returns a fully formed response (status line + headers + body) as a byte vector.
pub fn build_response_bytes_fast(
    /* @param status             HTTP status code (e.g. 200, 404) */
    status: u16,
    /* @param headers            response headers as name/value pairs */
    headers: &[(Box<str>, Box<str>)],
    /* @param body               raw response body bytes */
    body: &[u8],
    /* @param keep_alive         whether to set connection: keep-alive */
    keep_alive: bool,
    /* @param encoding           client-accepted encoding from Accept-Encoding */
    encoding: compress::AcceptedEncoding,
    /* @param compression_config per-content-type compression settings, if enabled */
    compression_config: Option<&compress::CompressionConfig>,
) -> Vec<u8> {
    // ── Scan headers for content-type / content-encoding ──
    let mut content_type: Option<&[u8]> = None;
    let mut has_content_encoding = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.as_bytes());
        } else if name.eq_ignore_ascii_case("content-encoding") {
            has_content_encoding = true;
        }
    }

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

    // ── Build HTTP response ──
    let reason = status_reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let body_len = final_body.len();

    let mut total_size =
        9 + 3 + 1 + reason.len() + 2 + 16 + count_digits(body_len) + 2 + 12 + connection.len() + 2;

    if applied_encoding.is_some() {
        // "content-encoding: br\r\nvary: accept-encoding\r\n" worst case ~50 bytes
        total_size += 50;
    }

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

    // Compression headers
    if let Some(enc) = applied_encoding {
        output.extend_from_slice(b"content-encoding: ");
        output.extend_from_slice(compress::encoding_header_value(enc));
        output.extend_from_slice(b"\r\nvary: accept-encoding\r\n");
    }

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
    output.extend_from_slice(final_body);
    output
}

/// Patch the `connection:` header value in an already-built HTTP response.
/// Searches for `connection: keep-alive` or `connection: close` and swaps to the
/// requested variant.  The two values differ in length (10 vs 5 bytes) so the
/// Vec may grow or shrink by a few bytes.
pub fn patch_connection_header(
    /* @param response   raw HTTP response bytes to patch */
    response: &[u8],
    /* @param keep_alive true → set keep-alive, false → set close */
    keep_alive: bool,
) -> Vec<u8> {
    let (find, replace) = if keep_alive {
        (&b"connection: close\r\n"[..], &b"connection: keep-alive\r\n"[..])
    } else {
        (&b"connection: keep-alive\r\n"[..], &b"connection: close\r\n"[..])
    };

    if let Some(pos) = memmem::find(response, find) {
        let mut out = Vec::with_capacity(response.len() + replace.len() - find.len());
        out.extend_from_slice(&response[..pos]);
        out.extend_from_slice(replace);
        out.extend_from_slice(&response[pos + find.len()..]);
        out
    } else {
        // Header not found (shouldn't happen) — return unchanged clone
        response.to_vec()
    }
}

/// Inject a Set-Cookie header into an already-built HTTP response.
/// Inserts the header just before the final \r\n\r\n (end of headers).
pub fn inject_set_cookie_header(
    /* @param response     mutable raw HTTP response bytes */
    response: &mut Vec<u8>,
    /* @param cookie_value full Set-Cookie value string */
    cookie_value: &str,
) {
    // Find the \r\n\r\n boundary between headers and body
    if let Some(pos) = memmem::find(response, b"\r\n\r\n") {
        let header_line = format!("set-cookie: {}\r\n", cookie_value);
        let header_bytes = header_line.as_bytes();

        // Insert before the final \r\n\r\n
        let insert_pos = pos + 2; // after the last header's \r\n, before the blank \r\n
        response.splice(insert_pos..insert_pos, header_bytes.iter().copied());

        // Update Content-Length — it shouldn't change since we're adding headers, not body.
        // Content-Length only measures the body, which is unchanged.
    }
}

/// Build a simple error response without going through the JS bridge
pub fn build_error_response_bytes(
    /* @param status     HTTP status code */
    status: u16,
    /* @param body       JSON error body bytes */
    body: &[u8],
    /* @param keep_alive whether to set connection: keep-alive */
    keep_alive: bool,
) -> Vec<u8> {
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
