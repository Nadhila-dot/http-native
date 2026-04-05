use std::io::Write;

use flate2::write::GzEncoder;
use flate2::Compression;

use crate::manifest::CompressionConfigInput;

// ─── Configuration ─────────────────────

#[derive(Clone)]
pub struct CompressionConfig {
    pub min_size: usize,
    pub brotli_quality: u32,
    pub gzip_level: u32,
    /// Per-content-type quality overrides, checked in order.
    pub quality_map: Vec<ContentTypeQuality>,
}

#[derive(Clone)]
pub struct ContentTypeQuality {
    /// Either an exact media-type prefix like "image/svg+xml" or a wildcard like "text/"
    pattern: ContentTypePattern,
    brotli_quality: Option<u32>,
    gzip_level: Option<u32>,
}

#[derive(Clone)]
enum ContentTypePattern {
    /// Matches "type/" prefix, e.g. "text/*" stored as "text/"
    Wildcard(Box<[u8]>),
    /// Exact media-type match (case-insensitive)
    Exact(Box<[u8]>),
}

impl CompressionConfig {
    pub fn from_manifest(input: Option<&CompressionConfigInput>) -> Option<Self> {
        let cfg = input?;
        if !cfg.enabled {
            return None;
        }

        let quality_map = cfg.quality_map.iter().map(|entry| {
            let pattern = if entry.pattern.ends_with("/*") {
                // "text/*" → match prefix "text/"
                let prefix = entry.pattern[..entry.pattern.len() - 1].to_ascii_lowercase();
                ContentTypePattern::Wildcard(prefix.into_bytes().into_boxed_slice())
            } else if entry.pattern.ends_with('/') {
                ContentTypePattern::Wildcard(entry.pattern.to_ascii_lowercase().into_bytes().into_boxed_slice())
            } else {
                ContentTypePattern::Exact(entry.pattern.to_ascii_lowercase().into_bytes().into_boxed_slice())
            };
            ContentTypeQuality {
                pattern,
                brotli_quality: entry.brotli_quality.map(|q| q.min(11)),
                gzip_level: entry.gzip_level.map(|l| l.min(9)),
            }
        }).collect();

        Some(Self {
            min_size: cfg.min_size,
            brotli_quality: cfg.brotli_quality.min(11),
            gzip_level: cfg.gzip_level.min(9),
            quality_map,
        })
    }

    /// Resolve brotli quality for a given content-type, checking quality_map first.
    fn brotli_quality_for(&self, content_type: Option<&[u8]>) -> u32 {
        if let Some(ct) = content_type {
            if let Some(q) = self.find_override(ct, |e| e.brotli_quality) {
                return q;
            }
        }
        self.brotli_quality
    }

    /// Resolve gzip level for a given content-type, checking quality_map first.
    fn gzip_level_for(&self, content_type: Option<&[u8]>) -> u32 {
        if let Some(ct) = content_type {
            if let Some(l) = self.find_override(ct, |e| e.gzip_level) {
                return l;
            }
        }
        self.gzip_level
    }

    fn find_override(&self, content_type: &[u8], getter: fn(&ContentTypeQuality) -> Option<u32>) -> Option<u32> {
        // Extract media type (before ;charset= etc.)
        let media = content_type
            .split(|&b| b == b';')
            .next()
            .map(trim_ascii)
            .unwrap_or(content_type);

        for entry in &self.quality_map {
            let matched = match &entry.pattern {
                ContentTypePattern::Wildcard(prefix) => {
                    media.len() >= prefix.len()
                        && media[..prefix.len()].eq_ignore_ascii_case(prefix)
                }
                ContentTypePattern::Exact(exact) => {
                    media.eq_ignore_ascii_case(exact)
                }
            };
            if matched {
                return getter(entry);
            }
        }
        None
    }
}

// ─── Accepted Encoding ─────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptedEncoding {
    Identity,
    Gzip,
    Brotli,
}

/// Parse the Accept-Encoding header value and return the best encoding.
/// Preference order: Brotli > Gzip > Identity.
pub fn parse_accept_encoding(value: &[u8]) -> AcceptedEncoding {
    let mut best = AcceptedEncoding::Identity;
    for part in value.split(|&b| b == b',') {
        let trimmed = trim_ascii(part);
        // Extract the encoding name (before any ;q= weight)
        let name = trimmed
            .split(|&b| b == b';')
            .next()
            .map(trim_ascii)
            .unwrap_or(trimmed);
        if name.eq_ignore_ascii_case(b"br") {
            return AcceptedEncoding::Brotli; // Best possible — return immediately
        }
        if name.eq_ignore_ascii_case(b"gzip") {
            best = AcceptedEncoding::Gzip;
        }
    }
    best
}

// ─── Compression Decision ──────────────

/// Determine whether compression should be applied.
/// Returns the encoding to use, or None if compression should be skipped.
pub fn should_compress(
    config: &CompressionConfig,
    encoding: AcceptedEncoding,
    body_len: usize,
    content_type: Option<&[u8]>,
    has_existing_content_encoding: bool,
) -> Option<AcceptedEncoding> {
    if encoding == AcceptedEncoding::Identity {
        return None;
    }
    if body_len < config.min_size {
        return None;
    }
    if has_existing_content_encoding {
        return None;
    }
    if let Some(ct) = content_type {
        if !is_compressible_content_type(ct) {
            return None;
        }
    }
    Some(encoding)
}

/// Check whether a content-type is eligible for compression.
fn is_compressible_content_type(content_type: &[u8]) -> bool {
    // Extract the media type (before any ;charset= etc.)
    let media = content_type
        .split(|&b| b == b';')
        .next()
        .map(trim_ascii)
        .unwrap_or(content_type);

    // text/* — always compressible
    if media.len() >= 5 && media[..5].eq_ignore_ascii_case(b"text/") {
        return true;
    }

    // application/* subtypes
    if media.len() >= 12 && media[..12].eq_ignore_ascii_case(b"application/") {
        let subtype = &media[12..];
        if subtype.eq_ignore_ascii_case(b"json")
            || subtype.eq_ignore_ascii_case(b"javascript")
            || subtype.eq_ignore_ascii_case(b"xml")
            || subtype.eq_ignore_ascii_case(b"xhtml+xml")
            || subtype.eq_ignore_ascii_case(b"x-javascript")
            || subtype.eq_ignore_ascii_case(b"ld+json")
            || subtype.eq_ignore_ascii_case(b"graphql+json")
            || subtype.eq_ignore_ascii_case(b"manifest+json")
            || subtype.eq_ignore_ascii_case(b"vnd.api+json")
        {
            return true;
        }
    }

    // image/svg+xml
    if media.eq_ignore_ascii_case(b"image/svg+xml") {
        return true;
    }

    false
}

// ─── Compression ───────────────────────

/// Compress a body with the given encoding.
/// Returns None if compression produces output >= the original size.
/// When `content_type` is provided, per-content-type quality overrides are applied.
pub fn compress_body(
    body: &[u8],
    encoding: AcceptedEncoding,
    config: &CompressionConfig,
    content_type: Option<&[u8]>,
) -> Option<Vec<u8>> {
    match encoding {
        AcceptedEncoding::Brotli => compress_brotli(body, config.brotli_quality_for(content_type)),
        AcceptedEncoding::Gzip => compress_gzip(body, config.gzip_level_for(content_type)),
        AcceptedEncoding::Identity => None,
    }
}

fn compress_brotli(body: &[u8], quality: u32) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(body.len());
    let params = brotli::enc::BrotliEncoderParams {
        quality: quality as i32,
        ..Default::default()
    };
    let mut cursor = std::io::Cursor::new(body);
    brotli::BrotliCompress(&mut cursor, &mut output, &params).ok()?;
    if output.len() < body.len() {
        Some(output)
    } else {
        None
    }
}

fn compress_gzip(body: &[u8], level: u32) -> Option<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::with_capacity(body.len()), Compression::new(level));
    encoder.write_all(body).ok()?;
    let output = encoder.finish().ok()?;
    if output.len() < body.len() {
        Some(output)
    } else {
        None
    }
}

/// Returns the Content-Encoding header value for the given encoding.
pub fn encoding_header_value(encoding: AcceptedEncoding) -> &'static [u8] {
    match encoding {
        AcceptedEncoding::Brotli => b"br",
        AcceptedEncoding::Gzip => b"gzip",
        AcceptedEncoding::Identity => b"identity",
    }
}

// ─── Helpers ───────────────────────────

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |p| p + 1);
    &bytes[start..end]
}
