use std::collections::HashMap;

use serde::Deserialize;
use serde::de;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestInput {
    pub version: u32,
    pub server_config: Option<HttpServerConfigInput>,
    #[serde(default)]
    pub tls: Option<TlsConfigInput>,
    pub middlewares: Vec<MiddlewareInput>,
    pub routes: Vec<RouteInput>,
    #[serde(default)]
    pub ws_routes: Vec<WsRouteInput>,
    #[serde(default)]
    pub session: Option<SessionConfigInput>,
    #[serde(default)]
    pub compression: Option<CompressionConfigInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsConfigInput {
    pub cert: String,
    pub key: String,
    #[serde(default)]
    pub ca: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfigInput {
    pub secret: String,
    #[serde(default = "default_max_age")]
    pub max_age_secs: u64,
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_true")]
    pub http_only: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default = "default_same_site")]
    pub same_site: String,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_max_data_size")]
    pub max_data_size: usize,
}

fn default_max_age() -> u64 { 3600 }
fn default_cookie_name() -> String { "sid".to_string() }
fn default_true() -> bool { true }
fn default_same_site() -> String { "lax".to_string() }
fn default_path() -> String { "/".to_string() }
fn default_max_sessions() -> usize { 100_000 }
fn default_max_data_size() -> usize { 4096 }

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpServerConfigInput {
    pub default_host: Option<String>,
    pub default_backlog: Option<i32>,
    pub max_header_bytes: Option<usize>,
    pub hot_get_root_http11: Option<String>,
    pub hot_get_root_http10: Option<String>,
    pub header_connection_prefix: Option<String>,
    pub header_content_length_prefix: Option<String>,
    pub header_transfer_encoding_prefix: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MiddlewareInput {
    pub path_prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteInput {
    pub method: String,
    pub method_code: u8,
    pub path: String,
    pub route_kind: u8,
    pub handler_id: u32,
    pub cache_namespace: String,
    pub handler_source: String,
    pub param_names: Vec<String>,
    #[allow(dead_code)]
    pub segment_count: u16,
    pub header_keys: Vec<String>,
    pub full_headers: bool,
    #[serde(default)]
    pub needs_path: bool,
    #[serde(default)]
    pub needs_url: bool,
    #[serde(default)]
    pub needs_query: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub needs_session: bool,
    #[serde(default)]
    pub cache: Option<CacheConfigInput>,
    #[serde(default)]
    pub static_response: Option<StaticResponseInput>,
    /// @DX-3.4: per-route maximum request body size in bytes. Overrides the
    /// global MAX_BODY_BYTES constant when set. Enforced in Rust before the
    /// full body is read into memory.
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheConfigInput {
    pub ttl_secs: u64,
    pub max_entries: usize,
    pub vary_by: Vec<CacheVaryInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheVaryInput {
    pub source: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticResponseInput {
    pub status: u16,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsRouteInput {
    pub path: String,
    pub handler_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompressionConfigInput {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_min_size")]
    pub min_size: usize,
    #[serde(default = "default_brotli_quality")]
    pub brotli_quality: u32,
    #[serde(default = "default_gzip_level")]
    pub gzip_level: u32,
    #[serde(default, deserialize_with = "deserialize_quality_map")]
    pub quality_map: Vec<ContentTypeQualityInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentTypeQualityInput {
    /// Content-type pattern, e.g. "image/svg+xml", "application/json", "text/*"
    pub pattern: String,
    pub brotli_quality: Option<u32>,
    pub gzip_level: Option<u32>,
}

fn deserialize_quality_map<'de, D>(deserializer: D) -> Result<Vec<ContentTypeQualityInput>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let opt: Option<Vec<ContentTypeQualityInput>> = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

fn default_min_size() -> usize { 1024 }
fn default_brotli_quality() -> u32 { 4 }
fn default_gzip_level() -> u32 { 6 }
