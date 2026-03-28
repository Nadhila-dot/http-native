use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestInput {
    pub version: u32,
    pub server_config: Option<HttpServerConfigInput>,
    pub middlewares: Vec<MiddlewareInput>,
    pub routes: Vec<RouteInput>,
}

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
}
