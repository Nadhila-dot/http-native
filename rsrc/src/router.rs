use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use crate::analyzer::{
    analyze_dynamic_fast_path, analyze_route, normalize_path, parse_segments, AnalysisResult,
    DynamicFastPathSpec, RouteSegment,
};
use crate::manifest::{ManifestInput, MiddlewareInput, RouteInput, StaticResponseInput};

const ROUTE_KIND_EXACT: u8 = 1;
const ROUTE_KIND_PARAM: u8 = 2;
const MAX_STACK_SEGMENTS: usize = 16;

// ─── Public Types ───────────────────────

#[derive(Clone)]
pub struct Router {
    exact_get_root: Option<ExactStaticRoute>,
    /// O(1) exact-match routes (HashMap<method, HashMap<path_bytes, spec>>)
    dynamic_exact_routes: HashMap<MethodKey, HashMap<Box<[u8]>, DynamicRouteSpec>>,
    /// O(1) static-response routes
    exact_static_routes: HashMap<MethodKey, HashMap<Box<[u8]>, ExactStaticRoute>>,
    /// O(M) radix-tree routes per method (M = path length)
    radix_trees: HashMap<MethodKey, RadixNode>,
    /// WebSocket routes: path → handler_id
    ws_routes: HashMap<String, u32>,
}

#[derive(Clone)]
pub struct ExactStaticRoute {
    pub close_response: Bytes,
    pub keep_alive_response: Bytes,
}

pub struct MatchedRoute<'a, 'b> {
    pub handler_id: u32,
    pub cache_namespace: u64,
    pub param_values: Vec<&'b str>,
    pub param_names: &'a [Box<str>],
    pub header_keys: &'a [Box<str>],
    pub full_headers: bool,
    pub needs_path: bool,
    pub needs_url: bool,
    pub needs_query: bool,
    pub fast_path: Option<&'a DynamicFastPathSpec>,
    pub cache_config: Option<&'a RouteCacheConfig>,
}

#[derive(Clone)]
pub struct RouteCacheConfig {
    pub ttl_secs: u64,
    pub max_entries: usize,
    pub vary_keys: Box<[CacheVaryKey]>,
}

#[derive(Clone)]
pub enum CacheVaryKey {
    QueryParam(Box<str>),
    PathParam(Box<str>),
    Header(Box<str>),
}

// ─── Internal Types ─────────────────────

#[derive(Clone)]
struct DynamicRouteSpec {
    handler_id: u32,
    cache_namespace: u64,
    param_names: Box<[Box<str>]>,
    header_keys: Box<[Box<str>]>,
    full_headers: bool,
    needs_path: bool,
    needs_url: bool,
    needs_query: bool,
    fast_path: Option<DynamicFastPathSpec>,
    cache_config: Option<RouteCacheConfig>,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum MethodKey {
    Delete,
    Get,
    Head,
    Options,
    Patch,
    Post,
    Put,
}

// ─── Radix Tree ─────────────────────────
//
// Each node represents either a static prefix or a parameter capture.
// Matching is O(M) where M is the number of path segments, not O(N) routes.

#[derive(Clone)]
struct RadixNode {
    children: Vec<RadixChild>,
    /// If this node is a terminal route, the handler spec
    handler: Option<DynamicRouteSpec>,
    /// Parameter capture node for this level
    param_child: Option<Box<RadixParamChild>>,
}

#[derive(Clone)]
struct RadixChild {
    /// The static segment this child matches
    segment: Box<str>,
    node: RadixNode,
}

#[derive(Clone)]
struct RadixParamChild {
    node: RadixNode,
}

impl RadixNode {
    fn new() -> Self {
        Self {
            children: Vec::new(),
            handler: None,
            param_child: None,
        }
    }

    /// Insert a route into the radix tree
    fn insert(&mut self, segments: &[RouteSegment], spec: DynamicRouteSpec) {
        if segments.is_empty() {
            self.handler = Some(spec);
            return;
        }

        match &segments[0] {
            RouteSegment::Static(value) => {
                // Find existing child with this segment
                for child in &mut self.children {
                    if child.segment.as_ref() == value.as_str() {
                        child.node.insert(&segments[1..], spec);
                        return;
                    }
                }

                // Create new child
                let mut child_node = RadixNode::new();
                child_node.insert(&segments[1..], spec);
                self.children.push(RadixChild {
                    segment: value.clone().into_boxed_str(),
                    node: child_node,
                });
            }
            RouteSegment::Param(_) => {
                if self.param_child.is_none() {
                    self.param_child = Some(Box::new(RadixParamChild {
                        node: RadixNode::new(),
                    }));
                }
                self.param_child
                    .as_mut()
                    .unwrap()
                    .node
                    .insert(&segments[1..], spec);
            }
        }
    }

    /// Match a request path against this radix tree — O(M) where M = segment count
    fn match_path<'a, 'b>(
        &'a self,
        segments: &[&'b str],
        param_values: &mut Vec<&'b str>,
    ) -> Option<&'a DynamicRouteSpec> {
        if segments.is_empty() {
            return self.handler.as_ref();
        }

        let segment = segments[0];
        let rest = &segments[1..];

        // Try static children first (higher priority)
        for child in &self.children {
            if child.segment.as_ref() == segment {
                if let Some(spec) = child.node.match_path(rest, param_values) {
                    return Some(spec);
                }
            }
        }

        // Try parameter capture
        if let Some(param_child) = &self.param_child {
            let prev_len = param_values.len();
            param_values.push(segment);
            if let Some(spec) = param_child.node.match_path(rest, param_values) {
                return Some(spec);
            }
            // Backtrack
            param_values.truncate(prev_len);
        }

        None
    }
}

// ─── Router Implementation ──────────────

impl Router {
    pub fn from_manifest(manifest: &ManifestInput) -> Result<Self> {
        let mut exact_get_root = None;
        let mut dynamic_exact_routes = HashMap::new();
        let mut exact_static_routes = HashMap::new();
        let mut radix_trees: HashMap<MethodKey, RadixNode> = HashMap::new();

        for route in &manifest.routes {
            let method = route.method.to_uppercase();
            let path = normalize_path(route.path.as_str());
            if let Some(static_response) = route.static_response.as_ref() {
                let Some(method_key) = MethodKey::from_method_str(method.as_str()) else {
                    continue;
                };

                let exact_route = build_exact_static_route(static_response);

                if method_key == MethodKey::Get && path == "/" {
                    exact_get_root = Some(exact_route);
                    continue;
                }

                exact_static_routes
                    .entry(method_key)
                    .or_insert_with(HashMap::new)
                    .insert(Box::<[u8]>::from(path.as_bytes()), exact_route);
                continue;
            }

            if let AnalysisResult::ExactStaticFastPath(spec) =
                analyze_route(route, &manifest.middlewares)
            {
                let Some(method_key) = MethodKey::from_method_str(method.as_str()) else {
                    continue;
                };

                let exact_route = ExactStaticRoute {
                    close_response: Bytes::from(build_close_response(
                        spec.status,
                        &spec.headers,
                        &spec.body,
                    )),
                    keep_alive_response: Bytes::from(build_keep_alive_response(
                        spec.status,
                        &spec.headers,
                        &spec.body,
                    )),
                };

                if method_key == MethodKey::Get && path == "/" {
                    exact_get_root = Some(exact_route);
                    continue;
                }

                exact_static_routes
                    .entry(method_key)
                    .or_insert_with(HashMap::new)
                    .insert(Box::<[u8]>::from(path.as_bytes()), exact_route);
                continue;
            }

            let Some(method_key) = MethodKey::from_code(route.method_code) else {
                continue;
            };

            match route.route_kind {
                ROUTE_KIND_EXACT => {
                    dynamic_exact_routes
                        .entry(method_key)
                        .or_insert_with(HashMap::new)
                        .insert(
                            Box::<[u8]>::from(path.as_bytes()),
                            compile_dynamic_route_spec(route, &manifest.middlewares),
                        );
                }
                ROUTE_KIND_PARAM => {
                    // Insert into radix tree instead of linear Vec
                    let segments = parse_segments(path.as_str());
                    let spec = compile_dynamic_route_spec(route, &manifest.middlewares);
                    radix_trees
                        .entry(method_key)
                        .or_insert_with(RadixNode::new)
                        .insert(&segments, spec);
                }
                _ => {}
            }
        }

        let mut ws_routes = HashMap::new();
        for ws_route in &manifest.ws_routes {
            let path = normalize_path(ws_route.path.as_str());
            ws_routes.insert(path, ws_route.handler_id);
        }

        Ok(Self {
            exact_get_root,
            dynamic_exact_routes,
            exact_static_routes,
            radix_trees,
            ws_routes,
        })
    }

    pub fn match_route<'a, 'b>(
        &'a self,
        method_code: u8,
        path: &'b str,
    ) -> Option<MatchedRoute<'a, 'b>> {
        let method_key = MethodKey::from_code(method_code)?;

        // Fast path: exact match (O(1))
        if let Some(route_spec) = self
            .dynamic_exact_routes
            .get(&method_key)
            .and_then(|routes| routes.get(path.as_bytes()))
        {
            return Some(MatchedRoute {
                handler_id: route_spec.handler_id,
                cache_namespace: route_spec.cache_namespace,
                param_values: Vec::new(),
                param_names: route_spec.param_names.as_ref(),
                header_keys: route_spec.header_keys.as_ref(),
                full_headers: route_spec.full_headers,
                needs_path: route_spec.needs_path,
                needs_url: route_spec.needs_url,
                needs_query: route_spec.needs_query,
                fast_path: route_spec.fast_path.as_ref(),
                cache_config: route_spec.cache_config.as_ref(),
            });
        }

        // Radix tree match (O(M) where M = segment count)
        let tree = self.radix_trees.get(&method_key)?;
        let mut seg_buf = [""; MAX_STACK_SEGMENTS];
        let seg_count = split_segments_stack(path, &mut seg_buf);
        let mut param_values = Vec::with_capacity(4);
        let spec = if seg_count <= MAX_STACK_SEGMENTS {
            tree.match_path(&seg_buf[..seg_count], &mut param_values)?
        } else {
            let segments = split_request_segments(path);
            tree.match_path(&segments, &mut param_values)?
        };

        Some(MatchedRoute {
            handler_id: spec.handler_id,
            cache_namespace: spec.cache_namespace,
            param_values,
            param_names: spec.param_names.as_ref(),
            header_keys: spec.header_keys.as_ref(),
            full_headers: spec.full_headers,
            needs_path: spec.needs_path,
            needs_url: spec.needs_url,
            needs_query: spec.needs_query,
            fast_path: spec.fast_path.as_ref(),
            cache_config: spec.cache_config.as_ref(),
        })
    }

    pub fn exact_static_route(&self, method: &[u8], path: &[u8]) -> Option<&ExactStaticRoute> {
        if method == b"GET" && path == b"/" {
            return self.exact_get_root.as_ref();
        }

        let method_key = MethodKey::from_method_bytes(method)?;
        self.exact_static_routes
            .get(&method_key)
            .and_then(|routes| routes.get(path))
    }

    pub fn exact_get_root(&self) -> Option<&ExactStaticRoute> {
        self.exact_get_root.as_ref()
    }

    pub fn match_ws_route(&self, path: &str) -> Option<u32> {
        self.ws_routes.get(path).copied()
    }

    pub fn cache_namespaces(&self) -> HashSet<u64> {
        let mut namespaces = HashSet::new();

        for routes in self.dynamic_exact_routes.values() {
            for route in routes.values() {
                namespaces.insert(route.cache_namespace);
            }
        }

        for tree in self.radix_trees.values() {
            collect_radix_cache_namespaces(tree, &mut namespaces);
        }

        namespaces
    }
}

// ─── MethodKey ──────────────────────────

impl MethodKey {
    fn from_method_str(method: &str) -> Option<Self> {
        match method {
            "DELETE" => Some(Self::Delete),
            "GET" => Some(Self::Get),
            "HEAD" => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            "PATCH" => Some(Self::Patch),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            _ => None,
        }
    }

    fn from_method_bytes(method: &[u8]) -> Option<Self> {
        match method {
            b"DELETE" => Some(Self::Delete),
            b"GET" => Some(Self::Get),
            b"HEAD" => Some(Self::Head),
            b"OPTIONS" => Some(Self::Options),
            b"PATCH" => Some(Self::Patch),
            b"POST" => Some(Self::Post),
            b"PUT" => Some(Self::Put),
            _ => None,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Get),
            2 => Some(Self::Post),
            3 => Some(Self::Put),
            4 => Some(Self::Delete),
            5 => Some(Self::Patch),
            6 => Some(Self::Options),
            7 => Some(Self::Head),
            _ => None,
        }
    }
}

// ─── Helpers ────────────────────────────

fn compile_dynamic_route_spec(route: &RouteInput, middlewares: &[MiddlewareInput]) -> DynamicRouteSpec {
    let param_names = route
        .param_names
        .iter()
        .map(|name| name.clone().into_boxed_str())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let header_keys = route
        .header_keys
        .iter()
        .map(|name| name.clone().into_boxed_str())
        .collect::<Vec<_>>()
        .into_boxed_slice();

    let cache_config = route.cache.as_ref().map(|cache_in| {
        let vary_keys = cache_in.vary_by.iter().map(|v| match v.source.as_str() {
            "query" => CacheVaryKey::QueryParam(v.name.clone().into_boxed_str()),
            "params" => CacheVaryKey::PathParam(v.name.clone().into_boxed_str()),
            "headers" | "header" => CacheVaryKey::Header(v.name.clone().into_boxed_str()),
            _ => CacheVaryKey::QueryParam(v.name.clone().into_boxed_str()),
        }).collect::<Vec<_>>().into_boxed_slice();

        RouteCacheConfig {
            ttl_secs: cache_in.ttl_secs,
            max_entries: cache_in.max_entries.max(1),
            vary_keys,
        }
    });

    DynamicRouteSpec {
        handler_id: route.handler_id,
        cache_namespace: hash_cache_namespace(route.cache_namespace.as_str()),
        param_names,
        header_keys,
        full_headers: route.full_headers,
        needs_path: route.needs_path,
        needs_url: route.needs_url,
        needs_query: route.needs_query,
        fast_path: analyze_dynamic_fast_path(route, middlewares),
        cache_config,
    }
}

fn build_exact_static_route(static_response: &StaticResponseInput) -> ExactStaticRoute {
    let body = static_response.body.as_bytes();
    ExactStaticRoute {
        close_response: Bytes::from(build_close_response(
            static_response.status,
            &static_response.headers,
            body,
        )),
        keep_alive_response: Bytes::from(build_keep_alive_response(
            static_response.status,
            &static_response.headers,
            body,
        )),
    }
}

fn hash_cache_namespace(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn collect_radix_cache_namespaces(node: &RadixNode, output: &mut HashSet<u64>) {
    if let Some(handler) = node.handler.as_ref() {
        output.insert(handler.cache_namespace);
    }

    if let Some(param_child) = node.param_child.as_ref() {
        collect_radix_cache_namespaces(&param_child.node, output);
    }

    for child in &node.children {
        collect_radix_cache_namespaces(&child.node, output);
    }
}

fn split_request_segments(path: &str) -> Vec<&str> {
    if path == "/" {
        return Vec::new();
    }

    path.trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// Stack-allocated segment splitting — avoids heap Vec for paths with ≤ MAX_STACK_SEGMENTS segments.
/// Returns the number of segments written into `buf`. If the path has more segments than `buf.len()`,
/// returns `buf.len() + 1` as an overflow sentinel.
fn split_segments_stack<'a>(path: &'a str, buf: &mut [&'a str]) -> usize {
    if path == "/" {
        return 0;
    }
    let mut count = 0;
    for segment in path.trim_start_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        if count >= buf.len() {
            return count + 1; // overflow sentinel
        }
        buf[count] = segment;
        count += 1;
    }
    count
}

fn build_keep_alive_response(
    status: u16,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> Vec<u8> {
    build_response_bytes(status, headers, body, true)
}

fn build_close_response(status: u16, headers: &HashMap<String, String>, body: &[u8]) -> Vec<u8> {
    build_response_bytes(status, headers, body, false)
}

fn build_response_bytes(
    status: u16,
    headers: &HashMap<String, String>,
    body: &[u8],
    keep_alive: bool,
) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: {}\r\n",
        status,
        status_reason(status),
        body.len(),
        if keep_alive { "keep-alive" } else { "close" }
    )
    .into_bytes();

    for (name, value) in headers {
        // Security: skip headers with CRLF injection
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            continue;
        }
        response.extend_from_slice(name.as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(value.as_bytes());
        response.extend_from_slice(b"\r\n");
    }

    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(body);
    response
}

// Todo: Are these expensive? if so remove them.

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

// ─── Native Zero-Allocation LRU Cache ───

pub struct CacheEntry {
    pub response_bytes: Bytes,
    pub response_bytes_close: Bytes,
    pub expires_at: Instant,
}

struct LruNode {
    key: u64,
    value: Option<CacheEntry>,
    prev: usize,
    next: usize,
}

pub struct RouteCache {
    map: HashMap<u64, usize>,
    nodes: Vec<LruNode>,
    head: usize,
    tail: usize,
    max_entries: usize,
    free_list: Vec<usize>,
}

const NULL_NODE: usize = usize::MAX;

impl RouteCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            map: HashMap::with_capacity(max_entries),
            nodes: Vec::with_capacity(max_entries),
            head: NULL_NODE,
            tail: NULL_NODE,
            max_entries,
            free_list: Vec::new(),
        }
    }

    pub fn get(&mut self, key: u64, now: Instant) -> Option<&CacheEntry> {
        if let Some(&idx) = self.map.get(&key) {
            // Check expiry
            if let Some(val) = &self.nodes[idx].value {
                if now < val.expires_at {
                    self.move_to_head(idx);
                    return self.nodes[idx].value.as_ref();
                }
            }
            // Expired -> remove
            self.remove_node(idx);
            self.map.remove(&key);
        }
        None
    }

    pub fn insert(&mut self, key: u64, entry: CacheEntry) {
        if let Some(&idx) = self.map.get(&key) {
            self.nodes[idx].value = Some(entry);
            self.move_to_head(idx);
            return;
        }

        let new_idx = if let Some(idx) = self.free_list.pop() {
            idx
        } else if self.nodes.len() < self.max_entries {
            let idx = self.nodes.len();
            self.nodes.push(LruNode {
                key: 0,
                value: None,
                prev: NULL_NODE,
                next: NULL_NODE,
            });
            idx
        } else {
            // Evict tail
            let tail_idx = self.tail;
            if tail_idx != NULL_NODE {
                let tail_key = self.nodes[tail_idx].key;
                self.remove_node(tail_idx);
                self.map.remove(&tail_key);
                tail_idx
            } else {
                return; // 0 entries
            }
        };

        self.nodes[new_idx].key = key;
        self.nodes[new_idx].value = Some(entry);
        self.map.insert(key, new_idx);
        self.push_head(new_idx);
    }
    
    #[allow(dead_code)]
    pub fn invalidate(&mut self, key: u64) {
        if let Some(&idx) = self.map.get(&key) {
            self.remove_node(idx);
            self.map.remove(&key);
        }
    }

    fn move_to_head(&mut self, idx: usize) {
        if self.head == idx {
            return;
        }
        self.remove_link(idx);
        self.push_head(idx);
    }

    fn push_head(&mut self, idx: usize) {
        self.nodes[idx].prev = NULL_NODE;
        self.nodes[idx].next = self.head;
        if self.head != NULL_NODE {
            self.nodes[self.head].prev = idx;
        }
        self.head = idx;
        if self.tail == NULL_NODE {
            self.tail = idx;
        }
    }

    fn remove_link(&mut self, idx: usize) {
        let prev = self.nodes[idx].prev;
        let next = self.nodes[idx].next;

        if prev != NULL_NODE {
            self.nodes[prev].next = next;
        } else {
            self.head = next;
        }

        if next != NULL_NODE {
            self.nodes[next].prev = prev;
        } else {
            self.tail = prev;
        }
    }

    fn remove_node(&mut self, idx: usize) {
        self.remove_link(idx);
        self.nodes[idx].value = None;
        self.free_list.push(idx);
    }
}

use std::cell::RefCell;
use std::cell::Cell;

thread_local! {
    static ROUTE_CACHES: RefCell<HashMap<u64, RouteCache>> = RefCell::new(HashMap::new());
    static ROUTE_CACHE_SYNC_GENERATION: Cell<u64> = Cell::new(0);
}

fn sync_route_caches() {
    let generation = crate::CACHE_NAMESPACE_GENERATION.load(std::sync::atomic::Ordering::Acquire);

    ROUTE_CACHE_SYNC_GENERATION.with(|seen_generation| {
        if seen_generation.get() == generation {
            return;
        }

        let valid_namespaces = crate::cache_namespace_counts();
        ROUTE_CACHES.with(|caches| {
            caches
                .borrow_mut()
                .retain(|cache_namespace, _| valid_namespaces.contains_key(cache_namespace));
        });

        seen_generation.set(generation);
    });
}

pub fn get_cached_response(cache_namespace: u64, key: u64, keep_alive: bool) -> Option<Bytes> {
    sync_route_caches();

    ROUTE_CACHES.with(|caches| {
        let mut caches = caches.borrow_mut();
        if let Some(cache) = caches.get_mut(&cache_namespace) {
            if let Some(entry) = cache.get(key, Instant::now()) {
                return Some(if keep_alive {
                    entry.response_bytes.clone()
                } else {
                    entry.response_bytes_close.clone()
                });
            }
        }
        None
    })
}

pub fn insert_cached_response(cache_namespace: u64, key: u64, entry: CacheEntry, max_entries: usize) {
    sync_route_caches();

    ROUTE_CACHES.with(|caches| {
        let mut caches = caches.borrow_mut();
        let cache = caches
            .entry(cache_namespace)
            .or_insert_with(|| RouteCache::new(max_entries));
        cache.max_entries = max_entries.max(1);
        cache.insert(key, entry);
    });
}

pub fn interpolate_cache_key(
    config: &RouteCacheConfig,
    parsed: &crate::ParsedRequest<'_>,
    url: &str,
    param_names: &[Box<str>],
    param_values: &[&str],
) -> u64 {
    let mut hasher = DefaultHasher::new();
    
    for vary_key in config.vary_keys.iter() {
        match vary_key {
            CacheVaryKey::QueryParam(name) => {
                let name_str = name.as_ref();
                let mut found = false;
                if let Some(query_idx) = url.find('?') {
                    let query_str = &url[query_idx + 1..];
                    for pair in query_str.split('&') {
                        let mut kv = pair.splitn(2, '=');
                        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                            if k == name_str {
                                name_str.hash(&mut hasher);
                                v.hash(&mut hasher);
                                found = true;
                                break;
                            }
                        }
                    }
                }
                if !found {
                    name_str.hash(&mut hasher);
                    b"".hash(&mut hasher);
                }
            }
            CacheVaryKey::PathParam(name) => {
                let name_str = name.as_ref();
                let mut found = false;
                for (i, p_name) in param_names.iter().enumerate() {
                    if p_name.as_ref() == name_str {
                        if let Some(val) = param_values.get(i) {
                            name_str.hash(&mut hasher);
                            val.hash(&mut hasher);
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    name_str.hash(&mut hasher);
                    b"".hash(&mut hasher);
                }
            }
            CacheVaryKey::Header(name) => {
                let name_str = name.as_ref();
                let mut found = false;
                for (h_name, h_val) in parsed.headers.iter() {
                    if h_name.eq_ignore_ascii_case(name_str) {
                        name_str.hash(&mut hasher);
                        h_val.hash(&mut hasher);
                        found = true;
                        break;
                    }
                }
                if !found {
                    name_str.hash(&mut hasher);
                    b"".hash(&mut hasher);
                }
            }
        }
    }
    
    hasher.finish()
}
