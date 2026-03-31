use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Instant;

use crate::analyzer::{
    analyze_dynamic_fast_path, analyze_route, normalize_path, parse_segments, AnalysisResult,
    DynamicFastPathSpec, RouteSegment,
};
use crate::manifest::{ManifestInput, MiddlewareInput, RouteInput};

const ROUTE_KIND_EXACT: u8 = 1;
const ROUTE_KIND_PARAM: u8 = 2;
const MAX_STACK_SEGMENTS: usize = 16;
/// Maximum number of path parameters supported on the stack.
/// Routes with more params fall back to heap allocation.
const MAX_STACK_PARAMS: usize = 8;
/// Number of methods supported (GET=0..HEAD=6).
const METHOD_COUNT: usize = 7;

// ─── Public Types ───────────────────────

#[derive(Clone)]
pub struct Router {
    exact_get_root: Option<ExactStaticRoute>,
    /// O(1) exact-match routes — array indexed by method code (no hashing)
    dynamic_exact_routes: [Option<HashMap<Box<[u8]>, DynamicRouteSpec>>; METHOD_COUNT],
    /// O(1) static-response routes — array indexed by method code
    exact_static_routes: [Option<HashMap<Box<[u8]>, ExactStaticRoute>>; METHOD_COUNT],
    /// O(M) radix-tree routes per method — array indexed by method code
    radix_trees: [Option<RadixNode>; METHOD_COUNT],
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
    param_names: Box<[Box<str>]>,
    header_keys: Box<[Box<str>]>,
    full_headers: bool,
    needs_path: bool,
    needs_url: bool,
    needs_query: bool,
    fast_path: Option<DynamicFastPathSpec>,
    cache_config: Option<RouteCacheConfig>,
}

// ─── Radix Tree ─────────────────────────
//
// Each node represents either a static prefix or a parameter capture.
// Matching is O(M) where M is the number of path segments, not O(N) routes.
//
// Optimizations applied:
// - Children are sorted by segment after tree construction for binary search
// - `is_unambiguous` flag enables iterative matching without backtracking
// - Children stored as boxed slice after freeze for cache locality

#[derive(Clone)]
struct RadixNode {
    /// Static children — sorted by segment after freeze() for binary search
    children: Vec<RadixChild>,
    /// If this node is a terminal route, the handler spec
    handler: Option<DynamicRouteSpec>,
    /// Parameter capture node for this level
    param_child: Option<Box<RadixParamChild>>,
    /// True when this node has EITHER static children OR a param child, but not both.
    /// When true, no backtracking is needed during matching.
    is_unambiguous: bool,
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
            is_unambiguous: true,
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

    /// Freeze the tree after all routes are inserted:
    /// - Sort children by segment for binary search
    /// - Compute is_unambiguous flags
    /// - Recursively freeze all children
    fn freeze(&mut self) {
        // Sort children by segment for binary search during matching
        self.children.sort_by(|a, b| a.segment.cmp(&b.segment));

        // A node is unambiguous if it has EITHER static children OR a param child, not both
        self.is_unambiguous = self.children.is_empty() || self.param_child.is_none();

        // Recursively freeze children
        for child in &mut self.children {
            child.node.freeze();
        }
        if let Some(param_child) = &mut self.param_child {
            param_child.node.freeze();
        }
    }

    /// Find a static child by segment using binary search (children must be sorted).
    #[inline]
    fn find_static_child(&self, segment: &str) -> Option<&RadixNode> {
        if self.children.len() <= 4 {
            // Linear scan is faster for small N due to cache locality
            for child in &self.children {
                if child.segment.as_ref() == segment {
                    return Some(&child.node);
                }
            }
            None
        } else {
            // Binary search for larger child sets
            self.children
                .binary_search_by(|child| child.segment.as_ref().cmp(segment))
                .ok()
                .map(|idx| &self.children[idx].node)
        }
    }

    /// Iterative match for unambiguous trees — no backtracking needed.
    /// Returns the matched spec and writes param values into the provided buffer.
    /// Returns (spec, param_count) on success.
    #[inline]
    fn match_path_iterative<'a, 'b>(
        &'a self,
        segments: &[&'b str],
        param_buf: &mut [&'b str; MAX_STACK_PARAMS],
    ) -> Option<(&'a DynamicRouteSpec, usize)> {
        let mut current = self;
        let mut param_count = 0usize;

        for &segment in segments {
            // Try static child first
            if let Some(child_node) = current.find_static_child(segment) {
                current = child_node;
                continue;
            }

            // Try parameter capture
            if let Some(param_child) = &current.param_child {
                if param_count < MAX_STACK_PARAMS {
                    param_buf[param_count] = segment;
                    param_count += 1;
                    current = &param_child.node;
                    continue;
                }
                // Overflow — fall through to None
                return None;
            }

            // No match
            return None;
        }

        current.handler.as_ref().map(|spec| (spec, param_count))
    }

    /// Recursive match with backtracking — used for ambiguous trees where a node
    /// has both static children AND a param child at the same level.
    fn match_path_recursive<'a, 'b>(
        &'a self,
        segments: &[&'b str],
        param_buf: &mut [&'b str; MAX_STACK_PARAMS],
        param_count: &mut usize,
    ) -> Option<&'a DynamicRouteSpec> {
        if segments.is_empty() {
            return self.handler.as_ref();
        }

        let segment = segments[0];
        let rest = &segments[1..];

        // Try static children first (higher priority)
        if let Some(child_node) = self.find_static_child(segment) {
            if let Some(spec) = child_node.match_path_recursive(rest, param_buf, param_count) {
                return Some(spec);
            }
        }

        // Try parameter capture
        if let Some(param_child) = &self.param_child {
            if *param_count < MAX_STACK_PARAMS {
                let prev_count = *param_count;
                param_buf[*param_count] = segment;
                *param_count += 1;
                if let Some(spec) =
                    param_child
                        .node
                        .match_path_recursive(rest, param_buf, param_count)
                {
                    return Some(spec);
                }
                // Backtrack
                *param_count = prev_count;
            }
        }

        None
    }

    /// Check if the entire subtree is unambiguous (no node has both static children and param child)
    fn is_fully_unambiguous(&self) -> bool {
        if !self.is_unambiguous {
            return false;
        }
        for child in &self.children {
            if !child.node.is_fully_unambiguous() {
                return false;
            }
        }
        if let Some(param_child) = &self.param_child {
            if !param_child.node.is_fully_unambiguous() {
                return false;
            }
        }
        true
    }
}

// ─── Method Index ───────────────────────
//
// Convert method codes to array indices. Method codes are 1-based (GET=1..HEAD=7),
// array indices are 0-based (GET=0..HEAD=6).

#[inline(always)]
fn method_index(code: u8) -> Option<usize> {
    if code >= 1 && code <= 7 {
        Some((code - 1) as usize)
    } else {
        None
    }
}

/// Convert a method string to an array index
fn method_index_from_str(method: &str) -> Option<usize> {
    match method {
        "GET" => Some(0),
        "POST" => Some(1),
        "PUT" => Some(2),
        "DELETE" => Some(3),
        "PATCH" => Some(4),
        "OPTIONS" => Some(5),
        "HEAD" => Some(6),
        _ => None,
    }
}

/// Convert method bytes to an array index
fn method_index_from_bytes(method: &[u8]) -> Option<usize> {
    match method {
        b"GET" => Some(0),
        b"POST" => Some(1),
        b"PUT" => Some(2),
        b"DELETE" => Some(3),
        b"PATCH" => Some(4),
        b"OPTIONS" => Some(5),
        b"HEAD" => Some(6),
        _ => None,
    }
}

// ─── Router Implementation ──────────────

const NONE_EXACT_MAP: Option<HashMap<Box<[u8]>, DynamicRouteSpec>> = None;
const NONE_STATIC_MAP: Option<HashMap<Box<[u8]>, ExactStaticRoute>> = None;
const NONE_RADIX: Option<RadixNode> = None;

impl Router {
    pub fn from_manifest(manifest: &ManifestInput) -> Result<Self> {
        let mut exact_get_root = None;
        let mut dynamic_exact_routes: [Option<HashMap<Box<[u8]>, DynamicRouteSpec>>; METHOD_COUNT] = [
            NONE_EXACT_MAP,
            NONE_EXACT_MAP,
            NONE_EXACT_MAP,
            NONE_EXACT_MAP,
            NONE_EXACT_MAP,
            NONE_EXACT_MAP,
            NONE_EXACT_MAP,
        ];
        let mut exact_static_routes: [Option<HashMap<Box<[u8]>, ExactStaticRoute>>; METHOD_COUNT] = [
            NONE_STATIC_MAP,
            NONE_STATIC_MAP,
            NONE_STATIC_MAP,
            NONE_STATIC_MAP,
            NONE_STATIC_MAP,
            NONE_STATIC_MAP,
            NONE_STATIC_MAP,
        ];
        let mut radix_trees: [Option<RadixNode>; METHOD_COUNT] = [
            NONE_RADIX, NONE_RADIX, NONE_RADIX, NONE_RADIX, NONE_RADIX, NONE_RADIX, NONE_RADIX,
        ];

        for route in &manifest.routes {
            let method = route.method.to_uppercase();
            let path = normalize_path(route.path.as_str());
            if let AnalysisResult::ExactStaticFastPath(spec) =
                analyze_route(route, &manifest.middlewares)
            {
                let Some(midx) = method_index_from_str(method.as_str()) else {
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

                // GET root fast path
                if midx == 0 && path == "/" {
                    exact_get_root = Some(exact_route);
                    continue;
                }

                exact_static_routes[midx]
                    .get_or_insert_with(HashMap::new)
                    .insert(Box::<[u8]>::from(path.as_bytes()), exact_route);
                continue;
            }

            let Some(midx) = method_index(route.method_code) else {
                continue;
            };

            match route.route_kind {
                ROUTE_KIND_EXACT => {
                    dynamic_exact_routes[midx]
                        .get_or_insert_with(HashMap::new)
                        .insert(
                            Box::<[u8]>::from(path.as_bytes()),
                            compile_dynamic_route_spec(route, &manifest.middlewares),
                        );
                }
                ROUTE_KIND_PARAM => {
                    let segments = parse_segments(path.as_str());
                    let spec = compile_dynamic_route_spec(route, &manifest.middlewares);
                    radix_trees[midx]
                        .get_or_insert_with(RadixNode::new)
                        .insert(&segments, spec);
                }
                _ => {}
            }
        }

        // Freeze all radix trees — sort children, compute unambiguous flags
        for tree in &mut radix_trees {
            if let Some(node) = tree {
                node.freeze();
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
        let midx = method_index(method_code)?;

        // Fast path: exact match (O(1)) — direct array index, no hashing for method
        if let Some(route_spec) = self.dynamic_exact_routes[midx]
            .as_ref()
            .and_then(|routes| routes.get(path.as_bytes()))
        {
            return Some(MatchedRoute {
                handler_id: route_spec.handler_id,
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

        // Radix tree match — direct array index, no hashing for method
        let tree = self.radix_trees[midx].as_ref()?;

        // SIMD-accelerated segment splitting into stack buffer
        let mut seg_buf = [""; MAX_STACK_SEGMENTS];
        let seg_count = split_segments_stack(path, &mut seg_buf);
        if seg_count > MAX_STACK_SEGMENTS {
            // Overflow: fall back to heap-allocated segments
            let segments = split_request_segments(path);
            return self.match_radix_heap(tree, &segments);
        }
        let segments = &seg_buf[..seg_count];

        // Stack-allocated param buffer — no heap allocation for ≤8 params
        let mut param_buf = [""; MAX_STACK_PARAMS];

        // Choose iterative or recursive matching based on tree ambiguity
        if tree.is_fully_unambiguous() {
            // Fast path: iterative matching — no backtracking, no recursion overhead
            let (spec, param_count) = tree.match_path_iterative(segments, &mut param_buf)?;
            let param_values = param_buf[..param_count].to_vec();
            Some(MatchedRoute {
                handler_id: spec.handler_id,
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
        } else {
            // Slow path: recursive matching with backtracking
            let mut param_count = 0usize;
            let spec = tree.match_path_recursive(segments, &mut param_buf, &mut param_count)?;
            let param_values = param_buf[..param_count].to_vec();
            Some(MatchedRoute {
                handler_id: spec.handler_id,
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
    }

    /// Fallback for paths with >MAX_STACK_SEGMENTS segments (heap-allocated)
    fn match_radix_heap<'a, 'b>(
        &'a self,
        tree: &'a RadixNode,
        segments: &[&'b str],
    ) -> Option<MatchedRoute<'a, 'b>> {
        let mut param_buf = [""; MAX_STACK_PARAMS];
        if tree.is_fully_unambiguous() {
            let (spec, param_count) = tree.match_path_iterative(segments, &mut param_buf)?;
            let param_values = param_buf[..param_count].to_vec();
            Some(MatchedRoute {
                handler_id: spec.handler_id,
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
        } else {
            let mut param_count = 0usize;
            let spec = tree.match_path_recursive(segments, &mut param_buf, &mut param_count)?;
            let param_values = param_buf[..param_count].to_vec();
            Some(MatchedRoute {
                handler_id: spec.handler_id,
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
    }

    pub fn exact_static_route(&self, method: &[u8], path: &[u8]) -> Option<&ExactStaticRoute> {
        if method == b"GET" && path == b"/" {
            return self.exact_get_root.as_ref();
        }

        let midx = method_index_from_bytes(method)?;
        self.exact_static_routes[midx]
            .as_ref()
            .and_then(|routes| routes.get(path))
    }

    pub fn exact_get_root(&self) -> Option<&ExactStaticRoute> {
        self.exact_get_root.as_ref()
    }

    pub fn match_ws_route(&self, path: &str) -> Option<u32> {
        self.ws_routes.get(path).copied()
    }
}

// ─── Helpers ────────────────────────────

fn compile_dynamic_route_spec(
    route: &RouteInput,
    middlewares: &[MiddlewareInput],
) -> DynamicRouteSpec {
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
        let vary_keys = cache_in
            .vary_by
            .iter()
            .map(|v| match v.source.as_str() {
                "query" => CacheVaryKey::QueryParam(v.name.clone().into_boxed_str()),
                "params" => CacheVaryKey::PathParam(v.name.clone().into_boxed_str()),
                "headers" | "header" => CacheVaryKey::Header(v.name.clone().into_boxed_str()),
                _ => CacheVaryKey::QueryParam(v.name.clone().into_boxed_str()),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        RouteCacheConfig {
            ttl_secs: cache_in.ttl_secs,
            max_entries: cache_in.max_entries.max(1),
            vary_keys,
        }
    });

    DynamicRouteSpec {
        handler_id: route.handler_id,
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

fn split_request_segments(path: &str) -> Vec<&str> {
    if path == "/" {
        return Vec::new();
    }

    path.trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// SIMD-accelerated segment splitting using memchr — avoids iterator overhead.
/// Stack-allocated: writes segments into `buf`. Returns segment count.
/// If the path has more segments than `buf.len()`, returns `buf.len() + 1` as overflow sentinel.
#[inline]
fn split_segments_stack<'a>(path: &'a str, buf: &mut [&'a str]) -> usize {
    let bytes = path.as_bytes();
    let len = bytes.len();
    if len <= 1 {
        // "/" or empty
        return 0;
    }

    let start = if bytes[0] == b'/' { 1 } else { 0 };
    let mut pos = start;
    let mut count = 0;

    while pos < len {
        // Use memchr for SIMD-accelerated slash finding
        let next = memchr::memchr(b'/', &bytes[pos..])
            .map(|i| pos + i)
            .unwrap_or(len);

        if next > pos {
            if count >= buf.len() {
                return count + 1; // overflow sentinel
            }
            // Safety: path is valid UTF-8, and we're splitting on ASCII '/'
            // which cannot split a multi-byte UTF-8 sequence
            buf[count] = unsafe { std::str::from_utf8_unchecked(&bytes[pos..next]) };
            count += 1;
        }
        pos = next + 1;
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

thread_local! {
    static ROUTE_CACHES: RefCell<HashMap<u32, RouteCache>> = RefCell::new(HashMap::new());
}

pub fn get_cached_response(handler_id: u32, key: u64, keep_alive: bool) -> Option<Bytes> {
    ROUTE_CACHES.with(|caches| {
        let mut caches = caches.borrow_mut();
        if let Some(cache) = caches.get_mut(&handler_id) {
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

pub fn insert_cached_response(handler_id: u32, key: u64, entry: CacheEntry, max_entries: usize) {
    ROUTE_CACHES.with(|caches| {
        let mut caches = caches.borrow_mut();
        let cache = caches
            .entry(handler_id)
            .or_insert_with(|| RouteCache::new(max_entries));
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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

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
