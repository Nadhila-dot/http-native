use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;

use crate::analyzer::{
    analyze_route, normalize_path, parse_segments, AnalysisResult, RouteSegment,
};
use crate::manifest::{ManifestInput, RouteInput};

const ROUTE_KIND_EXACT: u8 = 1;
const ROUTE_KIND_PARAM: u8 = 2;

// ─── Public Types ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Router {
    exact_get_root: Option<ExactStaticRoute>,
    /// O(1) exact-match routes (HashMap<method, HashMap<path_bytes, spec>>)
    dynamic_exact_routes: HashMap<MethodKey, HashMap<Box<[u8]>, DynamicRouteSpec>>,
    /// O(1) static-response routes
    exact_static_routes: HashMap<MethodKey, HashMap<Box<[u8]>, ExactStaticRoute>>,
    /// O(M) radix-tree routes per method (M = path length)  
    radix_trees: HashMap<MethodKey, RadixNode>,
}

#[derive(Clone)]
pub struct ExactStaticRoute {
    pub close_response: Bytes,
    pub keep_alive_response: Bytes,
}

pub struct MatchedRoute<'a, 'b> {
    pub handler_id: u32,
    pub param_values: Vec<&'b str>,
    pub header_keys: &'a [Box<str>],
    pub full_headers: bool,
}

// ─── Internal Types ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct DynamicRouteSpec {
    handler_id: u32,
    #[allow(dead_code)]
    param_names: Box<[Box<str>]>,
    header_keys: Box<[Box<str>]>,
    full_headers: bool,
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

// ─── Radix Tree ───────────────────────────────────────────────────────────────
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

// ─── Router Implementation ────────────────────────────────────────────────────

impl Router {
    pub fn from_manifest(manifest: &ManifestInput) -> Result<Self> {
        let mut exact_get_root = None;
        let mut dynamic_exact_routes = HashMap::new();
        let mut exact_static_routes = HashMap::new();
        let mut radix_trees: HashMap<MethodKey, RadixNode> = HashMap::new();

        for route in &manifest.routes {
            let method = route.method.to_uppercase();
            let path = normalize_path(route.path.as_str());
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
                            compile_dynamic_route_spec(route),
                        );
                }
                ROUTE_KIND_PARAM => {
                    // Insert into radix tree instead of linear Vec
                    let segments = parse_segments(path.as_str());
                    let spec = compile_dynamic_route_spec(route);
                    radix_trees
                        .entry(method_key)
                        .or_insert_with(RadixNode::new)
                        .insert(&segments, spec);
                }
                _ => {}
            }
        }

        Ok(Self {
            exact_get_root,
            dynamic_exact_routes,
            exact_static_routes,
            radix_trees,
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
                param_values: Vec::new(),
                header_keys: route_spec.header_keys.as_ref(),
                full_headers: route_spec.full_headers,
            });
        }

        // Radix tree match (O(M) where M = segment count)
        let segments = split_request_segments(path);
        let tree = self.radix_trees.get(&method_key)?;
        let mut param_values = Vec::new();
        let spec = tree.match_path(&segments, &mut param_values)?;

        Some(MatchedRoute {
            handler_id: spec.handler_id,
            param_values,
            header_keys: spec.header_keys.as_ref(),
            full_headers: spec.full_headers,
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
}

// ─── MethodKey ────────────────────────────────────────────────────────────────

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

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn compile_dynamic_route_spec(route: &RouteInput) -> DynamicRouteSpec {
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

    DynamicRouteSpec {
        handler_id: route.handler_id,
        param_names,
        header_keys,
        full_headers: route.full_headers,
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
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}
