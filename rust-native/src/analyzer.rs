use serde_json::Value;
use std::collections::HashMap;

use crate::manifest::{MiddlewareInput, RouteInput};

#[derive(Clone)]
pub struct StaticResponseSpec {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct DynamicFastPathSpec {
    pub status: u16,
    pub headers: Box<[(Box<str>, Box<str>)]>,
    pub response: DynamicFastPathResponse,
}

#[derive(Clone)]
pub enum DynamicFastPathResponse {
    Json(JsonTemplate),
    Text(TextTemplate),
}

#[derive(Clone)]
pub struct JsonTemplate {
    pub kind: JsonTemplateKind,
}

#[derive(Clone)]
pub enum JsonTemplateKind {
    Object(Box<[JsonObjectField]>),
    Literal(Box<[u8]>),
}

#[derive(Clone)]
pub struct JsonObjectField {
    pub key_prefix: Box<[u8]>,
    pub value: JsonValueTemplate,
}

#[derive(Clone)]
pub enum JsonValueTemplate {
    Literal(Box<[u8]>),
    Dynamic(DynamicValueSource),
}

#[derive(Clone)]
pub struct TextTemplate {
    pub segments: Box<[TextSegment]>,
}

#[derive(Clone)]
pub enum TextSegment {
    Literal(Box<str>),
    Dynamic(DynamicValueSource),
}

#[derive(Clone)]
pub struct DynamicValueSource {
    pub kind: DynamicValueSourceKind,
    pub key: Box<str>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum DynamicValueSourceKind {
    Param,
    Query,
    Header,
}

pub enum AnalysisResult {
    ExactStaticFastPath(StaticResponseSpec),
    Dynamic,
}

pub fn analyze_route(route: &RouteInput, middlewares: &[MiddlewareInput]) -> AnalysisResult {
    if route.method.as_str() != "GET" || route.path.contains(':') {
        return AnalysisResult::Dynamic;
    }

    if has_applicable_middleware(route.path.as_str(), middlewares) {
        return AnalysisResult::Dynamic;
    }

    let source = route.handler_source.as_str();
    if source.contains("await") {
        return AnalysisResult::Dynamic;
    }

    let body = trim_return_and_semicolon(extract_function_body(source));
    if body.is_empty() {
        return AnalysisResult::Dynamic;
    }

    if let Some((status, payload)) = parse_status_call(body, "json") {
        if let Some(spec) = build_json_response(status, payload) {
            return AnalysisResult::ExactStaticFastPath(spec);
        }
    }

    if let Some((status, payload)) = parse_status_call(body, "send") {
        if let Some(spec) = build_send_response(status, payload) {
            return AnalysisResult::ExactStaticFastPath(spec);
        }
    }

    if let Some(payload) = strip_call(body, "res.json(") {
        if let Some(spec) = build_json_response(200, payload) {
            return AnalysisResult::ExactStaticFastPath(spec);
        }
    }

    if let Some(payload) = strip_call(body, "res.send(") {
        if let Some(spec) = build_send_response(200, payload) {
            return AnalysisResult::ExactStaticFastPath(spec);
        }
    }

    AnalysisResult::Dynamic
}

pub fn analyze_dynamic_fast_path(
    route: &RouteInput,
    middlewares: &[MiddlewareInput],
) -> Option<DynamicFastPathSpec> {
    if has_applicable_middleware(route.path.as_str(), middlewares) {
        return None;
    }

    let source = route.handler_source.as_str();
    if source.contains("await") {
        return None;
    }

    let body = trim_return_and_semicolon(extract_function_body(source));
    if body.is_empty() {
        return None;
    }

    if let Some((status, payload)) = parse_status_call(body, "json") {
        return build_dynamic_json_response(status, payload);
    }

    if let Some((status, payload)) = parse_status_call(body, "send") {
        return build_dynamic_send_response(status, payload, None);
    }

    if let Some((status, content_type, payload)) = parse_status_type_send_call(body) {
        return build_dynamic_send_response(status, payload, Some(content_type));
    }

    if let Some((content_type, payload)) = parse_type_send_call(body) {
        return build_dynamic_send_response(200, payload, Some(content_type));
    }

    if let Some(payload) = strip_call(body, "res.json(") {
        return build_dynamic_json_response(200, payload);
    }

    if let Some(payload) = strip_call(body, "res.send(") {
        return build_dynamic_send_response(200, payload, None);
    }

    None
}

pub fn normalize_path(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }

    let trimmed = path.trim_end_matches('/');
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

pub fn parse_segments(path: &str) -> Vec<RouteSegment> {
    if path == "/" {
        return Vec::new();
    }

    normalize_path(path)
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if segment.strip_prefix(':').is_some() {
                RouteSegment::Param(())
            } else {
                RouteSegment::Static(segment.to_string())
            }
        })
        .collect()
}

#[derive(Clone)]
pub enum RouteSegment {
    Static(String),
    Param(()),
}

fn has_applicable_middleware(route_path: &str, middlewares: &[MiddlewareInput]) -> bool {
    middlewares
        .iter()
        .any(|middleware| path_prefix_matches(middleware.path_prefix.as_str(), route_path))
}

fn path_prefix_matches(path_prefix: &str, request_path: &str) -> bool {
    if path_prefix == "/" {
        return true;
    }

    request_path == path_prefix || request_path.starts_with(format!("{path_prefix}/").as_str())
}

fn extract_function_body(source: &str) -> &str {
    if let Some(arrow_index) = source.find("=>") {
        let right = source[arrow_index + 2..].trim();
        if right.starts_with('{') && right.ends_with('}') {
            return right[1..right.len() - 1].trim();
        }

        return right.trim();
    }

    if let Some(block_start) = source.find('{') {
        if let Some(block_end) = source.rfind('}') {
            if block_end > block_start {
                return source[block_start + 1..block_end].trim();
            }
        }
    }

    source.trim()
}

fn trim_return_and_semicolon(body: &str) -> &str {
    let mut value = body.trim();
    if let Some(stripped) = value.strip_prefix("return ") {
        value = stripped.trim();
    }

    if let Some(stripped) = value.strip_suffix(';') {
        value = stripped.trim();
    }

    value
}

fn parse_status_call<'a>(body: &'a str, method: &str) -> Option<(u16, &'a str)> {
    let status_prefix = "res.status(";
    let suffix = format!(").{method}(");

    if !body.starts_with(status_prefix) || !body.ends_with(')') {
        return None;
    }

    let after_status = &body[status_prefix.len()..];
    let separator_index = after_status.find(suffix.as_str())?;
    let status = after_status[..separator_index].trim().parse::<u16>().ok()?;
    let payload_start = separator_index + suffix.len();
    let payload = &after_status[payload_start..after_status.len() - 1];
    Some((status, payload.trim()))
}

fn parse_status_type_send_call(body: &str) -> Option<(u16, String, &str)> {
    let status_prefix = "res.status(";
    let type_separator = ").type(";
    let send_separator = ").send(";

    if !body.starts_with(status_prefix) || !body.ends_with(')') {
        return None;
    }

    let after_status = &body[status_prefix.len()..];
    let type_index = after_status.find(type_separator)?;
    let status = after_status[..type_index].trim().parse::<u16>().ok()?;
    let after_type = &after_status[type_index + type_separator.len()..];
    let send_index = after_type.find(send_separator)?;
    let content_type = parse_string_literal(after_type[..send_index].trim())?;
    let payload_start = send_index + send_separator.len();
    let payload = &after_type[payload_start..after_type.len() - 1];
    Some((status, content_type, payload.trim()))
}

fn parse_type_send_call(body: &str) -> Option<(String, &str)> {
    let type_prefix = "res.type(";
    let send_separator = ").send(";

    if !body.starts_with(type_prefix) || !body.ends_with(')') {
        return None;
    }

    let after_type = &body[type_prefix.len()..];
    let send_index = after_type.find(send_separator)?;
    let content_type = parse_string_literal(after_type[..send_index].trim())?;
    let payload_start = send_index + send_separator.len();
    let payload = &after_type[payload_start..after_type.len() - 1];
    Some((content_type, payload.trim()))
}

fn strip_call<'a>(body: &'a str, prefix: &str) -> Option<&'a str> {
    if !body.starts_with(prefix) || !body.ends_with(')') {
        return None;
    }

    Some(body[prefix.len()..body.len() - 1].trim())
}

fn build_json_response(status: u16, payload: &str) -> Option<StaticResponseSpec> {
    let value = parse_literal(payload)?;
    let body = serde_json::to_vec(&value).ok()?;
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );

    Some(StaticResponseSpec {
        status,
        headers,
        body,
    })
}

fn build_dynamic_json_response(status: u16, payload: &str) -> Option<DynamicFastPathSpec> {
    let template = parse_json_template(payload)?;
    let headers = [(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    )];

    Some(DynamicFastPathSpec {
        status,
        headers: headers
            .into_iter()
            .map(|(name, value)| (name.into_boxed_str(), value.into_boxed_str()))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        response: DynamicFastPathResponse::Json(template),
    })
}

fn build_dynamic_send_response(
    status: u16,
    payload: &str,
    forced_content_type: Option<String>,
) -> Option<DynamicFastPathSpec> {
    if let Some(text_template) = parse_text_template(payload) {
        let content_type = forced_content_type
            .map(normalize_content_type)
            .unwrap_or_else(|| "text/plain; charset=utf-8".to_string());
        let headers = [("content-type".to_string(), content_type)];

        return Some(DynamicFastPathSpec {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.into_boxed_str(), value.into_boxed_str()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            response: DynamicFastPathResponse::Text(text_template),
        });
    }

    let value = parse_literal(payload)?;
    match value {
        Value::String(text) => {
            let content_type = forced_content_type
                .map(normalize_content_type)
                .unwrap_or_else(|| "text/plain; charset=utf-8".to_string());
            let headers = [("content-type".to_string(), content_type)];
            Some(DynamicFastPathSpec {
                status,
                headers: headers
                    .into_iter()
                    .map(|(name, value)| (name.into_boxed_str(), value.into_boxed_str()))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                response: DynamicFastPathResponse::Text(TextTemplate {
                    segments: vec![TextSegment::Literal(text.into_boxed_str())].into_boxed_slice(),
                }),
            })
        }
        Value::Null => None,
        other => {
            if forced_content_type.is_some() {
                return None;
            }
            let body = serde_json::to_vec(&other).ok()?.into_boxed_slice();
            let headers = [(
                "content-type".to_string(),
                "application/json; charset=utf-8".to_string(),
            )];
            Some(DynamicFastPathSpec {
                status,
                headers: headers
                    .into_iter()
                    .map(|(name, value)| (name.into_boxed_str(), value.into_boxed_str()))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                response: DynamicFastPathResponse::Json(JsonTemplate {
                    kind: JsonTemplateKind::Literal(body),
                }),
            })
        }
    }
}

fn build_send_response(status: u16, payload: &str) -> Option<StaticResponseSpec> {
    let value = parse_literal(payload)?;
    match value {
        Value::String(text) => {
            let mut headers = HashMap::new();
            headers.insert(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            );

            Some(StaticResponseSpec {
                status,
                headers,
                body: text.into_bytes(),
            })
        }
        other => {
            let body = serde_json::to_vec(&other).ok()?;
            let mut headers = HashMap::new();
            headers.insert(
                "content-type".to_string(),
                "application/json; charset=utf-8".to_string(),
            );

            Some(StaticResponseSpec {
                status,
                headers,
                body,
            })
        }
    }
}

fn parse_json_template(payload: &str) -> Option<JsonTemplate> {
    let payload = payload.trim();

    if payload.starts_with('{') && payload.ends_with('}') {
        let fields = parse_json_object_fields(payload)?;
        return Some(JsonTemplate {
            kind: JsonTemplateKind::Object(fields.into_boxed_slice()),
        });
    }

    let literal = parse_literal(payload)?;
    let literal_bytes = serde_json::to_vec(&literal).ok()?.into_boxed_slice();
    Some(JsonTemplate {
        kind: JsonTemplateKind::Literal(literal_bytes),
    })
}

fn parse_json_object_fields(payload: &str) -> Option<Vec<JsonObjectField>> {
    let inner = payload[1..payload.len() - 1].trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }

    let entries = split_top_level(inner, ',')?;
    let mut fields = Vec::with_capacity(entries.len());

    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }

        let separator = find_top_level(trimmed, ':')?;
        let key = parse_object_key(trimmed[..separator].trim())?;
        let value_source = trimmed[separator + 1..].trim();
        let value = if let Some(source) = parse_dynamic_value_source(value_source) {
            JsonValueTemplate::Dynamic(source)
        } else {
            let literal = parse_literal(value_source)?;
            JsonValueTemplate::Literal(serde_json::to_vec(&literal).ok()?.into_boxed_slice())
        };

        let key_prefix = format!("{}:", serde_json::to_string(&key).ok()?).into_bytes();
        fields.push(JsonObjectField {
            key_prefix: key_prefix.into_boxed_slice(),
            value,
        });
    }

    Some(fields)
}

fn parse_object_key(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    if let Some(value) = parse_string_literal(raw) {
        return Some(value);
    }

    if is_identifier(raw) {
        return Some(raw.to_string());
    }

    None
}

fn parse_text_template(payload: &str) -> Option<TextTemplate> {
    let payload = payload.trim();

    if let Some(string_value) = parse_string_literal(payload) {
        return Some(TextTemplate {
            segments: vec![TextSegment::Literal(string_value.into_boxed_str())].into_boxed_slice(),
        });
    }

    parse_template_literal(payload)
}

fn parse_template_literal(payload: &str) -> Option<TextTemplate> {
    if !payload.starts_with('`') || !payload.ends_with('`') || payload.len() < 2 {
        return None;
    }

    let inner = &payload[1..payload.len() - 1];
    if !inner.contains("${") {
        return Some(TextTemplate {
            segments: vec![TextSegment::Literal(
                unescape_template_literal(inner)?.into_boxed_str(),
            )]
            .into_boxed_slice(),
        });
    }

    let mut segments = Vec::new();
    let mut cursor = 0usize;
    let bytes = inner.as_bytes();

    while cursor < bytes.len() {
        let mut expr_start = None;
        let mut index = cursor;
        while index + 1 < bytes.len() {
            if bytes[index] == b'$' && bytes[index + 1] == b'{' {
                expr_start = Some(index);
                break;
            }
            index += 1;
        }

        let Some(start) = expr_start else {
            let tail = unescape_template_literal(&inner[cursor..])?;
            if !tail.is_empty() {
                segments.push(TextSegment::Literal(tail.into_boxed_str()));
            }
            break;
        };

        if start > cursor {
            let literal = unescape_template_literal(&inner[cursor..start])?;
            if !literal.is_empty() {
                segments.push(TextSegment::Literal(literal.into_boxed_str()));
            }
        }

        let expr_end = find_template_expr_end(inner, start + 2)?;
        let expression = inner[start + 2..expr_end].trim();
        let source = parse_dynamic_value_source(expression)?;
        segments.push(TextSegment::Dynamic(source));
        cursor = expr_end + 1;
    }

    Some(TextTemplate {
        segments: segments.into_boxed_slice(),
    })
}

fn find_template_expr_end(input: &str, start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut depth = 0usize;
    let mut index = start;
    let mut string_delim: Option<u8> = None;
    let mut escaped = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(delim) = string_delim {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delim {
                string_delim = None;
            }
            index += 1;
            continue;
        }

        match byte {
            b'\'' | b'"' | b'`' => {
                string_delim = Some(byte);
            }
            b'{' => {
                depth += 1;
            }
            b'}' => {
                if depth == 0 {
                    return Some(index);
                }
                depth -= 1;
            }
            _ => {}
        }

        index += 1;
    }

    None
}

fn parse_dynamic_value_source(raw: &str) -> Option<DynamicValueSource> {
    let source = raw.trim();
    if let Some(key) = source.strip_prefix("req.params.") {
        if is_identifier(key) {
            return Some(DynamicValueSource {
                kind: DynamicValueSourceKind::Param,
                key: key.to_string().into_boxed_str(),
            });
        }
    }

    if let Some(key) = parse_bracket_access(source, "req.params[") {
        return Some(DynamicValueSource {
            kind: DynamicValueSourceKind::Param,
            key: key.into_boxed_str(),
        });
    }

    if let Some(key) = source.strip_prefix("req.query.") {
        if is_identifier(key) {
            return Some(DynamicValueSource {
                kind: DynamicValueSourceKind::Query,
                key: key.to_string().into_boxed_str(),
            });
        }
    }

    if let Some(key) = parse_bracket_access(source, "req.query[") {
        return Some(DynamicValueSource {
            kind: DynamicValueSourceKind::Query,
            key: key.into_boxed_str(),
        });
    }

    if let Some(key) = source.strip_prefix("req.headers.") {
        if is_identifier(key) {
            return Some(DynamicValueSource {
                kind: DynamicValueSourceKind::Header,
                key: key.to_ascii_lowercase().into_boxed_str(),
            });
        }
    }

    if let Some(key) = parse_bracket_access(source, "req.headers[") {
        return Some(DynamicValueSource {
            kind: DynamicValueSourceKind::Header,
            key: key.to_ascii_lowercase().into_boxed_str(),
        });
    }

    if let Some(key) = parse_function_call_string_arg(source, "req.header(") {
        return Some(DynamicValueSource {
            kind: DynamicValueSourceKind::Header,
            key: key.to_ascii_lowercase().into_boxed_str(),
        });
    }

    None
}

fn parse_function_call_string_arg(source: &str, prefix: &str) -> Option<String> {
    if !source.starts_with(prefix) || !source.ends_with(')') {
        return None;
    }

    parse_string_literal(source[prefix.len()..source.len() - 1].trim())
}

fn parse_bracket_access(source: &str, prefix: &str) -> Option<String> {
    if !source.starts_with(prefix) || !source.ends_with(']') {
        return None;
    }

    parse_string_literal(source[prefix.len()..source.len() - 1].trim())
}

fn parse_string_literal(source: &str) -> Option<String> {
    let value = parse_literal(source)?;
    match value {
        Value::String(text) => Some(text),
        _ => None,
    }
}

fn split_top_level<'a>(input: &'a str, separator: char) -> Option<Vec<&'a str>> {
    let mut values = Vec::new();
    let mut start = 0usize;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut string_delimiter: Option<char> = None;
    let mut escaped = false;

    for (index, ch) in input.char_indices() {
        if let Some(delimiter) = string_delimiter {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == delimiter {
                string_delimiter = None;
            }
            continue;
        }

        match ch {
            '"' | '\'' | '`' => string_delimiter = Some(ch),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.checked_sub(1)?,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.checked_sub(1)?,
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.checked_sub(1)?,
            _ if ch == separator && brace_depth == 0 && bracket_depth == 0 && paren_depth == 0 => {
                values.push(&input[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }

    if string_delimiter.is_some() || brace_depth != 0 || bracket_depth != 0 || paren_depth != 0 {
        return None;
    }

    values.push(&input[start..]);
    Some(values)
}

fn find_top_level(input: &str, target: char) -> Option<usize> {
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut string_delimiter: Option<char> = None;
    let mut escaped = false;

    for (index, ch) in input.char_indices() {
        if let Some(delimiter) = string_delimiter {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == delimiter {
                string_delimiter = None;
            }
            continue;
        }

        match ch {
            '"' | '\'' | '`' => string_delimiter = Some(ch),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.checked_sub(1)?,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.checked_sub(1)?,
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.checked_sub(1)?,
            _ if ch == target && brace_depth == 0 && bracket_depth == 0 && paren_depth == 0 => {
                return Some(index);
            }
            _ => {}
        }
    }

    None
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }

    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
}

fn normalize_content_type(value: String) -> String {
    if value.contains('/') {
        return value;
    }

    match value.as_str() {
        "json" => "application/json; charset=utf-8".to_string(),
        "html" => "text/html; charset=utf-8".to_string(),
        "text" => "text/plain; charset=utf-8".to_string(),
        _ => value,
    }
}

fn unescape_template_literal(input: &str) -> Option<String> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }

        let Some(next) = chars.next() else {
            return None;
        };
        match next {
            '\\' => output.push('\\'),
            '`' => output.push('`'),
            '"' => output.push('"'),
            '\'' => output.push('\''),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            '$' => output.push('$'),
            other => output.push(other),
        }
    }
    Some(output)
}

fn parse_literal(source: &str) -> Option<Value> {
    let normalized = normalize_js_literal(source);
    json5::from_str::<Value>(normalized.as_str()).ok()
}

fn normalize_js_literal(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut string_delimiter = None;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if let Some(delimiter) = string_delimiter {
            output.push(ch);
            if escaped {
                escaped = false;
                continue;
            }

            if ch == '\\' {
                escaped = true;
            } else if ch == delimiter {
                string_delimiter = None;
            }
            continue;
        }

        if matches!(ch, '"' | '\'' | '`') {
            string_delimiter = Some(ch);
            output.push(ch);
            continue;
        }

        if ch == '!' {
            if matches!(chars.peek(), Some('0')) {
                chars.next();
                output.push_str("true");
                continue;
            }

            if matches!(chars.peek(), Some('1')) {
                chars.next();
                output.push_str("false");
                continue;
            }
        }

        output.push(ch);
    }

    output
}
