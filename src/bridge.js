import { Buffer } from "node:buffer";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const PLAIN_OBJECT_PROTOTYPE = Object.prototype;
const EMPTY_ARRAY = Object.freeze([]);

export const BRIDGE_VERSION = 1;
export const REQUEST_FLAG_QUERY_PRESENT = 1 << 0;
export const REQUEST_FLAG_BODY_PRESENT = 1 << 1;

export const METHOD_CODES = Object.freeze({
  GET: 1,
  POST: 2,
  PUT: 3,
  DELETE: 4,
  PATCH: 5,
  OPTIONS: 6,
  HEAD: 7,
});

export const ROUTE_KIND = Object.freeze({
  EXACT: 1,
  PARAM: 2,
});

// Security: use null-prototype objects for user-facing data to prevent prototype pollution
const EMPTY_OBJECT = Object.freeze(Object.create(null));

// ─── Regex patterns for source analysis ───────────────────────────────────────

const PARAM_DOT_RE = /\breq\.params\.([A-Za-z_$][\w$]*)\b/g;
const PARAM_BRACKET_RE = /\breq\.params\[(['"])([^"'\\]+)\1\]/g;
const QUERY_DOT_RE = /\breq\.query\.([A-Za-z_$][\w$]*)\b/g;
const QUERY_BRACKET_RE = /\breq\.query\[(['"])([^"'\\]+)\1\]/g;
const HEADER_DOT_RE = /\breq\.headers\.([A-Za-z_$][\w$]*)\b/g;
const HEADER_BRACKET_RE = /\breq\.headers\[(['"])([^"'\\]+)\1\]/g;
const HEADER_CALL_RE = /\breq\.header\((['"])([^"'\\]+)\1\)/g;

// Pre-compiled patterns for full-access detection (using RegExp constructor to avoid escaping issues)
const PARAMS_FULL_ACCESS_RE = new RegExp('\\breq\\.params\\b(?!\\s*(?:\\.|\\[))');
const PARAMS_DYN_BRACKET_RE = new RegExp("\\breq\\.params\\[(?!['\"])");
const QUERY_FULL_ACCESS_RE = new RegExp('\\breq\\.query\\b(?!\\s*(?:\\.|\\[))');
const QUERY_DYN_BRACKET_RE = new RegExp("\\breq\\.query\\[(?!['\"])");
const HEADERS_FULL_ACCESS_RE = new RegExp('\\breq\\.headers\\b(?!\\s*(?:\\.|\\[))');
const HEADERS_DYN_BRACKET_RE = new RegExp("\\breq\\.headers\\[(?!['\"])");
const REQ_BRACKET_STR_RE = new RegExp("\\breq\\s*\\[(['\"])[^\"'\\\\]+\\1\\]");
const REQ_BRACKET_DYN_RE = new RegExp("\\breq\\s*\\[(?!['\"])");
const HEADER_CALL_DYN_RE = new RegExp("\\breq\\.header\\((?!['\"])");

// Security: dangerous prototype keys that must never be allowed in user objects
const DANGEROUS_KEYS = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
]);

// ─── Route Compilation ────────────────────────────────────────────────────────

export function compileRouteShape(method, path) {
  const methodCode = METHOD_CODES[method];
  if (!methodCode) {
    throw new TypeError(`Unsupported method code for ${method}`);
  }

  const segments =
    path === "/"
      ? []
      : path
          .slice(1)
          .split("/")
          .filter(Boolean);
  const paramNames = [];

  for (const segment of segments) {
    if (segment.startsWith(":")) {
      paramNames.push(segment.slice(1));
    }
  }

  return {
    methodCode,
    routeKind: paramNames.length === 0 ? ROUTE_KIND.EXACT : ROUTE_KIND.PARAM,
    paramNames,
    segmentCount: segments.length,
  };
}

// ─── Request Access Analysis ──────────────────────────────────────────────────

export function analyzeRequestAccess(source) {
  const plan = createEmptyAccessPlan();
  const normalizedSource = String(source ?? "");

  plan.method = /\breq\.method\b/.test(normalizedSource);
  plan.path = /\breq\.path\b/.test(normalizedSource);
  plan.url = /\breq\.url\b/.test(normalizedSource);

  if (/\{[^}]*\}\s*=\s*req\b/.test(normalizedSource)) {
    plan.method = true;
    plan.path = true;
    plan.url = true;
    plan.fullParams = true;
    plan.fullQuery = true;
    plan.fullHeaders = true;
    plan.dispatchKind = "generic_fallback";
  }

  collectMatches(normalizedSource, PARAM_DOT_RE, plan.paramKeys, identity);
  collectMatches(normalizedSource, PARAM_BRACKET_RE, plan.paramKeys, identity, 2);
  collectMatches(normalizedSource, QUERY_DOT_RE, plan.queryKeys, identity);
  collectMatches(normalizedSource, QUERY_BRACKET_RE, plan.queryKeys, identity, 2);
  collectMatches(normalizedSource, HEADER_DOT_RE, plan.headerKeys, normalizeHeaderLookup);
  collectMatches(normalizedSource, HEADER_BRACKET_RE, plan.headerKeys, normalizeHeaderLookup, 2);
  collectMatches(normalizedSource, HEADER_CALL_RE, plan.headerKeys, normalizeHeaderLookup, 2);

  if (PARAMS_FULL_ACCESS_RE.test(normalizedSource) || PARAMS_DYN_BRACKET_RE.test(normalizedSource)) {
    plan.fullParams = true;
    plan.dispatchKind = "generic_fallback";
  }

  if (QUERY_FULL_ACCESS_RE.test(normalizedSource) || QUERY_DYN_BRACKET_RE.test(normalizedSource)) {
    plan.fullQuery = true;
    plan.dispatchKind = "generic_fallback";
  }

  if (HEADERS_FULL_ACCESS_RE.test(normalizedSource) || HEADERS_DYN_BRACKET_RE.test(normalizedSource)) {
    plan.fullHeaders = true;
    plan.dispatchKind = "generic_fallback";
  }

  if (REQ_BRACKET_STR_RE.test(normalizedSource) || REQ_BRACKET_DYN_RE.test(normalizedSource)) {
    plan.method = true;
    plan.path = true;
    plan.url = true;
    plan.fullParams = true;
    plan.fullQuery = true;
    plan.fullHeaders = true;
    plan.dispatchKind = "generic_fallback";
  }

  if (HEADER_CALL_DYN_RE.test(normalizedSource)) {
    plan.fullHeaders = true;
    plan.dispatchKind = "generic_fallback";
  }

  plan.jsonFastPath = detectJsonFastPath(normalizedSource);
  return freezeAccessPlan(plan);
}

export function mergeRequestAccessPlans(plans) {
  const merged = createEmptyAccessPlan();

  for (const plan of plans) {
    if (!plan) {
      continue;
    }

    merged.method ||= plan.method === true;
    merged.path ||= plan.path === true;
    merged.url ||= plan.url === true;
    merged.fullParams ||= plan.fullParams === true;
    merged.fullQuery ||= plan.fullQuery === true;
    merged.fullHeaders ||= plan.fullHeaders === true;
    if (plan.dispatchKind === "generic_fallback") {
      merged.dispatchKind = "generic_fallback";
    }
    if (plan.jsonFastPath === "specialized") {
      merged.jsonFastPath = "specialized";
    } else if (plan.jsonFastPath === "generic" && merged.jsonFastPath === "fallback") {
      merged.jsonFastPath = "generic";
    }
    addSetEntries(merged.paramKeys, plan.paramKeys);
    addSetEntries(merged.queryKeys, plan.queryKeys);
    addSetEntries(merged.headerKeys, plan.headerKeys);
  }

  return freezeAccessPlan(merged);
}

// ─── Request Factory (with Object Pooling) ────────────────────────────────────

// Pool for request objects — avoids per-request allocations
const REQUEST_POOL_MAX = 512;
const requestPool = [];

function acquireRequestObject() {
  return requestPool.pop() || null;
}

export function releaseRequestObject(req) {
  if (requestPool.length >= REQUEST_POOL_MAX) {
    return;
  }
  // Reset all fields before pooling
  req.method = "";
  req._path = undefined;
  req._url = undefined;
  req._params = undefined;
  req._query = undefined;
  req._headers = undefined;
  req._decoded = null;
  req._routeParamNames = null;
  req._plan = null;
  req._routeMethod = null;
  requestPool.push(req);
}

function createPooledRequest() {
  const req = Object.create(null);

  // Internal state
  req._path = undefined;
  req._url = undefined;
  req._params = undefined;
  req._query = undefined;
  req._headers = undefined;
  req._bodyParsed = undefined;
  req._decoded = null;
  req._routeParamNames = null;
  req._plan = null;
  req._routeMethod = null;
  req.method = "";

  Object.defineProperty(req, "path", {
    configurable: true,
    enumerable: true,
    get() {
      if (req._path === undefined) {
        req._path = textDecoder.decode(req._decoded.pathBytes);
      }
      return req._path;
    },
  });

  Object.defineProperty(req, "url", {
    configurable: true,
    enumerable: true,
    get() {
      if (req._url === undefined) {
        req._url = textDecoder.decode(req._decoded.urlBytes);
      }
      return req._url;
    },
  });

  Object.defineProperty(req, "params", {
    configurable: true,
    enumerable: true,
    get() {
      if (req._params === undefined) {
        const needsParams = req._plan.fullParams || req._plan.paramKeys.size > 0;
        req._params = needsParams
          ? materializeParamObject(req._decoded.paramValues, req._routeParamNames, req._plan)
          : EMPTY_OBJECT;
      }
      return req._params;
    },
  });

  Object.defineProperty(req, "query", {
    configurable: true,
    enumerable: true,
    get() {
      if (req._query === undefined) {
        const needsQuery = req._plan.fullQuery || req._plan.queryKeys.size > 0;
        if (!needsQuery) {
          req._query = EMPTY_OBJECT;
        } else {
          // Compute URL for query parsing
          if (req._url === undefined) {
            req._url = textDecoder.decode(req._decoded.urlBytes);
          }
          req._query = materializeQueryObject(req._url, req._decoded.flags, req._plan);
        }
      }
      return req._query;
    },
  });

  Object.defineProperty(req, "headers", {
    configurable: true,
    enumerable: true,
    get() {
      if (req._headers === undefined) {
        const needsHeaders = req._plan.fullHeaders || req._plan.headerKeys.size > 0;
        req._headers = needsHeaders
          ? materializeHeaderObject(req._decoded.rawHeaders, req._plan)
          : EMPTY_OBJECT;
      }
      return req._headers;
    },
  });

  req.header = function header(name) {
    const lookup = normalizeHeaderLookup(name);
    if (req._headers && lookup in req._headers) {
      return req._headers[lookup];
    }
    if (req._decoded.rawHeaders.length === 0) {
      return undefined;
    }
    return lookupHeaderValue(req._decoded.rawHeaders, lookup);
  };

  // ─── Body APIs ────────────────────────────────────────────────────────

  Object.defineProperty(req, "body", {
    configurable: true,
    enumerable: true,
    get() {
      if (req._decoded.bodyBytes === null) {
        return null;
      }
      return Buffer.from(req._decoded.bodyBytes.buffer, req._decoded.bodyBytes.byteOffset, req._decoded.bodyBytes.byteLength);
    },
  });

  req.json = function json() {
    if (req._bodyParsed !== undefined) {
      return req._bodyParsed;
    }
    if (req._decoded.bodyBytes === null || req._decoded.bodyBytes.length === 0) {
      req._bodyParsed = null;
      return null;
    }
    const text = textDecoder.decode(req._decoded.bodyBytes);
    req._bodyParsed = JSON.parse(text);
    return req._bodyParsed;
  };

  req.text = function text() {
    if (req._decoded.bodyBytes === null || req._decoded.bodyBytes.length === 0) {
      return "";
    }
    return textDecoder.decode(req._decoded.bodyBytes);
  };

  req.arrayBuffer = function arrayBuffer() {
    if (req._decoded.bodyBytes === null) {
      return new ArrayBuffer(0);
    }
    return req._decoded.bodyBytes.buffer.slice(
      req._decoded.bodyBytes.byteOffset,
      req._decoded.bodyBytes.byteOffset + req._decoded.bodyBytes.byteLength,
    );
  };

  return req;
}

function methodNameFromCode(methodCode) {
  switch (methodCode) {
    case METHOD_CODES.GET:
      return "GET";
    case METHOD_CODES.POST:
      return "POST";
    case METHOD_CODES.PUT:
      return "PUT";
    case METHOD_CODES.DELETE:
      return "DELETE";
    case METHOD_CODES.PATCH:
      return "PATCH";
    case METHOD_CODES.OPTIONS:
      return "OPTIONS";
    case METHOD_CODES.HEAD:
      return "HEAD";
    default:
      return "";
  }
}

export function createRequestFactory(
  plan,
  routeParamNames = EMPTY_ARRAY,
  routeMethod = "GET",
) {
  return function buildRequest(decoded) {
    let request = acquireRequestObject();
    if (!request) {
      request = createPooledRequest();
    }

    // Initialize for this request
    request._decoded = decoded;
    request._routeParamNames = routeParamNames;
    request._plan = plan;
    request._routeMethod = routeMethod;
    request.method = routeMethod ?? methodNameFromCode(decoded.methodCode);
    request._path = undefined;
    request._url = undefined;
    request._params = undefined;
    request._query = undefined;
    request._headers = undefined;
    request._bodyParsed = undefined;

    return request;
  };
}

// ─── JSON Serialization ───────────────────────────────────────────────────────

export function createJsonSerializer(mode = "fallback") {
  // Performance: V8's native JSON.stringify is heavily optimized and almost always
  // faster than any JS-level reimplementation. Use it directly.
  const serializer = (value) => {
    const serialized = JSON.stringify(value);
    return Buffer.from(serialized, "utf8");
  };
  serializer.kind = mode;
  return serializer;
}

// ─── Binary Protocol Codec ────────────────────────────────────────────────────

export function decodeRequestEnvelope(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;

  const version = readU8(view, offset);
  offset += 1;
  if (version !== BRIDGE_VERSION) {
    throw new Error(`Unsupported request envelope version ${version}`);
  }

  const methodCode = readU8(view, offset);
  offset += 1;
  const flags = readU16(view, offset);
  offset += 2;
  const handlerId = readU32(view, offset);
  offset += 4;
  const urlLength = readU32(view, offset);
  offset += 4;
  const pathLength = readU16(view, offset);
  offset += 2;
  const paramCount = readU16(view, offset);
  offset += 2;
  const headerCount = readU16(view, offset);
  offset += 2;

  const bodyLength = readU32(view, offset);
  offset += 4;

  const urlBytes = readBytes(bytes, offset, urlLength);
  offset += urlLength;
  const pathBytes = readBytes(bytes, offset, pathLength);
  offset += pathLength;

  const paramValues = new Array(paramCount);
  for (let index = 0; index < paramCount; index += 1) {
    const valueLength = readU16(view, offset);
    offset += 2;
    const valueBytes = readBytes(bytes, offset, valueLength);
    offset += valueLength;
    paramValues[index] = valueBytes;
  }

  const rawHeaders = new Array(headerCount);
  for (let index = 0; index < headerCount; index += 1) {
    const nameLength = readU8(view, offset);
    offset += 1;
    const valueLength = readU16(view, offset);
    offset += 2;
    const nameBytes = readBytes(bytes, offset, nameLength);
    offset += nameLength;
    const valueBytes = readBytes(bytes, offset, valueLength);
    offset += valueLength;
    rawHeaders[index] = [nameBytes, valueBytes];
  }

  // Read body bytes
  const bodyBytes = bodyLength > 0 ? readBytes(bytes, offset, bodyLength) : null;
  offset += bodyLength;

  switch (methodCode) {
    case METHOD_CODES.GET:
    case METHOD_CODES.POST:
    case METHOD_CODES.PUT:
    case METHOD_CODES.DELETE:
    case METHOD_CODES.PATCH:
    case METHOD_CODES.OPTIONS:
    case METHOD_CODES.HEAD:
      break;
    default:
      throw new Error(`Unknown method code ${methodCode}`);
  }

  return {
    handlerId,
    flags,
    methodCode,
    urlBytes,
    pathBytes,
    paramValues,
    rawHeaders,
    bodyBytes,
  };
}

export function encodeResponseEnvelope(snapshot) {
  const headers = Object.entries(snapshot.headers ?? {}).map(([name, value]) => [
    encodeUtf8(name),
    encodeUtf8(String(value)),
  ]);
  const body = Buffer.isBuffer(snapshot.body)
    ? snapshot.body
    : snapshot.body instanceof Uint8Array
      ? Buffer.from(snapshot.body)
      : Buffer.alloc(0);

  let totalLength = 2 + 2 + 4 + body.length;
  for (const [nameBytes, valueBytes] of headers) {
    if (nameBytes.length > 0xff) {
      throw new Error(`Response header name too long: ${nameBytes.length}`);
    }
    if (valueBytes.length > 0xffff) {
      throw new Error(`Response header value too long: ${valueBytes.length}`);
    }
    totalLength += 1 + 2 + nameBytes.length + valueBytes.length;
  }

  const output = Buffer.allocUnsafe(totalLength);
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  let offset = 0;

  writeU16(view, offset, Number(snapshot.status ?? 200));
  offset += 2;
  writeU16(view, offset, headers.length);
  offset += 2;
  writeU32(view, offset, body.length);
  offset += 4;

  for (const [nameBytes, valueBytes] of headers) {
    writeU8(view, offset, nameBytes.length);
    offset += 1;
    writeU16(view, offset, valueBytes.length);
    offset += 2;
    output.set(nameBytes, offset);
    offset += nameBytes.length;
    output.set(valueBytes, offset);
    offset += valueBytes.length;
  }

  output.set(body, offset);
  return output;
}

// ─── Object Materialization (Security-Hardened) ───────────────────────────────
//
// All user-facing objects use Object.create(null) to prevent prototype pollution.

function materializeParamObject(entries, paramNames, plan) {
  if (plan.fullParams) {
    return materializeParamPairs(entries, paramNames);
  }

  return materializeSelectedParamPairs(entries, paramNames, plan.paramKeys);
}

function materializeHeaderObject(entries, plan) {
  if (plan.fullHeaders) {
    return materializePairs(entries, true);
  }

  return materializeSelectedPairs(entries, plan.headerKeys, true);
}

function materializeQueryObject(url, flags, plan) {
  if (!(flags & REQUEST_FLAG_QUERY_PRESENT)) {
    return Object.create(null);
  }

  if (plan.fullQuery) {
    return parseQuery(url);
  }

  return parseSelectedQuery(url, plan.queryKeys);
}

function materializePairs(entries, lowerCaseKeys = false) {
  // Security: null-prototype object prevents prototype pollution
  const result = Object.create(null);

  for (const [rawName, rawValue] of entries) {
    const name = textDecoder.decode(rawName);
    const key = lowerCaseKeys ? name.toLowerCase() : name;
    // Security: skip dangerous prototype keys
    if (DANGEROUS_KEYS.has(key)) {
      continue;
    }
    result[key] = textDecoder.decode(rawValue);
  }

  return result;
}

function materializeParamPairs(entries, paramNames) {
  const result = Object.create(null);

  for (let index = 0; index < entries.length; index += 1) {
    const key = paramNames[index];
    if (DANGEROUS_KEYS.has(key)) {
      continue;
    }
    result[key] = textDecoder.decode(entries[index]);
  }

  return result;
}

function materializeSelectedParamPairs(entries, paramNames, selectedKeys) {
  if (selectedKeys.size === 0) {
    return Object.create(null);
  }

  const result = Object.create(null);
  for (let index = 0; index < entries.length; index += 1) {
    const key = paramNames[index];
    if (selectedKeys.has(key) && !DANGEROUS_KEYS.has(key)) {
      result[key] = textDecoder.decode(entries[index]);
    }
  }

  return result;
}

function materializeSelectedPairs(entries, selectedKeys, lowerCaseKeys = false) {
  if (selectedKeys.size === 0) {
    return Object.create(null);
  }

  const result = Object.create(null);
  for (const [rawName, rawValue] of entries) {
    const name = textDecoder.decode(rawName);
    const key = lowerCaseKeys ? name.toLowerCase() : name;
    if (selectedKeys.has(key) && !DANGEROUS_KEYS.has(key)) {
      result[key] = textDecoder.decode(rawValue);
    }
  }

  return result;
}

function parseQuery(url) {
  const queryStart = url.indexOf("?");
  if (queryStart < 0 || queryStart === url.length - 1) {
    return Object.create(null);
  }

  const params = new URLSearchParams(url.slice(queryStart + 1));
  const result = Object.create(null);

  for (const [key, value] of params) {
    if (DANGEROUS_KEYS.has(key)) {
      continue;
    }
    pushQueryEntry(result, key, value);
  }

  return result;
}

function parseSelectedQuery(url, selectedKeys) {
  if (selectedKeys.size === 0) {
    return Object.create(null);
  }

  const queryStart = url.indexOf("?");
  if (queryStart < 0 || queryStart === url.length - 1) {
    return Object.create(null);
  }

  const params = new URLSearchParams(url.slice(queryStart + 1));
  const result = Object.create(null);

  for (const [key, value] of params) {
    if (selectedKeys.has(key) && !DANGEROUS_KEYS.has(key)) {
      pushQueryEntry(result, key, value);
    }
  }

  return result;
}

function pushQueryEntry(result, key, value) {
  if (key in result) {
    const current = result[key];
    if (Array.isArray(current)) {
      current.push(value);
    } else {
      result[key] = [current, value];
    }
    return;
  }

  result[key] = value;
}

function lookupHeaderValue(entries, targetName) {
  for (const [rawName, rawValue] of entries) {
    const name = textDecoder.decode(rawName).toLowerCase();
    if (name === targetName) {
      return textDecoder.decode(rawValue);
    }
  }

  return undefined;
}

// ─── Access Plan ──────────────────────────────────────────────────────────────

function createEmptyAccessPlan() {
  return {
    method: false,
    path: false,
    url: false,
    fullParams: false,
    fullQuery: false,
    fullHeaders: false,
    paramKeys: new Set(),
    queryKeys: new Set(),
    headerKeys: new Set(),
    dispatchKind: "specialized",
    jsonFastPath: "fallback",
  };
}

function freezeAccessPlan(plan) {
  return Object.freeze({
    ...plan,
    paramKeys: new Set(plan.paramKeys),
    queryKeys: new Set(plan.queryKeys),
    headerKeys: new Set(plan.headerKeys),
  });
}

function collectMatches(source, expression, target, transform, groupIndex = 1) {
  for (const match of source.matchAll(expression)) {
    const value = match[groupIndex];
    if (value) {
      target.add(transform(value));
    }
  }
}

function normalizeHeaderLookup(value) {
  return String(value).toLowerCase();
}

function detectJsonFastPath(source) {
  if (!source.includes("res.json(")) {
    return "fallback";
  }

  if (/res\.json\(\s*[{[]/.test(source)) {
    return "specialized";
  }

  return "generic";
}

function addSetEntries(target, source) {
  if (!source) {
    return;
  }

  for (const value of source) {
    target.add(value);
  }
}

function identity(value) {
  return value;
}

function encodeUtf8(value) {
  return textEncoder.encode(String(value));
}

// ─── Binary Protocol Helpers ──────────────────────────────────────────────────

function readBytes(bytes, offset, length) {
  if (offset + length > bytes.byteLength) {
    throw new Error("Request envelope truncated");
  }

  return bytes.subarray(offset, offset + length);
}

function readU8(view, offset) {
  if (offset + 1 > view.byteLength) {
    throw new Error("Request envelope truncated");
  }
  return view.getUint8(offset);
}

function readU16(view, offset) {
  if (offset + 2 > view.byteLength) {
    throw new Error("Request envelope truncated");
  }
  return view.getUint16(offset, true);
}

function readU32(view, offset) {
  if (offset + 4 > view.byteLength) {
    throw new Error("Request envelope truncated");
  }
  return view.getUint32(offset, true);
}

function writeU8(view, offset, value) {
  view.setUint8(offset, value);
}

function writeU16(view, offset, value) {
  view.setUint16(offset, value, true);
}

function writeU32(view, offset, value) {
  view.setUint32(offset, value, true);
}
