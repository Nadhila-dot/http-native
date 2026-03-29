import { Buffer } from "node:buffer";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const PLAIN_OBJECT_PROTOTYPE = Object.prototype;
const EMPTY_ARRAY = Object.freeze([]);
const HEADER_LOOKUP_CACHE_MAX = 128;
const headerLookupNameCache = new Map();

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

// ─── Regex patterns for source analysis ─

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

// ─── Route Compilation ──────────────────

/**
 * Compile a route method + path pair into an efficient shape descriptor
 * used by the Rust router for O(1) exact or O(M) radix-tree matching.
 *
 * @param {string} method - HTTP method (GET, POST, etc.)
 * @param {string} path   - Route path, e.g. "/users/:id"
 * @returns {{ methodCode: number, routeKind: number, paramNames: string[], segmentCount: number }}
 */
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

// ─── Request Access Analysis ────────────

/**
 * Static-analyze a handler/middleware source string to determine which
 * parts of the request object it actually reads (params, query, headers,
 * method, path, url). The result drives zero-copy optimizations: fields
 * that are never accessed are never materialized.
 *
 * @param {string} source - Function.prototype.toString() output
 * @returns {Object} Frozen access plan describing required request fields
 */
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

/**
 * Merge multiple access plans (route + middlewares + error handlers)
 * into a single superset plan. The merged plan is the union of all
 * required fields — if any plan needs a field, the merged plan needs it.
 *
 * @param {Object[]} plans - Array of frozen access plans
 * @returns {Object} Frozen merged access plan
 */
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

/**
 * Return a request object to the pool for reuse, resetting all internal
 * state including any properties added by validation middleware.
 *
 * @param {Object} req - The request object to release
 */
export function releaseRequestObject(req) {
  if (requestPool.length >= REQUEST_POOL_MAX) {
    return;
  }
  req.method = "";
  req._path = undefined;
  req._url = undefined;
  req._params = undefined;
  req._query = undefined;
  req._headers = undefined;
  req._headerLookup = undefined;
  req._decoded = null;
  req._routeParamNames = null;
  req._plan = null;
  req._routeMethod = null;
  req.validatedBody = undefined;
  req.validatedQuery = undefined;
  req.validatedParams = undefined;
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
  req._headerLookup = undefined;
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
        if (!needsHeaders) {
          req._headers = EMPTY_OBJECT;
        } else if (req._plan.fullHeaders) {
          req._headers = ensureHeaderLookup(req);
        } else {
          req._headers = materializeSelectedHeadersFromLookup(
            ensureHeaderLookup(req),
            req._plan.headerKeys,
          );
        }
      }
      return req._headers;
    },
  });

  req.header = function header(name) {
    const lookup = normalizeHeaderLookupCached(name);
    if (req._headers && lookup in req._headers) {
      return req._headers[lookup];
    }
    return ensureHeaderLookup(req)[lookup];
  };

  // ─── Body APIs ──────────────────

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

  /** @returns {*|null} Parsed JSON body, or null if empty/missing */
  req.json = function json() {
    if (req._bodyParsed !== undefined) {
      return req._bodyParsed;
    }
    if (req._decoded.bodyBytes === null || req._decoded.bodyBytes.length === 0) {
      req._bodyParsed = null;
      return null;
    }
    const text = textDecoder.decode(req._decoded.bodyBytes);
    try {
      req._bodyParsed = JSON.parse(text);
    } catch (parseError) {
      throw new SyntaxError(
        `Invalid JSON in request body: ${parseError.message}`,
      );
    }
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

/**
 * Build a factory function that stamps out request objects pre-configured
 * for a specific route's access plan. The factory pulls from the object
 * pool to avoid per-request allocations.
 *
 * @param {Object}   plan           - Frozen access plan for the target route
 * @param {string[]} routeParamNames - Ordered parameter names from the route path
 * @param {string}   routeMethod     - HTTP method string ("GET", "POST", etc.)
 * @returns {Function} (decoded: Object) => request object
 */
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
    request._headerLookup = undefined;
    request._bodyParsed = undefined;

    return request;
  };
}

// ─── JSON Serialization ─────────────────

/**
 * Create a JSON serializer that converts a value to a UTF-8 Buffer.
 * V8's native JSON.stringify is heavily optimized and almost always
 * faster than any JS-level reimplementation, so we use it directly.
 *
 * @param {string} [mode="fallback"] - Serialization mode hint ("fallback"|"generic"|"specialized")
 * @returns {Function & { kind: string }} Serializer: (value) => Buffer
 */
export function createJsonSerializer(mode = "fallback") {
  const serializer = (value) => {
    const serialized = JSON.stringify(value);
    return Buffer.from(serialized, "utf8");
  };
  serializer.kind = mode;
  return serializer;
}

// ─── Binary Protocol Codec ──────────────

/**
 * Decode a binary request envelope produced by the Rust native layer.
 * Layout (little-endian): version(1) | methodCode(1) | flags(2) |
 * handlerId(4) | urlLen(4) | pathLen(2) | paramCount(2) |
 * headerCount(2) | bodyLen(4) | url | path | params… | headers… | body
 *
 * @param {Buffer|Uint8Array} buffer - Raw envelope bytes from Rust
 * @returns {Object} Decoded envelope with handlerId, flags, methodCode, etc.
 * @throws {Error} If the envelope version is unsupported or data is truncated
 */
export function decodeRequestEnvelope(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let offset = 0;

  const version = readU8(bytes, offset);
  offset += 1;
  if (version !== BRIDGE_VERSION) {
    throw new Error(`Unsupported request envelope version ${version}`);
  }

  const methodCode = readU8(bytes, offset);
  offset += 1;
  const flags = readU16(bytes, offset);
  offset += 2;
  const handlerId = readU32(bytes, offset);
  offset += 4;
  const urlLength = readU32(bytes, offset);
  offset += 4;
  const pathLength = readU16(bytes, offset);
  offset += 2;
  const paramCount = readU16(bytes, offset);
  offset += 2;
  const headerCount = readU16(bytes, offset);
  offset += 2;

  const bodyLength = readU32(bytes, offset);
  offset += 4;

  const urlBytes = readBytes(bytes, offset, urlLength);
  offset += urlLength;
  const pathBytes = readBytes(bytes, offset, pathLength);
  offset += pathLength;

  const paramValues = paramCount === 0 ? EMPTY_ARRAY : new Array(paramCount);
  for (let index = 0; index < paramCount; index += 1) {
    const valueLength = readU16(bytes, offset);
    offset += 2;
    const valueBytes = readBytes(bytes, offset, valueLength);
    offset += valueLength;
    paramValues[index] = valueBytes;
  }

  const rawHeaders = headerCount === 0 ? EMPTY_ARRAY : new Array(headerCount);
  for (let index = 0; index < headerCount; index += 1) {
    const nameLength = readU8(bytes, offset);
    offset += 1;
    const valueLength = readU16(bytes, offset);
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

  if (methodCode !== 0) {
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

// Header name encoding cache — avoids re-encoding common names like "content-type"
const headerNameCache = new Map();

function getCachedHeaderNameBytes(name) {
  let bytes = headerNameCache.get(name);
  if (bytes === undefined) {
    bytes = textEncoder.encode(name);
    if (headerNameCache.size < 64) {
      headerNameCache.set(name, bytes);
    }
  }
  return bytes;
}

// Pre-encoded content-type header name + common values to skip textEncoder.encode() on hot path
const CT_NAME_BYTES = textEncoder.encode("content-type");
const PREENCODED_CT_VALUES = {
  "application/json; charset=utf-8": textEncoder.encode("application/json; charset=utf-8"),
  "text/plain; charset=utf-8": textEncoder.encode("text/plain; charset=utf-8"),
  "text/html; charset=utf-8": textEncoder.encode("text/html; charset=utf-8"),
  "application/octet-stream": textEncoder.encode("application/octet-stream"),
};

/**
 * Encode a JS response snapshot into the binary envelope that the Rust
 * layer can decode directly into HTTP/1.1 response bytes.
 * Layout: status(2) | headerCount(2) | bodyLen(4) | headers… | body
 *
 * @param {{ status: number, headers: Object, body: Buffer }} snapshot
 * @returns {Buffer} Binary-encoded response envelope
 */
export function encodeResponseEnvelope(snapshot) {
  const rawHeaders = snapshot.headers;
  const body = Buffer.isBuffer(snapshot.body)
    ? snapshot.body
    : snapshot.body instanceof Uint8Array
      ? Buffer.from(snapshot.body)
      : Buffer.alloc(0);

  const ncache = snapshot.ncache || null;
  const headerKeys = rawHeaders ? Object.keys(rawHeaders) : EMPTY_ARRAY;
  const headerCount = headerKeys.length;
  const encodedHeaders = new Array(headerCount);
  // status(2) + count(2) + bodylen(4) + body + optional ncache trailer(10)
  let totalLength = 8 + body.length + (ncache ? 10 : 0);

  for (let i = 0; i < headerCount; i++) {
    const name = headerKeys[i];
    const rawValue = String(rawHeaders[name]);

    // Fast path: use pre-encoded bytes for content-type
    let nameBytes, valueBytes;
    if (name === "content-type") {
      nameBytes = CT_NAME_BYTES;
      const preValue = PREENCODED_CT_VALUES[rawValue];
      valueBytes = preValue || textEncoder.encode(rawValue);
    } else {
      nameBytes = getCachedHeaderNameBytes(name);
      valueBytes = textEncoder.encode(rawValue);
    }

    if (nameBytes.length > 0xff) {
      throw new Error(`Response header name too long: ${nameBytes.length}`);
    }
    if (valueBytes.length > 0xffff) {
      throw new Error(`Response header value too long: ${valueBytes.length}`);
    }
    encodedHeaders[i] = [nameBytes, valueBytes];
    totalLength += 3 + nameBytes.length + valueBytes.length;
  }

  const output = Buffer.allocUnsafe(totalLength);
  let offset = 0;

  writeU16(output, offset, Number(snapshot.status ?? 200));
  offset += 2;
  writeU16(output, offset, headerCount);
  offset += 2;
  writeU32(output, offset, body.length);
  offset += 4;

  for (let i = 0; i < headerCount; i++) {
    const [nameBytes, valueBytes] = encodedHeaders[i];
    output[offset++] = nameBytes.length;
    writeU16(output, offset, valueBytes.length);
    offset += 2;
    output.set(nameBytes, offset);
    offset += nameBytes.length;
    output.set(valueBytes, offset);
    offset += valueBytes.length;
  }

  output.set(body, offset);
  offset += body.length;

  // Append ncache trailer: magic(2) | ttlSecs(4) | maxEntries(4)
  if (ncache) {
    output[offset] = 0xca;
    output[offset + 1] = 0xce;
    offset += 2;
    writeU32(output, offset, ncache.ttl);
    offset += 4;
    writeU32(output, offset, ncache.maxEntries);
  }

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

function materializeQueryObject(url, flags, plan) {
  if (!(flags & REQUEST_FLAG_QUERY_PRESENT)) {
    return Object.create(null);
  }

  if (plan.fullQuery) {
    return parseQuery(url);
  }

  return parseSelectedQuery(url, plan.queryKeys);
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

function materializeSelectedHeadersFromLookup(headerLookup, selectedKeys) {
  if (selectedKeys.size === 0 || headerLookup === EMPTY_OBJECT) {
    return EMPTY_OBJECT;
  }

  const result = Object.create(null);
  for (const key of selectedKeys) {
    if (DANGEROUS_KEYS.has(key)) {
      continue;
    }
    const value = headerLookup[key];
    if (value !== undefined) {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Parse an HTTP query string into an object, avoiding URLSearchParams
 * overhead. Automatically handles array values for duplicate keys.
 *
 * @param {string} url - The full requested URL
 * @returns {Object} Null-prototype dictionary of parsed bounds
 */
function parseQuery(url) {
  const queryStart = url.indexOf("?");
  if (queryStart < 0 || queryStart === url.length - 1) {
    return Object.create(null);
  }

  const result = Object.create(null);
  const queryStr = url.slice(queryStart + 1);
  const pairs = queryStr.split("&");

  for (let i = 0; i < pairs.length; i++) {
    const pair = pairs[i];
    if (!pair) continue;

    const eqIndex = pair.indexOf("=");
    let key, value;

    if (eqIndex < 0) {
      key = decodeUriComponentFast(pair);
      value = "";
    } else {
      key = decodeUriComponentFast(pair.slice(0, eqIndex));
      value = decodeUriComponentFast(pair.slice(eqIndex + 1));
    }

    if (DANGEROUS_KEYS.has(key)) {
      continue;
    }
    pushQueryEntry(result, key, value);
  }

  return result;
}

/**
 * Same as parseQuery, but only yields keys in the selectedKeys set.
 *
 * @param {string} url
 * @param {Set<string>} selectedKeys
 * @returns {Object}
 */
function parseSelectedQuery(url, selectedKeys) {
  if (selectedKeys.size === 0) {
    return Object.create(null);
  }

  const queryStart = url.indexOf("?");
  if (queryStart < 0 || queryStart === url.length - 1) {
    return Object.create(null);
  }

  const result = Object.create(null);
  const queryStr = url.slice(queryStart + 1);
  const pairs = queryStr.split("&");

  for (let i = 0; i < pairs.length; i++) {
    const pair = pairs[i];
    if (!pair) continue;

    const eqIndex = pair.indexOf("=");
    let key, value;

    if (eqIndex < 0) {
      key = decodeUriComponentFast(pair);
      value = "";
    } else {
      key = decodeUriComponentFast(pair.slice(0, eqIndex));
      value = decodeUriComponentFast(pair.slice(eqIndex + 1));
    }

    if (selectedKeys.has(key) && !DANGEROUS_KEYS.has(key)) {
      pushQueryEntry(result, key, value);
    }
  }

  return result;
}

/**
 * Fast decoding helper replacing all '+' with ' ' before decoding.
 * Fallback to raw value if decodeURIComponent throws.
 *
 * @param {string} str
 * @returns {string}
 */
function decodeUriComponentFast(str) {
  const normalized = str.replace(/\+/g, " ");
  try {
    return decodeURIComponent(normalized);
  } catch (e) {
    return normalized;
  }
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

function ensureHeaderLookup(req) {
  if (req._headerLookup !== undefined) {
    return req._headerLookup;
  }

  const entries = req._decoded.rawHeaders;
  if (entries.length === 0) {
    req._headerLookup = EMPTY_OBJECT;
    return req._headerLookup;
  }

  const result = Object.create(null);
  for (const [rawName, rawValue] of entries) {
    const name = textDecoder.decode(rawName).toLowerCase();
    if (DANGEROUS_KEYS.has(name)) {
      continue;
    }
    result[name] = textDecoder.decode(rawValue);
  }

  req._headerLookup = result;
  return result;
}

// ─── Access Plan ────────────────────────

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

function normalizeHeaderLookupCached(value) {
  if (typeof value !== "string") {
    return normalizeHeaderLookup(value);
  }

  const cached = headerLookupNameCache.get(value);
  if (cached !== undefined) {
    return cached;
  }

  const normalized = value.toLowerCase();
  if (headerLookupNameCache.size < HEADER_LOOKUP_CACHE_MAX) {
    headerLookupNameCache.set(value, normalized);
  }
  return normalized;
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



// ─── Binary Protocol Helpers ────────────

function readBytes(bytes, offset, length) {
  if (offset + length > bytes.byteLength) {
    throw new Error("Request envelope truncated");
  }

  return bytes.subarray(offset, offset + length);
}

function readU8(bytes, offset) {
  if (offset + 1 > bytes.byteLength) {
    throw new Error("Request envelope truncated");
  }
  return bytes[offset];
}

function readU16(bytes, offset) {
  if (offset + 2 > bytes.byteLength) {
    throw new Error("Request envelope truncated");
  }
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32(bytes, offset) {
  if (offset + 4 > bytes.byteLength) {
    throw new Error("Request envelope truncated");
  }
  return (
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24 >>> 0)
  ) >>> 0;
}

function writeU16(bytes, offset, value) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeU32(bytes, offset, value) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}
