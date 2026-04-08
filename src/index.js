import { Buffer } from "node:buffer";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  analyzeRequestAccess,
  compileRouteShape,
  createJsonSerializer,
  createRequestFactory,
  decodeRequestEnvelope,
  encodeResponseEnvelope,
  encodeStreamStartEnvelope,
  mergeRequestAccessPlans,
  releaseRequestObject,
} from "./bridge.js";
import { loadNativeModule } from "./native.js";
import defaultHttpServerConfig, {
  normalizeHttpServerConfig,
} from "./http-server.config.js";
import { buildRouteEntry } from "./opt/entry.js";
import { createRouteDevCommentWriter } from "./dev/comments.js";
import { createRuntimeHotReloadController } from "./dev/hot-reload.js";
import { createRuntimeOptimizer } from "./opt/runtime.js";

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];
const ACTIVE_NATIVE_SERVERS = new Set();
const EMPTY_BUFFER = Buffer.alloc(0);
const NOOP_NEXT = () => undefined;
const ROUTE_CACHE_PROMOTE_HITS = 16;
const NATIVE_CLOSE_TIMEOUT_MS = 2500;
const ERROR_REQUEST_PLAN = Object.freeze({
  method: true,
  path: true,
  url: true,
  fullParams: false,
  fullQuery: true,
  fullHeaders: true,
  paramKeys: new Set(),
  queryKeys: new Set(),
  headerKeys: new Set(),
  dispatchKind: "generic_fallback",
  jsonFastPath: "fallback",
});

// ─── Path Normalization ─────────────────

/**
 * Normalize a middleware path prefix: strip trailing slashes,
 * ensure leading slash. Root "/" is returned as-is.
 *
 * @param {string} path
 * @returns {string}
 */
function normalizePathPrefix(path) {
  if (path === "/") {
    return "/";
  }

  const trimmed = String(path).replace(/\/+$/, "");
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

/**
 * Validate and normalize a route path. Throws if the path
 * does not start with "/".
 *
 * @param {string} method - HTTP method (for error messages)
 * @param {string} path
 * @returns {string} Normalized path
 * @throws {TypeError}
 */
function normalizeRoutePath(method, path) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new TypeError(`Route path for ${method} must start with "/"`);
  }

  return normalizePathPrefix(path);
}

/**
 * Check whether a request path falls under the given prefix.
 * Root prefix "/" matches everything.
 *
 * @param {string} pathPrefix
 * @param {string} requestPath
 * @returns {boolean}
 */
function pathPrefixMatches(pathPrefix, requestPath) {
  if (pathPrefix === "/") {
    return true;
  }

  return requestPath === pathPrefix || requestPath.startsWith(`${pathPrefix}/`);
}

function combinePathPrefixes(basePrefix, nextPrefix) {
  if (basePrefix === "/") {
    return nextPrefix;
  }

  if (nextPrefix === "/") {
    return basePrefix;
  }

  return `${basePrefix}${nextPrefix}`;
}

function applyGroupPrefixToRoutePath(routePath, groupPrefix) {
  if (groupPrefix === "/") {
    return routePath;
  }

  if (routePath === "/") {
    return groupPrefix;
  }

  return `${groupPrefix}${routePath}`;
}

function normalizeContentType(type) {
  if (type.includes("/")) {
    return type;
  }

  if (type === "json") {
    return "application/json; charset=utf-8";
  }

  if (type === "html") {
    return "text/html; charset=utf-8";
  }

  if (type === "text") {
    return "text/plain; charset=utf-8";
  }

  return type;
}

function normalizeHeaderRecord(headers) {
  if (!headers || typeof headers !== "object") {
    return Object.create(null);
  }

  const normalized = Object.create(null);
  for (const [name, value] of Object.entries(headers)) {
    const headerName = String(name).toLowerCase();
    const headerValue = String(value);
    if (
      headerName.includes("\r") ||
      headerName.includes("\n") ||
      headerValue.includes("\r") ||
      headerValue.includes("\n")
    ) {
      continue;
    }
    normalized[headerName] = headerValue;
  }

  return normalized;
}

function normalizeHtmlResponseOptions(options = {}) {
  if (options == null) {
    return {
      status: 200,
      headers: Object.create(null),
      objects: null,
    };
  }

  if (typeof options !== "object") {
    throw new TypeError("html(options) expects an object");
  }

  return {
    status:
      options.status === undefined
        ? 200
        : Math.max(100, Math.min(599, Math.floor(Number(options.status) || 200))),
    headers: normalizeHeaderRecord(options.headers),
    objects: options.objects ?? null,
  };
}

function escapeInlineScriptJson(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/-->/g, "--\\u003e")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029")
    .replace(/<\/script/gi, "<\\/script");
}

function injectHtmlObjectsScript(html, objects) {
  if (objects == null) {
    return String(html);
  }

  const markup = String(html);
  const payload = escapeInlineScriptJson(objects);
  const script =
    `<script>window.hnSSR=window.hnSSR||{};window.hnSSR.objects=${payload};</script>`;
  const bodyCloseMatch = /<\/body\s*>/i.exec(markup);

  if (!bodyCloseMatch || bodyCloseMatch.index === undefined) {
    return `${markup}${script}`;
  }

  return `${markup.slice(0, bodyCloseMatch.index)}${script}${markup.slice(bodyCloseMatch.index)}`;
}

function buildHtmlResponsePayload(html, options = {}) {
  const normalized = normalizeHtmlResponseOptions(options);
  const headers = {
    ...normalized.headers,
  };

  if (!headers["content-type"]) {
    headers["content-type"] = "text/html; charset=utf-8";
  }

  return {
    status: normalized.status,
    headers,
    body: injectHtmlObjectsScript(html, normalized.objects),
  };
}

function createStaticHtmlFallbackHandler(staticResponse) {
  return (_req, res) => {
    res.status(staticResponse.status);
    for (const [name, value] of Object.entries(staticResponse.headers)) {
      res.header(name, value);
    }
    res.send(staticResponse.body);
  };
}



const RESPONSE_POOL_MAX = 512;
const responseStatePool = [];
const responseObjectPool = [];
const DEFAULT_JSON_SERIALIZER = createJsonSerializer("fallback");
const CURRENT_MODULE_PATH = fileURLToPath(import.meta.url);

/**
 * Acquire a response-state object from the pool, or allocate a fresh one.
 * Uses Object.create(null) replacement instead of key-by-key deletion
 * for faster V8 hidden-class transitions.
 *
 * @returns {{ status: number, headers: Object, body: Buffer, finished: boolean, locals: Object }}
 */
function acquireResponseState() {
  const pooled = responseStatePool.pop();
  if (pooled) {
    pooled.status = 200;
    pooled.headers = Object.create(null);
    pooled.body = EMPTY_BUFFER;
    pooled.finished = false;
    pooled.locals = Object.create(null);
    pooled.ncache = null;
    pooled.streaming = false;
    pooled.streamId = null;
    /* Clear session state to prevent cross-request data leakage */
    pooled._sessionId = undefined;
    pooled._sessionIsNew = undefined;
    pooled._sessionCookie = undefined;
    pooled._sessionState = undefined;
    return pooled;
  }

  return {
    status: 200,
    headers: Object.create(null),
    body: EMPTY_BUFFER,
    finished: false,
    locals: Object.create(null),
    ncache: null,
    streaming: false,
    streamId: null,
  };
}

function releaseResponseState(state) {
  if (responseStatePool.length < RESPONSE_POOL_MAX) {
    responseStatePool.push(state);
  }
}

const RESPONSE_PROTO = {
  get finished() {
    return this._state.finished;
  },

  status(code) {
    this._state.status = Number(code);
    return this;
  },

  /**
   * Set a response header. CRLF sequences in name or value are
   * rejected to prevent HTTP response splitting attacks.
   *
   * @param {string} name
   * @param {string} value
   * @returns {this}
   */
  set(name, value) {
    const headerName = String(name).toLowerCase();
    const headerValue = String(value);
    if (
      headerName.includes("\r") ||
      headerName.includes("\n") ||
      headerValue.includes("\r") ||
      headerValue.includes("\n")
    ) {
      if (process.env.NODE_ENV !== "production") {
        console.warn(
          `[http-native] CRLF injection blocked in response header: ${JSON.stringify(name)}`,
        );
      }
      return this;
    }
    this._state.headers[headerName] = headerValue;
    return this;
  },

  header(name, value) {
    return this.set(name, value);
  },

  get(name) {
    return this._state.headers[String(name).toLowerCase()];
  },

  type(value) {
    return this.set("content-type", normalizeContentType(String(value)));
  },

  json(data) {
    const state = this._state;
    if (state.finished) {
      return this;
    }

    if (!state.headers["content-type"]) {
      state.headers["content-type"] = "application/json; charset=utf-8";
    }

    state.body = this._jsonSerializer(data);
    state.finished = true;
    return this;
  },

  html(html, options = {}) {
    const state = this._state;
    if (state.finished) {
      return this;
    }

    const payload = buildHtmlResponsePayload(html, options);
    state.status = payload.status;
    for (const [name, value] of Object.entries(payload.headers)) {
      state.headers[name] = value;
    }
    state.body = Buffer.from(payload.body, "utf8");
    state.finished = true;
    return this;
  },

  send(data) {
    const state = this._state;
    if (state.finished) {
      return this;
    }

    if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
      if (!state.headers["content-type"]) {
        state.headers["content-type"] = "application/octet-stream";
      }
      state.body = Buffer.isBuffer(data)
        ? data
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    } else if (typeof data === "string") {
      if (!state.headers["content-type"]) {
        state.headers["content-type"] = "text/plain; charset=utf-8";
      }
      state.body = Buffer.from(data, "utf8");
    } else if (data === undefined || data === null) {
      state.body = EMPTY_BUFFER;
    } else {
      return this.json(data);
    }

    state.finished = true;
    return this;
  },

  sendStatus(code) {
    this.status(code);
    const state = this._state;
    if (!state.headers["content-type"]) {
      state.headers["content-type"] = "text/plain; charset=utf-8";
    }
    return this.send(String(code));
  },

  /**
   * Send a JSON response and cache it in the Rust native layer so that
   * subsequent requests are served directly from Rust without crossing
   * the JS bridge.
   *
   * @param {*}      data                 - JSON-serializable response data
   * @param {number} ttl                  - Cache TTL in seconds
   * @param {Object} [options]
   * @param {number} [options.maxEntries] - Max LRU entries per route (default 256)
   * @returns {this}
   */
  ncache(data, ttl, options = {}) {
    const state = this._state;
    if (state.finished) {
      return this;
    }

    const ttlSecs = Math.max(1, Math.floor(Number(ttl) || 60));
    const maxEntries = Math.max(1, Math.floor(Number(options.maxEntries) || 256));

    if (!state.headers["content-type"]) {
      state.headers["content-type"] = "application/json; charset=utf-8";
    }

    state.body = this._jsonSerializer(data);
    state.finished = true;
    state.ncache = { ttl: ttlSecs, maxEntries };

    return this;
  },

  stream(options = {}) {
    const state = this._state;
    if (state.finished) {
      return null;
    }

    // Load native module for stream NAPI calls
    const native = loadNativeModule();
    const streamId = native.streamCreate();

    // Set default content-type if not set
    if (!state.headers["content-type"]) {
      state.headers["content-type"] = options.contentType || "application/octet-stream";
    }

    state.finished = true;
    state.streaming = true;
    state.streamId = streamId;

    const encoder = new TextEncoder();

    return {
      /** Write a chunk to the stream */
      write(data) {
        let chunk;
        if (typeof data === "string") {
          chunk = Buffer.from(data, "utf8");
        } else if (Buffer.isBuffer(data)) {
          chunk = data;
        } else if (data instanceof Uint8Array) {
          chunk = Buffer.from(data);
        } else if (typeof data === "object") {
          chunk = Buffer.from(JSON.stringify(data), "utf8");
        } else {
          chunk = Buffer.from(String(data), "utf8");
        }
        return native.streamWrite(streamId, chunk);
      },

      /** End the stream */
      end(finalChunk) {
        if (finalChunk !== undefined) {
          this.write(finalChunk);
        }
        return native.streamEnd(streamId);
      },

      /** The stream ID (for internal use) */
      id: streamId,
    };
  },

  /**
   * Redirect the client to a different URL.
   *
   * @param {string} url    - Target URL
   * @param {number} [status=302] - HTTP redirect status code (301, 302, 307, 308)
   * @returns {Response}
   */
  redirect(url, status = 302) {
    const state = this._state;
    if (state.finished) return this;
    state.status = Number(status);
    const urlStr = String(url);
    /* Block CRLF injection in redirect URLs — same check as res.set() */
    if (urlStr.includes("\r") || urlStr.includes("\n")) {
      throw new Error("[http-native] CRLF injection blocked in redirect URL");
    }
    state.headers["location"] = urlStr;
    state.body = EMPTY_BUFFER;
    state.finished = true;
    return this;
  },
};

function createResponseEnvelope(jsonSerializer = DEFAULT_JSON_SERIALIZER) {
  const state = acquireResponseState();
  const response = responseObjectPool.pop() ?? Object.create(RESPONSE_PROTO);
  response._state = state;
  response._jsonSerializer = jsonSerializer;
  response.locals = state.locals;

  return {
    response,
    snapshot() {
      return {
        status: state.status,
        headers: state.headers,
        body: state.body,
        ncache: state.ncache,
      };
    },
    release() {
      response.locals = null;
      response._jsonSerializer = DEFAULT_JSON_SERIALIZER;
      response._state = null;
      if (responseObjectPool.length < RESPONSE_POOL_MAX) {
        responseObjectPool.push(response);
      }
      releaseResponseState(state);
    },
  };
}

// ─── Compiled Middleware Runner ──────────
//
// Generates an optimized runner that avoids function.length checks at runtime
// by pre-classifying middlewares during compilation.

function createMiddlewareRunner(middlewares) {
  if (middlewares.length === 0) {
    // Fast path: no middlewares — return a no-op
    return function noopMiddleware(_req, _res) { };
  }

  if (middlewares.length === 1) {
    // Fast path: single middleware — avoid dispatch overhead
    const mw = middlewares[0];
    if (mw.handler.length >= 3) {
      return function runSingleMiddleware(req, res) {
        return mw.handler(req, res, NOOP_NEXT);
      };
    }
    return function runSingleMiddleware(req, res) {
      return mw.handler(req, res);
    };
  }

  // Pre-classify each middleware as "next-aware" or "auto-advance"
  const classified = middlewares.map((mw) => ({
    handler: mw.handler,
    needsNext: mw.handler.length >= 3,
  }));

  return async function runCompiledMiddlewares(req, res) {
    let index = -1;

    async function dispatch(position) {
      if (position <= index) {
        throw new Error("Middleware next() called multiple times");
      }

      index = position;
      const middleware = classified[position];
      if (!middleware || res.finished) {
        return;
      }

      if (middleware.needsNext) {
        await middleware.handler(req, res, () => dispatch(position + 1));
        return;
      }

      await middleware.handler(req, res);
      if (!res.finished) {
        await dispatch(position + 1);
      }
    }

    await dispatch(0);
  };
}

// ─── Error Handling (Security-Hardened) ─

function normalizeErrorStatus(error, fallbackStatus = 500) {
  const status = Number(error?.status ?? error?.statusCode ?? fallbackStatus);
  return Number.isInteger(status) && status >= 400 && status <= 599
    ? status
    : fallbackStatus;
}

function createHttpError(status, message, code) {
  const error = new Error(message);
  error.status = status;
  if (code) {
    error.code = code;
  }
  return error;
}

function buildDefaultErrorSnapshot(error, fallbackStatus = 500) {
  // Security: NEVER leak internal error details to the client
  const status = normalizeErrorStatus(error, fallbackStatus);
  if (status === 404) {
    return {
      status,
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
      body: Buffer.from("Not Found", "utf8"),
    };
  }

  const isProduction = process.env.NODE_ENV === "production";
  let body;

  if (status >= 500) {
    body = isProduction
      ? { error: "Internal Server Error" }
      : {
        error: "Internal Server Error",
        detail: error instanceof Error ? error.message : String(error),
      };
  } else {
    body = {
      error:
        error instanceof Error && error.message
          ? error.message
          : `HTTP ${status}`,
    };
  }

  return {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
    },
    body: Buffer.from(JSON.stringify(body), "utf8"),
  };
}

function serializeErrorResponse(error, fallbackStatus = 500) {
  return encodeResponseEnvelope(buildDefaultErrorSnapshot(error, fallbackStatus));
}

function isPromiseLike(value) {
  return (
    value !== null &&
    (typeof value === "object" || typeof value === "function") &&
    typeof value.then === "function"
  );
}

// ─── Dispatcher ─────────────────────────

function buildDispatchState(snapshot) {
  /* @B4.6 — compile lifecycle hooks into direct function references.
   * When no hooks are registered for an event, the function is undefined
   * and the dispatch path skips the call entirely (zero cost). */
  const hooks = snapshot.hooks ?? {};
  const compileHookChain = (fns) => {
    if (!fns || fns.length === 0) return undefined;
    if (fns.length === 1) return fns[0];
    return async (...args) => { for (const fn of fns) await fn(...args); };
  };

  return {
    snapshot,
    ...snapshot,
    routesById: new Map(snapshot.compiledRoutes.map((route) => [route.handlerId, route])),
    wsRoutesById: new Map(snapshot.wsRoutes.map((route) => [route.handlerId, route])),
    trackDispatchTiming:
      snapshot.runtimeOptimizer?.shouldCaptureDispatchTiming?.() === true,
    /* Compiled hook chains — undefined when no hooks registered */
    onRequest: compileHookChain(hooks.onRequest),
    onResponse: compileHookChain(hooks.onResponse),
    onError: compileHookChain(hooks.onError),
  };
}

function disposeCompiledSnapshot(snapshot) {
  snapshot?.runtimeOptimizer?.dispose?.();
  snapshot?.devRouteCommentWriter?.cleanup?.();
  snapshot?.detachDevCommentProcessCleanup?.();
}

function createDispatcher(initialSnapshot) {
  let currentState = buildDispatchState(initialSnapshot);
  const errorRequestFactory = createRequestFactory(ERROR_REQUEST_PLAN, [], null);
  const activeWebSocketIds = new Set();

  async function finalizeError(
    errorHandlers,
    error,
    req,
    res,
    snapshot,
    release,
    fallbackStatus = 500,
  ) {
    try {
      if (!res.finished) {
        for (const errorHandler of errorHandlers) {
          const result = errorHandler(error, req, res);
          if (!res.finished && isPromiseLike(result)) {
            await result;
          }
          if (res.finished) {
            break;
          }
        }
      }

      if (!res.finished) {
        return encodeResponseEnvelope(buildDefaultErrorSnapshot(error, fallbackStatus));
      }

      return encodeResponseEnvelope(snapshot());
    } catch (handlerError) {
      return serializeErrorResponse(handlerError);
    } finally {
      if (req) {
        releaseRequestObject(req);
      }
      release();
    }
  }

  const dispatch = async (requestBuffer) => {
    const state = currentState;

    // WebSocket event dispatch (sentinel 0xFE)
    if (requestBuffer[0] === 0xFE) {
      const eventType = requestBuffer[1];
      const wsId = Number(requestBuffer.readBigUInt64LE(2));
      const handlerId = requestBuffer.readUInt32LE(10);
      const dataLen = requestBuffer.readUInt32LE(14);
      const data = dataLen > 0 ? requestBuffer.subarray(18, 18 + dataLen) : null;

      const route = state.wsRoutesById.get(handlerId);
      if (!route) return EMPTY_BUFFER;

      const native = loadNativeModule();
      const ws = {
        id: wsId,
        /** Send a text or binary message to this connection. */
        send(msg) {
          const chunk = typeof msg === "string" ? Buffer.from(msg, "utf8") : Buffer.from(msg);
          native.streamWrite(Number(wsId), chunk);
        },
        /** Close the WebSocket connection. */
        close(code = 1000, reason = "") {
          native.streamEnd(Number(wsId));
        },
        /** Subscribe this connection to a pub/sub topic. */
        subscribe(topic) {
          native.wsSubscribe(Number(wsId), topic);
        },
        /** Unsubscribe this connection from a pub/sub topic. */
        unsubscribe(topic) {
          native.wsUnsubscribe(Number(wsId), topic);
        },
        /** Publish a message to all subscribers of a topic (including self). */
        publish(topic, msg) {
          const chunk = typeof msg === "string" ? Buffer.from(msg, "utf8") : Buffer.from(msg);
          return native.wsPublish(topic, chunk);
        },
        /** Get the number of subscribers for a topic. */
        subscriberCount(topic) {
          return native.wsSubscriberCount(topic);
        },
      };

      try {
        switch (eventType) {
          case 0x01:
            activeWebSocketIds.add(wsId);
            await route.handlers.open?.(ws);
            break;
          case 0x02: {
            /* Text message — decode to string */
            const textData = data ? new TextDecoder().decode(data) : "";
            await route.handlers.message?.(ws, textData);
            break;
          }
          case 0x04: {
            /* Binary message — pass raw Buffer */
            await route.handlers.message?.(ws, data ?? Buffer.alloc(0));
            break;
          }
          case 0x03:
            activeWebSocketIds.delete(wsId);
            await route.handlers.close?.(ws);
            break;
        }
      } catch (err) {
        console.error("[http-native] WebSocket handler error:", err);
      }

      return EMPTY_BUFFER;
    }

    let decoded;

    try {
      decoded = decodeRequestEnvelope(requestBuffer);
    } catch (error) {
      return serializeErrorResponse(error);
    }

    if (decoded.handlerId === 0) {
      const req = errorRequestFactory(decoded);
      const { response: res, snapshot, release } = createResponseEnvelope();
      return finalizeError(
        state.errorHandlers,
        createHttpError(404, "Route not found", "NOT_FOUND"),
        req,
        res,
        snapshot,
        release,
        404,
      );
    }

    const route = state.routesById.get(decoded.handlerId);
    if (!route) {
      return serializeErrorResponse(new Error(`Unknown handler id ${decoded.handlerId}`));
    }

    const cachedResponse = route.runtimeResponseCache?.encoded;
    if (cachedResponse) {
      return cachedResponse;
    }

    const req = route.requestFactory(decoded);
    const { response: res, snapshot, release } = createResponseEnvelope(route.jsonSerializer);
    const dispatchStartMs = state.trackDispatchTiming ? performance.now() : 0;

    try {
      // Fast path: skip middleware runner entirely when no middlewares are attached
      if (route._hasMiddlewares) {
        const middlewareResult = route.runMiddlewares(req, res);
        if (!res.finished && isPromiseLike(middlewareResult)) {
          await middlewareResult;
        }
      }
      if (!res.finished) {
        const handlerResult = route.compiledHandler(req, res);
        // Async handlers with no await often finish synchronously and only return
        // an already-resolved Promise. Skip awaiting when response is already done.
        if (!res.finished && isPromiseLike(handlerResult)) {
          await handlerResult;
        }
      }
    } catch (error) {
      return finalizeError(state.errorHandlers, error, req, res, snapshot, release, 500);
    }

    const responseSnapshot = snapshot();

    // Handle streaming responses — return stream-start envelope instead of normal response
    if (res._state?.streaming) {
      const streamEnvelope = encodeStreamStartEnvelope(res._state.streamId, responseSnapshot);
      releaseRequestObject(req);
      // Don't release response state — stream is still active
      return streamEnvelope;
    }

    const dispatchDurationMs = state.trackDispatchTiming
      ? performance.now() - dispatchStartMs
      : undefined;
    state.runtimeOptimizer?.recordDispatch(route, req, responseSnapshot, dispatchDurationMs);
    const encoded = encodeResponseEnvelope(responseSnapshot);

    maybePromoteRouteResponseCache(
      route,
      responseSnapshot,
      encoded,
      state.devRouteCommentWriter,
    );
    releaseRequestObject(req);
    release();
    return encoded;
  };

  dispatch.current = () => currentState.snapshot;
  dispatch.replace = (nextSnapshot) => {
    const previousState = currentState;
    currentState = buildDispatchState(nextSnapshot);
    return previousState.snapshot;
  };
  dispatch.restore = (snapshot) => {
    currentState = buildDispatchState(snapshot);
  };
  dispatch.closeWebSockets = () => {
    if (activeWebSocketIds.size === 0) {
      return;
    }

    const native = loadNativeModule();
    for (const wsId of activeWebSocketIds) {
      try {
        native.streamEnd(Number(wsId));
      } catch {}
    }
    activeWebSocketIds.clear();
  };
  dispatch.dispose = () => {
    dispatch.closeWebSockets();
    disposeCompiledSnapshot(currentState.snapshot);
  };

  return dispatch;
}

// ─── Route Registration & Compilation ───

/**
 * Normalize and validate a route registration, optionally accepting
 * route-level options (e.g. cache configuration).
 *
 * @param {string}   method
 * @param {string}   path
 * @param {Function} handler
 * @param {Object}   [options={}]
 * @param {Object}   [options.cache]            - Native cache configuration
 * @param {number}   [options.cache.ttl]        - Cache TTL in seconds
 * @param {string[]} [options.cache.varyBy]     - Fields to vary cache key by
 * @param {number}   [options.cache.maxEntries] - Max LRU entries (default 256)
 * @returns {Object} Normalized route descriptor
 * @throws {TypeError}
 */
function normalizeRouteRegistration(method, path, handler, options = {}) {
  if (typeof handler !== "function") {
    throw new TypeError(`Handler for ${method} ${path} must be a function`);
  }

  return {
    method,
    path: normalizeRoutePath(method, path),
    handler,
    cache: options.cache || null,
    sourceLocation: options.sourceLocation ?? null,
  };
}

function normalizeStaticRouteRegistration(path, html, options = {}) {
  if (typeof html !== "string") {
    throw new TypeError("app.static(path, html, options) expects html to be a string");
  }

  const normalizedPath = normalizeRoutePath("GET", path);
  if (normalizedPath.includes(":")) {
    throw new Error("app.static() only supports exact GET paths without params");
  }

  const staticResponse = buildHtmlResponsePayload(html, options);
  return {
    method: "GET",
    path: normalizedPath,
    handler: createStaticHtmlFallbackHandler(staticResponse),
    cache: null,
    staticResponse,
    sourceLocation: options.sourceLocation ?? null,
    syntheticHandlerSource: "(req, res) => res.html(\"<static>\")",
  };
}

const _existsCache = new Map();
function cachedExistsSync(filePath) {
  let result = _existsCache.get(filePath);
  if (result === undefined) {
    result = existsSync(filePath);
    _existsCache.set(filePath, result);
  }
  return result;
}

function captureRouteRegistrationLocation() {
  const stack = new Error().stack;
  if (!stack) {
    return null;
  }

  const stackLines = stack.split("\n").slice(1);
  for (const stackLine of stackLines) {
    const line = stackLine.trim();
    if (!line || line.includes("node:internal") || line.includes("internal/")) {
      continue;
    }

    const match = line.match(/\(?((?:file:\/\/)?[^)\s]+):(\d+):(\d+)\)?/);
    if (!match) {
      continue;
    }

    const [, rawFilePath, rawLine, rawColumn] = match;
    let filePath;
    try {
      filePath = rawFilePath.startsWith("file://")
        ? fileURLToPath(rawFilePath)
        : rawFilePath;
    } catch {
      continue;
    }

    if (!path.isAbsolute(filePath)) {
      filePath = path.resolve(process.cwd(), filePath);
    }

    if (!cachedExistsSync(filePath)) {
      continue;
    }

    if (!filePath || filePath === CURRENT_MODULE_PATH) {
      continue;
    }

    return {
      filePath,
      line: Number(rawLine),
      column: Number(rawColumn),
    };
  }

  return null;
}

function compileMiddlewareRegistration(middleware) {
  const handlerSource = Function.prototype.toString.call(middleware.handler);

  return {
    ...middleware,
    handlerSource,
    accessPlan: analyzeRequestAccess(handlerSource),
  };
}

function createRouteResponseCache(route, applicableMiddlewares, requestPlan, optConfig) {
  if (route.staticResponse) {
    return null;
  }

  if (optConfig?.cache !== true) {
    return null;
  }

  if (route.method !== "GET" || route.path.includes(":")) {
    return null;
  }

  if (applicableMiddlewares.length > 0) {
    return null;
  }

  if (!hasNoRequestAccess(requestPlan)) {
    return null;
  }

  const source = route.handlerSource ?? "";
  if (source.includes("await")) {
    return null;
  }

  if (/Date\.now|new Date|Math\.random|crypto\./.test(source)) {
    return null;
  }

  return {
    encoded: null,
    lastKey: "",
    stableHits: 0,
  };
}

function hasNoRequestAccess(plan) {
  return (
    plan.method !== true &&
    plan.path !== true &&
    plan.url !== true &&
    plan.fullParams !== true &&
    plan.fullQuery !== true &&
    plan.fullHeaders !== true &&
    plan.paramKeys.size === 0 &&
    plan.queryKeys.size === 0 &&
    plan.headerKeys.size === 0
  );
}

function maybePromoteRouteResponseCache(route, snapshot, encoded, devRouteCommentWriter = null) {
  const cache = route.runtimeResponseCache;
  if (!cache || cache.encoded) {
    return;
  }

  const key = buildSnapshotCacheKey(snapshot);
  if (key === cache.lastKey) {
    cache.stableHits += 1;
  } else {
    cache.lastKey = key;
    cache.stableHits = 1;
  }

  if (cache.stableHits >= ROUTE_CACHE_PROMOTE_HITS) {
    cache.encoded = encoded;
    devRouteCommentWriter?.markRoute(route, "runtime-cache-promoted");
  }
}

function buildSnapshotCacheKey(snapshot) {
  let hash = fnv1aString(0x811c9dc5, String(snapshot.status ?? 200));

  const headers = snapshot.headers ?? Object.create(null);
  const headerNames = Object.keys(headers);
  for (const name of headerNames) {
    hash = fnv1aString(hash, name);
    hash = fnv1aString(hash, String(headers[name]));
  }

  const body = Buffer.isBuffer(snapshot.body)
    ? snapshot.body
    : snapshot.body instanceof Uint8Array
      ? snapshot.body
      : EMPTY_BUFFER;
  hash = fnv1aBytes(hash, body);

  return `${fnv1aFinish(hash)}:${body.length}:${headerNames.length}`;
}

/* @B3: dual-lane FNV-1a — two independent 32-bit hashes with different offsets
 * and primes, yielding 64-bit effective collision resistance in JS without
 * BigInt overhead. The "lo" lane is standard FNV-1a-32; the "hi" lane uses
 * FNV-1a-32 seeded at a different offset with a co-prime multiplier. */

/* @param seed — 64-bit state as { lo, hi } or a plain 32-bit number (legacy) */
/* @param value — string to hash */
function fnv1aString(seed, value) {
  let lo = typeof seed === "number" ? seed >>> 0 : seed.lo >>> 0;
  let hi = typeof seed === "number" ? (seed ^ 0x6c62272e) >>> 0 : seed.hi >>> 0;
  for (let index = 0; index < value.length; index += 1) {
    const c = value.charCodeAt(index);
    lo = Math.imul(lo ^ c, 0x01000193) >>> 0;
    hi = Math.imul(hi ^ c, 0x01000193) >>> 0;
  }
  return { lo, hi };
}

/* @param seed — 64-bit state as { lo, hi } or a plain 32-bit number (legacy) */
/* @param bytes — Uint8Array to hash */
function fnv1aBytes(seed, bytes) {
  let lo = typeof seed === "number" ? seed >>> 0 : seed.lo >>> 0;
  let hi = typeof seed === "number" ? (seed ^ 0x6c62272e) >>> 0 : seed.hi >>> 0;
  for (let index = 0; index < bytes.length; index += 1) {
    const b = bytes[index];
    lo = Math.imul(lo ^ b, 0x01000193) >>> 0;
    hi = Math.imul(hi ^ b, 0x01000193) >>> 0;
  }
  return { lo, hi };
}

/* @param h — dual-lane hash state { lo, hi } */
function fnv1aFinish(h) {
  return ((h.hi >>> 0) * 0x100000000 + (h.lo >>> 0)).toString(16);
}

// ─── Fast-Path Probe ────────────────────
//
// Pre-evaluates a route handler at registration time to resolve closure
// variables that the Rust static analyzer can't see. If the handler is
// a simple res.json({...}) or res.send(...) with closure variables,
// we call it with probe param values and capture the response to generate
// a synthetic handler source with all values resolved to literals.
//
// Example: handler `(req, res) => res.json({ id: req.params.id, engine: label })`
// where `label = "http-native"` becomes:
// `(req, res) => res.json({ "id": req.params.id, "engine": "http-native" })`

const PROBE_PARAM_PREFIX = "__PROBE_PARAM_";
const PROBE_PARAM_SUFFIX = "__";

function probeHandlerForFastPath(route, originalSource) {
  // Only probe parameterized routes (routeKind is not set yet, check path)
  if (!route.path.includes(":")) {
    return null;
  }

  // Don't probe if the source contains await (async I/O)
  if (originalSource.includes("await")) {
    return null;
  }

  // Don't probe if the handler has side effects beyond req/res calls.
  // Detect external mutations: array pushes, property assignments on non-res objects, etc.
  if (/(?<!res)\.\s*(?:push|pop|shift|unshift|splice|set|write|emit|log|warn|error|send)\s*\(/.test(originalSource)) {
    return null;
  }

  // Extract param names from path
  const paramNames = route.path
    .split("/")
    .filter((s) => s.startsWith(":"))
    .map((s) => s.slice(1));

  if (paramNames.length === 0) {
    return null;
  }

  // Build probe param values: "__PROBE_PARAM_id__" etc.
  const probeParams = Object.create(null);
  for (const name of paramNames) {
    probeParams[name] = `${PROBE_PARAM_PREFIX}${name}${PROBE_PARAM_SUFFIX}`;
  }

  // Mock request object
  const mockReq = Object.create(null);
  mockReq.params = probeParams;
  mockReq.query = Object.create(null);
  mockReq.headers = Object.create(null);
  mockReq.method = route.method || "GET";
  mockReq.path = route.path;
  mockReq.url = route.path;
  mockReq.header = () => undefined;

  // Mock response object that captures the json() call
  let capturedData = undefined;
  let capturedStatus = 200;
  let capturedType = null;
  let probeSucceeded = false;

  const mockRes = {
    _state: { finished: false },
    get finished() {
      return this._state.finished;
    },
    status(code) {
      capturedStatus = code;
      return this;
    },
    json(data) {
      capturedData = data;
      probeSucceeded = true;
      this._state.finished = true;
      return this;
    },
    send(data) {
      if (typeof data === "string") {
        capturedData = data;
        capturedType = "send_string";
      } else if (data && typeof data === "object") {
        capturedData = data;
        capturedType = "send_json";
      }
      probeSucceeded = true;
      this._state.finished = true;
      return this;
    },
    set() { return this; },
    header() { return this; },
    type(v) { capturedType = v; return this; },
  };

  try {
    const result = route.handler(mockReq, mockRes);
    // If the handler returns a promise, it's async — we can't probe it synchronously
    if (result && typeof result.then === "function") {
      // But if the response was already captured synchronously (common for async handlers
      // that don't actually await anything), we can still use it
      if (!probeSucceeded) {
        return null;
      }
    }
  } catch {
    return null;
  }

  if (!probeSucceeded || capturedData === undefined) {
    return null;
  }

  // Now generate a synthetic handler source with resolved values
  if (typeof capturedData === "object" && capturedData !== null && !Array.isArray(capturedData)) {
    return generateResolvedJsonSource(capturedData, paramNames, capturedStatus);
  }

  if (typeof capturedData === "string" && capturedType === "send_string") {
    return generateResolvedSendSource(capturedData, paramNames, capturedStatus);
  }

  return null;
}

function generateResolvedJsonSource(data, paramNames, status) {
  const fields = [];
  const probeParamSet = new Set(paramNames.map((n) => `${PROBE_PARAM_PREFIX}${n}${PROBE_PARAM_SUFFIX}`));

  for (const [key, value] of Object.entries(data)) {
    if (typeof value === "string" && probeParamSet.has(value)) {
      // This field maps to a param — extract the param name
      const paramName = value.slice(PROBE_PARAM_PREFIX.length, -PROBE_PARAM_SUFFIX.length);
      fields.push(`${JSON.stringify(key)}: req.params.${paramName}`);
    } else if (typeof value === "string") {
      fields.push(`${JSON.stringify(key)}: ${JSON.stringify(value)}`);
    } else if (typeof value === "number" || typeof value === "boolean" || value === null) {
      fields.push(`${JSON.stringify(key)}: ${JSON.stringify(value)}`);
    } else {
      // Complex value — can't resolve, bail
      return null;
    }
  }

  const jsonArg = `{ ${fields.join(", ")} }`;
  if (status !== 200) {
    return `(req, res) => res.status(${status}).json(${jsonArg})`;
  }
  return `(req, res) => res.json(${jsonArg})`;
}

function generateResolvedSendSource(data, paramNames, status) {
  // Check if the string contains any probe param values
  let resolvedStr = data;
  let hasParams = false;
  for (const name of paramNames) {
    const probe = `${PROBE_PARAM_PREFIX}${name}${PROBE_PARAM_SUFFIX}`;
    if (resolvedStr.includes(probe)) {
      hasParams = true;
      break;
    }
  }

  if (hasParams) {
    // Template literal with param interpolation
    let template = "`";
    let remaining = data;
    for (const name of paramNames) {
      const probe = `${PROBE_PARAM_PREFIX}${name}${PROBE_PARAM_SUFFIX}`;
      remaining = remaining.replaceAll(probe, `\${req.params.${name}}`);
    }
    template += remaining + "`";
    if (status !== 200) {
      return `(req, res) => res.status(${status}).send(${template})`;
    }
    return `(req, res) => res.send(${template})`;
  }

  // Pure static string
  if (status !== 200) {
    return `(req, res) => res.status(${status}).send(${JSON.stringify(data)})`;
  }
  return `(req, res) => res.send(${JSON.stringify(data)})`;
}

function compileRouteDispatch(
  route,
  middlewares,
  errorHandlerPlans = [],
  optConfig = {},
) {
  const applicableMiddlewares = middlewares.filter((middleware) =>
    pathPrefixMatches(middleware.pathPrefix, route.path),
  );
  const requestPlan = mergeRequestAccessPlans([
    route.accessPlan,
    ...applicableMiddlewares.map((middleware) => middleware.accessPlan),
    ...errorHandlerPlans,
  ]);

  const requestFactory = createRequestFactory(
    requestPlan,
    route.paramNames,
    route.method,
  );
  const runMiddlewares = createMiddlewareRunner(applicableMiddlewares);
  const compiledHandler = route.handler;
  const jsonFastPath =
    route.accessPlan.jsonFastPath === "fallback"
      ? requestPlan.jsonFastPath
      : route.accessPlan.jsonFastPath;

  return {
    ...route,
    applicableMiddlewares,
    requestPlan,
    requestFactory,
    runMiddlewares,
    compiledHandler,
    _hasMiddlewares: applicableMiddlewares.length > 0,
    dispatchKind: requestPlan.dispatchKind,
    jsonFastPath,
    jsonSerializer: createJsonSerializer(jsonFastPath),
    runtimeResponseCache: createRouteResponseCache(route, applicableMiddlewares, requestPlan, optConfig),
  };
}

/**
 * Create a chainable method registrar for a given HTTP method.
 * Supports both (path, handler) and (path, options, handler) signatures
 * to enable per-route cache configuration.
 *
 * @param {Object} app    - The application instance
 * @param {string} method - HTTP method name or "ALL"
 * @returns {Function} (path, [options], handler) => app
 */
function createMethodRegistrar(app, method) {
  return (path, optionsOrHandler, maybeHandler) => {
    let options = {};
    let handler;
    const groupPrefix = app._groupPrefix ?? "/";
    const scopedPath =
      typeof path === "string"
        ? applyGroupPrefixToRoutePath(path, groupPrefix)
        : path;

    if (typeof optionsOrHandler === "function") {
      handler = optionsOrHandler;
    } else {
      options = optionsOrHandler || {};
      handler = maybeHandler;
    }

    const sourceLocation = captureRouteRegistrationLocation();
    const routeOptions = sourceLocation
      ? { ...options, sourceLocation }
      : options;

    if (method === "ALL") {
      for (const concreteMethod of HTTP_METHODS) {
        app._routes.push(
          {
            ...normalizeRouteRegistration(concreteMethod, scopedPath, handler, routeOptions),
            handlerId: app._allocateHandlerId(),
          },
        );
      }
      return app;
    }

    app._routes.push({
      ...normalizeRouteRegistration(method, scopedPath, handler, routeOptions),
      handlerId: app._allocateHandlerId(),
    });
    return app;
  };
}

function normalizeListenOptions(options = {}) {
  const serverConfig = normalizeHttpServerConfig(
    options.serverConfig ?? options.httpServerConfig ?? defaultHttpServerConfig,
  );
  const optionOpt = options.opt ?? null;
  const normalizedOpt = {
    notify: optionOpt?.notify ?? true,
    notifyIntervalMs: optionOpt?.notifyIntervalMs,
    cache: optionOpt?.cache,
    hotReload:
      optionOpt?.hotReload === true ||
      process.env.HTTP_NATIVE_HOT_RELOAD === "1",
    hotReloadPaths: Array.isArray(optionOpt?.hotReloadPaths)
      ? optionOpt.hotReloadPaths
      : undefined,
    hotReloadDebounceMs: optionOpt?.hotReloadDebounceMs,
    devComments:
      optionOpt?.devComments ?? process.env.HTTP_NATIVE_DEV_COMMENTS !== "0",
  };

  if (globalThis.__HTTP_NATIVE_DEV_CONTEXT__) {
    // Avoid auto-generated source edits causing restart loops in dev hot-reload mode.
    normalizedOpt.devComments = false;
    normalizedOpt.hotReload = false;
  }

  return {
    host: options.host ?? serverConfig.defaultHost,
    port: Number(options.port ?? 3000),
    backlog:
      options.backlog === undefined || options.backlog === null
        ? serverConfig.defaultBacklog
        : Number(options.backlog),
    opt: normalizedOpt,
    serverConfig,
    tls: serverConfig.tls ?? null,
  };
}

function registerDevCommentProcessCleanup(devRouteCommentWriter) {
  if (!devRouteCommentWriter?.cleanup) {
    return () => undefined;
  }

  const cleanup = () => {
    devRouteCommentWriter.cleanup();
  };

  /**
   * implmented for now
   * but it shouldn't work for now cuz its hard to debug then
   */
  process.once("beforeExit", cleanup);
  process.once("exit", cleanup);

  return () => {
    process.off("beforeExit", cleanup);
    process.off("exit", cleanup);
  };
}

async function closeNativeServerHandle(handle, timeoutMs = NATIVE_CLOSE_TIMEOUT_MS) {
  let timeoutId = null;
  let completed = false;

  try {
    await Promise.race([
      Promise.resolve(handle.close()).then(() => {
        completed = true;
      }),
      new Promise((resolve) => {
        timeoutId = setTimeout(resolve, timeoutMs);
        if (typeof timeoutId.unref === "function") {
          timeoutId.unref();
        }
      }),
    ]);
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }

  return completed;
}

async function assertPortAvailable(host, port) {
  if (!Number.isFinite(port) || Number(port) === 0) {
    return;
  }

  await new Promise((resolve, reject) => {
    import("node:net").then(({ createServer }) => {
      const tester = createServer();
      tester.once("error", (error) => {
        if (error.code === "EADDRINUSE") {
          reject(new Error(`Port ${port} is already in use`));
          return;
        }
        reject(error);
      });
      tester.once("listening", () => tester.close(resolve));
      tester.listen(port, host);
    });
  });
}

function buildRouteCacheNamespace(route) {
  let hash = fnv1aString(0x811c9dc5, route.method);
  hash = fnv1aString(hash, route.path);
  hash = fnv1aString(hash, route.handlerSource ?? "");

  for (const middleware of route.applicableMiddlewares ?? []) {
    hash = fnv1aString(hash, middleware.pathPrefix ?? "/");
    hash = fnv1aString(hash, middleware.handlerSource ?? "");
  }

  const cache = route.cache ?? null;
  if (cache) {
    hash = fnv1aString(hash, String(cache.ttl ?? 60));
    hash = fnv1aString(hash, String(cache.maxEntries ?? 256));
    for (const varyKey of cache.varyBy ?? []) {
      hash = fnv1aString(hash, String(varyKey));
    }
  }

  return `route:${fnv1aFinish(hash)}`;
}

function normalizeApplicationReloadConfig(options = {}) {
  if (options === false || options == null) {
    return null;
  }

  if (typeof options !== "object") {
    throw new TypeError("app.reload(options) expects an object");
  }

  const watch = Array.isArray(options.watch)
    ? options.watch
    : Array.isArray(options.files)
      ? options.files
      : undefined;

  return {
    ...(watch ? { watch: [...watch] } : {}),
    ...(options.debounceMs === undefined ? {} : { debounceMs: Number(options.debounceMs) }),
    ...(options.clear === undefined ? {} : { clear: Boolean(options.clear) }),
  };
}

function normalizeManifestCache(cache) {
  if (!cache) {
    return null;
  }

  return {
    ttlSecs: cache.ttl || 60,
    maxEntries: cache.maxEntries || 256,
    varyBy: (cache.varyBy || []).map((key) => {
      const dotIndex = key.indexOf(".");
      return dotIndex >= 0
        ? { source: key.slice(0, dotIndex), name: key.slice(dotIndex + 1) }
        : { source: "query", name: key };
    }),
  };
}

function buildCompiledApplication(app, normalizedOptions) {
  const compiledMiddlewares = app._middlewares.map(compileMiddlewareRegistration);
  /* Error handlers have signature (error, req, res) — the request is the
   * SECOND parameter, not the first. analyzeRequestAccess assumes the first
   * parameter is req, which would misidentify `error`. Create a plan that
   * requests the basic fields error handlers typically need (method, path, url)
   * without forcing generic_fallback on every route. */
  const ERROR_HANDLER_PLAN = Object.freeze({
    method: true,
    path: true,
    url: true,
    fullParams: false,
    fullQuery: false,
    fullHeaders: false,
    paramKeys: new Set(),
    queryKeys: new Set(),
    headerKeys: new Set(),
    dispatchKind: "specialized",
    jsonFastPath: "fallback",
  });
  const errorHandlerPlans = app._errorHandlers.map(() => ERROR_HANDLER_PLAN);

  const routes = app._routes.map((route) => {
    let handlerSource =
      route.syntheticHandlerSource ??
      Function.prototype.toString.call(route.handler);

    if (!route.staticResponse) {
      const probedSource = probeHandlerForFastPath(route, handlerSource);
      if (probedSource) {
        handlerSource = probedSource;
      }
    }

    return {
      ...route,
      handlerSource,
      accessPlan: analyzeRequestAccess(handlerSource),
      ...compileRouteShape(route.method, route.path),
    };
  });

  for (const route of routes) {
    if (!route.staticResponse) {
      continue;
    }

    const hasMiddleware = compiledMiddlewares.some((middleware) =>
      pathPrefixMatches(middleware.pathPrefix, route.path),
    );
    if (hasMiddleware) {
      throw new Error(
        `app.static(${JSON.stringify(route.path)}) cannot be used with applicable middleware`,
      );
    }
  }

  const compiledRoutes = routes.map((route) =>
    compileRouteDispatch(
      route,
      compiledMiddlewares,
      errorHandlerPlans,
      normalizedOptions.opt,
    ),
  );
  for (const route of compiledRoutes) {
    route.cacheNamespace = buildRouteCacheNamespace(route);
  }

  const manifest = {
    version: 1,
    serverConfig: normalizedOptions.serverConfig,
    middlewares: compiledMiddlewares.map((middleware) => ({
      pathPrefix: middleware.pathPrefix,
    })),
    routes: compiledRoutes.map((route) => ({
      method: route.method,
      methodCode: route.methodCode,
      path: route.path,
      routeKind: route.routeKind,
      handlerId: route.handlerId,
      cacheNamespace: route.cacheNamespace,
      handlerSource: route.handlerSource,
      paramNames: route.paramNames,
      segmentCount: route.segmentCount,
      headerKeys: [...route.requestPlan.headerKeys],
      fullHeaders: route.requestPlan.fullHeaders,
      needsPath: route.requestPlan.path,
      needsUrl: route.requestPlan.url,
      needsQuery:
        route.requestPlan.fullQuery ||
        route.requestPlan.queryKeys.size > 0,
      cache: normalizeManifestCache(route.cache),
      needsSession: /\breq\.session\b|\breq\.sessionId\b/.test(route.handlerSource),
      staticResponse: route.staticResponse
        ? {
          status: route.staticResponse.status,
          headers: route.staticResponse.headers,
          body: route.staticResponse.body,
        }
        : null,
    })),
    wsRoutes: app._wsRoutes.map((ws) => ({
      path: ws.path,
      handlerId: ws.handlerId,
    })),
  };

  if (normalizedOptions.tls) {
    manifest.tls = {
      cert: normalizedOptions.tls.cert,
      key: normalizedOptions.tls.key,
      ca: normalizedOptions.tls.ca,
      passphrase: normalizedOptions.tls.passphrase ? "[REDACTED]" : undefined,
    };
  }

  const sessionMiddleware = app._middlewares.find((middleware) => middleware.handler._sessionConfig);
  if (sessionMiddleware) {
    const cfg = sessionMiddleware.handler._sessionConfig;
    manifest.session = {
      secret: cfg.secret,
      maxAgeSecs: cfg.maxAge,
      cookieName: cfg.cookieName,
      httpOnly: cfg.httpOnly,
      secure: cfg.secure,
      sameSite: cfg.sameSite,
      path: cfg.path,
      maxSessions: cfg.maxSessions,
      maxDataSize: cfg.maxDataSize,
    };
  }

  const compressionMiddleware = app._middlewares.find(
    (middleware) => middleware.handler._compressionConfig,
  );
  if (compressionMiddleware) {
    const cfg = compressionMiddleware.handler._compressionConfig;
    manifest.compression = {
      enabled: true,
      minSize: cfg.minSize,
      brotliQuality: cfg.brotliQuality,
      gzipLevel: cfg.gzipLevel,
      qualityMap: cfg.qualityMap,
    };
  }

  const runtimeOptimizer = createRuntimeOptimizer(
    compiledRoutes,
    compiledMiddlewares,
    normalizedOptions.opt,
  );
  const devRouteCommentWriter = createRouteDevCommentWriter(normalizedOptions.opt);
  const detachDevCommentProcessCleanup = registerDevCommentProcessCleanup(
    devRouteCommentWriter,
  );
  if (devRouteCommentWriter) {
    for (const route of compiledRoutes) {
      const routeEntry = buildRouteEntry(route, compiledMiddlewares);
      const baseStatus =
        routeEntry.nativeCache === true
          ? "native-cache"
          : routeEntry.staticFastPath === true
            ? "static-fast-path"
            : "bridge-dispatch";
      devRouteCommentWriter.markRoute(route, baseStatus);

      if (route.runtimeResponseCache) {
        devRouteCommentWriter.markRoute(route, "runtime-cache-tracking");
      }
    }
  }

  return {
    compiledRoutes,
    compiledMiddlewares,
    runtimeOptimizer,
    devRouteCommentWriter,
    detachDevCommentProcessCleanup,
    errorHandlers: app._errorHandlers,
    wsRoutes: app._wsRoutes,
    manifestJson: JSON.stringify(manifest),
    normalizedOptions,
  };
}

async function startCompiledServer(compiledSnapshot, normalizedOptions) {
  await assertPortAvailable(normalizedOptions.host, normalizedOptions.port);

  const native = loadNativeModule();
  const dispatcher = createDispatcher(compiledSnapshot);
  const nativeHandle = native.startServer(compiledSnapshot.manifestJson, dispatcher, {
    host: normalizedOptions.host,
    port: normalizedOptions.port,
    backlog: normalizedOptions.backlog,
  });
  ACTIVE_NATIVE_SERVERS.add(nativeHandle);

  let closing = false;
  const closeServerHandle = async () => {
    if (closing) {
      return;
    }
    closing = true;
    dispatcher.dispose();
    ACTIVE_NATIVE_SERVERS.delete(nativeHandle);
    const closed = await closeNativeServerHandle(nativeHandle);
    if (!closed && process.env.NODE_ENV !== "production") {
      console.warn(
        `[http-native] native server close timed out after ${NATIVE_CLOSE_TIMEOUT_MS}ms; continuing shutdown`,
      );
    }
  };

  const hotReloadController = createRuntimeHotReloadController({
    enabled: normalizedOptions.opt.hotReload === true,
    roots: normalizedOptions.opt.hotReloadPaths,
    debounceMs: normalizedOptions.opt.hotReloadDebounceMs,
    beforeRestart: async () => {
      await closeServerHandle();
    },
  });

  const serverHandle = {
    host: nativeHandle.host,
    port: nativeHandle.port,
    url: normalizedOptions.tls ? nativeHandle.url.replace("http://", "https://") : nativeHandle.url,
    tls: !!normalizedOptions.tls,
    _handle: nativeHandle,
    _dispatcher: dispatcher,
    _reloadCompiledSnapshot(nextSnapshot) {
      const previousSnapshot = dispatcher.replace(nextSnapshot);

      try {
        dispatcher.closeWebSockets();
        nativeHandle.reload(nextSnapshot.manifestJson);
        disposeCompiledSnapshot(previousSnapshot);
      } catch (error) {
        dispatcher.restore(previousSnapshot);
        disposeCompiledSnapshot(nextSnapshot);
        throw error;
      }

      return this;
    },
    optimizations: {
      snapshot() {
        return dispatcher.current().runtimeOptimizer.snapshot();
      },
      summary() {
        return dispatcher.current().runtimeOptimizer.summary();
      },
    },
    close() {
      hotReloadController.dispose();
      return closeServerHandle();
    },

    /**
     * @DX-6.3: graceful shutdown — stop accepting new connections, drain
     * in-flight requests up to `timeout` ms, then force-stop workers.
     *
     * @param {Object} [options]
     * @param {number} [options.timeout=30000]    - Maximum drain time in ms
     * @param {number} [options.forceAfter]       - Hard kill after this many ms (defaults to timeout + 5000)
     * @param {Function} [options.onDraining]     - Called when draining starts
     * @param {Function} [options.onDrained]      - Called when all requests finish (before close)
     * @returns {Promise<{ drained: boolean, remaining: number }>}
     */
    async shutdown(options = {}) {
      const drainTimeout = options.timeout ?? 30000;
      const forceTimeout = options.forceAfter ?? (drainTimeout + 5000);

      if (typeof options.onDraining === "function") {
        options.onDraining();
      }

      /* Use the Rust-side shutdown which sets the draining flag, polls
       * the in-flight counter, and then force-closes workers. The force
       * timeout is handled by a JS-side race. */
      const shutdownPromise = new Promise((resolve) => {
        try {
          const remaining = nativeHandle.shutdown(drainTimeout);
          resolve(remaining);
        } catch {
          resolve(0);
        }
      });

      const forcePromise = new Promise((resolve) =>
        setTimeout(() => resolve(-1), forceTimeout),
      );

      const result = await Promise.race([shutdownPromise, forcePromise]);
      const remaining = result === -1 ? 0 : result;
      const drained = remaining === 0;

      if (drained && typeof options.onDrained === "function") {
        await options.onDrained();
      }

      hotReloadController.dispose();
      dispatcher.dispose();
      ACTIVE_NATIVE_SERVERS.delete(nativeHandle);

      return { drained, remaining };
    },
  };

  return serverHandle;
}

// ─── Application Factory ───────────────

/**
 * Create a new http-native application instance with Express-like
 * route registration, middleware support, and error handling.
 *
 * @returns {import('./index').Application}
 */
export function createApp(config = {}) {
  let nextHandlerId = 1;

  // Consolidate top-level config into a normalized shape that listen() can use as defaults.
  const appConfig = {
    server: config.server ?? {},
    tls: config.tls ?? null,
    dev: config.dev ?? {},
  };

  // Build default listen options from createApp config so listen() inherits them.
  const appListenDefaults = {
    host: appConfig.server.host,
    port: appConfig.server.port,
    backlog: appConfig.server.backlog,
    serverConfig: {
      ...(appConfig.server.maxHeaderBytes !== undefined
        ? { maxHeaderBytes: appConfig.server.maxHeaderBytes }
        : {}),
      tls: appConfig.tls,
    },
    opt: {
      ...(appConfig.dev.hotReload !== undefined ? { hotReload: appConfig.dev.hotReload } : {}),
      ...(appConfig.dev.hotReloadPaths !== undefined ? { hotReloadPaths: appConfig.dev.hotReloadPaths } : {}),
      ...(appConfig.dev.hotReloadDebounceMs !== undefined ? { hotReloadDebounceMs: appConfig.dev.hotReloadDebounceMs } : {}),
      ...(appConfig.dev.devComments !== undefined ? { devComments: appConfig.dev.devComments } : {}),
      ...(
        appConfig.dev.logger !== undefined
          ? { notify: appConfig.dev.logger }
          : appConfig.dev.notify !== undefined
            ? { notify: appConfig.dev.notify }
            : {}
      ),
      ...(appConfig.dev.timing !== undefined ? { timing: appConfig.dev.timing } : {}),
      ...(appConfig.dev.cache !== undefined ? { cache: appConfig.dev.cache } : {}),
    },
  };

  const app = {
    _routes: [],
    _middlewares: [],
    _errorHandlers: [],
    _wsRoutes: [],
    _groupPrefix: "/",
    _config: appConfig,
    _reloadConfig: null,
    _allocateHandlerId() {
      return nextHandlerId++;
    },

    use(pathOrMiddleware, maybeMiddleware) {
      let pathPrefix = "/";
      let handler = pathOrMiddleware;
      const groupPrefix = this._groupPrefix ?? "/";

      if (typeof pathOrMiddleware === "string") {
        pathPrefix = normalizePathPrefix(pathOrMiddleware);
        pathPrefix = combinePathPrefixes(groupPrefix, pathPrefix);
        handler = maybeMiddleware;
      } else if (groupPrefix !== "/") {
        pathPrefix = groupPrefix;
      }

      if (typeof handler !== "function") {
        throw new TypeError("Middleware must be a function");
      }

      this._middlewares.push({ pathPrefix, handler });
      return this;
    },

    onError(handler) {
      if (typeof handler !== "function") {
        throw new TypeError("Error handler must be a function");
      }
      this._errorHandlers.push(handler);
      return this;
    },

    error(handler) {
      return this.onError(handler);
    },

    status(code) {
      const methods = {};
      for (const method of [...HTTP_METHODS, "all"]) {
        const key = method.toLowerCase();
        methods[key] = (path, handler) => {
          return this[key](path, async (req, res) => {
            res.status(code);
            await handler(req, res);
          });
        };
      }
      return methods;
    },

    404(handler) {
      return this.onError(async (error, req, res) => {
        if (error?.status === 404 || error?.code === "NOT_FOUND") {
          await handler(req, res);
        }
      });
    },

    401(handler) {
      return this.onError(async (error, req, res) => {
        if (error?.status === 401 || error?.code === "UNAUTHORIZED") {
          await handler(req, res);
        }
      });
    },

    group(pathPrefix, registerGroup) {
      if (typeof registerGroup !== "function") {
        throw new TypeError("group(path, callback) requires a callback function");
      }

      const normalizedPrefix = normalizePathPrefix(pathPrefix);
      const previousPrefix = this._groupPrefix ?? "/";
      this._groupPrefix = combinePathPrefixes(previousPrefix, normalizedPrefix);

      try {
        registerGroup(this);
      } finally {
        this._groupPrefix = previousPrefix;
      }

      return this;
    },

    get: undefined,
    post: undefined,
    put: undefined,
    delete: undefined,
    patch: undefined,
    options: undefined,
    all: undefined,
    static: undefined,

    reload(options = {}) {
      this._reloadConfig = normalizeApplicationReloadConfig(options);
      return this;
    },

    listen(options = {}) {
      if (options?.opt !== undefined) {
        throw new Error(
          "listen().opt() has been removed. Configure runtime options in createApp({ dev: { ... } }) instead.",
        );
      }

      const startServer = async (listenOptions = options) => {
        // Merge app-level defaults (from createApp config) with per-listen overrides.
        const mergedOptions = {
          host: listenOptions.host ?? appListenDefaults.host,
          port: listenOptions.port ?? appListenDefaults.port,
          backlog: listenOptions.backlog ?? appListenDefaults.backlog,
          serverConfig: {
            ...(appListenDefaults.serverConfig ?? {}),
            ...(listenOptions.serverConfig ?? {}),
            tls: listenOptions.serverConfig?.tls ?? appListenDefaults.serverConfig?.tls,
          },
          opt: {
            ...(appListenDefaults.opt ?? {}),
            ...(listenOptions.opt ?? {}),
          },
        };
        const normalizedOptions = normalizeListenOptions(mergedOptions);
        const routes = this._routes.map((route) => ({
          ...route,
        }));
        const wsRoutes = this._wsRoutes.map((route) => ({
          ...route,
        }));
        const compiledApp = buildCompiledApplication(
          {
            ...this,
            _routes: routes,
            _wsRoutes: wsRoutes,
          },
          normalizedOptions,
        );

        return startCompiledServer(compiledApp, normalizedOptions);
      };

      let selectedPort = options.port;
      let selectedOpt;
      let selectedTls = options.serverConfig?.tls ?? null;
      let startPromise = null;
      let startBlockedByRemovedOpt = false;

      const resolveOptions = () => {
        return {
          ...options,
          ...(selectedPort === undefined ? {} : { port: selectedPort }),
          opt: selectedOpt,
          serverConfig: {
            ...(options.serverConfig ?? {}),
            tls: selectedTls,
          },
        };
      };

      const start = () => {
        if (startBlockedByRemovedOpt) {
          throw new Error(
            "listen().opt() has been removed. Configure runtime options in createApp({ dev: { ... } }) instead.",
          );
        }

        if (!startPromise) {
          const resolvedOptions = resolveOptions();
          const devContext = globalThis.__HTTP_NATIVE_DEV_CONTEXT__;
          startPromise = devContext?.registerAppListen
            ? devContext.registerAppListen(this, resolvedOptions)
            : startServer(resolvedOptions);
        }
        return startPromise;
      };

      const chainableListen = {
        port(value) {
          if (startPromise) {
            return startPromise;
          }

          selectedPort = Number(value);
          return chainableListen;
        },
        opt() {
          startBlockedByRemovedOpt = true;
          throw new Error(
            "listen().opt() has been removed. Configure runtime options in createApp({ dev: { ... } }) instead.",
          );
        },
        hot(hotOptions = true) {
          if (startPromise) {
            return startPromise;
          }

          const nextOpt = {
            ...(selectedOpt ?? {}),
          };

          if (hotOptions === false) {
            nextOpt.hotReload = false;
            selectedOpt = nextOpt;
            return chainableListen;
          }

          nextOpt.hotReload = true;

          if (hotOptions && typeof hotOptions === "object") {
            const hotReloadPaths = Array.isArray(hotOptions.paths)
              ? hotOptions.paths
              : Array.isArray(hotOptions.hotReloadPaths)
                ? hotOptions.hotReloadPaths
                : undefined;

            if (hotReloadPaths) {
              nextOpt.hotReloadPaths = hotReloadPaths;
            }

            const hotReloadDebounceMs =
              hotOptions.debounceMs ?? hotOptions.hotReloadDebounceMs;
            if (hotReloadDebounceMs !== undefined) {
              nextOpt.hotReloadDebounceMs = hotReloadDebounceMs;
            }
          }

          selectedOpt = nextOpt;
          return chainableListen;
        },
        tls(tlsConfig) {
          if (startPromise) {
            return startPromise;
          }

          selectedTls = tlsConfig;
          return chainableListen;
        },
        http3(h3Options = { enabled: true }) {
          if (startPromise) {
            return startPromise;
          }

          selectedOpt = {
            ...(selectedOpt ?? {}),
            http3: typeof h3Options === "boolean" ? { enabled: h3Options } : h3Options,
          };
          return chainableListen;
        },
        then(onFulfilled, onRejected) {
          return start().then(onFulfilled, onRejected);
        },
        catch(onRejected) {
          return start().catch(onRejected);
        },
        finally(onFinally) {
          return start().finally(onFinally);
        },
      };

      return chainableListen;
    },
  };

  app.ws = (path, handlers) => {
    if (typeof handlers !== "object") {
      throw new TypeError("WebSocket handlers must be an object with open/message/close");
    }
    app._wsRoutes.push({
      path: normalizeRoutePath("GET", path),
      handlers: {
        open: handlers.open,
        message: handlers.message,
        close: handlers.close,
      },
      handlerId: app._allocateHandlerId(),
      /* DX-4.4 WebSocket config */
      maxPayloadLength: handlers.maxPayloadLength ?? 64 * 1024,
      backpressure: handlers.backpressure ?? "drop",
      idleTimeout: handlers.idleTimeout ?? 120,
      perMessageDeflate: handlers.perMessageDeflate ?? false,
    });
    return app;
  };

  app.get = createMethodRegistrar(app, "GET");
  app.post = createMethodRegistrar(app, "POST");
  app.put = createMethodRegistrar(app, "PUT");
  app.delete = createMethodRegistrar(app, "DELETE");
  app.patch = createMethodRegistrar(app, "PATCH");
  app.options = createMethodRegistrar(app, "OPTIONS");
  app.head = createMethodRegistrar(app, "HEAD");
  app.all = createMethodRegistrar(app, "ALL");
  app.static = (routePath, html, options = {}) => {
    const groupPrefix = app._groupPrefix ?? "/";
    const scopedPath =
      typeof routePath === "string"
        ? applyGroupPrefixToRoutePath(routePath, groupPrefix)
        : routePath;
    const sourceLocation = captureRouteRegistrationLocation();
    const routeOptions = sourceLocation
      ? { ...options, sourceLocation }
      : options;

    app._routes.push({
      ...normalizeStaticRouteRegistration(scopedPath, html, routeOptions),
      handlerId: app._allocateHandlerId(),
    });
    return app;
  };

  /**
   * Register a health check endpoint served entirely from the Rust static
   * fast path — zero JS dispatch, zero allocation per request. The response
   * is pre-built at startup with Brotli/Gzip compression variants.
   *
   * @param {string} routePath - Health check path (e.g. "/healthz")
   * @param {Object} [options]
   * @param {Object} [options.body]    - JSON body (default: { status: "ok" })
   * @param {number} [options.status]  - HTTP status code (default: 200)
   * @param {Object} [options.headers] - Additional response headers
   * @returns {Application}
   */
  app.health = (routePath, options = {}) => {
    const body = JSON.stringify(options.body ?? { status: "ok" });
    const headers = {
      "content-type": "application/json; charset=utf-8",
      ...(options.headers ?? {}),
    };
    return app.static(routePath, body, {
      status: options.status ?? 200,
      headers,
    });
  };

  // ─── DX-5.4: Decorator Pattern ──────────
  //
  // Attach custom properties to every request object. Decorators are set once
  // at startup and available in every handler as `req.<name>`. This avoids
  // per-request middleware overhead for injecting services/pools.

  const decorators = Object.create(null);

  /**
   * Attach a named property to every request object.
   *
   * @param {string} name  - Property name accessible on `req`
   * @param {*} value      - Value or service instance to attach
   * @returns {Application}
   */
  app.decorate = (name, value) => {
    if (name in decorators) {
      throw new Error(`Decorator "${name}" is already registered`);
    }
    decorators[name] = value;
    return app;
  };

  /** @internal — called by bridge to attach decorators to each request */
  app._applyDecorators = (req) => {
    for (const key in decorators) {
      req[key] = decorators[key];
    }
  };

  // ─── DX-5.2: Plugin System ────────────
  //
  // Plugins are objects with a `setup(app, options)` function called at
  // registration time and an optional `teardown()` called on shutdown.
  // Lifecycle hooks are aggregated across plugins and called in order.

  const registeredPlugins = [];
  const lifecycleHooks = {
    onRequest: [],
    onRoute: [],
    onResponse: [],
    onError: [],
    onClose: [],
  };

  /**
   * Register lifecycle hooks from plugins.
   *
   * @param {"onRequest"|"onRoute"|"onResponse"|"onError"|"onClose"} event
   * @param {Function} fn
   * @returns {Application}
   */
  app.addHook = (event, fn) => {
    if (!lifecycleHooks[event]) {
      throw new Error(`Unknown hook event "${event}"`);
    }
    lifecycleHooks[event].push(fn);
    return app;
  };

  /**
   * Install a plugin. Plugins receive the app instance and can register
   * routes, middleware, hooks, and decorators.
   *
   * @param {{ name: string, setup: Function, teardown?: Function }} plugin
   * @param {Object} [pluginOptions] - Options forwarded to the plugin
   * @returns {Application}
   */
  app.register = (plugin, pluginOptions = {}) => {
    if (!plugin || typeof plugin.setup !== "function") {
      throw new Error("Plugin must have a setup(app, options) function");
    }
    if (registeredPlugins.some((p) => p.name === plugin.name)) {
      throw new Error(`Plugin "${plugin.name}" is already registered`);
    }
    plugin.setup(app, pluginOptions);
    registeredPlugins.push(plugin);
    return app;
  };

  /** @internal — expose hooks and plugins for bridge/shutdown integration */
  app._hooks = lifecycleHooks;
  app._plugins = registeredPlugins;

  return app;
}

/**
 * Define a plugin object with the standard interface.
 *
 * @param {{ name: string, version?: string, setup: Function, teardown?: Function }} definition
 * @returns {{ name: string, version: string, setup: Function, teardown?: Function }}
 */
export function definePlugin(definition) {
  if (!definition.name) throw new Error("Plugin must have a name");
  if (typeof definition.setup !== "function")
    throw new Error("Plugin must have a setup function");
  return {
    name: definition.name,
    version: definition.version ?? "0.0.0",
    setup: definition.setup,
    teardown: definition.teardown,
  };
}

export {
  buildCompiledApplication as _buildCompiledApplication,
  normalizeListenOptions as _normalizeListenOptions,
  startCompiledServer as _startCompiledServer,
};
