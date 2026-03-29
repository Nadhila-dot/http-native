import { Buffer } from "node:buffer";

import {
  analyzeRequestAccess,
  compileRouteShape,
  createJsonSerializer,
  createRequestFactory,
  decodeRequestEnvelope,
  encodeResponseEnvelope,
  mergeRequestAccessPlans,
  releaseRequestObject,
} from "./bridge.js";
import { loadNativeModule } from "./native.js";
import defaultHttpServerConfig, {
  normalizeHttpServerConfig,
} from "./http-server.config.js";
import { createRuntimeOptimizer } from "./opt/runtime.js";

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];
const ACTIVE_NATIVE_SERVERS = new Set();
const EMPTY_BUFFER = Buffer.alloc(0);
const NOOP_NEXT = () => undefined;
const ROUTE_CACHE_PROMOTE_HITS = 16;
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



const RESPONSE_POOL_MAX = 512;
const responseStatePool = [];
const responseObjectPool = [];
const DEFAULT_JSON_SERIALIZER = createJsonSerializer("fallback");

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
    return pooled;
  }

  return {
    status: 200,
    headers: Object.create(null),
    body: EMPTY_BUFFER,
    finished: false,
    locals: Object.create(null),
    ncache: null,
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
    return function noopMiddleware(_req, _res) {};
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

function createDispatcher(compiledRoutes, runtimeOptimizer, errorHandlers = []) {
  const routesById = new Map(compiledRoutes.map((route) => [route.handlerId, route]));
  const errorRequestFactory = createRequestFactory(ERROR_REQUEST_PLAN, [], null);
  const trackDispatchTiming =
    runtimeOptimizer?.shouldCaptureDispatchTiming?.() === true;

  async function finalizeError(error, req, res, snapshot, release, fallbackStatus = 500) {
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

  return async function dispatch(requestBuffer) {
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
        createHttpError(404, "Route not found", "NOT_FOUND"),
        req,
        res,
        snapshot,
        release,
        404,
      );
    }

    const route = routesById.get(decoded.handlerId);
    if (!route) {
      return serializeErrorResponse(new Error(`Unknown handler id ${decoded.handlerId}`));
    }

    const cachedResponse = route.runtimeResponseCache?.encoded;
    if (cachedResponse) {
      return cachedResponse;
    }

    const req = route.requestFactory(decoded);
    const { response: res, snapshot, release } = createResponseEnvelope(route.jsonSerializer);
    const dispatchStartMs = trackDispatchTiming ? performance.now() : 0;

    try {
      const middlewareResult = route.runMiddlewares(req, res);
      if (!res.finished && isPromiseLike(middlewareResult)) {
        await middlewareResult;
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
      return finalizeError(error, req, res, snapshot, release, 500);
    }

    const responseSnapshot = snapshot();
    const dispatchDurationMs = trackDispatchTiming
      ? performance.now() - dispatchStartMs
      : undefined;
    runtimeOptimizer?.recordDispatch(route, req, responseSnapshot, dispatchDurationMs);
    const encoded = encodeResponseEnvelope(responseSnapshot);
    maybePromoteRouteResponseCache(route, responseSnapshot, encoded);
    releaseRequestObject(req);
    release();
    return encoded;
  };
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
  };
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

function maybePromoteRouteResponseCache(route, snapshot, encoded) {
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
  }
}

function buildSnapshotCacheKey(snapshot) {
  let hash = 0x811c9dc5;
  hash = fnv1aString(hash, String(snapshot.status ?? 200));

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

  return `${hash}:${body.length}:${headerNames.length}`;
}

function fnv1aString(seed, value) {
  let hash = seed >>> 0;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function fnv1aBytes(seed, bytes) {
  let hash = seed >>> 0;
  for (let index = 0; index < bytes.length; index += 1) {
    hash ^= bytes[index];
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
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

    if (typeof optionsOrHandler === "function") {
      handler = optionsOrHandler;
    } else {
      options = optionsOrHandler || {};
      handler = maybeHandler;
    }

    if (method === "ALL") {
      for (const concreteMethod of HTTP_METHODS) {
        app._routes.push(
          normalizeRouteRegistration(concreteMethod, path, handler, options),
        );
      }
      return app;
    }

    app._routes.push(normalizeRouteRegistration(method, path, handler, options));
    return app;
  };
}

function normalizeListenOptions(options = {}) {
  const serverConfig = normalizeHttpServerConfig(
    options.serverConfig ?? options.httpServerConfig ?? defaultHttpServerConfig,
  );

  return {
    host: options.host ?? serverConfig.defaultHost,
    port: Number(options.port ?? 3000),
    backlog:
      options.backlog === undefined || options.backlog === null
        ? serverConfig.defaultBacklog
        : Number(options.backlog),
    opt: options.opt ?? {},
    serverConfig,
  };
}

// ─── Application Factory ───────────────

/**
 * Create a new http-native application instance with Express-like
 * route registration, middleware support, and error handling.
 *
 * @returns {import('./index').Application}
 */
export function createApp() {
  const native = loadNativeModule();
  let nextHandlerId = 1;

  const app = {
    _routes: [],
    _middlewares: [],
    _errorHandlers: [],

    use(pathOrMiddleware, maybeMiddleware) {
      let pathPrefix = "/";
      let handler = pathOrMiddleware;

      if (typeof pathOrMiddleware === "string") {
        pathPrefix = normalizePathPrefix(pathOrMiddleware);
        handler = maybeMiddleware;
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

    get: undefined,
    post: undefined,
    put: undefined,
    delete: undefined,
    patch: undefined,
    options: undefined,
    all: undefined,

    async listen(options = {}) {
      const normalizedOptions = normalizeListenOptions(options);
      const compiledMiddlewares = this._middlewares.map(compileMiddlewareRegistration);
      const errorHandlerPlans = this._errorHandlers.map((handler) =>
        analyzeRequestAccess(Function.prototype.toString.call(handler)),
      );

      const routes = this._routes.map((route) => {
        const handlerSource = Function.prototype.toString.call(route.handler);

        return {
          ...route,
          handlerId: nextHandlerId++,
          handlerSource,
          accessPlan: analyzeRequestAccess(handlerSource),
          ...compileRouteShape(route.method, route.path),
        };
      });
      const compiledRoutes = routes.map((route) =>
        compileRouteDispatch(
          route,
          compiledMiddlewares,
          errorHandlerPlans,
          normalizedOptions.opt,
        ),
      );

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
          cache: route.cache
            ? {
                ttlSecs: route.cache.ttl || 60,
                maxEntries: route.cache.maxEntries || 256,
                varyBy: (route.cache.varyBy || []).map((key) => {
                  const dotIndex = key.indexOf(".");
                  return dotIndex >= 0
                    ? { source: key.slice(0, dotIndex), name: key.slice(dotIndex + 1) }
                    : { source: "query", name: key };
                }),
              }
            : null,
        })),
      };

      const runtimeOptimizer = createRuntimeOptimizer(
        compiledRoutes,
        compiledMiddlewares,
        normalizedOptions.opt,
      );
      const dispatcher = createDispatcher(compiledRoutes, runtimeOptimizer, this._errorHandlers);
      const handle = native.startServer(JSON.stringify(manifest), dispatcher, {
        host: normalizedOptions.host,
        port: normalizedOptions.port,
        backlog: normalizedOptions.backlog,
      });
      ACTIVE_NATIVE_SERVERS.add(handle);

      return {
        host: handle.host,
        port: handle.port,
        url: handle.url,
        _handle: handle,
        optimizations: {
          snapshot() {
            return runtimeOptimizer.snapshot();
          },
          summary() {
            return runtimeOptimizer.summary();
          },
        },
        close() {
          ACTIVE_NATIVE_SERVERS.delete(handle);
          runtimeOptimizer?.dispose?.();
          return handle.close();
        },
      };
    },
  };

  app.get = createMethodRegistrar(app, "GET");
  app.post = createMethodRegistrar(app, "POST");
  app.put = createMethodRegistrar(app, "PUT");
  app.delete = createMethodRegistrar(app, "DELETE");
  app.patch = createMethodRegistrar(app, "PATCH");
  app.options = createMethodRegistrar(app, "OPTIONS");
  app.all = createMethodRegistrar(app, "ALL");

  return app;
}
