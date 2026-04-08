/**
 * http-native CORS middleware
 *
 * Usage:
 *   import { cors } from "http-native/cors";
 *   app.use(cors({ origin: "*" }));
 *   app.use(cors({ origin: ["https://example.com"], credentials: true }));
 */

const DEFAULT_METHODS = "GET,HEAD,PUT,PATCH,POST,DELETE";
const DEFAULT_HEADERS = "Content-Type,Authorization,Accept,X-Requested-With";

/**
 * @param {Object} [options]
 * @param {string | string[] | ((origin: string) => boolean)} [options.origin="*"]
 * @param {string | string[]} [options.methods]
 * @param {string | string[]} [options.allowedHeaders]
 * @param {string | string[]} [options.exposedHeaders]
 * @param {boolean} [options.credentials=false]
 * @param {number} [options.maxAge]
 * @param {boolean} [options.preflight=true]
 */
export function cors(options = {}) {
  const {
    origin = "*",
    methods = DEFAULT_METHODS,
    allowedHeaders = DEFAULT_HEADERS,
    exposedHeaders,
    credentials = false,
    maxAge,
    preflight = true,
  } = options;

  const methodsString = Array.isArray(methods) ? methods.join(",") : methods;
  const allowedHeadersString = Array.isArray(allowedHeaders)
    ? allowedHeaders.join(",")
    : allowedHeaders;
  const exposedHeadersString = exposedHeaders
    ? Array.isArray(exposedHeaders)
      ? exposedHeaders.join(",")
      : exposedHeaders
    : null;

  // Pre-compute origin matching function
  const matchOrigin = buildOriginMatcher(origin);

  return async function corsMiddleware(req, res, next) {
    const requestOrigin = req.header("origin") ?? req.headers?.origin;

    // Not a CORS request
    if (!requestOrigin) {
      await next();
      return;
    }

    const allowed = matchOrigin(requestOrigin);

    if (!allowed) {
      await next();
      return;
    }

    // Set CORS headers
    const effectiveOrigin =
      origin === "*" && !credentials ? "*" : requestOrigin;
    res.set("Access-Control-Allow-Origin", effectiveOrigin);

    if (credentials) {
      res.set("Access-Control-Allow-Credentials", "true");
    }

    if (effectiveOrigin !== "*") {
      const existing = res.get("vary");
      if (existing) {
        if (!existing.toLowerCase().includes("origin")) {
          res.set("vary", `${existing}, Origin`);
        }
      } else {
        res.set("vary", "Origin");
      }
    }

    if (exposedHeadersString) {
      res.set("Access-Control-Expose-Headers", exposedHeadersString);
    }

    // Handle preflight
    if (preflight && req.method === "OPTIONS") {
      res.set("Access-Control-Allow-Methods", methodsString);
      res.set("Access-Control-Allow-Headers", allowedHeadersString);

      if (maxAge !== undefined) {
        res.set("Access-Control-Max-Age", String(maxAge));
      }

      res.status(204).send();
      return;
    }

    await next();
  };
}

function buildOriginMatcher(origin) {
  if (origin === "*") {
    return () => true;
  }

  if (typeof origin === "function") {
    return origin;
  }

  if (typeof origin === "string") {
    return (requestOrigin) => requestOrigin === origin;
  }

  if (Array.isArray(origin)) {
    const originSet = new Set(origin);
    return (requestOrigin) => originSet.has(requestOrigin);
  }

  return () => false;
}
