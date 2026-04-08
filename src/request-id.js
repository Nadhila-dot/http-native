/**
 * http-native request ID middleware.
 *
 * Generates or propagates a unique request identifier on every request.
 * The ID is attached to `req.id` and echoed back in a configurable
 * response header for end-to-end correlation in distributed systems.
 *
 * Usage:
 *   import { requestId } from "@http-native/core/request-id";
 *
 *   // Defaults: reads/writes "x-request-id", generates crypto.randomUUID()
 *   app.use(requestId());
 *
 *   // Custom header + generator
 *   app.use(requestId({
 *     header: "x-correlation-id",
 *     generate: () => `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
 *   }));
 *
 *   // Disable response header echo
 *   app.use(requestId({ responseHeader: false }));
 */

import { randomUUID } from "node:crypto";

// ─── Default Generator ─────────────────

/**
 * Default ID generator using crypto.randomUUID() — RFC 4122 v4 UUID.
 * Available in Bun, Node 19+, and modern browsers.
 *
 * @returns {string} UUID v4 string
 */
function defaultGenerate() {
  return randomUUID();
}

// ─── Middleware Factory ────────────────

/**
 * Create a request ID middleware.
 *
 * @param {Object} [options]
 * @param {string} [options.header="x-request-id"]        - Incoming header to read
 * @param {string|false} [options.responseHeader]          - Response header to set (defaults to same as header; false to disable)
 * @param {() => string} [options.generate]                - Custom ID generator function
 * @returns {Function} Middleware function
 */
export function requestId(options = {}) {
  if (typeof options !== "object" || options === null) {
    throw new TypeError("requestId(options) expects an object");
  }

  const headerName = String(options.header ?? "x-request-id").toLowerCase();
  const responseHeader = options.responseHeader === false
    ? null
    : String(options.responseHeader ?? headerName).toLowerCase();
  const generate = options.generate ?? defaultGenerate;

  if (typeof generate !== "function") {
    throw new TypeError("requestId generate must be a function");
  }

  return async function requestIdMiddleware(req, res, next) {
    /* Propagate existing ID from upstream proxy, or generate a new one */
    const id = req.header(headerName) || generate();
    req.id = id;

    if (responseHeader) {
      res.set(responseHeader, id);
    }

    await next();
  };
}
