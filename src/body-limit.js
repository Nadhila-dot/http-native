/**
 * http-native per-route request body size limit middleware.
 *
 * Provides a JS-side guard for body size enforcement. The primary
 * enforcement is in Rust (via `maxBodyBytes` in the route manifest),
 * but this middleware offers a composable fallback for routes where
 * the Rust-side limit is not configured or for post-parse validation.
 *
 * Usage:
 *   import { bodyLimit } from "@http-native/core/body-limit";
 *
 *   app.post("/upload", bodyLimit("50mb"), handler);
 *   app.post("/api/data", bodyLimit("1mb"), handler);
 *   app.post("/small", bodyLimit(1024), handler);  // bytes
 */

// ─── Size Parser ──────────────────────────

const SIZE_UNITS = {
  b: 1,
  kb: 1024,
  mb: 1024 * 1024,
  gb: 1024 * 1024 * 1024,
};

/**
 * Parse a human-readable size string into bytes.
 *
 * @param {string|number} input - e.g. "50mb", "1kb", 1024
 * @returns {number} Size in bytes
 */
function parseSize(input) {
  if (typeof input === "number") {
    if (!Number.isFinite(input) || input < 0) {
      throw new TypeError("bodyLimit size must be a non-negative number");
    }
    return Math.floor(input);
  }

  if (typeof input !== "string") {
    throw new TypeError("bodyLimit size must be a string or number");
  }

  const match = input.trim().match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/i);
  if (!match) {
    throw new TypeError(`Invalid body limit size: "${input}"`);
  }

  const value = parseFloat(match[1]);
  const unit = (match[2] || "b").toLowerCase();
  const multiplier = SIZE_UNITS[unit];

  if (!multiplier) {
    throw new TypeError(`Unknown size unit: "${match[2]}"`);
  }

  return Math.floor(value * multiplier);
}

// ─── Middleware Factory ───────────────────

/**
 * Create a body size limit middleware.
 *
 * @param {string|number} limit - Maximum body size (e.g. "50mb", 1024)
 * @returns {Function} Middleware function
 */
export function bodyLimit(limit) {
  const maxBytes = parseSize(limit);

  return async function bodyLimitMiddleware(req, res, next) {
    /* Check Content-Length header first (fast reject before body access) */
    const contentLength = req.header("content-length");
    if (contentLength !== undefined) {
      const length = parseInt(contentLength, 10);
      if (Number.isFinite(length) && length > maxBytes) {
        return res.status(413).json({ error: "Payload Too Large" });
      }
    }

    /* Also check actual body size — Content-Length can be absent or wrong */
    const body = req.body;
    if (body != null && body.length > maxBytes) {
      return res.status(413).json({ error: "Payload Too Large" });
    }

    await next();
  };
}
