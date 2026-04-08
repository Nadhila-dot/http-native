/**
 * http-native CSRF protection middleware.
 *
 * Implements the double-submit cookie pattern: a random token is set in
 * a cookie and must be echoed back in a request header or body field.
 * Safe methods (GET, HEAD, OPTIONS) are skipped by default.
 *
 * Usage:
 *   import { csrf } from "@http-native/core/csrf";
 *
 *   app.use(csrf());
 *
 *   app.use(csrf({
 *     cookie: { name: "_csrf", httpOnly: true, sameSite: "strict" },
 *     ignoreMethods: ["GET", "HEAD", "OPTIONS"],
 *     tokenHeader: "x-csrf-token",
 *     tokenField: "_csrf",
 *   }));
 */

import { randomBytes, timingSafeEqual } from "node:crypto";

// ─── Constants ────────────────────────────

const TOKEN_BYTES = 32;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// ─── Token Generation ─────────────────────

/**
 * Generate a cryptographically random CSRF token.
 *
 * @returns {string} Hex-encoded 32-byte token
 */
function generateToken() {
  return randomBytes(TOKEN_BYTES).toString("hex");
}

// ─── Cookie Helpers ───────────────────────

/**
 * Build a Set-Cookie header value from options.
 *
 * @param {string} name
 * @param {string} value
 * @param {Object} options
 * @returns {string}
 */
function buildSetCookie(name, value, options) {
  let cookie = `${name}=${value}; Path=${options.path ?? "/"}`;

  if (options.httpOnly !== false) {
    cookie += "; HttpOnly";
  }
  if (options.secure) {
    cookie += "; Secure";
  }
  if (options.sameSite) {
    cookie += `; SameSite=${options.sameSite}`;
  }
  if (typeof options.maxAge === "number") {
    cookie += `; Max-Age=${options.maxAge}`;
  }

  return cookie;
}

/**
 * Extract a cookie value by name from the Cookie header.
 *
 * @param {string|undefined} cookieHeader
 * @param {string} name
 * @returns {string|undefined}
 */
function parseCookieValue(cookieHeader, name) {
  if (!cookieHeader) return undefined;

  const prefix = `${name}=`;
  const cookies = cookieHeader.split(";");

  for (let i = 0; i < cookies.length; i++) {
    const trimmed = cookies[i].trim();
    if (trimmed.startsWith(prefix)) {
      return trimmed.slice(prefix.length);
    }
  }

  return undefined;
}

// ─── Middleware Factory ───────────────────

/**
 * Create a CSRF protection middleware.
 *
 * @param {Object} [options]
 * @param {Object} [options.cookie]            - Cookie options
 * @param {string} [options.cookie.name="_csrf"] - Cookie name
 * @param {boolean} [options.cookie.httpOnly=true]
 * @param {string} [options.cookie.sameSite="strict"]
 * @param {boolean} [options.cookie.secure=false]
 * @param {string} [options.cookie.path="/"]
 * @param {number} [options.cookie.maxAge]
 * @param {string[]} [options.ignoreMethods]   - Methods to skip (default: GET, HEAD, OPTIONS)
 * @param {string} [options.tokenHeader]       - Header to read token from (default: x-csrf-token)
 * @param {string} [options.tokenField]        - Body field to read token from (default: _csrf)
 * @returns {Function} Middleware function
 */
export function csrf(options = {}) {
  if (typeof options !== "object" || options === null) {
    throw new TypeError("csrf(options) expects an object");
  }

  const cookieOpts = {
    name: "_csrf",
    httpOnly: true,
    sameSite: "strict",
    secure: false,
    path: "/",
    ...options.cookie,
  };

  const ignoreMethods = options.ignoreMethods
    ? new Set(options.ignoreMethods.map((m) => m.toUpperCase()))
    : SAFE_METHODS;

  const tokenHeader = (options.tokenHeader ?? "x-csrf-token").toLowerCase();
  const tokenField = options.tokenField ?? "_csrf";

  return async function csrfMiddleware(req, res, next) {
    const cookieHeader = req.header("cookie");
    let cookieToken = parseCookieValue(cookieHeader, cookieOpts.name);

    /* Ensure a CSRF cookie is always set — new visitors get a token on
     * their first request (even safe methods) so forms can include it. */
    if (!cookieToken) {
      cookieToken = generateToken();
      res.set(
        "set-cookie",
        buildSetCookie(cookieOpts.name, cookieToken, cookieOpts),
      );
    }

    /* Expose token on req so templates/handlers can embed it in forms */
    req.csrfToken = cookieToken;

    /* Safe methods pass through — only state-changing requests need validation */
    if (ignoreMethods.has(req.method)) {
      return next();
    }

    /* Validate: token must match in header or body field */
    const headerToken = req.header(tokenHeader);

    /* Extract body token: req.body is a Buffer, so parse JSON first.
     * Only attempt JSON parse for content-types that could carry form data. */
    let bodyToken;
    if (req.body && Buffer.isBuffer(req.body) && req.body.length > 0) {
      try {
        const parsed = JSON.parse(req.body.toString("utf8"));
        if (parsed && typeof parsed === "object") {
          bodyToken = parsed[tokenField];
        }
      } catch {
        /* Not JSON — ignore body token */
      }
    }

    /* Constant-time comparison to prevent timing side-channel attacks */
    if (safeTokenEquals(headerToken, cookieToken) || safeTokenEquals(bodyToken, cookieToken)) {
      return next();
    }

    return res.status(403).json({
      error: "Forbidden",
      code: "CSRF_TOKEN_MISMATCH",
      message: "CSRF token validation failed",
    });
  };
}

/**
 * Constant-time string comparison to prevent timing side-channel attacks.
 * Returns false if either value is not a string or lengths differ.
 */
function safeTokenEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}
