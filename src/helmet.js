/**
 * http-native security headers middleware (helmet).
 *
 * Sets sensible default security headers on every response. Each header
 * is individually configurable or can be disabled by setting it to `false`.
 * Header values are pre-computed at middleware creation time — per-request
 * cost is the minimum: a flat loop of `res.set()` calls.
 *
 * Usage:
 *   import { helmet } from "@http-native/core/helmet";
 *
 *   // Sane defaults
 *   app.use(helmet());
 *
 *   // Customize
 *   app.use(helmet({
 *     hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
 *     contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "cdn.example.com"] } },
 *     xFrameOptions: "SAMEORIGIN",
 *     permissionsPolicy: { camera: [], microphone: [], geolocation: ["self"] },
 *   }));
 *
 *   // Disable a specific header
 *   app.use(helmet({ xFrameOptions: false }));
 */

// ─── Default Values ────────────────────

const DEFAULT_HSTS_MAX_AGE = 31536000; // 1 year

// ─── Header Builders ───────────────────

/**
 * Build HSTS header value from options.
 *
 * @param {Object|boolean} hsts
 * @returns {string|null}
 */
function buildHsts(hsts) {
  if (hsts === false) return null;

  const config = typeof hsts === "object" && hsts !== null ? hsts : {};
  const maxAge = Number(config.maxAge ?? DEFAULT_HSTS_MAX_AGE);
  if (!Number.isFinite(maxAge) || maxAge < 0) {
    throw new TypeError("helmet hsts.maxAge must be a non-negative number");
  }

  let value = `max-age=${Math.floor(maxAge)}`;
  if (config.includeSubDomains !== false) {
    value += "; includeSubDomains";
  }
  if (config.preload === true) {
    value += "; preload";
  }
  return value;
}

/**
 * Build CSP header value from directives.
 *
 * @param {Object|boolean} csp
 * @returns {string|null}
 */
function buildContentSecurityPolicy(csp) {
  if (csp === false || csp === undefined || csp === null) return null;
  if (csp === true) return "default-src 'self'";

  const directives = csp.directives ?? csp;
  if (typeof directives !== "object" || directives === null) {
    throw new TypeError("helmet contentSecurityPolicy.directives must be an object");
  }

  const parts = [];
  for (const [key, sources] of Object.entries(directives)) {
    /* camelCase → kebab-case: defaultSrc → default-src */
    const directive = key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
    const value = Array.isArray(sources) ? sources.join(" ") : String(sources);
    parts.push(`${directive} ${value}`);
  }

  return parts.join("; ");
}

/**
 * Build Permissions-Policy header value.
 *
 * @param {Object|boolean} policy
 * @returns {string|null}
 */
function buildPermissionsPolicy(policy) {
  if (policy === false || policy === undefined || policy === null) return null;
  if (policy === true) {
    return "camera=(), microphone=(), geolocation=()";
  }

  if (typeof policy !== "object") {
    throw new TypeError("helmet permissionsPolicy must be an object");
  }

  const parts = [];
  for (const [feature, allowlist] of Object.entries(policy)) {
    const directive = feature.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
    if (Array.isArray(allowlist)) {
      parts.push(`${directive}=(${allowlist.join(" ")})`);
    } else {
      parts.push(`${directive}=${String(allowlist)}`);
    }
  }

  return parts.join(", ");
}

/**
 * Build the full list of [name, value] header pairs from options.
 *
 * @param {Object} options
 * @returns {Array<[string, string]>}
 */
function buildHeaderMap(options) {
  const headers = [];

  /* X-Content-Type-Options: prevents MIME-type sniffing */
  if (options.xContentTypeOptions !== false) {
    headers.push(["x-content-type-options", "nosniff"]);
  }

  /* X-Frame-Options: clickjacking protection */
  if (options.xFrameOptions !== false) {
    const value = typeof options.xFrameOptions === "string"
      ? options.xFrameOptions.toUpperCase()
      : "DENY";
    headers.push(["x-frame-options", value]);
  }

  /* X-XSS-Protection: modern best practice is to disable it (CSP replaces it) */
  if (options.xXssProtection !== false) {
    headers.push(["x-xss-protection", "0"]);
  }

  /* Referrer-Policy */
  if (options.referrerPolicy !== false) {
    const value = typeof options.referrerPolicy === "string"
      ? options.referrerPolicy
      : "strict-origin-when-cross-origin";
    headers.push(["referrer-policy", value]);
  }

  /* Strict-Transport-Security */
  const hstsValue = buildHsts(options.hsts);
  if (hstsValue !== null) {
    headers.push(["strict-transport-security", hstsValue]);
  }

  /* Content-Security-Policy */
  const cspValue = buildContentSecurityPolicy(options.contentSecurityPolicy);
  if (cspValue !== null) {
    headers.push(["content-security-policy", cspValue]);
  }

  /* Cross-Origin-Opener-Policy */
  if (options.crossOriginOpenerPolicy !== false) {
    const value = typeof options.crossOriginOpenerPolicy === "string"
      ? options.crossOriginOpenerPolicy
      : "same-origin";
    headers.push(["cross-origin-opener-policy", value]);
  }

  /* Cross-Origin-Resource-Policy */
  if (options.crossOriginResourcePolicy !== false) {
    const value = typeof options.crossOriginResourcePolicy === "string"
      ? options.crossOriginResourcePolicy
      : "same-origin";
    headers.push(["cross-origin-resource-policy", value]);
  }

  /* Permissions-Policy */
  const ppValue = buildPermissionsPolicy(options.permissionsPolicy);
  if (ppValue !== null) {
    headers.push(["permissions-policy", ppValue]);
  }

  /* X-DNS-Prefetch-Control */
  if (options.xDnsPrefetchControl !== false) {
    const value = options.xDnsPrefetchControl === "on" ? "on" : "off";
    headers.push(["x-dns-prefetch-control", value]);
  }

  /* X-Permitted-Cross-Domain-Policies */
  if (options.xPermittedCrossDomainPolicies !== false) {
    const value = typeof options.xPermittedCrossDomainPolicies === "string"
      ? options.xPermittedCrossDomainPolicies
      : "none";
    headers.push(["x-permitted-cross-domain-policies", value]);
  }

  return headers;
}

// ─── Middleware Factory ────────────────

/**
 * Create a security headers middleware.
 *
 * @param {Object} [options] - Per-header configuration; set any to `false` to disable
 * @returns {Function} Middleware function
 */
export function helmet(options = {}) {
  if (typeof options !== "object" || options === null) {
    throw new TypeError("helmet(options) expects an object");
  }

  /* Pre-compute all header pairs at startup — zero allocation per request */
  const headers = buildHeaderMap(options);

  return async function helmetMiddleware(req, res, next) {
    for (let i = 0; i < headers.length; i++) {
      res.set(headers[i][0], headers[i][1]);
    }
    await next();
  };
}
