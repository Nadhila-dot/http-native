/**
 * http-native audit logging middleware
 *
 * Emits structured security-relevant events for compliance (SOC2, PCI-DSS).
 * Events are sent to a configurable sink — file, stream, or custom function.
 *
 * Usage:
 *   import { auditLog } from "@http-native/core/audit-log";
 *   app.use(auditLog({ sink: (event) => console.log(JSON.stringify(event)) }));
 */

/**
 * @param {Object} options
 * @param {Function} options.sink                 - Receives each audit event object
 * @param {string[]} [options.events]             - Event types to capture (default: all)
 * @param {boolean}  [options.includeHeaders]     - Include request headers (default: false)
 * @param {string[]} [options.redactHeaders]      - Header names to redact from logs
 * @param {boolean}  [options.includeBody]        - Include request body (default: false)
 */
export function auditLog(options = {}) {
  if (typeof options.sink !== "function") {
    throw new Error("auditLog requires a sink function");
  }

  const sink = options.sink;
  const allowedEvents = options.events ? new Set(options.events) : null;
  const includeHeaders = options.includeHeaders ?? false;
  const includeBody = options.includeBody ?? false;
  const redactSet = options.redactHeaders
    ? new Set(options.redactHeaders.map((h) => h.toLowerCase()))
    : new Set(["authorization", "cookie", "set-cookie"]);

  function emit(event) {
    if (allowedEvents && !allowedEvents.has(event.type)) return;
    event.timestamp = new Date().toISOString();
    try {
      sink(event);
    } catch {
      /* Audit sink failure must not crash the request */
    }
  }

  return async function auditLogMiddleware(req, res, next) {
    const start = performance.now();

    /* Capture request metadata */
    const event = {
      type: "http.request",
      method: req.method,
      path: req.path,
      ip: req.ip,
      requestId: req.id ?? undefined,
      userId: undefined,
      statusCode: undefined,
      durationMs: undefined,
    };

    if (includeHeaders) {
      const headers = { ...req.headers };
      for (const name of redactSet) {
        if (headers[name]) headers[name] = "[REDACTED]";
      }
      event.headers = headers;
    }

    if (includeBody && req.body != null) {
      event.body =
        typeof req.body === "string" ? req.body : JSON.stringify(req.body);
    }

    try {
      await next();
    } catch (err) {
      event.type = "http.error";
      event.error = err.message ?? String(err);
      event.statusCode = err.status ?? 500;
      event.durationMs = Math.round((performance.now() - start) * 100) / 100;
      emit(event);
      throw err;
    }

    event.statusCode = res._state?.status ?? 200;
    event.durationMs = Math.round((performance.now() - start) * 100) / 100;
    event.userId = req.userId ?? req.session?.userId ?? undefined;
    emit(event);
  };
}

/**
 * Create pre-defined audit event emitters for use outside middleware.
 *
 * @param {Function} sink - The same sink passed to auditLog()
 */
export function createAuditEmitter(sink) {
  return {
    emit(type, data = {}) {
      sink({ type, timestamp: new Date().toISOString(), ...data });
    },
    authLogin: (userId, ip) =>
      sink({
        type: "auth.login",
        userId,
        ip,
        timestamp: new Date().toISOString(),
      }),
    authLogout: (userId, ip) =>
      sink({
        type: "auth.logout",
        userId,
        ip,
        timestamp: new Date().toISOString(),
      }),
    authFailed: (reason, ip) =>
      sink({
        type: "auth.failed",
        reason,
        ip,
        timestamp: new Date().toISOString(),
      }),
    rateLimitExceeded: (ip, path) =>
      sink({
        type: "rate_limit.exceeded",
        ip,
        path,
        timestamp: new Date().toISOString(),
      }),
  };
}
