/**
 * http-native structured logging middleware (DX-2.1)
 *
 * Emits structured JSON logs for every request/response cycle.
 * Compatible with pino, winston, or any logger with info/warn/error methods.
 *
 * Usage:
 *   import { logger } from "@http-native/core/logger";
 *   app.use(logger());
 *   app.use(logger({ level: "debug", format: "pretty", redact: ["req.headers.authorization"] }));
 */

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };

/**
 * @param {Object} [options]
 * @param {"debug"|"info"|"warn"|"error"|"silent"} [options.level="info"]
 * @param {"json"|"pretty"} [options.format="json"]
 * @param {string[]} [options.redact] - Dot-paths to redact (e.g. "req.headers.authorization")
 * @param {(entry: Object) => void} [options.sink] - Custom output function (default: stderr)
 * @param {boolean} [options.timestamp=true]
 * @param {(req: Object) => Object} [options.customProps] - Extra fields to include per request
 */
export function logger(options = {}) {
  const {
    level = "info",
    format = "json",
    redact = [],
    sink,
    timestamp = true,
    customProps,
  } = options;

  const minLevel = LEVELS[level] ?? LEVELS.info;
  const redactSet = new Set(redact);
  const write = sink ?? ((entry) => process.stderr.write(formatEntry(entry, format) + "\n"));

  return async function loggerMiddleware(req, res, next) {
    const start = performance.now();
    const reqId = req.id; // from requestId middleware, if present

    try {
      await next();
    } finally {
      const duration = performance.now() - start;
      const status = res._state?.status ?? 200;
      const entryLevel = status >= 500 ? "error" : status >= 400 ? "warn" : "info";

      if (LEVELS[entryLevel] >= minLevel) {
        const entry = {
          level: entryLevel,
          method: req.method,
          path: req.path,
          status,
          duration_ms: Math.round(duration * 100) / 100,
        };

        if (timestamp) entry.time = Date.now();
        if (reqId) entry.requestId = reqId;
        if (customProps) Object.assign(entry, customProps(req));

        /* Apply redaction before output */
        applyRedaction(entry, req, res, redactSet);

        write(entry);
      }
    }
  };
}

/**
 * Create a standalone logger instance for use outside middleware.
 *
 * @param {Object} [options]
 * @param {"debug"|"info"|"warn"|"error"|"silent"} [options.level="info"]
 * @param {"json"|"pretty"} [options.format="json"]
 * @param {(entry: Object) => void} [options.sink]
 */
export function createLogger(options = {}) {
  const {
    level = "info",
    format = "json",
    sink,
  } = options;

  const minLevel = LEVELS[level] ?? LEVELS.info;
  const write = sink ?? ((entry) => process.stderr.write(formatEntry(entry, format) + "\n"));

  function emit(entryLevel, msg, fields = {}) {
    if (LEVELS[entryLevel] < minLevel) return;
    const entry = { level: entryLevel, msg, time: Date.now(), ...fields };
    write(entry);
  }

  return {
    debug: (msg, fields) => emit("debug", msg, fields),
    info: (msg, fields) => emit("info", msg, fields),
    warn: (msg, fields) => emit("warn", msg, fields),
    error: (msg, fields) => emit("error", msg, fields),
    child(defaults) {
      return createLogger({
        level,
        format,
        sink: (entry) => write({ ...defaults, ...entry }),
      });
    },
  };
}

function formatEntry(entry, format) {
  if (format === "pretty") {
    const ts = entry.time ? new Date(entry.time).toISOString() : "";
    const lvl = (entry.level ?? "info").toUpperCase().padEnd(5);
    const dur = entry.duration_ms != null ? ` ${entry.duration_ms}ms` : "";
    const id = entry.requestId ? ` [${entry.requestId}]` : "";
    const msg = entry.msg ?? `${entry.method} ${entry.path} ${entry.status}`;
    return `${ts} ${lvl}${id} ${msg}${dur}`;
  }
  return JSON.stringify(entry);
}

/**
 * Redact specific fields from the log entry.
 * Dot-paths like "req.headers.authorization" are resolved and replaced with "[REDACTED]".
 */
function applyRedaction(entry, req, res, redactSet) {
  for (const path of redactSet) {
    const parts = path.split(".");
    const root = parts[0];
    if (root === "req" && parts.length >= 2) {
      /* Walk nested path in entry: "req.headers.authorization" → entry.headers.authorization */
      const keys = parts.slice(1);
      let target = entry;
      for (let i = 0; i < keys.length - 1; i++) {
        target = target?.[keys[i]];
        if (!target || typeof target !== "object") break;
      }
      if (target && typeof target === "object") {
        const leafKey = keys[keys.length - 1];
        if (target[leafKey] !== undefined) {
          target[leafKey] = "[REDACTED]";
        }
      }
    }
  }
}
