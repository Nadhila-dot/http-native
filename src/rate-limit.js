import { randomUUID } from "node:crypto";

import { loadNativeModule } from "./native.js";

const DEFAULT_HEADERS = Object.freeze({
  limit: "x-ratelimit-limit",
  remaining: "x-ratelimit-remaining",
  reset: "x-ratelimit-reset",
  retryAfter: "retry-after",
});

function ensurePositiveInteger(name, value) {
  const normalized = Number(value);
  if (!Number.isFinite(normalized) || !Number.isInteger(normalized) || normalized <= 0) {
    throw new TypeError(`rateLimit ${name} must be a positive integer`);
  }
  return normalized;
}

function resolveValue(input, req, res, label) {
  if (typeof input === "function") {
    return input(req, res);
  }
  if (input === undefined) {
    throw new TypeError(`rateLimit ${label} is required`);
  }
  return input;
}

function normalizeNamespace(value) {
  if (value === undefined || value === null || value === "") {
    return `rate-limit:${randomUUID()}`;
  }
  const normalized = String(value).trim();
  if (!normalized) {
    throw new TypeError("rateLimit namespace must be a non-empty string when provided");
  }
  return normalized;
}

function getHeader(req, name) {
  if (!req) {
    return undefined;
  }
  if (typeof req.header === "function") {
    const fromMethod = req.header(name);
    if (fromMethod !== undefined && fromMethod !== null && fromMethod !== "") {
      return String(fromMethod);
    }
  }
  const fromHeaders = req.headers?.[name.toLowerCase()];
  if (fromHeaders !== undefined && fromHeaders !== null && fromHeaders !== "") {
    return String(fromHeaders);
  }
  return undefined;
}

function parseForwardedFor(value) {
  if (!value) {
    return "";
  }
  const first = String(value)
    .split(",")
    .map((part) => part.trim())
    .find(Boolean);
  return first ?? "";
}

function defaultRequestKey(req) {
  /* Use the peer IP from the native connection — this cannot be spoofed.
   * Only fall back to proxy headers if req.ip is unavailable (e.g., tests).
   * Users behind a reverse proxy should provide a custom `key` function
   * that extracts the real IP from trusted proxy headers. */
  if (typeof req?.ip === "string" && req.ip.trim() !== "") {
    return req.ip.trim();
  }

  return "unknown";
}

function normalizeHeaders(headers) {
  if (headers === false) {
    return null;
  }

  if (headers === true || headers === undefined || headers === null) {
    return DEFAULT_HEADERS;
  }

  if (typeof headers !== "object") {
    throw new TypeError("rateLimit headers must be true, false, or an object");
  }

  return Object.freeze({
    limit: String(headers.limit ?? DEFAULT_HEADERS.limit),
    remaining: String(headers.remaining ?? DEFAULT_HEADERS.remaining),
    reset: String(headers.reset ?? DEFAULT_HEADERS.reset),
    retryAfter: String(headers.retryAfter ?? DEFAULT_HEADERS.retryAfter),
  });
}

function normalizeNativeDecision(raw) {
  if (!raw || typeof raw !== "object") {
    throw new Error("rateLimitCheck returned an invalid native response");
  }

  const resetAtMs = Number(raw.resetAtMs ?? raw.reset_at_ms ?? 0);
  const retryAfterSecs = Number(raw.retryAfterSecs ?? raw.retry_after_secs ?? 0);
  const nowMs = Number(raw.nowMs ?? raw.now_ms ?? Date.now());

  return {
    allowed: Boolean(raw.allowed),
    limit: Number(raw.limit ?? 0),
    remaining: Number(raw.remaining ?? 0),
    resetAtMs: Number.isFinite(resetAtMs) ? resetAtMs : 0,
    retryAfterSecs: Number.isFinite(retryAfterSecs) ? retryAfterSecs : 0,
    nowMs: Number.isFinite(nowMs) ? nowMs : Date.now(),
  };
}

export function createNativeRateLimiter(options = {}) {
  const native = loadNativeModule();
  const namespace = normalizeNamespace(options.namespace);
  const baseMax = options.max;
  const baseWindow = options.window;
  const baseCost = options.cost ?? 1;

  const check = (key, overrides = {}) => {
    if (key === undefined || key === null || key === "") {
      throw new TypeError("createNativeRateLimiter().check(key) requires a non-empty key");
    }

    const max = ensurePositiveInteger("max", overrides.max ?? baseMax);
    const window = ensurePositiveInteger("window", overrides.window ?? baseWindow);
    const cost = ensurePositiveInteger("cost", overrides.cost ?? baseCost);
    const normalizedKey = String(key).trim();

    if (!normalizedKey) {
      throw new TypeError("createNativeRateLimiter().check(key) requires a non-empty key");
    }

    const decision = native.rateLimitCheck(
      namespace,
      normalizedKey,
      max,
      window,
      cost,
    );

    return normalizeNativeDecision(decision);
  };

  const reset = (key) => {
    if (key === undefined || key === null) {
      return native.rateLimitReset(namespace, null);
    }
    return native.rateLimitReset(namespace, String(key));
  };

  return {
    namespace,
    check,
    reset,
    clear() {
      return native.rateLimitReset(namespace, null);
    },
  };
}

function normalizeRejectPayload(message, decision) {
  if (message === undefined) {
    return {
      error: "Too Many Requests",
      limit: decision.limit,
      remaining: decision.remaining,
      resetAtMs: decision.resetAtMs,
      retryAfterSecs: decision.retryAfterSecs,
    };
  }

  if (typeof message === "string") {
    return {
      error: message,
      limit: decision.limit,
      remaining: decision.remaining,
      resetAtMs: decision.resetAtMs,
      retryAfterSecs: decision.retryAfterSecs,
    };
  }

  if (message && typeof message === "object") {
    return {
      ...message,
      limit: decision.limit,
      remaining: decision.remaining,
      resetAtMs: decision.resetAtMs,
      retryAfterSecs: decision.retryAfterSecs,
    };
  }

  throw new TypeError("rateLimit message must be a string or object when provided");
}

export function rateLimit(options = {}) {
  if (typeof options !== "object" || options === null) {
    throw new TypeError("rateLimit(options) expects an object");
  }

  const keySelector = options.key ?? defaultRequestKey;
  if (typeof keySelector !== "function") {
    throw new TypeError("rateLimit key must be a function");
  }

  const shouldSkip = options.skip;
  if (shouldSkip !== undefined && typeof shouldSkip !== "function" && typeof shouldSkip !== "boolean") {
    throw new TypeError("rateLimit skip must be a boolean or function");
  }

  const onRejected = options.onRejected;
  if (onRejected !== undefined && typeof onRejected !== "function") {
    throw new TypeError("rateLimit onRejected must be a function when provided");
  }

  const statusCode = options.statusCode === undefined
    ? 429
    : ensurePositiveInteger("statusCode", options.statusCode);

  const headerNames = normalizeHeaders(options.headers);
  const limiter = createNativeRateLimiter({
    namespace: options.namespace,
  });

  return async function rateLimitMiddleware(req, res, next) {
    if (shouldSkip === true) {
      return next();
    }

    if (typeof shouldSkip === "function") {
      const skipped = await shouldSkip(req, res);
      if (skipped) {
        return next();
      }
    }

    const max = ensurePositiveInteger("max", await resolveValue(options.max, req, res, "max"));
    const window = ensurePositiveInteger(
      "window",
      await resolveValue(options.window, req, res, "window"),
    );
    const cost = ensurePositiveInteger("cost", await resolveValue(options.cost ?? 1, req, res, "cost"));
    const key = await keySelector(req, res);
    const decision = limiter.check(key, { max, window, cost });

    if (headerNames) {
      const resetEpochSeconds = Math.ceil(decision.resetAtMs / 1000);
      res.set(headerNames.limit, String(decision.limit));
      res.set(headerNames.remaining, String(decision.remaining));
      res.set(headerNames.reset, String(resetEpochSeconds));
    }

    if (decision.allowed) {
      return next();
    }

    if (headerNames?.retryAfter) {
      res.set(headerNames.retryAfter, String(decision.retryAfterSecs));
    }

    if (onRejected) {
      await onRejected(req, res, decision);
      return;
    }

    res.status(statusCode).json(normalizeRejectPayload(options.message, decision));
  };
}
