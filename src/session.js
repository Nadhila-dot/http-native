/**
 * http-native session middleware.
 *
 * Default store: Rust in-memory (sharded RwLock, cross-worker safe).
 * Pluggable: pass any store with get/set/delete/destroy/getAll methods.
 *
 * Usage:
 *   import { session, MemoryStore, RedisStore } from "http-native/session";
 *
 *   // In-memory (default, Rust-backed)
 *   app.use(session({ secret: "my-key" }));
 *
 *   // Redis
 *   import Redis from "ioredis";
 *   app.use(session({ secret: "my-key", store: new RedisStore(new Redis()) }));
 *
 *   // Custom store
 *   app.use(session({ secret: "my-key", store: myCustomStore }));
 */

import { Buffer } from "node:buffer";
import { loadNativeModule } from "./native.js";

const SESSION_DEFAULTS = {
  secret: "",
  maxAge: 3600,
  cookieName: "sid",
  httpOnly: true,
  secure: false,
  sameSite: "lax",
  path: "/",
  maxSessions: 100_000,
  maxDataSize: 4096,
};

// ─── Store Interface ──────────────────────

/**
 * In-memory session store backed by Rust's native sharded RwLock.
 * All operations are synchronous (direct NAPI calls into Rust).
 */
export class MemoryStore {
  #native;

  constructor() {
    this.#native = loadNativeModule();
  }

  get(sessionId, key) {
    const raw = this.#native.sessionGet(sessionId, key);
    if (raw === null || raw === undefined) return undefined;
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }

  set(sessionId, key, value) {
    this.#native.sessionSet(sessionId, key, JSON.stringify(value));
  }

  delete(sessionId, key) {
    this.#native.sessionDelete(sessionId, key);
  }

  destroy(sessionId) {
    this.#native.sessionDestroy(sessionId);
  }

  getAll(sessionId) {
    const raw = this.#native.sessionGetAll(sessionId);
    if (raw === null || raw === undefined) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  setAll(sessionId, data) {
    this.#native.sessionSetAll(sessionId, JSON.stringify(data));
  }
}

/**
 * Redis session store. Requires an ioredis (or compatible) client.
 *
 * Usage:
 *   import Redis from "ioredis";
 *   const store = new RedisStore(new Redis());
 */
export class RedisStore {
  #client;
  #prefix;
  #maxAge;

  /**
   * @param {import("ioredis").Redis} client - ioredis client instance
   * @param {Object} [options]
   * @param {string} [options.prefix] - Key prefix (default "sess:")
   * @param {number} [options.maxAge] - TTL in seconds (default from session config)
   */
  constructor(client, options = {}) {
    if (!client) throw new TypeError("RedisStore requires a Redis client");
    this.#client = client;
    this.#prefix = options.prefix || "sess:";
    this.#maxAge = options.maxAge || 3600;
  }

  _key(sessionId) {
    return `${this.#prefix}${sessionId}`;
  }

  async get(sessionId, key) {
    const raw = await this.#client.hget(this._key(sessionId), key);
    if (raw === null) return undefined;
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }

  async set(sessionId, key, value) {
    const k = this._key(sessionId);
    await this.#client.hset(k, key, JSON.stringify(value));
    await this.#client.expire(k, this.#maxAge);
  }

  async delete(sessionId, key) {
    await this.#client.hdel(this._key(sessionId), key);
  }

  async destroy(sessionId) {
    await this.#client.del(this._key(sessionId));
  }

  async getAll(sessionId) {
    const data = await this.#client.hgetall(this._key(sessionId));
    if (!data || Object.keys(data).length === 0) return null;
    const result = Object.create(null);
    for (const [key, raw] of Object.entries(data)) {
      try {
        result[key] = JSON.parse(raw);
      } catch {
        result[key] = raw;
      }
    }
    return result;
  }

  async setAll(sessionId, data) {
    const k = this._key(sessionId);
    const flat = [];
    for (const [key, value] of Object.entries(data)) {
      flat.push(key, JSON.stringify(value));
    }
    if (flat.length > 0) {
      await this.#client.hset(k, ...flat);
      await this.#client.expire(k, this.#maxAge);
    }
  }
}

// ─── Session Middleware ───────────────────

/**
 * Create a session middleware.
 *
 * @param {Object} options
 * @param {string} options.secret       - HMAC signing secret (required)
 * @param {number} [options.maxAge]     - Session TTL in seconds (default 3600)
 * @param {string} [options.cookieName] - Cookie name (default "sid")
 * @param {boolean} [options.httpOnly]  - HttpOnly flag (default true)
 * @param {boolean} [options.secure]    - Secure flag (default false)
 * @param {string} [options.sameSite]   - SameSite policy (default "lax")
 * @param {string} [options.path]       - Cookie path (default "/")
 * @param {Object} [options.store]      - Session store (default: MemoryStore)
 * @returns {Function} Middleware function
 */
export function session(options = {}) {
  if (!options.secret || typeof options.secret !== "string") {
    throw new TypeError("session({ secret }) is required and must be a non-empty string");
  }

  const config = { ...SESSION_DEFAULTS, ...options };
  const store = config.store || new MemoryStore();
  const native = loadNativeModule();
  const isAsync = !(store instanceof MemoryStore);

  /**
   * Session middleware.
   */
  const sessionMiddleware = isAsync
    ? async function sessionMiddlewareAsync(req, res, next) {
        const sessionId = resolveSessionId(req, res, config, native);
        attachSession(req, res, sessionId, store, config);
        await next();
        await flushSession(req, res, config);
      }
    : function sessionMiddlewareSync(req, res, next) {
        const sessionId = resolveSessionId(req, res, config, native);
        attachSession(req, res, sessionId, store, config);
        return next();
      };

  // Attach config for manifest serialization
  sessionMiddleware._sessionConfig = config;
  return sessionMiddleware;
}

/**
 * Resolve the session ID from cookies or create a new one.
 */
function resolveSessionId(req, res, config, native) {
  const cookieHeader = req.header?.("cookie") || req.headers?.cookie || "";
  const cookieName = config.cookieName;

  // Extract cookie value
  let cookieValue = null;
  for (const part of cookieHeader.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(`${cookieName}=`)) {
      cookieValue = trimmed.slice(cookieName.length + 1).trim().replace(/^"|"$/g, "");
      break;
    }
  }

  if (cookieValue) {
    // Verify the signed cookie via Rust
    const verifiedId = native.sessionVerifyCookie(cookieValue);
    if (verifiedId) {
      res._sessionId = verifiedId;
      res._sessionIsNew = false;
      return verifiedId;
    }
  }

  // Generate new session via Rust
  const newCookie = native.sessionNewCookie();
  if (newCookie) {
    const dotIndex = newCookie.indexOf(".");
    const newId = dotIndex >= 0 ? newCookie.slice(0, dotIndex) : newCookie;
    res._sessionId = newId;
    res._sessionIsNew = true;
    res._sessionCookie = newCookie;
    return newId;
  }

  return null;
}

/**
 * Attach the session proxy to req.session.
 */
function attachSession(req, res, sessionId, store, config) {
  let destroyed = false;
  let dirty = false;
  const pendingAsync = [];

  req.sessionId = sessionId;

  req.session = {
    get(key) {
      if (destroyed || !sessionId) return undefined;
      return store.get(sessionId, key);
    },

    set(key, value) {
      if (destroyed || !sessionId) return;
      dirty = true;
      const result = store.set(sessionId, key, value);
      if (result && typeof result.then === "function") {
        pendingAsync.push(result);
      }
    },

    delete(key) {
      if (destroyed || !sessionId) return;
      dirty = true;
      const result = store.delete(sessionId, key);
      if (result && typeof result.then === "function") {
        pendingAsync.push(result);
      }
    },

    has(key) {
      if (destroyed || !sessionId) return false;
      const val = store.get(sessionId, key);
      // Handle async stores
      if (val && typeof val.then === "function") {
        return val.then((v) => v !== undefined);
      }
      return val !== undefined;
    },

    destroy() {
      if (!sessionId) return;
      destroyed = true;
      dirty = true;
      const result = store.destroy(sessionId);
      if (result && typeof result.then === "function") {
        pendingAsync.push(result);
      }
    },

    get isDestroyed() {
      return destroyed;
    },
  };

  // Store references for flush
  res._sessionState = { dirty: () => dirty, destroyed: () => destroyed, pendingAsync };
}

/**
 * Flush async session operations and set cookies (for async stores).
 */
async function flushSession(req, res, config) {
  const state = res._sessionState;
  if (!state) return;

  // Wait for any pending async operations
  if (state.pendingAsync.length > 0) {
    await Promise.all(state.pendingAsync);
  }

  // Set-Cookie injection is handled by Rust for MemoryStore.
  // For async stores, we need to set it from JS.
  if (res._sessionIsNew && state.dirty() && !state.destroyed()) {
    const cookie = buildSetCookie(res._sessionCookie, config);
    res.set("set-cookie", cookie);
  } else if (state.destroyed()) {
    const cookie = buildDestroyCookie(config);
    res.set("set-cookie", cookie);
  }
}

function buildSetCookie(cookieValue, config) {
  let cookie = `${config.cookieName}=${cookieValue}; Path=${config.path}; Max-Age=${config.maxAge}`;
  if (config.httpOnly) cookie += "; HttpOnly";
  if (config.secure) cookie += "; Secure";
  cookie += `; SameSite=${capitalize(config.sameSite)}`;
  return cookie;
}

function buildDestroyCookie(config) {
  let cookie = `${config.cookieName}=; Path=${config.path}; Max-Age=0`;
  if (config.httpOnly) cookie += "; HttpOnly";
  if (config.secure) cookie += "; Secure";
  cookie += `; SameSite=${capitalize(config.sameSite)}`;
  return cookie;
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

// ─── Session Trailer (for backward compat) ──

/**
 * Encode session write trailer. Returns null since session ops now go
 * directly through NAPI — no trailer needed for MemoryStore.
 * Kept for API compatibility.
 */
export function encodeSessionTrailer(sessionState) {
  return null;
}
