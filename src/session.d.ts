import type { Middleware, Session } from "./index.js";

// ─── Session Store Interface ───────────

/**
 * Pluggable session store contract. Implementations must provide
 * get/set/delete/destroy/getAll operations. Operations may be sync
 * (MemoryStore) or async (RedisStore, custom stores).
 */
export interface SessionStore {
  /** Retrieve a single session value by key */
  get(sessionId: string, key: string): unknown | Promise<unknown>;

  /** Set a single session value */
  set(sessionId: string, key: string, value: unknown): void | Promise<void>;

  /** Delete a single session key */
  delete(sessionId: string, key: string): void | Promise<void>;

  /** Destroy the entire session (all keys) */
  destroy(sessionId: string): void | Promise<void>;

  /** Retrieve all session data as a key-value record */
  getAll(sessionId: string): Record<string, unknown> | null | Promise<Record<string, unknown> | null>;

  /** Replace all session data (optional — used for bulk session restoration) */
  setAll?(sessionId: string, data: Record<string, unknown>): void | Promise<void>;
}

// ─── Built-in Stores ───────────────────

/**
 * In-memory session store backed by Rust's native sharded RwLock.
 * All operations are synchronous (direct NAPI calls into the Rust layer).
 */
export class MemoryStore implements SessionStore {
  constructor();
  get(sessionId: string, key: string): unknown;
  set(sessionId: string, key: string, value: unknown): void;
  delete(sessionId: string, key: string): void;
  destroy(sessionId: string): void;
  getAll(sessionId: string): Record<string, unknown> | null;
  setAll(sessionId: string, data: Record<string, unknown>): void;
}

export interface RedisStoreOptions {
  /** Key prefix for session hashes (default "sess:") */
  prefix?: string;
  /** TTL in seconds (default: from session config maxAge) */
  maxAge?: number;
}

/**
 * Redis session store. Requires an ioredis-compatible client.
 * All operations are async (Redis round-trips).
 */
export class RedisStore implements SessionStore {
  constructor(client: unknown, options?: RedisStoreOptions);
  get(sessionId: string, key: string): Promise<unknown>;
  set(sessionId: string, key: string, value: unknown): Promise<void>;
  delete(sessionId: string, key: string): Promise<void>;
  destroy(sessionId: string): Promise<void>;
  getAll(sessionId: string): Promise<Record<string, unknown> | null>;
  setAll(sessionId: string, data: Record<string, unknown>): Promise<void>;
}

// ─── Session Middleware ─────────────────

export interface SessionMiddlewareOptions {
  /** HMAC signing secret (required) */
  secret: string;

  /** Session TTL in seconds (default 3600) */
  maxAge?: number;

  /** Cookie name (default "sid") */
  cookieName?: string;

  /** HttpOnly flag (default true) */
  httpOnly?: boolean;

  /** Secure flag (default false) */
  secure?: boolean;

  /** SameSite policy (default "lax") */
  sameSite?: "strict" | "lax" | "none";

  /** Cookie path (default "/") */
  path?: string;

  /** Pluggable session store (default: MemoryStore — Rust-backed) */
  store?: SessionStore;

  /** Maximum sessions per shard before LRU eviction (default 100_000) */
  maxSessions?: number;

  /** Maximum serialized data size per session in bytes (default 4096) */
  maxDataSize?: number;
}

/**
 * Create a session middleware.
 *
 * Default store: Rust in-memory (sharded RwLock, cross-worker safe).
 * Pluggable: pass any store with get/set/delete/destroy/getAll methods.
 *
 * @example
 * // In-memory (default, Rust-backed)
 * app.use(session({ secret: "my-key" }));
 *
 * @example
 * // Redis
 * import Redis from "ioredis";
 * app.use(session({ secret: "my-key", store: new RedisStore(new Redis()) }));
 */
export function session(options: SessionMiddlewareOptions): Middleware;
