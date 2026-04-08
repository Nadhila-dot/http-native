import { Buffer } from "node:buffer";

// Types by rishi
// Just simple types for now, we can expand as needed. The main goal is to provide a good developer 
// experience with TypeScript and IDEs, 
// so we want to be careful about adding too much complexity here.

export interface Request {
  /** HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) */
  readonly method: string;

  /** Request ID (available when requestId middleware is used) */
  id?: string;

  /** CSRF token (available when csrf middleware is used) */
  csrfToken?: string;

  /** URL path without query string */
  readonly path: string;

  /** Full request URL including query string */
  readonly url: string;

  /** Client IP address from the native connection peer */
  readonly ip: string;

  /** Route parameters extracted from path segments (e.g., /users/:id → { id: "42" }) */
  readonly params: Record<string, string>;

  /** Parsed query string parameters. Multi-value params are arrays. */
  readonly query: Record<string, string | string[]>;

  /** Lowercase request headers as key-value pairs */
  readonly headers: Record<string, string>;

  /** Raw request body as a Buffer, or null if no body was sent */
  readonly body: Buffer | null;

  /** Get a specific header value by name (case-insensitive) */
  header(name: string): string | undefined;

  /** Parse the request body as JSON */
  json<T = unknown>(): T | null;

  /** Get the request body as a UTF-8 string */
  text(): string;

  /** Get the request body as an ArrayBuffer */
  arrayBuffer(): ArrayBuffer;

  /** Session object (available when session middleware is used) */
  session: Session;

  /** Current session ID (available when session middleware is used) */
  readonly sessionId?: string;

  /** Trace ID (available when otel middleware is used) */
  traceId?: string;

  /** Span ID (available when otel middleware is used) */
  spanId?: string;

  /** Parsed multipart fields (available when multipart middleware is used) */
  fields?: Record<string, string>;

  /** Parsed multipart files (available when multipart middleware is used) */
  files?: MultipartFile[];

  /** Validated request body (available when validate middleware is used) */
  validatedBody?: unknown;

  /** Validated query params (available when validate middleware is used) */
  validatedQuery?: unknown;

  /** Validated route params (available when validate middleware is used) */
  validatedParams?: unknown;

  /** Decorator values attached via app.decorate() */
  [key: string]: unknown;
}

export interface Session {
  /** Get a session value by key (sync for MemoryStore, async for RedisStore) */
  get<T = unknown>(key: string): T | undefined | Promise<T | undefined>;

  /** Set a session value */
  set(key: string, value: unknown): void;

  /** Delete a session key */
  delete(key: string): void;

  /** Check if a key exists (sync for MemoryStore, async for RedisStore) */
  has(key: string): boolean | Promise<boolean>;

  /** Destroy the entire session */
  destroy(): void;

  /** Whether the session has been destroyed */
  readonly isDestroyed: boolean;
}

export interface SessionOptions {
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
  /** Maximum concurrent sessions in Rust store (default 100000) */
  maxSessions?: number;
  /** Maximum session data size in bytes (default 4096) */
  maxDataSize?: number;
  /** Custom session store (default: MemoryStore backed by Rust) */
  store?: SessionStore;
}

export interface SessionStore {
  get(sessionId: string, key: string): unknown | Promise<unknown>;
  set(sessionId: string, key: string, value: unknown): void | Promise<void>;
  delete(sessionId: string, key: string): void | Promise<void>;
  destroy(sessionId: string): void | Promise<void>;
  getAll(sessionId: string): Record<string, unknown> | null | Promise<Record<string, unknown> | null>;
}

export interface Response {
  /** Whether the response has already been finalized */
  readonly finished: boolean;

  /** Per-request storage for passing data between middlewares */
  locals: Record<string, unknown>;

  /** Set the HTTP status code */
  status(code: number): Response;

  /** Set a response header */
  set(name: string, value: string): Response;

  /** Alias for set() */
  header(name: string, value: string): Response;

  /** Get a response header value */
  get(name: string): string | undefined;

  /** Set the Content-Type header */
  type(value: string): Response;

  /** Send a JSON response with proper Content-Type */
  json(data: unknown): Response;

  /** Send an HTML response, optionally injecting window.hnSSR.objects */
  html(html: string, options?: HtmlResponseOptions): Response;

  /** Send a response body (string, Buffer, or object) */
  send(data?: string | Buffer | Uint8Array | null): Response;

  /** Set status and send status code as text body */
  sendStatus(code: number): Response;

  /**
   * Send a JSON response and cache it in the Rust native layer.
   * Subsequent requests are served directly from Rust without crossing the JS bridge.
   *
   * @param data - JSON-serializable response data
   * @param ttl  - Cache TTL in seconds
   * @param options.maxEntries - Max LRU entries per route (default 256)
   */
  ncache(data: unknown, ttl: number, options?: { maxEntries?: number }): Response;

  /**
   * Redirect the client to a different URL.
   *
   * @param url - Target URL
   * @param status - HTTP redirect status code (default 302)
   */
  redirect(url: string, status?: number): Response;

  /**
   * Start a chunked streaming response. Returns a StreamWriter for writing
   * chunks incrementally, or null if the response is already finished.
   */
  stream(options?: { contentType?: string }): StreamWriter | null;
}

export interface StreamWriter {
  /** Write a chunk to the stream (string, Buffer, Uint8Array, or object → JSON) */
  write(data: string | Buffer | Uint8Array | object): boolean;

  /** End the stream, optionally writing a final chunk */
  end(finalChunk?: string | Buffer | Uint8Array | object): boolean;

  /** The internal stream ID */
  readonly id: number;
}

export type NextFunction = () => Promise<void>;

export type Middleware = (
  req: Request,
  res: Response,
  next: NextFunction,
) => void | Promise<void>;

export type RouteHandler = (
  req: Request,
  res: Response,
) => void | Promise<void>;

export type ErrorHandler = (
  error: Error,
  req: Request,
  res: Response,
) => void | Promise<void>;

// ─── Listen Options ─────────────────────

export interface TlsConfig {
  /** Path to PEM certificate file, or PEM string */
  cert: string;
  /** Path to PEM private key file, or PEM string */
  key: string;
  /** Path to CA bundle file, or PEM string (optional) */
  ca?: string;
  /** Passphrase for encrypted private key (optional) */
  passphrase?: string;
}

export interface HttpServerConfig {
  defaultHost?: string;
  defaultBacklog?: number;
  maxHeaderBytes?: number;
  /** TLS/SSL configuration — set to enable HTTPS */
  tls?: TlsConfig | null;
}

export interface RuntimeOptimizationOptions {
  /** Emit optimization and live-hit logs */
  notify?: boolean;
  /** Live notify interval in milliseconds (default: 1000) */
  notifyIntervalMs?: number;
  /** Collect per-route dispatch timing metrics */
  timing?: boolean;
  /** Enable runtime response cache promotion for deterministic routes */
  cache?: boolean;
  /** Restart the current runtime process on source changes (Node and Bun) */
  hotReload?: boolean;
  /** Override watched roots for runtime hot reload */
  hotReloadPaths?: string[];
  /** Debounce window for runtime hot reload triggers in ms */
  hotReloadDebounceMs?: number;
  /** Write dev comments above route declarations with optimization flags (default: true) */
  devComments?: boolean;
}

export interface ListenOptions {
  /** Host to bind to (default: "127.0.0.1") */
  host?: string;

  /** Port to bind to (default: 3000, use 0 for random) */
  port?: number;

  /** TCP listen backlog (default: 2048) */
  backlog?: number;

  /** Override server configuration */
  serverConfig?: HttpServerConfig;
}

export interface ReloadOptions {
  /** Files or directories to watch for reload */
  watch?: string[];
  /** Alias of watch for app-level reload configuration */
  files?: string[];
  /** Debounce window before a reload is applied */
  debounceMs?: number;
  /** Clear the console after successful reloads */
  clear?: boolean;
}

export interface HtmlResponseOptions {
  /** HTTP status code (default: 200) */
  status?: number;
  /** Extra response headers */
  headers?: Record<string, string>;
  /** Static SSR payload injected as window.hnSSR.objects */
  objects?: Record<string, unknown> | null;
}

export interface HotReloadOptions {
  /** Files or directories to watch for runtime process respawn */
  paths?: string[];
  /** Alias of paths for compatibility */
  hotReloadPaths?: string[];
  /** Debounce window before process respawn */
  debounceMs?: number;
  /** Alias of debounceMs for compatibility */
  hotReloadDebounceMs?: number;
}

// ─── Server Handle ──────────────────────

export interface ServerHandle {
  /** Bound hostname */
  readonly host: string;

  /** Bound port number */
  readonly port: number;

  /** Full URL (http(s)://host:port) */
  readonly url: string;

  /** Whether TLS is enabled */
  readonly tls: boolean;

  /** Runtime optimization introspection */
  readonly optimizations: {
    /** Get a snapshot of route optimization state */
    snapshot(): OptimizationSnapshot;
    /** Get a human-readable optimization summary */
    summary(): string;
  };

  /** Gracefully close the server */
  close(): Promise<void>;

  /**
   * Graceful shutdown — stop accepting new connections, drain in-flight
   * requests up to the timeout, then force-stop workers.
   */
  shutdown(options?: ShutdownOptions): Promise<ShutdownResult>;
}

export interface ListenHandle extends Promise<ServerHandle> {
  /** Override port before the server starts */
  port(value: number): ListenHandle;

  /**
   * Enable TLS/HTTPS with cert and key.
   * Accepts file paths or PEM strings.
   *
   * @example
   * await app.listen().port(443).tls({ cert: "./cert.pem", key: "./key.pem" })
   */
  tls(config: TlsConfig): ListenHandle;

  /** Enable runtime hot reload respawn for self-starting apps */
  hot(options?: boolean | HotReloadOptions): ListenHandle;

  /**
   * Enable HTTP/3 (QUIC) support. Requires TLS.
   * Binds a UDP listener on the same port as TCP.
   * Alt-Svc headers are automatically injected in HTTP/1.1 and HTTP/2 responses.
   */
  http3(options?: boolean | Http3Options): ListenHandle;
}

export interface Http3Options {
  /** Enable HTTP/3 (default: true) */
  enabled?: boolean;
  /** Max idle timeout in ms before closing QUIC connections (default: 30000) */
  maxIdleTimeout?: number;
}

export interface OptimizationSnapshot {
  routes: RouteOptimizationInfo[];
}

export interface RouteOptimizationInfo {
  method: string;
  path: string;
  staticFastPath: boolean;
  binaryBridge: boolean;
  bridgeObserved: boolean;
  cacheCandidate: boolean;
  hits: number;
  avgDurationMs?: number;
  lastDurationMs?: number;
  maxDurationMs?: number;
  recommendation?: string;
  dispatchKind?: string;
  jsonFastPath?: string;
}

// ─── App Configuration ─────────────────

export interface AppConfig {
  /** Server configuration (host, port, backlog, maxHeaderBytes) */
  server?: {
    /** Host to bind to (default: "127.0.0.1") */
    host?: string;
    /** Port to bind to (default: 3000, use 0 for random) */
    port?: number;
    /** TCP listen backlog (default: 2048) */
    backlog?: number;
    /** Maximum header block size in bytes */
    maxHeaderBytes?: number;
  };

  /** TLS/SSL configuration — set to enable HTTPS */
  tls?: TlsConfig | null;

  /** Development and optimization options */
  dev?: {
    /** Emit optimizer/logger output (default: true) */
    logger?: boolean;
    /** Restart process on source changes (dev only, default: false) */
    hotReload?: boolean;
    /** Watch roots for hot reload */
    hotReloadPaths?: string[];
    /** Debounce window for restart triggers in ms (default: 120) */
    hotReloadDebounceMs?: number;
    /** Write dev comments above route declarations (default: true) */
    devComments?: boolean;
    /** Alias for logger */
    notify?: boolean;
    /** Collect per-route dispatch timing metrics */
    timing?: boolean;
    /** Enable runtime response cache promotion */
    cache?: boolean;
  };
}

// ─── Application ────────────────────────

export interface RouteOptions {
  /** Native cache configuration for this route */
  cache?: {
    /** Cache TTL in seconds */
    ttl?: number;
    /** Fields to vary cache key by (e.g. "query.page", "header.accept") */
    varyBy?: string[];
    /** Max LRU entries (default 256) */
    maxEntries?: number;
  };
}

export interface Application {
  /** Register path-scoped or global middleware */
  use(middleware: Middleware): Application;
  use(path: string, middleware: Middleware): Application;

  /** Register a global error / not-found handler */
  error(handler: ErrorHandler): Application;

  /** Register a global error handler */
  onError(handler: ErrorHandler): Application;

  /**
   * Create route registrars scoped to a fixed HTTP status code.
   * @example app.status(201).post("/users", handler)
   */
  status(code: number): Record<"get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "all", (path: string, handler: RouteHandler) => Application>;

  /**
   * Register a 404 error handler — called when no route matches.
   * @example app[404]((req, res) => res.status(404).json({ error: "Not found" }))
   */
  404(handler: RouteHandler): Application;

  /**
   * Register a 401 error handler — called when UNAUTHORIZED error is thrown.
   * @example app[401]((req, res) => res.status(401).json({ error: "Unauthorized" }))
   */
  401(handler: RouteHandler): Application;

  /** Group routes under a shared path prefix */
  group(pathPrefix: string, registerGroup: (group: Application) => void): Application;

  /** Register a GET route handler */
  get(path: string, handler: RouteHandler): Application;
  get(path: string, options: RouteOptions, handler: RouteHandler): Application;

  /** Register a POST route handler */
  post(path: string, handler: RouteHandler): Application;
  post(path: string, options: RouteOptions, handler: RouteHandler): Application;

  /** Register a PUT route handler */
  put(path: string, handler: RouteHandler): Application;
  put(path: string, options: RouteOptions, handler: RouteHandler): Application;

  /** Register a DELETE route handler */
  delete(path: string, handler: RouteHandler): Application;
  delete(path: string, options: RouteOptions, handler: RouteHandler): Application;

  /** Register a PATCH route handler */
  patch(path: string, handler: RouteHandler): Application;
  patch(path: string, options: RouteOptions, handler: RouteHandler): Application;

  /** Register an OPTIONS route handler */
  options(path: string, handler: RouteHandler): Application;
  options(path: string, options: RouteOptions, handler: RouteHandler): Application;

  /** Register a HEAD route handler */
  head(path: string, handler: RouteHandler): Application;
  head(path: string, options: RouteOptions, handler: RouteHandler): Application;

  /** Register a handler for all HTTP methods */
  all(path: string, handler: RouteHandler): Application;
  all(path: string, options: RouteOptions, handler: RouteHandler): Application;

  /** Register an exact GET HTML route served from the native static fast path */
  static(path: string, html: string, options?: HtmlResponseOptions): Application;

  /**
   * Register a health check endpoint served from the Rust static fast path.
   * Zero JS dispatch overhead — response is pre-built at startup.
   */
  health(path: string, options?: HealthCheckOptions): Application;

  /** Register a WebSocket upgrade handler for a path */
  ws(path: string, handlers: WebSocketHandlers): Application;

  /** Configure first-class app reload behavior for dev runtimes */
  reload(options?: ReloadOptions): Application;

  /** Start the server and listen for connections */
  listen(options?: ListenOptions): ListenHandle;

  /**
   * Attach a named property/service to every request object.
   * Decorators are set once at startup — zero per-request overhead.
   */
  decorate<T>(name: string, value: T): Application;

  /**
   * Register a lifecycle hook called at the specified event.
   */
  addHook(
    event: "onRequest" | "onRoute" | "onResponse" | "onError" | "onClose",
    fn: (...args: unknown[]) => void | Promise<void>,
  ): Application;

  /**
   * Install a plugin. Plugins can register routes, middleware, hooks, and decorators.
   */
  register(plugin: Plugin, options?: Record<string, unknown>): Application;
}

// ─── WebSocket Types ───────────────────

export interface WebSocketHandlers {
  /** Called when a new WebSocket connection opens */
  open?(ws: WebSocketConnection): void | Promise<void>;

  /** Called when a message is received from the client */
  message?(ws: WebSocketConnection, data: string | Buffer): void | Promise<void>;

  /** Called when the WebSocket connection closes */
  close?(ws: WebSocketConnection, code?: number, reason?: string): void | Promise<void>;

  /** Maximum payload length in bytes (default: 65536) */
  maxPayloadLength?: number;

  /** Backpressure strategy: "drop" discards, "buffer" queues, "block" awaits (default: "drop") */
  backpressure?: "drop" | "buffer" | "block";

  /** Idle timeout in seconds — connections with no activity are closed (default: 120) */
  idleTimeout?: number;

  /** Enable per-message deflate compression (RFC 7692) (default: false) */
  perMessageDeflate?: boolean;
}

export interface WebSocketConnection {
  /** Send a text or binary message to the client */
  send(data: string | Buffer | Uint8Array): void;

  /** Close the WebSocket connection */
  close(code?: number, reason?: string): void;

  /** Subscribe this connection to a pub/sub topic */
  subscribe(topic: string): void;

  /** Unsubscribe this connection from a pub/sub topic */
  unsubscribe(topic: string): void;

  /** Publish a message to all subscribers of a topic */
  publish(topic: string, data: string | Buffer | Uint8Array): number;

  /** Get the number of subscribers for a topic */
  subscriberCount(topic: string): number;

  /** The internal connection ID */
  readonly id: number;
}

/** Create a new http-native application */
export function createApp(config?: AppConfig): Application;

// ─── CORS Types ─────────────────────────

export interface CorsOptions {
  /** Allowed origin(s). Default: "*" */
  origin?: string | string[] | ((origin: string) => boolean);

  /** Allowed HTTP methods */
  methods?: string | string[];

  /** Allowed request headers */
  allowedHeaders?: string | string[];

  /** Headers exposed to the browser */
  exposedHeaders?: string | string[];

  /** Allow credentials (cookies, authorization) */
  credentials?: boolean;

  /** Cache duration for preflight response (seconds) */
  maxAge?: number;

  /** Handle preflight OPTIONS requests. Default: true */
  preflight?: boolean;
}

/** Create a CORS middleware */
export function cors(options?: CorsOptions): Middleware;

// ─── Compression Types ────────────────────

export interface ContentTypeQualityOption {
  /** Content-type pattern, e.g. "image/svg+xml", "application/json", "text/*" */
  pattern: string;
  /** Brotli quality override for this content-type (0-11) */
  brotliQuality?: number;
  /** Gzip level override for this content-type (0-9) */
  gzipLevel?: number;
}

export interface CompressOptions {
  /** Minimum body size in bytes to compress (default 1024) */
  minSize?: number;
  /** Brotli quality level 0-11 (default 4) */
  brotliQuality?: number;
  /** Gzip compression level 0-9 (default 6) */
  gzipLevel?: number;
  /** Per-content-type quality overrides, checked in order */
  qualityMap?: ContentTypeQualityOption[];
}

/** Create a compression middleware (Brotli + Gzip, handled in native layer) */
export function compress(options?: CompressOptions): Middleware;

// ─── Validation Types ───────────────────

export interface ValidationSchema<T = unknown> {
  parse(data: unknown): T;
}

export interface ValidateOptions<TBody = unknown, TQuery = unknown, TParams = unknown> {
  body?: ValidationSchema<TBody>;
  query?: ValidationSchema<TQuery>;
  params?: ValidationSchema<TParams>;
}

/** Create a validation middleware (works with Zod, TypeBox, or any schema with .parse()) */
export function validate<TBody = unknown, TQuery = unknown, TParams = unknown>(
  schema: ValidateOptions<TBody, TQuery, TParams>,
): Middleware;

// ─── Rate Limit Types ───────────────────

export interface NativeRateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAtMs: number;
  retryAfterSecs: number;
  nowMs: number;
}

export interface NativeRateLimiterOptions {
  namespace?: string;
  max?: number;
  window?: number;
  cost?: number;
}

export interface NativeRateLimiter {
  readonly namespace: string;
  check(
    key: string,
    options?: {
      max?: number;
      window?: number;
      cost?: number;
    },
  ): NativeRateLimitDecision;
  reset(key?: string): number;
  clear(): number;
}

export interface RateLimitHeaderNames {
  limit?: string;
  remaining?: string;
  reset?: string;
  retryAfter?: string;
}

export interface RateLimitOptions {
  namespace?: string;
  max: number | ((req: Request, res: Response) => number | Promise<number>);
  window: number | ((req: Request, res: Response) => number | Promise<number>);
  cost?: number | ((req: Request, res: Response) => number | Promise<number>);
  key?: (req: Request, res: Response) => string | Promise<string>;
  skip?: boolean | ((req: Request, res: Response) => boolean | Promise<boolean>);
  headers?: boolean | RateLimitHeaderNames;
  statusCode?: number;
  message?: string | Record<string, unknown>;
  onRejected?: (
    req: Request,
    res: Response,
    decision: NativeRateLimitDecision,
  ) => void | Promise<void>;
}

/** Create a low-level native sliding-window limiter handle. */
export function createNativeRateLimiter(options?: NativeRateLimiterOptions): NativeRateLimiter;

/** Create a high-level middleware wrapper around the native limiter handle. */
export function rateLimit(options: RateLimitOptions): Middleware;

// ─── Health Check Types ────────────────

export interface HealthCheckOptions {
  /** JSON body to return (default: { status: "ok" }) */
  body?: Record<string, unknown>;
  /** HTTP status code (default: 200) */
  status?: number;
  /** Additional response headers */
  headers?: Record<string, string>;
}

// ─── Security Headers Types ────────────

export interface HstsOptions {
  /** Max age in seconds (default: 31536000 = 1 year) */
  maxAge?: number;
  /** Include subdomains (default: true) */
  includeSubDomains?: boolean;
  /** Add preload flag */
  preload?: boolean;
}

export interface ContentSecurityPolicyOptions {
  /** CSP directives as camelCase keys → source arrays */
  directives?: Record<string, string | string[]>;
}

export interface HelmetOptions {
  /** HSTS header (default: enabled with 1-year max-age). Set false to disable. */
  hsts?: HstsOptions | boolean;
  /** Content-Security-Policy. Set false or omit to disable. */
  contentSecurityPolicy?: ContentSecurityPolicyOptions | boolean;
  /** X-Frame-Options value (default: "DENY"). Set false to disable. */
  xFrameOptions?: string | boolean;
  /** X-Content-Type-Options (default: "nosniff"). Set false to disable. */
  xContentTypeOptions?: boolean;
  /** X-XSS-Protection (default: "0"). Set false to disable. */
  xXssProtection?: boolean;
  /** Referrer-Policy (default: "strict-origin-when-cross-origin"). Set false to disable. */
  referrerPolicy?: string | boolean;
  /** Cross-Origin-Opener-Policy (default: "same-origin"). Set false to disable. */
  crossOriginOpenerPolicy?: string | boolean;
  /** Cross-Origin-Resource-Policy (default: "same-origin"). Set false to disable. */
  crossOriginResourcePolicy?: string | boolean;
  /** Permissions-Policy. Set false or omit to disable. */
  permissionsPolicy?: Record<string, string[]> | boolean;
  /** X-DNS-Prefetch-Control (default: "off"). Set false to disable. */
  xDnsPrefetchControl?: string | boolean;
  /** X-Permitted-Cross-Domain-Policies (default: "none"). Set false to disable. */
  xPermittedCrossDomainPolicies?: string | boolean;
}

/** Create a security headers middleware with sane defaults */
export function helmet(options?: HelmetOptions): Middleware;

// ─── Request ID Types ──────────────────

export interface RequestIdOptions {
  /** Incoming request header to read (default: "x-request-id") */
  header?: string;
  /** Response header to set (default: same as header; false to disable) */
  responseHeader?: string | false;
  /** Custom ID generator function (default: crypto.randomUUID) */
  generate?: () => string;
}

/** Create a request ID middleware for distributed tracing correlation */
export function requestId(options?: RequestIdOptions): Middleware;

// ─── Body Limit Types ────────────────────

/**
 * Create a per-route body size limit middleware.
 * Accepts a human-readable size string ("50mb", "1kb") or byte count.
 */
export function bodyLimit(limit: string | number): Middleware;

// ─── CSRF Types ──────────────────────────

export interface CsrfCookieOptions {
  /** Cookie name (default: "_csrf") */
  name?: string;
  /** HttpOnly flag (default: true) */
  httpOnly?: boolean;
  /** SameSite policy (default: "strict") */
  sameSite?: "strict" | "lax" | "none";
  /** Secure flag (default: false) */
  secure?: boolean;
  /** Cookie path (default: "/") */
  path?: string;
  /** Cookie max age in seconds */
  maxAge?: number;
}

export interface CsrfOptions {
  /** Cookie configuration for the CSRF token */
  cookie?: CsrfCookieOptions;
  /** HTTP methods to skip CSRF validation (default: GET, HEAD, OPTIONS) */
  ignoreMethods?: string[];
  /** Request header to read the CSRF token from (default: "x-csrf-token") */
  tokenHeader?: string;
  /** Request body field to read the CSRF token from (default: "_csrf") */
  tokenField?: string;
}

/** Create a CSRF protection middleware using double-submit cookie pattern */
export function csrf(options?: CsrfOptions): Middleware;

// ─── IP Filter Types ─────────────────────

export interface IpFilterOptions {
  /** CIDR ranges to allow (e.g. ["10.0.0.0/8", "192.168.0.0/16"]) */
  allow?: string[];
  /** CIDR ranges to deny (e.g. ["0.0.0.0/0"]) */
  deny?: string[];
  /** Use X-Forwarded-For header for client IP (default: false) */
  trustProxy?: boolean;
  /** Custom handler for denied requests */
  onDenied?: (req: Request, res: Response) => void | Promise<void>;
}

/** Create an IP allowlist/denylist middleware with CIDR range matching */
export function ipFilter(options: IpFilterOptions): Middleware;

// ─── Error Types ─────────────────────────

export class HttpError extends Error {
  /** HTTP status code */
  readonly status: number;
  /** Machine-readable error code (e.g. "VALIDATION_FAILED") */
  readonly code: string;
  /** Additional error details */
  readonly details?: unknown;

  constructor(status: number, code?: string, message?: string, details?: unknown);

  /** Serialize to JSON-safe plain object */
  toJSON(): { status: number; code: string; message: string; details?: unknown };
}

export class BadRequest extends HttpError {
  constructor(message?: string, details?: unknown);
}

export class Unauthorized extends HttpError {
  constructor(message?: string, details?: unknown);
}

export class Forbidden extends HttpError {
  constructor(message?: string, details?: unknown);
}

export class NotFound extends HttpError {
  constructor(message?: string, details?: unknown);
}

export class Conflict extends HttpError {
  constructor(message?: string, details?: unknown);
}

export class UnprocessableEntity extends HttpError {
  constructor(message?: string, details?: unknown);
}

export class TooManyRequests extends HttpError {
  constructor(message?: string, details?: unknown);
}

export class InternalServerError extends HttpError {
  constructor(message?: string, details?: unknown);
}

export class BadGateway extends HttpError {
  constructor(message?: string, details?: unknown);
}

export class ServiceUnavailable extends HttpError {
  constructor(message?: string, details?: unknown);
}

// ─── Shutdown Types ──────────────────────

export interface ShutdownOptions {
  /** Maximum drain time in milliseconds (default: 30000) */
  timeout?: number;
  /** Force kill after this many ms (default: timeout + 5000) */
  forceAfter?: number;
  /** Called when draining starts — mark service as unhealthy for load balancers */
  onDraining?: () => void;
  /** Called after all in-flight requests finish (before close) */
  onDrained?: () => void | Promise<void>;
}

export interface ShutdownResult {
  /** Whether all in-flight requests completed before the timeout */
  drained: boolean;
  /** Number of requests still in-flight when the timeout expired */
  remaining: number;
}

// ─── Plugin Types ──────────────────────

export interface Plugin {
  /** Unique plugin name */
  name: string;
  /** Semver version string */
  version?: string;
  /** Called once when the plugin is registered */
  setup(app: Application, options?: Record<string, unknown>): void;
  /** Called during server shutdown */
  teardown?(): void | Promise<void>;
}

/**
 * Define a plugin with the standard interface.
 */
export function definePlugin(definition: Plugin): Plugin;

// ─── Audit Log Types ───────────────────

export interface AuditEvent {
  type: string;
  timestamp: string;
  method?: string;
  path?: string;
  ip?: string;
  requestId?: string;
  userId?: string;
  statusCode?: number;
  durationMs?: number;
  error?: string;
  headers?: Record<string, string>;
  body?: string;
  [key: string]: unknown;
}

export interface AuditLogOptions {
  /** Receives each audit event — write to file, stream, SIEM, etc. */
  sink: (event: AuditEvent) => void;
  /** Event types to capture (default: all) */
  events?: string[];
  /** Include request headers in events (default: false) */
  includeHeaders?: boolean;
  /** Header names to redact (default: authorization, cookie, set-cookie) */
  redactHeaders?: string[];
  /** Include request body in events (default: false) */
  includeBody?: boolean;
}

/** Create an audit logging middleware for compliance events */
export function auditLog(options: AuditLogOptions): Middleware;

export interface AuditEmitter {
  emit(type: string, data?: Record<string, unknown>): void;
  authLogin(userId: string, ip: string): void;
  authLogout(userId: string, ip: string): void;
  authFailed(reason: string, ip: string): void;
  rateLimitExceeded(ip: string, path: string): void;
}

/** Create pre-defined audit event emitters for use outside middleware */
export function createAuditEmitter(
  sink: (event: AuditEvent) => void,
): AuditEmitter;

// ─── Test Client Types ─────────────────

export interface TestResponse {
  status: number;
  headers: Record<string, string>;
  ok: boolean;
  json(): Promise<unknown>;
  text(): Promise<string>;
  raw: Response;
}

export interface TestWebSocket {
  send(data: string | Buffer | Uint8Array): void;
  next(): Promise<string>;
  close(): void;
  raw: WebSocket;
}

export interface TestClient {
  baseUrl: string;
  request(path: string, init?: RequestInit & { json?: unknown }): Promise<TestResponse>;
  get(path: string, init?: RequestInit): Promise<TestResponse>;
  post(path: string, init?: RequestInit & { json?: unknown }): Promise<TestResponse>;
  put(path: string, init?: RequestInit & { json?: unknown }): Promise<TestResponse>;
  patch(path: string, init?: RequestInit & { json?: unknown }): Promise<TestResponse>;
  delete(path: string, init?: RequestInit): Promise<TestResponse>;
  ws(path: string): Promise<TestWebSocket>;
  close(): Promise<void>;
}

/** Create a test client that starts the app on an ephemeral port */
export function testClient(
  app: Application,
  options?: { port?: number; host?: string },
): Promise<TestClient>;

// ─── Circuit Breaker Types ─────────────

export interface CircuitBreakerOptions {
  /** Unique circuit name (for logging/metrics) */
  name: string;
  /** Consecutive failures before opening (default: 5) */
  threshold?: number;
  /** ms in open state before half-open probe (default: 30000) */
  timeout?: number;
  /** Max concurrent requests in half-open state (default: 1) */
  halfOpenMax?: number;
  /** Called when circuit opens */
  onOpen?: () => void;
  /** Called when circuit transitions to half-open */
  onHalfOpen?: () => void;
  /** Called when circuit closes (healthy again) */
  onClose?: () => void;
  /** Custom failure detection (default: any thrown error) */
  isFailure?: (err: unknown) => boolean;
}

export interface CircuitBreaker {
  readonly name: string;
  readonly state: "closed" | "open" | "half-open";
  readonly failureCount: number;
  call<T>(fn: () => Promise<T>): Promise<T>;
  reset(): void;
  trip(): void;
}

export function circuitBreaker(options: CircuitBreakerOptions): CircuitBreaker;

export class CircuitOpenError extends Error {
  circuit: string;
  status: 503;
  code: "CIRCUIT_OPEN";
}

// ─── Environment Config Types ──────────

export interface EnvVarSpec {
  type?: "string" | "number" | "boolean" | "json";
  required?: boolean;
  default?: unknown;
}

export interface LoadEnvOptions {
  /** Prefix all env var names (e.g. "APP_") */
  prefix?: string;
}

type EnvVarType<S extends EnvVarSpec> =
  S["type"] extends "number" ? number :
  S["type"] extends "boolean" ? boolean :
  S["type"] extends "json" ? unknown :
  string;

/** Load and validate environment variables */
export function loadEnv<T extends Record<string, EnvVarSpec>>(
  schema: T,
  options?: LoadEnvOptions,
): { [K in keyof T]: EnvVarType<T[K]> };

export class EnvValidationError extends Error {
  errors: string[];
}

// ─── OpenAPI Types ─────────────────────

export interface OpenApiOptions {
  /** OpenAPI info object */
  info?: { title: string; version: string; description?: string };
  /** Server URLs */
  servers?: { url: string; description?: string }[];
  /** Path to serve the raw JSON spec (default: "/openapi.json") */
  json?: string;
  /** Path to serve Swagger UI (optional) */
  ui?: string;
  /** Extra OpenAPI components to merge */
  components?: Record<string, unknown>;
  /** Top-level tag definitions */
  tags?: (string | { name: string; description?: string })[];
}

export function openapi(options?: OpenApiOptions): Middleware;
export function generateSpec(
  appMeta: { routes?: { path: string; method: string; meta?: Record<string, unknown> }[] },
  options?: OpenApiOptions,
): Record<string, unknown>;

// ─── Multipart Types ───────────────────

export interface MultipartOptions {
  /** Max size per file (e.g. "10mb", 1048576). Default: 10MB */
  maxFileSize?: string | number;
  /** Max number of files. Default: 10 */
  maxFiles?: number;
  /** Max size per text field. Default: 1MB */
  maxFieldSize?: string | number;
  /** Auto-save directory (optional) */
  uploadDir?: string;
}

export interface MultipartFile {
  name: string;
  fieldName: string;
  mimetype: string;
  size: number;
  data: Buffer;
  saveTo?(destPath?: string): Promise<string>;
}

export function multipart(options?: MultipartOptions): Middleware;

// ─── Logger Types ───────────────────────

export interface LoggerOptions {
  /** Minimum log level (default: "info") */
  level?: "debug" | "info" | "warn" | "error" | "silent";
  /** Output format (default: "json") */
  format?: "json" | "pretty";
  /** Dot-paths to redact from log output (e.g. "req.headers.authorization") */
  redact?: string[];
  /** Custom output function (default: JSON to stderr) */
  sink?: (entry: Record<string, unknown>) => void;
  /** Include timestamps (default: true) */
  timestamp?: boolean;
  /** Extra fields to include per request */
  customProps?: (req: Request) => Record<string, unknown>;
}

export interface Logger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
  child(defaults: Record<string, unknown>): Logger;
}

export function logger(options?: LoggerOptions): Middleware;
export function createLogger(options?: Omit<LoggerOptions, "redact" | "customProps" | "timestamp">): Logger;

// ─── OpenTelemetry Types ────────────────

export interface OtelOptions {
  /** Service name for trace/metric resource */
  serviceName?: string;
  /** OTLP collector endpoint */
  endpoint?: string;
  /** Context propagation format (default: "w3c") */
  propagation?: "w3c" | "b3" | "jaeger";
  /** Fraction of requests to trace, 0.0–1.0 (default: 1.0) */
  sampleRate?: number;
  /** Custom span exporter function */
  exporter?: (spans: OtelSpan[]) => void;
  /** Enable request metrics collection (default: true) */
  metrics?: boolean;
  /** Metrics flush interval in ms (default: 60000) */
  metricsInterval?: number;
}

export interface OtelSpan {
  traceId: string;
  spanId: string;
  parentSpanId: string | null;
  operationName: string;
  serviceName: string;
  startTime: number;
  duration: number;
  tags: Record<string, unknown>;
  status: "OK" | "ERROR";
}

export type OtelMiddleware = Middleware & {
  /** Flush pending spans to the exporter immediately */
  flushSpans(): void;
  /** Get the number of pending (unbatched) spans */
  pendingSpans(): number;
};

export function otel(options?: OtelOptions): OtelMiddleware;

/** Flush pending spans from the otel middleware (convenience for shutdown) */
export function flushSpans(middleware: OtelMiddleware): void;
