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
}

export interface Session {
  /** Get a session value by key */
  get<T = unknown>(key: string): T | undefined;

  /** Set a session value */
  set(key: string, value: unknown): void;

  /** Delete a session key */
  delete(key: string): void;

  /** Check if a key exists */
  has(key: string): boolean;

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

export interface Application {
  /** Register path-scoped or global middleware */
  use(middleware: Middleware): Application;
  use(path: string, middleware: Middleware): Application;

  /** Register a global error / not-found handler */
  error(handler: ErrorHandler): Application;

  /** 
   * Deprecate soon
   * Not very needed rn
   * Register a global error handler */
  onError(handler: ErrorHandler): Application;

  /** Group routes under a shared path prefix */
  group(pathPrefix: string, registerGroup: (group: Application) => void): Application;

  /** Register a GET route handler */
  get(path: string, handler: RouteHandler): Application;

  /** Register a POST route handler */
  post(path: string, handler: RouteHandler): Application;

  /** Register a PUT route handler */
  put(path: string, handler: RouteHandler): Application;

  /** Register a DELETE route handler */
  delete(path: string, handler: RouteHandler): Application;

  /** Register a PATCH route handler */
  patch(path: string, handler: RouteHandler): Application;

  /** Register an OPTIONS route handler */
  options(path: string, handler: RouteHandler): Application;

  /** Register a HEAD route handler */
  head(path: string, handler: RouteHandler): Application;

  /** Register a handler for all HTTP methods */
  all(path: string, handler: RouteHandler): Application;

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
}

// ─── WebSocket Types ───────────────────

export interface WebSocketHandlers {
  /** Called when a new WebSocket connection opens */
  open?(ws: WebSocketConnection): void | Promise<void>;

  /** Called when a message is received from the client */
  message?(ws: WebSocketConnection, data: string | Buffer): void | Promise<void>;

  /** Called when the WebSocket connection closes */
  close?(ws: WebSocketConnection, code?: number, reason?: string): void | Promise<void>;
}

export interface WebSocketConnection {
  /** Send a text or binary message to the client */
  send(data: string | Buffer | Uint8Array): void;

  /** Close the WebSocket connection */
  close(code?: number, reason?: string): void;

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
