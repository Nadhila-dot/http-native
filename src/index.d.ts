import { Buffer } from "node:buffer";

// Types by rishi
// Just simple types for now, we can expand as needed. The main goal is to provide a good developer 
// experience with TypeScript and IDEs, 
// so we want to be careful about adding too much complexity here.

export interface Request {
  /** HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) */
  readonly method: string;

  /** URL path without query string */
  readonly path: string;

  /** Full request URL including query string */
  readonly url: string;

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

  /** Send a response body (string, Buffer, or object) */
  send(data?: string | Buffer | Uint8Array | null): Response;

  /** Set status and send status code as text body */
  sendStatus(code: number): Response;
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

export interface HttpServerConfig {
  defaultHost?: string;
  defaultBacklog?: number;
  maxHeaderBytes?: number;
}

export interface RuntimeOptimizationOptions {
  /** Emit optimization and live-hit logs */
  notify?: boolean;
  /** Live notify interval in milliseconds (default: 1000) */
  notifyIntervalMs?: number;
  /** Enable runtime response cache promotion for deterministic routes */
  cache?: boolean;
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

  /** Runtime optimization options */
  opt?: RuntimeOptimizationOptions;
}

// ─── Server Handle ──────────────────────

export interface ServerHandle {
  /** Bound hostname */
  readonly host: string;

  /** Bound port number */
  readonly port: number;

  /** Full URL (http://host:port) */
  readonly url: string;

  /** Runtime optimization introspection */
  readonly optimizations: {
    /** Get a snapshot of route optimization state */
    snapshot(): OptimizationSnapshot;
    /** Get a human-readable optimization summary */
    summary(): string;
  };

  /** Gracefully close the server */
  close(): void;
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
  recommendation?: string;
  dispatchKind?: string;
  jsonFastPath?: string;
}

// ─── Application ────────────────────────

export interface Application {
  /** Register path-scoped or global middleware */
  use(middleware: Middleware): Application;
  use(path: string, middleware: Middleware): Application;

  /** Register a global error / not-found handler */
  error(handler: ErrorHandler): Application;

  /** Register a global error handler */
  onError(handler: ErrorHandler): Application;

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

  /** Register a handler for all HTTP methods */
  all(path: string, handler: RouteHandler): Application;

  /** Start the server and listen for connections */
  listen(options?: ListenOptions): Promise<ServerHandle>;
}

/** Create a new http-native application */
export function createApp(): Application;

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
