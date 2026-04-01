import type { Middleware, Request, Response } from "./index.js";

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

export function createNativeRateLimiter(options?: NativeRateLimiterOptions): NativeRateLimiter;
export function rateLimit(options: RateLimitOptions): Middleware;
