# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`@http-native/core` — a fast, Express-like HTTP framework for JavaScript powered by a Rust native module via napi-rs. The Rust layer (monoio-based async TCP server) handles routing, connection management, TLS, sessions, rate limiting, and response caching. JavaScript handles route registration, middleware execution, and handler dispatch. The two layers communicate through a custom binary protocol (bridge.js).

## Build & Development Commands

```bash
bun run build            # Debug build of the Rust native module (.node binary)
bun run build:release    # Release build (LTO, stripped symbols)
bun run test             # Build + run all tests
bun run dev              # Dev server with hot reload (via CLI)
```

Individual test files can be run directly after building:
```bash
bun .github/tests/test.js
bun .github/tests/test-dev.js
bun .github/tests/test-rate-limit.js
```

The native `.node` binary is output to the project root as `http-native.node`. It can be overridden via `HTTP_NATIVE_NATIVE_PATH` env var.

## Architecture

### Rust Native Layer (`rsrc/src/`)

- **lib.rs** — NAPI entry point. Runs monoio event loop on worker threads, accepts TCP connections, parses HTTP/1.1 requests, performs routing, and dispatches to JS via `ThreadsafeFunction`. Handles keep-alive, TLS (via rustls), streaming, static route responses, and native response caching entirely in Rust without crossing the JS bridge.
- **router.rs** — O(1) exact-match HashMap router + O(M) radix-tree router for parameterized routes. Handles static response routes, WebSocket upgrade detection, and dynamic fast-path responses.
- **analyzer.rs** — Static analysis of JS handler source code at compile time. Generates fast-path response templates so Rust can serve certain dynamic routes without calling into JS.
- **manifest.rs** — Deserializes the JSON manifest from JS that describes routes, middlewares, session config, TLS, and server settings.
- **session.rs** — Rust-backed in-memory session store (HMAC-SHA256 signed cookies).
- **rate_limit.rs** — Native sliding-window rate limiter exposed via NAPI.
- **websocket.rs** — WebSocket frame encoding/decoding.

### JavaScript Layer (`src/`)

- **index.js** — `createApp()` factory. Express-like API for routes, middleware, groups, error handlers, static routes, WebSocket, and the chainable `listen().port().tls().hot()` builder. Compiles routes into a manifest, creates the dispatcher, and starts the native server.
- **bridge.js** — Binary protocol codec between Rust and JS. Encodes/decodes request/response envelopes, static-analyzes handler source to build access plans (determines which request fields to materialize), and manages object pooling for zero-allocation hot paths.
- **native.js** — Loads the compiled `.node` binary via `createRequire`.
- **session.js** — JS-side session middleware that integrates with the Rust session store.
- **cors.js** — CORS middleware.
- **validate.js** — Request validation middleware (works with Zod schemas).
- **rate-limit.js** — JS wrapper for the native rate limiter.
- **cli.js** — CLI entry point (`http-native` binary). Supports `dev`, `setup`, and `start` subcommands.
- **dev/** — Dev server with hot reload and route source-annotation comments.
- **opt/** — Runtime optimization tracking (dispatch timing, route analysis, optimization summaries).

### Key Design Pattern: Binary Bridge Protocol

Rust and JS communicate via a custom binary envelope format (bridge version 2). Requests are encoded as: `version | methodCode | flags | handlerId | lengths... | url | path | ip | params | headers | body`. Responses use: `status | headerCount | bodyLen | headers | body`. This avoids JSON serialization overhead on every request.

### Key Design Pattern: Access Plans

Handler source code is statically analyzed (`analyzeRequestAccess`) to determine which request fields (params, query, headers, method, path, url) are actually accessed. Fields that are never read are never materialized from the binary envelope — this is the primary zero-copy optimization.

## Commit Convention

Prefix commits with type: `opt:`, `chore:`, `rm:`, `other:`. Types can be combined with `&` (e.g., `opt&chore:`). See CONTRIBUTING.md.

## Runtime Requirements

- Bun (primary) or Node.js for the JS layer
- Rust toolchain for building the native module
- The native binary must exist at project root (or `HTTP_NATIVE_NATIVE_PATH`) before tests or the server can run
