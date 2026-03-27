# http-native Examples

Each folder contains a self-contained example you can run with `bun`:

```bash
# Make sure to build the native module first
bun run build

# Then run any example
bun examples/basic/server.js
bun examples/cors/server.js
bun examples/middleware/server.js
bun examples/rest-api/server.js
bun examples/validation/server.js
bun examples/error-handling/server.js
```

## Examples

| Example | Description |
|---------|-------------|
| **[basic](./basic/)** | Routes, params, query strings, status codes, custom headers |
| **[cors](./cors/)** | CORS with wildcard, specific origins, dynamic origins, credentials |
| **[middleware](./middleware/)** | Logging, path-scoped auth, request IDs, `res.locals` data passing |
| **[rest-api](./rest-api/)** | Full CRUD Todo API — GET, POST, PUT, PATCH, DELETE with body parsing |
| **[validation](./validation/)** | Request body & query validation (Zod-compatible schema interface) |
| **[error-handling](./error-handling/)** | Custom error classes, global `onError()` handler, async error catching |
