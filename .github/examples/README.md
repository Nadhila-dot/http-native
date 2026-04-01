# http-native Examples

Each folder contains a self-contained example you can run with `bun`:

```bash
# Native binary is downloaded automatically on install.
# If needed, force refresh:
http-native setup --force

# Then run any example
bun .github/examples/basic/server.js
bun .github/examples/cors/server.js
bun .github/examples/middleware/server.js
bun .github/examples/rest-api/server.js
bun .github/examples/validation/server.js
bun .github/examples/error-handling/server.js
bun .github/examples/reload/server.js
```

## Examples

| Example | Description |
|---------|-------------|
| **[basic](./basic/)** | Routes, params, query strings, status codes, custom headers |
| **[cors](./cors/)** | CORS with wildcard, specific origins, dynamic origins, credentials |
| **[middleware](./middleware/)** | Logging, path-scoped auth, request IDs, `res.locals` data passing |
| **[rest-api](./rest-api/)** | Full CRUD Todo API — GET, POST, PUT, PATCH, DELETE with body parsing |
| **[validation](./validation/)** | Request body & query validation (Zod-compatible schema interface) |
| **[error-handling](./error-handling/)** | Custom error classes, global `error()` handler, async error catching |
| **[reload](./reload/)** | `app.reload({...})` + `.listen().hot()` runtime reload flow |
