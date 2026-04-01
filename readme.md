<p align="center">
  <img src="https://cf-data.pkg.lat/httpnative-banner.png" style="width: 600px; height: 450px; object-fit: cover;" />
</p>

# @http-native/core

A fast, Express-like HTTP framework for JavaScript powered by a Rust native module via napi-rs.

## Install

```sh
bun add @http-native/core
```

Native binaries are downloaded automatically during install for your OS/arch.
If you need to repair/re-download manually:

```sh
http-native setup --force
```

## Usage

```js
import { createApp } from "@http-native/core";

const app = createApp();

app.get("/", async (req, res) => {
  res.json({ ok: true });
});

app.get("/user/:id", async (req, res) => {
  res.json({ id: req.params.id });
});

app.error(async (error, req, res) => {
  res.status(500).json({ error: error.message });
});

const server = await app.listen().port(8190);
console.log(`Listening on ${server.url}`);
```

## Imports

```js
import { createApp } from "@http-native/core";
import { cors } from "@http-native/core/cors";
import { validate } from "@http-native/core/validate";
import { session } from "@http-native/core/session";
import { createDevServer } from "@http-native/core/dev";
import httpServerConfig from "@http-native/core/http-server.config";
```

## Middleware

```js
import { cors } from "@http-native/core/cors";
import { session } from "@http-native/core/session";

// CORS — allow all origins
app.use(cors());

// CORS — specific origins with credentials
app.use(cors({
  origin: ["https://myapp.com", "https://admin.myapp.com"],
  credentials: true,
}));

// Sessions — Rust-backed in-memory store (default)
app.use(session({ secret: "your-secret-key" }));
```

## Route Grouping

```js
app.group("/api/v1", (api) => {
  api.get("/users", async (req, res) => {
    res.json({ users: [] });
  });

  api.post("/users", async (req, res) => {
    res.status(201).json({ created: true });
  });
});
```

## Validation

```js
import { validate } from "@http-native/core/validate";
import { z } from "zod";

const schema = z.object({
  name: z.string(),
  email: z.string().email(),
});

app.post("/users", validate({ body: schema }), async (req, res) => {
  // req.validatedBody is the parsed and validated body
  res.status(201).json(req.validatedBody);
});
```

## Static Routes

```js
// Serve a pre-rendered HTML string from the Rust fast path,
// bypassing the JS bridge on every request after the first.
app.static("/about", "<html>...</html>");

// With SSR object injection — window.hnSSR.objects is available in the browser
app.static("/dashboard", html, {
  objects: { user: { id: 1, name: "Alice" } },
});
```

## Native Response Cache

```js
app.get("/data", async (req, res) => {
  const data = await fetchData();
  // Cache this JSON response in Rust for 60 seconds.
  // Subsequent requests are served without crossing the JS bridge.
  res.ncache(data, 60);
});
```

## Optimizations

```js
const app = createApp({
  dev: {
    logger: true, // default
    devComments: true,
  },
});

const server = await app.listen().port(8190);

console.log(server.optimizations.summary());
console.log(server.optimizations.snapshot());
```

## Dev Reload

```sh
http-native dev ./server.js --port 3000
```

```js
import { createDevServer } from "@http-native/core/dev";

const dev = await createDevServer({
  entry: "./server.js",
  port: 3000,
});

console.log(dev.status());
```

You can define reload behavior on the app itself:

```js
const app = createApp().reload({
  files: ["src", "routes", "rsrc/src"],
  debounceMs: 80,
  clear: true,
});
```

`createDevServer()` and `http-native dev` keep the current runtime. If you launch with Bun, reload stays on Bun. If you launch with Node, reload stays on Node.

For existing self-starting apps, runtime hot reload still works:

```js
await app.listen().hot();
```

## TLS / HTTPS

```js
const server = await app.listen().port(443).tls({
  cert: "./cert.pem",
  key: "./key.pem",
});
```
