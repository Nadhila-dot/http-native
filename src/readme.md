<p align="center">
  <img src="https://cf-data.pkg.lat/httpnative-banner.png" style="width: 600px; height: 450px; object-fit: cover;" />
</p>

# @http-native/core

A fast, Express-like HTTP framework for JavaScript powered by a Rust native module via napi-rs.

## Install

```sh
npm install @http-native/core
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
import cors from "@http-native/core/cors";
import { validate } from "@http-native/core/validate";
import httpServerConfig from "@http-native/core/http-server.config";
```

## Optimizations

```js
const server = await app.listen().port(8190).opt({ devComments: true });

console.log(server.optimizations.summary());
console.log(server.optimizations.snapshot());
```
