<p align="center">
 <img src="https://cf-data.pkg.lat/httpnative-banner.png" style="width: 600px; height: 450px; object-fit: cover;" />
</p>


Http-native

Http native is a express like server framework for Javascript that uses the Node-compatible framework with Rust native module way, where the rust binary is evoked through napi-rs or something faster.

You can also import the default server tuning config and override it before `listen()`:

```js
import httpServerConfig from "http-native/http-server.config";
```

Rust handler (http) <-> (javascript logic) 

The rust server handles all the http, while the core javascript logic is run sperately (EXREMELY fast)

Extrat performance features:

    1) Ahead of time constant data indentification. (If the data in the route's logic isn't manipulated at runtime we directly store it in rust so we don't envoke the javascript logic)

    2) Faster than bun.server() aswell as fastify.

    3) Default async handling (Yes rust handles the async for you.)

So start by just writing 

```js
import { createApp } from "../src/index.js";

const db = {
  async getUser(id) {
    return {
      id,
      name: "Ada Lovelace",
      role: "admin",
    };
  },
};

const app = createApp();

app.use(async (req, res, next) => {
  res.header("x-powered-by", "http-native");
  await next();
});

app.get("/", (req, res) => {
  res.json({
    ok: true,
    engine: "rust",
    bridge: "napi-rs",
  });
});

app.get("/users/:id", async (req, res) => {
  const user = await db.getUser(req.params.id);
  res.json(user);
});

const server = await app.listen({
  port: 3001,
  serverConfig: {
    ...httpServerConfig,
    maxHeaderBytes: 32 * 1024,
  },
});
```

Runtime optimization reporting:

```js
console.log(server.optimizations.summary());
console.log(server.optimizations.snapshot());
```

Pass `opt: { notify: true }` to `listen()` if you want runtime logs when a route is already native static or looks stable enough to cache later.


This architecture is designed to outperform previous iterations and provide top-tier performance on par with or exceeding `bun.serve()`.
Run tests via `test.js` and use the benchmark suite to validate performance gains.


Since this is designed to be a core library, please ensure strict adherence to API stability and zero-allocation principles where possible.

Remeber nadhi u moron this will be a library so don't go around doing shit.


bump action
