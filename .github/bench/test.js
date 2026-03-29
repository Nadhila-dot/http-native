import assert from "node:assert/strict";

import { createApp } from "../../src/index.js";

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

app.all("/ping", (req, res) => {
  res.type("text").send(`pong:${req.method}`);
});

const server = await app.listen({
  port: 0,
});

try {
  const rootResponse = await fetch(new URL("/", server.url));
  assert.equal(rootResponse.status, 200);
  assert.equal(rootResponse.headers.get("x-powered-by"), "http-native");
  assert.deepEqual(await rootResponse.json(), {
    ok: true,
    engine: "rust",
    bridge: "napi-rs",
  });

  const userResponse = await fetch(new URL("/users/42", server.url));
  assert.equal(userResponse.status, 200);
  assert.equal(userResponse.headers.get("x-powered-by"), "http-native");
  assert.deepEqual(await userResponse.json(), {
    id: "42",
    name: "Ada Lovelace",
    role: "admin",
  });

  const pingResponse = await fetch(new URL("/ping", server.url), {
    method: "OPTIONS",
  });
  assert.equal(pingResponse.status, 200);
  assert.equal(await pingResponse.text(), "pong:OPTIONS");

  const notFoundResponse = await fetch(new URL("/missing", server.url));
  assert.equal(notFoundResponse.status, 404);
  assert.deepEqual(await notFoundResponse.json(), {
    error: "Route not found",
  });
} finally {
  await server.close();
}

console.log("[http-native] test.js passed");
