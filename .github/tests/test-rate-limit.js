import assert from "node:assert/strict";

import { createApp } from "../../src/index.js";
import { createNativeRateLimiter, rateLimit } from "../../src/rate-limit.js";

async function main() {
  const lowLevel = createNativeRateLimiter({
    namespace: "test-rate-limit-low-level",
    max: 2,
    window: 60,
  });

  assert.equal(lowLevel.check("client-a").allowed, true);
  assert.equal(lowLevel.check("client-a").allowed, true);
  const denied = lowLevel.check("client-a");
  assert.equal(denied.allowed, false);
  assert.ok(denied.retryAfterSecs >= 1);
  lowLevel.clear();

  const app = createApp();
  app.use("/limited", rateLimit({
    namespace: "test-rate-limit-http",
    max: 2,
    window: 60,
  }));
  app.use("/token", rateLimit({
    namespace: "test-rate-limit-token",
    max: 1,
    window: 60,
    key(req) {
      return String(req.query.token ?? req.ip);
    },
    headers: {
      limit: "ratelimit-limit",
      remaining: "ratelimit-remaining",
      reset: "ratelimit-reset",
      retryAfter: "retry-after",
    },
    message: {
      error: "Slow down",
    },
  }));

  app.get("/limited", (req, res) => {
    res.json({ ok: true, ip: req.ip });
  });
  app.get("/token", (req, res) => {
    res.json({ token: req.query.token ?? null });
  });

  const server = await app.listen().port(0);
  let closed = false;

  try {
    const limited1 = await fetch(new URL("/limited", server.url));
    const limited2 = await fetch(new URL("/limited", server.url));
    const limited3 = await fetch(new URL("/limited", server.url));

    assert.equal(limited1.status, 200);
    assert.equal(limited2.status, 200);
    assert.equal(limited3.status, 429);
    assert.equal(limited1.headers.get("x-ratelimit-limit"), "2");
    assert.equal(limited2.headers.get("x-ratelimit-remaining"), "0");
    assert.ok(Number(limited3.headers.get("retry-after")) >= 1);
    const limitedBody = await limited3.json();
    assert.equal(limitedBody.error, "Too Many Requests");
    const ipPayload = await limited1.json();
    assert.equal(typeof ipPayload.ip, "string");
    assert.ok(ipPayload.ip.length > 0);

    const tokenA1 = await fetch(new URL("/token?token=a", server.url));
    const tokenA2 = await fetch(new URL("/token?token=a", server.url));
    const tokenB1 = await fetch(new URL("/token?token=b", server.url));

    assert.equal(tokenA1.status, 200);
    assert.equal(tokenA2.status, 429);
    assert.equal(tokenB1.status, 200);
    assert.equal(tokenA1.headers.get("ratelimit-limit"), "1");
    assert.equal(tokenA2.headers.get("ratelimit-remaining"), "0");
    const tokenBody = await tokenA2.json();
    assert.equal(tokenBody.error, "Slow down");

    await Promise.resolve(server.close());
    closed = true;
  } finally {
    if (!closed) {
      await Promise.resolve(server.close());
    }
  }

  console.log("[http-native] rate-limit test suite passed");
}

await main();
