import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import net from "node:net";

import httpServerConfig from "../../src/http-server.config.js";
import { createApp } from "../../src/index.js";
import { createNativeRateLimiter, rateLimit } from "../../src/rate-limit.js";

const stablePayload = {
  ok: true,
  mode: "js-cache-candidate",
};

async function sendKeepAliveSequence(serverUrl, requests) {
  const url = new URL(serverUrl);
  const expectedResponses = requests.length;
  const responses = [];
  let raw = "";

  await new Promise((resolve, reject) => {
    const socket = net.createConnection({
      host: url.hostname,
      port: Number(url.port),
    });

    socket.setEncoding("utf8");
    socket.once("error", reject);

    socket.on("data", (chunk) => {
      raw += chunk;

      while (responses.length < expectedResponses) {
        const parsed = parseNextHttpResponse(raw);
        if (!parsed) {
          break;
        }

        responses.push(parsed.response);
        raw = parsed.rest;
      }

      if (responses.length === expectedResponses) {
        socket.end();
      }
    });

    socket.once("end", () => {
      if (responses.length === expectedResponses) {
        resolve();
        return;
      }

      reject(new Error(`socket closed early with ${responses.length}/${expectedResponses} responses`));
    });

    socket.write(requests.join(""));
  });

  return responses;
}

function parseNextHttpResponse(raw) {
  const headerEnd = raw.indexOf("\r\n\r\n");
  if (headerEnd < 0) {
    return null;
  }

  const headerBlock = raw.slice(0, headerEnd);
  const lines = headerBlock.split("\r\n");
  const statusLine = lines.shift();
  if (!statusLine) {
    return null;
  }

  const statusMatch = /^HTTP\/1\.1\s+(\d{3})/.exec(statusLine);
  if (!statusMatch) {
    return null;
  }

  const headers = {};
  for (const line of lines) {
    const separatorIndex = line.indexOf(":");
    if (separatorIndex < 0) {
      continue;
    }

    const name = line.slice(0, separatorIndex).toLowerCase();
    const value = line.slice(separatorIndex + 1).trim();
    headers[name] = value;
  }

  const contentLength = Number(headers["content-length"] ?? 0);
  const bodyStart = headerEnd + 4;
  const bodyEnd = bodyStart + contentLength;
  if (raw.length < bodyEnd) {
    return null;
  }

  return {
    response: {
      status: Number(statusMatch[1]),
      headers,
      body: raw.slice(bodyStart, bodyEnd),
    },
    rest: raw.slice(bodyEnd),
  };
}

async function main() {
  assert.equal(httpServerConfig.defaultHost, "127.0.0.1");
  assert.equal(httpServerConfig.defaultBacklog, 2048);
  assert.equal(httpServerConfig.maxHeaderBytes, 16 * 1024);

  const db = {
    async getUser(id) {
      return {
        id,
        name: "Ada Lovelace",
      };
    },
  };
  const chainOrder = [];
  const observedErrors = [];

  const lowLevelLimiter = createNativeRateLimiter({
    namespace: "test-low-level-rate-limit",
    max: 2,
    window: 60,
  });
  const firstLowLevel = lowLevelLimiter.check("127.0.0.1");
  const secondLowLevel = lowLevelLimiter.check("127.0.0.1");
  const thirdLowLevel = lowLevelLimiter.check("127.0.0.1");
  assert.equal(firstLowLevel.allowed, true);
  assert.equal(secondLowLevel.allowed, true);
  assert.equal(thirdLowLevel.allowed, false);
  lowLevelLimiter.clear();

  const app = createApp();
  assert.equal(typeof app.error, "function");

  assert.throws(
    () => app.static("/users/:id", "<html>invalid</html>"),
    /app\.static\(\) only supports exact GET paths without params/,
  );

  const middlewareBlockedApp = createApp();
  middlewareBlockedApp.use(async (_req, _res, next) => {
    await next();
  });
  middlewareBlockedApp.static("/blocked", "<html><body>blocked</body></html>");

  await assert.rejects(
    () => middlewareBlockedApp.listen({ port: 0 }),
    /app\.static\(\"\/blocked\"\) cannot be used with applicable middleware/,
  );

  httpServerConfig.tls = {
    cert: "/tst/cert.pem",
    key: "/tst/key.pem"
  };

  app.error((error, req, res) => {
    observedErrors.push({
      path: req.path,
      status: Number(error?.status ?? 500),
      code: error?.code ?? null,
      message: error?.message ?? "",
    });

    if (Number(error?.status) === 404) {
      res.status(404).json({
        handled: true,
        path: req.path,
        code: error.code,
      });
      return;
    }

    res.status(Number(error?.status ?? 500)).json({
      handled: true,
      path: req.path,
      message: error?.message ?? "unknown",
    });
  });

  app.use("/users", async (req, res, next) => {
    res.header("x-powered-by", "http-native");
    await next();
  });
  app.use("/limited", rateLimit({
    namespace: "test-rate-limit-global",
    max: 2,
    window: 60,
  }));
  app.use("/token-limited", rateLimit({
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
  app.get("/", (req, res) => {
    res.json({
      ok: true,
      engine: "rust",
    });
  });
  app.static(
    "/ssr",
    "<html><body><main>ssr</main></body></html>",
    {
      objects: {
        page: "ssr",
        safe: "</script><b>nope</b>",
      },
    },
  );
  app.static(
    "/ssr-tail",
    "<html><main>tail</main></html>",
    {
      objects: {
        page: "tail",
      },
    },
  );
  app.get("/stable", (req, res) => {
    res.json(stablePayload);
  });
  app.get("/ip", (req, res) => {
    res.json({ ip: req.ip });
  });
  app.get("/limited", (_req, res) => {
    res.json({ ok: true });
  });
  app.get("/token-limited", (req, res) => {
    res.json({ token: req.query.token ?? null });
  });
  app.get("/html-helper", (_req, res) => {
    res.html("<html><body><main>helper</main></body></html>", {
      status: 201,
      objects: {
        helper: true,
      },
    });
  });
  app.get("/native/:id", (req, res) => {
    res.json({
      id: req.params.id,
      q: req.query.q,
      tag: req.query.tag,
      trace: req.header("x-trace"),
      accept: req.headers.accept,
    });
  });
  app.get("/users/:id", async (req, res) => {
    const user = await db.getUser(req.params.id);
    res.json(user);
  });

  app.use("/chain", async (req, res, next) => {
    chainOrder.push(`a:${req.method}:${req.path}`);
    await next();
    chainOrder.push("a:after");
  });

  app.use("/chain", async (req, res, next) => {
    chainOrder.push(`b:${req.query.q}:${req.header("x-chain")}`);
    await next();
  });
  app.get("/chain/:id", (req, res) => {
    chainOrder.push(`h:${req.params.id}`);
    res.json({
      id: req.params.id,
      q: req.query.q,
      header: req.headers["x-chain"],
    });
  });
  app.get("/fallback", (req, res) => {
    const { headers, query } = req;
    res.json({
      accept: headers.accept,
      q: query.q,
    });
  });
  app.get("/search", (req, res) => {
    res.json({
      q: req.query.q,
      tag: req.query.tag,
      trace: req.header("x-trace"),
      accept: req.headers.accept,
    });
  });
  app.get("/text", (req, res) => {
    res.type("text").send("hello from binary bridge");
  });
  app.get("/binary", (req, res) => {
    res.send(Buffer.from([1, 2, 3, 4]));
  });
  app.get("/empty", (req, res) => {
    res.status(204).send();
  });
  app.get("/explode", () => {
    throw new Error("boom");
  });

  const server = await app.listen({
    port: 0,
    serverConfig: {
      ...httpServerConfig,
      maxHeaderBytes: httpServerConfig.maxHeaderBytes,
      tls: null,
    },
  });
  let closed = false;

  try {
    const keepAliveResponses = await sendKeepAliveSequence(server.url, [
      "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
      "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    ]);
    assert.equal(keepAliveResponses.length, 2);
    assert.deepEqual(
      keepAliveResponses.map((response) => ({
        status: response.status,
        body: JSON.parse(response.body),
      })),
      [
        {
          status: 200,
          body: {
            ok: true,
            engine: "rust",
          },
        },
        {
          status: 200,
          body: {
            ok: true,
            engine: "rust",
          },
        },
      ],
    );

    const rootResponse = await fetch(new URL("/", server.url));
    assert.equal(rootResponse.status, 200);
    assert.deepEqual(await rootResponse.json(), {
      ok: true,
      engine: "rust",
    });

    const limitedFirst = await fetch(new URL("/limited", server.url));
    assert.equal(limitedFirst.status, 200);
    assert.equal(limitedFirst.headers.get("x-ratelimit-limit"), "2");
    assert.equal(limitedFirst.headers.get("x-ratelimit-remaining"), "1");

    const limitedSecond = await fetch(new URL("/limited", server.url));
    assert.equal(limitedSecond.status, 200);
    assert.equal(limitedSecond.headers.get("x-ratelimit-limit"), "2");
    assert.equal(limitedSecond.headers.get("x-ratelimit-remaining"), "0");

    const limitedThird = await fetch(new URL("/limited", server.url));
    assert.equal(limitedThird.status, 429);
    assert.equal(limitedThird.headers.get("x-ratelimit-limit"), "2");
    assert.equal(limitedThird.headers.get("x-ratelimit-remaining"), "0");
    assert.ok(Number(limitedThird.headers.get("retry-after")) >= 1);
    const limitedThirdBody = await limitedThird.json();
    assert.equal(limitedThirdBody.error, "Too Many Requests");

    const tokenFirst = await fetch(new URL("/token-limited?token=a", server.url));
    assert.equal(tokenFirst.status, 200);
    assert.equal(tokenFirst.headers.get("ratelimit-limit"), "1");
    assert.equal(tokenFirst.headers.get("ratelimit-remaining"), "0");

    const tokenSecond = await fetch(new URL("/token-limited?token=a", server.url));
    assert.equal(tokenSecond.status, 429);
    assert.equal(tokenSecond.headers.get("ratelimit-limit"), "1");
    assert.equal(tokenSecond.headers.get("ratelimit-remaining"), "0");
    const tokenSecondBody = await tokenSecond.json();
    assert.equal(tokenSecondBody.error, "Slow down");

    const tokenOther = await fetch(new URL("/token-limited?token=b", server.url));
    assert.equal(tokenOther.status, 200);

    const ipResponse = await fetch(new URL("/ip", server.url));
    assert.equal(ipResponse.status, 200);
    const ipPayload = await ipResponse.json();
    assert.equal(typeof ipPayload.ip, "string");
    assert.ok(ipPayload.ip.length > 0);

    const ssrResponse = await fetch(new URL("/ssr", server.url));
    assert.equal(ssrResponse.status, 200);
    assert.equal(ssrResponse.headers.get("content-type"), "text/html; charset=utf-8");
    const ssrMarkup = await ssrResponse.text();
    assert.match(
      ssrMarkup,
      /<main>ssr<\/main><script>window\.hnSSR=window\.hnSSR\|\|\{\};window\.hnSSR\.objects=/,
    );
    assert.match(ssrMarkup, /"page":"ssr"/);
    assert.doesNotMatch(ssrMarkup, /<\/script><b>nope<\/b>/);
    assert.match(ssrMarkup, /<\/script><\/body><\/html>$/);

    const ssrTailResponse = await fetch(new URL("/ssr-tail", server.url));
    assert.equal(ssrTailResponse.status, 200);
    const ssrTailMarkup = await ssrTailResponse.text();
    assert.match(ssrTailMarkup, /<\/html><script>/);

    const htmlHelperResponse = await fetch(new URL("/html-helper", server.url));
    assert.equal(htmlHelperResponse.status, 201);
    assert.equal(htmlHelperResponse.headers.get("content-type"), "text/html; charset=utf-8");
    const htmlHelperMarkup = await htmlHelperResponse.text();
    assert.match(htmlHelperMarkup, /window\.hnSSR\.objects=\{"helper":true\}/);

    const userResponse = await fetch(new URL("/users/42", server.url));
    assert.equal(userResponse.status, 200);
    assert.equal(userResponse.headers.get("x-powered-by"), "http-native");
    assert.deepEqual(await userResponse.json(), {
      id: "42",
      name: "Ada Lovelace",
    });

    const chainResponse = await fetch(new URL("/chain/7?q=fast", server.url), {
      headers: {
        "x-chain": "compiled",
      },
    });
    assert.equal(chainResponse.status, 200);
    assert.deepEqual(await chainResponse.json(), {
      id: "7",
      q: "fast",
      header: "compiled",
    });
    assert.deepEqual(chainOrder, [
      "a:GET:/chain/7",
      "b:fast:compiled",
      "a:after",
      "h:7",
    ]);

    const searchResponse = await fetch(new URL("/search?q=ada&tag=math&tag=logic", server.url), {
      headers: {
        "x-trace": "bridge-test",
        accept: "application/json",
      },
    });
    assert.equal(searchResponse.status, 200);
    assert.deepEqual(await searchResponse.json(), {
      q: "ada",
      tag: ["math", "logic"],
      trace: "bridge-test",
      accept: "application/json",
    });

    const nativeResponse = await fetch(
      new URL("/native/9?q=ada&tag=math&tag=logic", server.url),
      {
        headers: {
          "x-trace": "native-fast",
          accept: "application/json",
        },
      },
    );
    assert.equal(nativeResponse.status, 200);
    assert.deepEqual(await nativeResponse.json(), {
      id: "9",
      q: "ada",
      tag: ["math", "logic"],
      trace: "native-fast",
      accept: "application/json",
    });

    const textResponse = await fetch(new URL("/text", server.url));
    assert.equal(textResponse.status, 200);
    assert.equal(await textResponse.text(), "hello from binary bridge");

    const binaryResponse = await fetch(new URL("/binary", server.url));
    assert.equal(binaryResponse.status, 200);
    assert.deepEqual(
      Array.from(new Uint8Array(await binaryResponse.arrayBuffer())),
      [1, 2, 3, 4],
    );

    const emptyResponse = await fetch(new URL("/empty", server.url));
    assert.equal(emptyResponse.status, 204);
    assert.equal(await emptyResponse.text(), "");

    const fallbackResponse = await fetch(new URL("/fallback?q=safe", server.url), {
      headers: {
        accept: "application/json",
      },
    });
    assert.equal(fallbackResponse.status, 200);
    assert.deepEqual(await fallbackResponse.json(), {
      accept: "application/json",
      q: "safe",
    });

    const notFoundResponse = await fetch(new URL("/missing?q=nope", server.url), {
      headers: {
        accept: "application/json",
      },
    });
    assert.equal(notFoundResponse.status, 404);
    assert.deepEqual(await notFoundResponse.json(), {
      handled: true,
      path: "/missing",
      code: "NOT_FOUND",
    });

    const explodedResponse = await fetch(new URL("/explode", server.url));
    assert.equal(explodedResponse.status, 500);
    assert.deepEqual(await explodedResponse.json(), {
      handled: true,
      path: "/explode",
      message: "boom",
    });

    assert.deepEqual(observedErrors, [
      {
        path: "/missing",
        status: 404,
        code: "NOT_FOUND",
        message: "Route not found",
      },
      {
        path: "/explode",
        status: 500,
        code: null,
        message: "boom",
      },
    ]);

    for (let index = 0; index < 32; index += 1) {
      const stableResponse = await fetch(new URL("/stable", server.url));
      assert.equal(stableResponse.status, 200);
      assert.deepEqual(await stableResponse.json(), stablePayload);
    }

    const snapshot = server.optimizations.snapshot();
    const rootRoute = snapshot.routes.find(
      (route) => route.method === "GET" && route.path === "/",
    );
    const stableRoute = snapshot.routes.find(
      (route) => route.method === "GET" && route.path === "/stable",
    );
    const ssrRoute = snapshot.routes.find(
      (route) => route.method === "GET" && route.path === "/ssr",
    );
    const userRoute = snapshot.routes.find(
      (route) => route.method === "GET" && route.path === "/users/:id",
    );
    const nativeRoute = snapshot.routes.find(
      (route) => route.method === "GET" && route.path === "/native/:id",
    );
    const chainRoute = snapshot.routes.find(
      (route) => route.method === "GET" && route.path === "/chain/:id",
    );
    const fallbackRoute = snapshot.routes.find(
      (route) => route.method === "GET" && route.path === "/fallback",
    );

    assert.ok(rootRoute);
    assert.ok(stableRoute);
    assert.ok(ssrRoute);
    assert.ok(userRoute);
    assert.ok(nativeRoute);
    assert.ok(chainRoute);
    assert.ok(fallbackRoute);

    assert.equal(rootRoute.staticFastPath, true);
    assert.equal(rootRoute.binaryBridge, true);
    assert.equal(rootRoute.bridgeObserved, false);

    assert.equal(stableRoute.staticFastPath, false);
    assert.equal(stableRoute.binaryBridge, true);
    assert.equal(stableRoute.bridgeObserved, true);
    assert.equal(stableRoute.cacheCandidate, true);
    assert.equal(stableRoute.hits, 32);
    assert.equal(stableRoute.recommendation, null);

    assert.equal(ssrRoute.staticFastPath, true);
    assert.equal(ssrRoute.binaryBridge, true);
    assert.equal(ssrRoute.bridgeObserved, false);

    assert.equal(userRoute.staticFastPath, false);
    assert.equal(userRoute.binaryBridge, true);
    assert.equal(userRoute.bridgeObserved, true);
    assert.equal(userRoute.cacheCandidate, false);
    assert.equal(userRoute.hits, 1);
    assert.equal(userRoute.dispatchKind, "specialized");
    assert.equal(userRoute.jsonFastPath, "generic");

    assert.equal(nativeRoute.staticFastPath, false);
    assert.equal(nativeRoute.bridgeObserved, false);
    assert.equal(nativeRoute.hits, 0);
    assert.equal(nativeRoute.dispatchKind, "specialized");
    assert.equal(nativeRoute.jsonFastPath, "specialized");

    assert.equal(chainRoute.dispatchKind, "specialized");
    assert.equal(chainRoute.jsonFastPath, "specialized");
    assert.equal(fallbackRoute.dispatchKind, "generic_fallback");
    assert.equal(fallbackRoute.jsonFastPath, "specialized");

    const summary = server.optimizations.summary();
    assert.match(summary, /GET \/ \[static-fast-path, binary-bridge\]/);
    assert.match(summary, /GET \/ssr \[static-fast-path, binary-bridge\]/);
    assert.match(summary, /GET \/stable \[bridge-dispatch, binary-bridge, bridge-observed, cache-candidate\]/);
    assert.match(summary, /GET \/users\/:id \[bridge-dispatch, binary-bridge, bridge-observed\]/);

    await Promise.resolve(server.close());
    closed = true;
  } finally {
    if (!closed) {
      await Promise.resolve(server.close());
    }
  }

  console.log("[http-native] test suite passed");
}

await main();
