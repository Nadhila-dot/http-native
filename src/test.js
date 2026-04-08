/**
 * http-native test utilities
 *
 * Provides a lightweight test client that spins up the app on an ephemeral
 * port and exposes fetch-style methods for integration testing.
 *
 * Usage:
 *   import { testClient } from "@http-native/core/test";
 *
 *   const client = await testClient(app);
 *   const res = await client.get("/users/1");
 *   expect(res.status).toBe(200);
 *   await client.close();
 */

/**
 * Create a test client bound to an ephemeral port.
 *
 * @param {import("./index.js").Application} app
 * @param {{ port?: number, host?: string }} [options]
 * @returns {Promise<TestClient>}
 */
export async function testClient(app, options = {}) {
  const port = options.port ?? 0;
  const host = options.host ?? "127.0.0.1";

  /* Start the server on an ephemeral port — the OS assigns a free one */
  let serverHandle;
  const baseUrl = await new Promise((resolve, reject) => {
    try {
      const builder = app.listen(port);
      if (typeof builder.host === "function") builder.host(host);
      builder.start((handle) => {
        serverHandle = handle;
        const addr = handle.address?.() ?? { port: handle.port ?? port };
        resolve(`http://${host}:${addr.port ?? port}`);
      });
    } catch (err) {
      reject(err);
    }
  });

  /**
   * @param {string} path
   * @param {RequestInit & { json?: unknown }} [init]
   */
  async function request(path, init = {}) {
    const url = `${baseUrl}${path}`;
    const headers = { ...init.headers };

    /* Convenience: if `json` is set, auto-serialize and set content-type */
    let body = init.body;
    if (init.json !== undefined) {
      body = JSON.stringify(init.json);
      headers["content-type"] = headers["content-type"] ?? "application/json";
    }

    const res = await fetch(url, { ...init, headers, body });

    /* Attach helper methods for easy assertion */
    const wrapped = {
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      ok: res.ok,
      /** Parse body as JSON */
      json: () => res.json(),
      /** Read body as text */
      text: () => res.text(),
      /** Access raw Response object */
      raw: res,
    };
    return wrapped;
  }

  return {
    /** Base URL the server is listening on (e.g. "http://127.0.0.1:54321") */
    baseUrl,

    /** Raw request — any method */
    request,

    /** GET helper */
    get: (path, init) => request(path, { ...init, method: "GET" }),

    /** POST helper */
    post: (path, init) => request(path, { ...init, method: "POST" }),

    /** PUT helper */
    put: (path, init) => request(path, { ...init, method: "PUT" }),

    /** PATCH helper */
    patch: (path, init) => request(path, { ...init, method: "PATCH" }),

    /** DELETE helper */
    delete: (path, init) => request(path, { ...init, method: "DELETE" }),

    /** Open a WebSocket connection */
    ws: (path) => {
      const wsUrl = baseUrl.replace(/^http/, "ws") + path;
      const ws = new WebSocket(wsUrl);
      return new Promise((resolve) => {
        const messages = [];
        let nextResolve = null;

        ws.onmessage = (event) => {
          if (nextResolve) {
            nextResolve(event.data);
            nextResolve = null;
          } else {
            messages.push(event.data);
          }
        };

        ws.onopen = () => {
          resolve({
            send: (data) => ws.send(data),
            /** Await the next message from the server */
            next: () =>
              messages.length > 0
                ? Promise.resolve(messages.shift())
                : new Promise((r) => { nextResolve = r; }),
            close: () => ws.close(),
            raw: ws,
          });
        };
      });
    },

    /** Shut down the test server */
    close: async () => {
      if (serverHandle) {
        if (typeof serverHandle.shutdown === "function") {
          await serverHandle.shutdown({ timeout: 2000 });
        } else if (typeof serverHandle.close === "function") {
          serverHandle.close();
        }
      }
    },
  };
}
