/**
 * http-native hot reloading.
 *
 * Watches source files for changes, gracefully shuts down the Rust server,
 * re-imports the app module, and restarts — preserving the same port.
 *
 * Usage:
 *   // server.js
 *   import { createApp } from "http-native";
 *   const app = createApp();
 *   app.get("/", (req, res) => res.json({ ok: true }));
 *   export default app;
 *
 *   // dev.js
 *   import { hot } from "http-native/hot";
 *   hot("./server.js", { port: 3000 });
 *
 * Or run directly:
 *   bun run --hot src/hot.js ./server.js
 */

import { watch } from "node:fs";
import { resolve, dirname, extname } from "node:path";
import { pathToFileURL } from "node:url";

const DEBOUNCE_MS = 100;
const WATCHABLE_EXTENSIONS = new Set([".js", ".ts", ".mjs", ".mts", ".json"]);

/**
 * Start a hot-reloading dev server.
 *
 * @param {string} appModulePath   - Path to the module that exports the app (default export)
 * @param {Object} [options]
 * @param {number} [options.port]  - Port to listen on (default 3000)
 * @param {string} [options.host]  - Host to bind (default "127.0.0.1")
 * @param {string|string[]} [options.watch] - Directories/files to watch (default: app module's directory)
 * @param {boolean} [options.clear] - Clear console on reload (default true)
 * @param {Function} [options.onReload] - Callback after successful reload
 * @param {Function} [options.onError]  - Callback on reload error
 */
export async function hot(appModulePath, options = {}) {
  const absolutePath = resolve(process.cwd(), appModulePath);
  const port = options.port ?? 3000;
  const host = options.host ?? "127.0.0.1";
  const clearConsole = options.clear ?? true;
  const onReload = options.onReload ?? null;
  const onError = options.onError ?? null;

  // Determine watch directories
  const watchPaths = options.watch
    ? Array.isArray(options.watch)
      ? options.watch.map((p) => resolve(process.cwd(), p))
      : [resolve(process.cwd(), options.watch)]
    : [dirname(absolutePath)];

  let currentServer = null;
  let reloadVersion = 0;
  let debounceTimer = null;
  let isReloading = false;

  /**
   * Load (or reload) the app module and start the server.
   */
  async function loadAndStart() {
    const version = ++reloadVersion;

    // Gracefully close the existing server and wait for port release
    if (currentServer) {
      try {
        await currentServer.close();
      } catch (err) {
        // Server may already be closed
      }
      currentServer = null;
      // Wait for the OS to release the port
      await new Promise((r) => setTimeout(r, 200));
    }

    try {
      // Intercept self-starting modules: set a global flag that index.js can check
      // to override the port and capture the server handle.
      globalThis.__HTTP_NATIVE_HOT__ = { port, host, server: null };

      // Bust the module cache by appending a query param
      const moduleUrl = `${pathToFileURL(absolutePath).href}?v=${version}`;
      const mod = await import(moduleUrl);

      // Wait for any microtask-queued or setTimeout-deferred app.listen() to complete
      await new Promise((r) => setTimeout(r, 100));

      // Check if the module self-started (called app.listen() during import)
      const hotCtx = globalThis.__HTTP_NATIVE_HOT__;
      if (hotCtx?.server) {
        currentServer = hotCtx.server;
      } else {
        // Module exports the app without calling listen()
        const app = mod.default ?? mod.app ?? mod;

        if (app && typeof app.listen === "function") {
          currentServer = await app.listen({
            port,
            host,
            opt: { notify: false },
          });
        } else {
          // Nothing worked — the module probably self-started but we missed
          // the capture. This can happen if listen() failed silently.
          throw new Error(
            `Hot reload failed: the module did not export an app or start a server on port ${port}.\n` +
              `Either add \`export default app\` to your file, or check for startup errors above.`,
          );
        }
      }

      globalThis.__HTTP_NATIVE_HOT__ = null;

      if (clearConsole && version > 1) {
        console.clear();
      }

      const reloadTag = version > 1 ? ` (reload #${version - 1})` : "";
      console.log(
        `\x1b[32m[hot]\x1b[0m Server running at ${currentServer.url}${reloadTag}`,
      );

      if (onReload && version > 1) {
        onReload(currentServer);
      }
    } catch (error) {
      console.error(`\x1b[31m[hot]\x1b[0m Failed to start server:`, error);
      if (onError) {
        onError(error);
      }
      // Don't crash — wait for the next file change to retry
    } finally {
      isReloading = false;
    }
  }

  /**
   * Debounced reload triggered by file changes.
   */
  function scheduleReload(filename) {
    if (isReloading) return;

    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      isReloading = true;
      console.log(
        `\x1b[33m[hot]\x1b[0m File changed: ${filename ?? "unknown"} — reloading...`,
      );
      loadAndStart();
    }, DEBOUNCE_MS);
  }

  // Start watching files
  const watchers = [];
  for (const watchPath of watchPaths) {
    try {
      const watcher = watch(watchPath, { recursive: true }, (event, filename) => {
        if (!filename) return;

        // Only reload for relevant file types
        const ext = extname(filename).toLowerCase();
        if (!WATCHABLE_EXTENSIONS.has(ext)) return;

        // Ignore node_modules and build artifacts
        if (
          filename.includes("node_modules") ||
          filename.includes(".node") ||
          filename.includes("target/")
        ) {
          return;
        }

        scheduleReload(filename);
      });

      watchers.push(watcher);
    } catch (err) {
      console.warn(`\x1b[33m[hot]\x1b[0m Could not watch ${watchPath}:`, err.message);
    }
  }

  // Cleanup on exit
  function cleanup() {
    for (const w of watchers) {
      try {
        w.close();
      } catch {}
    }
    if (currentServer) {
      try {
        currentServer.close();
      } catch {}
    }
  }

  process.on("SIGINT", () => {
    console.log("\n\x1b[32m[hot]\x1b[0m Shutting down...");
    cleanup();
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    cleanup();
    process.exit(0);
  });

  // Initial load
  await loadAndStart();

  return {
    /** Manually trigger a reload */
    reload() {
      scheduleReload("manual");
    },
    /** Stop watching and close the server */
    close() {
      cleanup();
    },
  };
}

// ─── CLI Entry Point ──────────────────────
//
// Allow running directly: bun src/hot.js ./server.js [--port 3000]

const isMain =
  typeof process !== "undefined" &&
  process.argv[1] &&
  (process.argv[1].endsWith("/hot.js") || process.argv[1].endsWith("\\hot.js"));

if (isMain) {
  const args = process.argv.slice(2);
  let appPath = null;
  let port = 3000;
  let host = "127.0.0.1";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--port" && args[i + 1]) {
      port = Number(args[i + 1]);
      i++;
    } else if (args[i] === "--host" && args[i + 1]) {
      host = args[i + 1];
      i++;
    } else if (!args[i].startsWith("-")) {
      appPath = args[i];
    }
  }

  if (!appPath) {
    console.error("Usage: bun src/hot.js <app-module> [--port 3000] [--host 127.0.0.1]");
    process.exit(1);
  }

  hot(appPath, { port, host });
}
