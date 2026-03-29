import { spawn } from "node:child_process";
import { existsSync, watch } from "node:fs";
import path from "node:path";

const DEFAULT_WATCH_ROOTS = ["src", "rsrc/src", ".github/tests"];
const DEFAULT_DEBOUNCE_MS = 120;
const WATCHED_EXTENSIONS = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".rs",
  ".toml",
  ".json",
]);

const IGNORED_SEGMENTS = new Set([
  "node_modules",
  ".git",
  "target",
  ".github/bench/results",
  ".http-native",
]);

export function createHotReloadController(options = {}) {
  if (options.enabled !== true) {
    return {
      dispose() {},
    };
  }

  const roots = normalizeWatchRoots(options.roots);
  const debounceMs = normalizeDebounceMs(options.debounceMs);
  const log = options.log ?? ((message) => console.log(message));
  const beforeRestart = options.beforeRestart ?? (async () => {});

  const watchers = [];
  let restartTimer = null;
  let restartPendingFile = "";
  let restarting = false;

  for (const root of roots) {
    if (!existsSync(root)) {
      continue;
    }

    try {
      const watcher = watch(
        root,
        { recursive: true },
        (_eventType, filename) => {
          if (restarting) {
            return;
          }
          const changedFile = filename
            ? path.resolve(root, String(filename))
            : root;
          if (!shouldWatchFile(changedFile)) {
            return;
          }
          restartPendingFile = changedFile;
          if (restartTimer) {
            clearTimeout(restartTimer);
          }
          restartTimer = setTimeout(() => {
            void restartProcess();
          }, debounceMs);
        },
      );
      watchers.push(watcher);
    } catch (error) {
      log(
        `[http-native][hot-reload] failed to watch ${root}: ${error.message}`,
      );
    }
  }

  if (watchers.length === 0) {
    log("[http-native][hot-reload] no watch roots available; disabled");
    return {
      dispose() {},
    };
  }

  log(
    `[http-native][hot-reload] enabled (${watchers.length} roots, debounce=${debounceMs}ms)`,
  );

  async function restartProcess() {
    if (restarting) {
      return;
    }
    restarting = true;
    stopWatching();

    const changedFile = restartPendingFile || "unknown file";
    log(`[http-native][hot-reload] change detected: ${changedFile}`);
    log("[http-native][hot-reload] restarting process...");

    try {
      await beforeRestart(changedFile);
    } catch (error) {
      log(`[http-native][hot-reload] pre-restart cleanup failed: ${error.message}`);
    }

    const argv = process.argv.slice(1);
    const child = spawn(process.execPath, argv, {
      cwd: process.cwd(),
      env: { ...process.env, HTTP_NATIVE_HOT_RELOAD: "1" },
      stdio: "inherit",
    });

    child.on("error", (error) => {
      log(`[http-native][hot-reload] failed to respawn: ${error.message}`);
    });

    process.exit(0);
  }

  function stopWatching() {
    if (restartTimer) {
      clearTimeout(restartTimer);
      restartTimer = null;
    }
    for (const watcher of watchers) {
      try {
        watcher.close();
      } catch {
        // ignore
      }
    }
    watchers.length = 0;
  }

  return {
    dispose() {
      stopWatching();
    },
  };
}

function normalizeWatchRoots(roots) {
  const values =
    Array.isArray(roots) && roots.length > 0 ? roots : DEFAULT_WATCH_ROOTS;
  return values
    .map((value) => path.resolve(process.cwd(), String(value)))
    .filter((value, index, all) => all.indexOf(value) === index);
}

function normalizeDebounceMs(value) {
  const normalized = Number(value);
  if (!Number.isFinite(normalized) || normalized <= 0) {
    return DEFAULT_DEBOUNCE_MS;
  }
  return Math.floor(normalized);
}

function shouldWatchFile(filePath) {
  const normalizedPath = filePath.replaceAll("\\", "/");
  for (const segment of IGNORED_SEGMENTS) {
    if (normalizedPath.includes(segment)) {
      return false;
    }
  }

  const extension = path.extname(filePath).toLowerCase();
  return WATCHED_EXTENSIONS.has(extension);
}
