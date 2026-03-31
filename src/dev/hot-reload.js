import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import { catLog } from "../opt/notify.js";

const DEFAULT_DEBOUNCE_MS = 120;
const DEFAULT_STARTUP_IGNORE_MS = 250;

const IGNORED_SEGMENTS = new Set([
  "node_modules",
  ".git",
  "target",
  ".github/bench/results",
  ".http-native",
]);

export function normalizeWatchRoots(entryPath, roots) {
  const values =
    Array.isArray(roots) && roots.length > 0
      ? roots
      : [path.dirname(entryPath), path.resolve(process.cwd(), "rsrc/src")];

  return values
    .map((value) => path.resolve(process.cwd(), String(value)))
    .filter((value, index, all) => all.indexOf(value) === index)
    .filter((value) => existsSync(value));
}

export function createDevWatchController(options = {}) {
  const roots = normalizeWatchRoots(
    options.entryPath ?? path.resolve(process.cwd(), "src/index.js"),
    options.roots,
  );
  const debounceMs = normalizeDebounceMs(options.debounceMs);
  const startupIgnoreMs = normalizeDelayMs(
    options.startupIgnoreMs,
    DEFAULT_STARTUP_IGNORE_MS,
  );
  const onChange = typeof options.onChange === "function" ? options.onChange : () => {};
  const log = options.log ?? ((message) => catLog("warn", message));

  let watchReadyAt = Date.now() + startupIgnoreMs;
  let restartTimer = null;
  let pendingFile = null;
  let previousSnapshot = snapshotWatchedFiles(roots);
  const pollIntervalMs = Math.max(120, Math.min(debounceMs, 250));
  const pollTimer = setInterval(() => {
    if (Date.now() < watchReadyAt) {
      return;
    }

    const nextSnapshot = snapshotWatchedFiles(roots);
    const changedFile = diffSnapshots(previousSnapshot, nextSnapshot);
    previousSnapshot = nextSnapshot;

    if (!changedFile) {
      return;
    }

    pendingFile = changedFile;
    if (restartTimer) {
      clearTimeout(restartTimer);
    }
    restartTimer = setTimeout(() => {
      const file = pendingFile;
      pendingFile = null;
      void Promise.resolve(onChange(file)).catch((error) => {
        log(`[http-native][dev] reload callback failed: ${error.message}`);
      });
    }, debounceMs);
  }, pollIntervalMs);

  return {
    roots,
    refresh() {
      watchReadyAt = Date.now() + startupIgnoreMs;
      previousSnapshot = snapshotWatchedFiles(roots);
    },
    dispose() {
      if (restartTimer) {
        clearTimeout(restartTimer);
        restartTimer = null;
      }
      clearInterval(pollTimer);
    },
  };
}

export function createRuntimeHotReloadController(options = {}) {
  if (options.enabled !== true) {
    return {
      dispose() {},
    };
  }

  const roots = normalizeRuntimeWatchRoots(options.roots);
  const debounceMs = normalizeDebounceMs(options.debounceMs);
  const startupIgnoreMs = normalizeDelayMs(
    options.startupIgnoreMs,
    DEFAULT_STARTUP_IGNORE_MS,
  );
  const beforeRestart = options.beforeRestart ?? (async () => {});
  const beforeRestartTimeoutMs = normalizeDelayMs(options.beforeRestartTimeoutMs, 2500);
  const emit = (level, message) => {
    if (typeof options.log === "function") {
      options.log(message);
      return;
    }
    catLog(level, message);
  };

  let restarting = false;
  const watcher = createDevWatchController({
    roots,
    debounceMs,
    startupIgnoreMs,
    onChange: async (changedFile) => {
      if (restarting) {
        return;
      }

      restarting = true;
      emit("warn", `hot-reload change detected: ${changedFile}`);
      emit("info", "hot-reload restarting runtime process");
      watcher.dispose();
      await runBeforeRestart(beforeRestart, changedFile, beforeRestartTimeoutMs, emit);

      const argv = process.argv.slice(1);
      let child = null;
      try {
        child = spawn(process.execPath, argv, {
          cwd: process.cwd(),
          env: { ...process.env, HTTP_NATIVE_HOT_RELOAD: "1" },
          stdio: "inherit",
        });
        child.on("error", (error) => {
          emit("error", `hot-reload failed to respawn runtime: ${error.message}`);
        });
        if (typeof child.unref === "function") {
          child.unref();
        }
      } catch (error) {
        emit("error", `hot-reload failed to respawn runtime: ${error.message}`);
      }

      process.exit(child ? 0 : 1);
    },
    log(message) {
      emit("warn", message);
    },
  });

  emit(
    "success",
    `hot-reload enabled roots=${watcher.roots.length} debounce=${debounceMs}ms runtime=${process.release?.name ?? "unknown"}`,
  );

  return {
    roots: watcher.roots,
    dispose() {
      watcher.dispose();
    },
  };
}

function normalizeDebounceMs(value) {
  const normalized = Number(value);
  if (!Number.isFinite(normalized) || normalized <= 0) {
    return DEFAULT_DEBOUNCE_MS;
  }
  return Math.floor(normalized);
}

function normalizeDelayMs(value, fallback) {
  const normalized = Number(value);
  if (!Number.isFinite(normalized) || normalized < 0) {
    return fallback;
  }
  return Math.floor(normalized);
}

function shouldWatchFile(filePath) {
  const normalizedPath = filePath.replaceAll("\\", "/");

  if (normalizedPath.includes(".github/bench/results")) {
    return false;
  }

  const pathSegments = normalizedPath.split("/");
  for (const segment of pathSegments) {
    if (
      segment === "node_modules" ||
      segment === ".git" ||
      segment === "target" ||
      segment === ".http-native"
    ) {
      return false;
    }
  }

  return true;
}

function snapshotWatchedFiles(roots) {
  const snapshot = new Map();

  for (const root of roots) {
    collectWatchedFiles(root, snapshot);
  }

  return snapshot;
}

function collectWatchedFiles(targetPath, snapshot) {
  if (!existsSync(targetPath)) {
    return;
  }

  const stat = statSync(targetPath);
  if (stat.isDirectory()) {
    for (const entry of readdirSync(targetPath)) {
      collectWatchedFiles(path.join(targetPath, entry), snapshot);
    }
    return;
  }

  if (!shouldWatchFile(targetPath)) {
    return;
  }

  const fileBytes = readFileSync(targetPath);
  snapshot.set(
    targetPath,
    `${stat.mtimeMs}:${stat.size}:${hashBytes(fileBytes)}`,
  );
}

function diffSnapshots(previousSnapshot, nextSnapshot) {
  for (const [filePath, mtimeMs] of nextSnapshot) {
    if (previousSnapshot.get(filePath) !== mtimeMs) {
      return filePath;
    }
  }

  for (const filePath of previousSnapshot.keys()) {
    if (!nextSnapshot.has(filePath)) {
      return filePath;
    }
  }

  return null;
}

function hashBytes(bytes) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < bytes.length; index += 1) {
    hash ^= bytes[index];
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function normalizeRuntimeWatchRoots(roots) {
  const values =
    Array.isArray(roots) && roots.length > 0 ? roots : [process.cwd()];

  return values
    .map((value) => path.resolve(process.cwd(), String(value)))
    .filter((value, index, all) => all.indexOf(value) === index)
    .filter((value) => existsSync(value));
}

async function runBeforeRestart(beforeRestart, changedFile, timeoutMs, emit) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    try {
      await Promise.resolve(beforeRestart(changedFile));
    } catch (error) {
      emit("error", `hot-reload pre-restart cleanup failed: ${error.message}`);
    }
    return;
  }

  let timeoutId = null;
  try {
    await Promise.race([
      Promise.resolve(beforeRestart(changedFile)),
      new Promise((_, reject) => {
        timeoutId = setTimeout(() => {
          reject(new Error(`timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  } catch (error) {
    emit("error", `hot-reload pre-restart cleanup failed: ${error.message}`);
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
}
