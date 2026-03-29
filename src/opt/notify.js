// cat-loggr-style logger (native ANSI, no dependencies)
const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",

  // Foreground colors
  black: "\x1b[30m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
  
  // Background colors
  bgBlack: "\x1b[40m",
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
  bgBlue: "\x1b[44m",
  bgMagenta: "\x1b[45m",
  bgCyan: "\x1b[46m",
};

const ANSI_256 = {
  fg: (code) => `\x1b[38;5;${code}m`,
  bg: (code) => `\x1b[48;5;${code}m`,
};

// Log level styles mimicking cat-loggr
const LOG_LEVELS = {
  debug: { bg: ANSI.bgBlue, fg: ANSI.white, label: "debug" },
  info: { bg: ANSI.bgBlue, fg: ANSI.white, label: "info" },
  success: { bg: ANSI.bgGreen, fg: ANSI.white, label: "success" },
  warn: { bg: ANSI.bgYellow, fg: ANSI.black, label: "warn" },
  error: { bg: ANSI.bgRed, fg: ANSI.white, label: "error" },
};

function pad(num, width = 2) {
  return String(num).padStart(width, "0");
}

function getTimestamp() {
  const now = new Date();
  const month = pad(now.getMonth() + 1);
  const day = pad(now.getDate());
  const hours = pad(now.getHours());
  const minutes = pad(now.getMinutes());
  const seconds = pad(now.getSeconds());
  return `${month}/${day} ${hours}:${minutes}:${seconds}`;
}

function formatLog(level, message) {
  const style = LOG_LEVELS[level] || LOG_LEVELS.info;
  const timestamp = getTimestamp();

  const timestampBadge = `${ANSI_256.bg(229)}${ANSI_256.fg(238)} ${timestamp} ${ANSI.reset}`;
  const levelBadge = `${style.bg}${style.fg} ${style.label.padEnd(7, " ")} ${ANSI.reset}`;
  const separator = `${ANSI.dim}${ANSI_256.fg(245)}||${ANSI.reset}`;

  return `${timestampBadge}${levelBadge} ${separator} ${message}`;
}

function log(level, message) {
  console.log(formatLog(level, message));
}

export function createOptimizerNotifier(routeEntries, enabled, intervalMs) {
  if (!enabled) {
    return {
      markDirty() {},
      printStartup() {},
      maybeNotify(_entry, _message) {},
      dispose() {},
    };
  }

  let dirty = false;
  const timer =
    intervalMs > 0
      ? setInterval(() => {
          if (!dirty) {
            return;
          }
          dirty = false;
          printLiveRouteHits(routeEntries);
        }, intervalMs)
      : null;

  if (timer && typeof timer.unref === "function") {
    timer.unref();
  }

  return {
    markDirty() {
      dirty = true;
    },
    printStartup() {
      log("success", `http-native optimizer enabled (interval=${intervalMs}ms)`);
      printRouteCatalog(routeEntries);
    },
    maybeNotify(_entry, message) {
      log("info", message);
    },
    dispose() {
      if (timer) {
        clearInterval(timer);
      }
    },
  };
}

export function normalizeNotifyInterval(value, fallback) {
  const normalized = Number(value);
  if (!Number.isFinite(normalized) || normalized <= 0) {
    return fallback;
  }
  return Math.floor(normalized);
}

function printRouteCatalog(routeEntries) {
  if (routeEntries.length === 0) {
    log("warn", "no routes registered");
    return;
  }

  log("info", "Route information / Tracking:");
  for (const entry of routeEntries) {
    log("debug", `${ANSI.magenta}${entry.label}${ANSI.reset} staticFastPath=${entry.staticFastPath} dispatch=${entry.dispatchKind}`);
  }
}

function printLiveRouteHits(routeEntries) {
  const active = routeEntries.filter((entry) => entry.hits > 0);
  if (active.length === 0) {
    log("warn", "no bridge-dispatch hits yet (static fast path bypasses JS dispatch counters)");
    return;
  }

  // this is not needed just makes things ugly
  //log("info", "Router & Routes:");
  for (const entry of active.sort((a, b) => b.hits - a.hits)) {
    const intervalHits = entry.hits - entry.lastIntervalHits;
    const intervalDurationMs = entry.totalDurationMs - entry.lastIntervalDurationMs;
    const avgMs = entry.hits > 0 ? entry.totalDurationMs / entry.hits : 0;
    const intervalAvgMs =
      intervalHits > 0 ? intervalDurationMs / intervalHits : 0;

    log(
      "success",
      `${ANSI.magenta}${entry.label}${ANSI.reset} total=${entry.hits} +${intervalHits} avg=${formatMs(avgMs)} last=${formatMs(entry.lastDurationMs)} max=${formatMs(entry.maxDurationMs)} intervalAvg=${formatMs(intervalAvgMs)}`,
    );
    entry.lastIntervalHits = entry.hits;
    entry.lastIntervalDurationMs = entry.totalDurationMs;
  }
}

function formatMs(value) {
  if (!Number.isFinite(value) || value <= 0) {
    return "0.00ms";
  }
  return `${value.toFixed(2)}ms`;
}
