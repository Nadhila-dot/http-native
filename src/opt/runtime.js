import { Buffer } from "node:buffer";

import {
  DEFAULT_NOTIFY_INTERVAL_MS,
  HOT_HIT_THRESHOLD,
  STABLE_RESPONSE_THRESHOLD,
} from "./constants.js";
import { buildRouteEntry } from "./entry.js";
import {
  createOptimizerNotifier,
  normalizeNotifyInterval,
} from "./notify.js";
import { snapshotRouteEntries, summarizeRouteEntries } from "./summary.js";

export function createRuntimeOptimizer(routes, middlewares, options = {}) {
  const notifyEnabled =
    options.notify === true || process.env.HTTP_NATIVE_OPT_NOTIFY === "1";
  const notifyIntervalMs = normalizeNotifyInterval(
    options.notifyIntervalMs,
    DEFAULT_NOTIFY_INTERVAL_MS,
  );

  const routeEntries = routes.map((route) => buildRouteEntry(route, middlewares));
  const routesByHandlerId = new Map(
    routeEntries.map((entry) => [entry.handlerId, entry]),
  );
  const notifier = createOptimizerNotifier(
    routeEntries,
    notifyEnabled,
    notifyIntervalMs,
  );
  notifier.printStartup();

  return {
    recordDispatch(route, _request, snapshot) {
      const entry = routesByHandlerId.get(route.handlerId);
      if (!entry || entry.settled) {
        return;
      }

      entry.hits += 1;
      entry.bridgeObserved = true;
      notifier.markDirty();

      if (entry.stage === "cold") {
        if (entry.hits >= HOT_HIT_THRESHOLD) {
          entry.stage = "hot";
          entry.lastHitAt = Date.now();
          notifier.maybeNotify(
            entry,
            entry.staticFastPath
              ? `${entry.label} is serving from the static fast path`
              : `${entry.label} is hot on bridge dispatch`,
          );

          if (!entry.cacheCandidate) {
            entry.settled = true;
          }
        }
        return;
      }

      if (!entry.cacheCandidate) {
        entry.settled = true;
        return;
      }

      const responseKey = buildResponseKey(snapshot);
      if (entry.lastResponseKey === responseKey) {
        entry.stableResponses += 1;
      } else {
        entry.lastResponseKey = responseKey;
        entry.stableResponses = 1;
      }

      if (
        entry.recommendation === null &&
        entry.stableResponses >= STABLE_RESPONSE_THRESHOLD
      ) {
        entry.recommendation = "cache-candidate";
        entry.settled = true;
        entry.lastHitAt = Date.now();
        notifier.maybeNotify(
          entry,
          `${entry.label} looks stable at runtime; cached values may be safe`,
        );
      }
    },

    snapshot() {
      return snapshotRouteEntries(routeEntries);
    },

    summary() {
      return summarizeRouteEntries(routeEntries);
    },

    dispose() {
      notifier.dispose();
    },
  };
}

// Faster key than JSON.stringify + base64 on every dispatch.
function buildResponseKey(snapshot) {
  let hash = 0x811c9dc5;
  hash = fnv1aString(hash, String(snapshot.status ?? 200));

  const headers = snapshot.headers ?? Object.create(null);
  const headerNames = Object.keys(headers);
  for (const name of headerNames) {
    hash = fnv1aString(hash, name);
    hash = fnv1aString(hash, String(headers[name]));
  }

  const body = Buffer.isBuffer(snapshot.body)
    ? snapshot.body
    : snapshot.body instanceof Uint8Array
      ? snapshot.body
      : Buffer.alloc(0);
  hash = fnv1aBytes(hash, body);

  return `${hash}:${body.length}:${headerNames.length}`;
}

function fnv1aString(seed, value) {
  let hash = seed >>> 0;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function fnv1aBytes(seed, bytes) {
  let hash = seed >>> 0;
  for (let index = 0; index < bytes.length; index += 1) {
    hash ^= bytes[index];
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}
