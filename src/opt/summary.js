export function summarizeRouteEntries(routeEntries) {
  return routeEntries
    .map((entry) => {
      const flags = [];
      if (entry.staticFastPath) {
        flags.push("static-fast-path");
      } else {
        flags.push("bridge-dispatch");
      }
      if (entry.binaryBridge) {
        flags.push("binary-bridge");
      }
      if (entry.bridgeObserved) {
        flags.push("bridge-observed");
      }
      if (entry.cacheCandidate) {
        flags.push("cache-candidate");
      }
      if (entry.recommendation) {
        flags.push(entry.recommendation);
      }
      const uniqueFlags = [...new Set(flags)];
      return `${entry.label} [${uniqueFlags.join(", ")}] hits=${entry.hits}`;
    })
    .join("\n");
}

export function snapshotRouteEntries(routeEntries) {
  return {
    generatedAt: new Date().toISOString(),
    routes: routeEntries.map((entry) => ({
      method: entry.method,
      path: entry.path,
      label: entry.label,
      stage: entry.stage,
      hits: entry.hits,
      staticFastPath: entry.staticFastPath,
      binaryBridge: entry.binaryBridge,
      dispatchKind: entry.dispatchKind,
      jsonFastPath: entry.jsonFastPath,
      bridgeObserved: entry.bridgeObserved,
      cacheCandidate: entry.cacheCandidate,
      recommendation: entry.recommendation,
      reasons: [...entry.reasons],
      lastHitAt: entry.lastHitAt,
    })),
  };
}
