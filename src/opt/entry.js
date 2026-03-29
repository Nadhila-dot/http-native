export function buildRouteEntry(route, middlewares) {
  const hasParams = route.path.includes(":");
  const hasMiddleware = middlewares.some((middleware) =>
    pathPrefixMatches(middleware.pathPrefix, route.path),
  );
  const source = route.handlerSource ?? "";
  const staticFastPath = isStaticFastPathCandidate(route, hasMiddleware, source);
  const cacheCandidate =
    !staticFastPath &&
    route.method === "GET" &&
    !hasParams &&
    !hasMiddleware &&
    !source.includes("await") &&
    !/req\.(params|query|body|headers|url|path|method)\b/.test(source) &&
    !/Date\.now|new Date|Math\.random|crypto\./.test(source);

  const reasons = [];
  if (staticFastPath) {
    reasons.push("served by static fast path");
  } else {
    reasons.push("served through bridge dispatch");
  }
  if (hasMiddleware) {
    reasons.push("middleware blocks static promotion");
  }
  if (hasParams) {
    reasons.push("route params require dynamic dispatch");
  }
  if (cacheCandidate) {
    reasons.push("runtime-stable responses can be cached later");
  }

  return {
    handlerId: route.handlerId,
    method: route.method,
    path: route.path,
    label: `${route.method} ${route.path}`,
    stage: "cold",
    hits: 0,
    lastHitAt: null,
    staticFastPath,
    binaryBridge: true,
    dispatchKind: route.dispatchKind ?? "generic_fallback",
    jsonFastPath: route.jsonFastPath ?? "fallback",
    bridgeObserved: false,
    cacheCandidate,
    recommendation: null,
    reasons,
    stableResponses: 0,
    lastResponseKey: null,
    settled: false,
    totalDurationMs: 0,
    maxDurationMs: 0,
    lastDurationMs: 0,
    lastIntervalHits: 0,
    lastIntervalDurationMs: 0,
  };
}

function isStaticFastPathCandidate(route, hasMiddleware, source) {
  if (route.method !== "GET" || route.path.includes(":") || hasMiddleware) {
    return false;
  }

  if (source.includes("await")) {
    return false;
  }

  const body = trimReturnAndSemicolon(extractFunctionBody(source));
  if (!body) {
    return false;
  }

  return (
    isDirectLiteralCall(body, "res.json(") ||
    isDirectLiteralCall(body, "res.send(") ||
    isDirectStatusLiteralCall(body, "json") ||
    isDirectStatusLiteralCall(body, "send")
  );
}

function extractFunctionBody(source) {
  const arrowIndex = source.indexOf("=>");
  if (arrowIndex >= 0) {
    const right = source.slice(arrowIndex + 2).trim();
    if (right.startsWith("{") && right.endsWith("}")) {
      return right.slice(1, -1).trim();
    }
    return right;
  }

  const blockStart = source.indexOf("{");
  const blockEnd = source.lastIndexOf("}");
  if (blockStart >= 0 && blockEnd > blockStart) {
    return source.slice(blockStart + 1, blockEnd).trim();
  }

  return source.trim();
}

function trimReturnAndSemicolon(body) {
  let value = body.trim();
  if (value.startsWith("return ")) {
    value = value.slice("return ".length).trim();
  }
  if (value.endsWith(";")) {
    value = value.slice(0, -1).trim();
  }
  return value;
}

function isDirectLiteralCall(body, prefix) {
  if (!body.startsWith(prefix) || !body.endsWith(")")) {
    return false;
  }

  const payload = body.slice(prefix.length, -1).trim();
  return looksLiteralPayload(payload);
}

function isDirectStatusLiteralCall(body, method) {
  if (!body.startsWith("res.status(") || !body.endsWith(")")) {
    return false;
  }

  const separator = `).${method}(`;
  const separatorIndex = body.indexOf(separator);
  if (separatorIndex < 0) {
    return false;
  }

  const payload = body.slice(separatorIndex + separator.length, -1).trim();
  return looksLiteralPayload(payload);
}

function looksLiteralPayload(payload) {
  if (!payload) {
    return false;
  }

  if (
    payload.startsWith("{") ||
    payload.startsWith("[") ||
    payload.startsWith('"') ||
    payload.startsWith("'") ||
    payload.startsWith("`")
  ) {
    return true;
  }

  if (/^-?\d/.test(payload)) {
    return true;
  }

  return payload === "true" || payload === "false" || payload === "null";
}

function pathPrefixMatches(pathPrefix, requestPath) {
  if (pathPrefix === "/") {
    return true;
  }

  return requestPath === pathPrefix || requestPath.startsWith(`${pathPrefix}/`);
}
