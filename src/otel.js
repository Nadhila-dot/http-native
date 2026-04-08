/**
 * http-native OpenTelemetry integration middleware (DX-2.2)
 *
 * Emits W3C-compatible trace spans and request metrics.
 * Works standalone (collects & exports) or integrates with an existing
 * OpenTelemetry SDK setup.
 *
 * Usage:
 *   import { otel } from "@http-native/core/otel";
 *   app.use(otel({ serviceName: "my-api", endpoint: "http://collector:4317" }));
 */

import { randomBytes } from "node:crypto";

/**
 * @param {Object} options
 * @param {string} options.serviceName - Service name for trace/metric resource
 * @param {string} [options.endpoint] - OTLP collector endpoint (e.g. "http://localhost:4317")
 * @param {"w3c"|"b3"|"jaeger"} [options.propagation="w3c"] - Context propagation format
 * @param {number} [options.sampleRate=1.0] - Fraction of requests to trace (0.0 - 1.0)
 * @param {(spans: Object[]) => void} [options.exporter] - Custom span exporter function
 * @param {boolean} [options.metrics=true] - Enable request metrics collection
 * @param {number} [options.metricsInterval=60000] - Metrics flush interval in ms
 */
export function otel(options = {}) {
  const {
    serviceName = "http-native",
    propagation = "w3c",
    sampleRate = 1.0,
    exporter,
    metrics: enableMetrics = true,
    metricsInterval = 60000,
  } = options;

  /* Metrics accumulators */
  const counters = { requests: 0, errors: 0, rateLimitRejections: 0 };
  const histograms = { duration: [] };
  const statusCounts = Object.create(null);
  const methodCounts = Object.create(null);

  /* Span buffer for batch export */
  const spanBuffer = [];
  const MAX_SPAN_BUFFER = 512;

  /* Periodic metrics flush */
  let metricsTimer;
  if (enableMetrics && exporter) {
    metricsTimer = setInterval(() => {
      flushMetrics(exporter, serviceName, counters, histograms, statusCounts, methodCounts);
    }, metricsInterval);
    if (metricsTimer.unref) metricsTimer.unref();
  }

  const middleware = async function otelMiddleware(req, res, next) {
    /* Extract or generate trace context */
    const parentCtx = extractTraceContext(req, propagation);
    const sampled = Math.random() < sampleRate;

    const traceId = parentCtx.traceId || generateTraceId();
    const spanId = generateSpanId();
    const parentSpanId = parentCtx.spanId || null;

    /* Attach trace context to request for downstream use */
    req.traceId = traceId;
    req.spanId = spanId;

    const start = performance.now();
    let error = null;

    try {
      await next();
    } catch (err) {
      error = err;
      throw err;
    } finally {
      const duration = performance.now() - start;
      const status = res._state?.status ?? (error ? 500 : 200);

      /* Inject trace context into response headers */
      injectTraceContext(res, propagation, traceId, spanId, sampled);

      /* Build span */
      if (sampled) {
        const span = {
          traceId,
          spanId,
          parentSpanId,
          operationName: "http.request",
          serviceName,
          startTime: Date.now() - duration,
          duration: Math.round(duration * 1000) / 1000,
          tags: {
            "http.method": req.method,
            "http.url": req.path,
            "http.status_code": status,
            "http.route": req._matchedRoute || req.path,
          },
          status: error ? "ERROR" : "OK",
        };

        if (error) {
          span.tags["error.message"] = error.message;
          span.tags["error.type"] = error.constructor.name;
        }

        if (req.id) span.tags["http.request_id"] = req.id;

        spanBuffer.push(span);
        if (spanBuffer.length >= MAX_SPAN_BUFFER && exporter) {
          const batch = spanBuffer.splice(0, spanBuffer.length);
          exporter(batch);
        }
      }

      /* Metrics */
      if (enableMetrics) {
        counters.requests++;
        if (status >= 500) counters.errors++;
        statusCounts[status] = (statusCounts[status] || 0) + 1;
        methodCounts[req.method] = (methodCounts[req.method] || 0) + 1;
        histograms.duration.push(duration);
        /* Keep histogram bounded */
        if (histograms.duration.length > 10000) histograms.duration.splice(0, 5000);
      }
    }
  };

  /** Flush pending spans — exposed for graceful shutdown. */
  middleware.flushSpans = () => {
    if (spanBuffer.length > 0 && exporter) {
      const batch = spanBuffer.splice(0, spanBuffer.length);
      exporter(batch);
    }
  };

  /** Access the current span buffer length. */
  middleware.pendingSpans = () => spanBuffer.length;

  return middleware;
}

/**
 * Flush pending spans to the exporter.
 * Call this on graceful shutdown to ensure no spans are lost.
 *
 * @param {Function} middleware - The otel middleware returned by otel()
 */
export function flushSpans(middleware) {
  if (typeof middleware?.flushSpans === "function") {
    middleware.flushSpans();
  }
}

/* ─── Trace Context Propagation ─── */

function extractTraceContext(req, format) {
  const get = (name) => req.header?.(name) ?? req.headers?.[name] ?? "";

  if (format === "w3c") {
    /* W3C Trace Context: traceparent header */
    const tp = get("traceparent");
    const match = tp.match(/^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/);
    if (match) {
      return { traceId: match[1], spanId: match[2], sampled: match[3] === "01" };
    }
  } else if (format === "b3") {
    /* B3 single-header or multi-header */
    const single = get("b3");
    if (single) {
      const parts = single.split("-");
      return { traceId: parts[0], spanId: parts[1], sampled: parts[2] !== "0" };
    }
    const traceId = get("x-b3-traceid");
    const spanId = get("x-b3-spanid");
    if (traceId && spanId) {
      return { traceId, spanId, sampled: get("x-b3-sampled") !== "0" };
    }
  } else if (format === "jaeger") {
    /* Jaeger uber-trace-id: {trace-id}:{span-id}:{parent-span-id}:{flags} */
    const uber = get("uber-trace-id");
    const parts = uber.split(":");
    if (parts.length >= 4) {
      return { traceId: parts[0], spanId: parts[1], sampled: parts[3] !== "0" };
    }
  }

  return { traceId: null, spanId: null, sampled: true };
}

function injectTraceContext(res, format, traceId, spanId, sampled) {
  if (format === "w3c") {
    res.set("traceparent", `00-${traceId}-${spanId}-${sampled ? "01" : "00"}`);
  } else if (format === "b3") {
    res.set("b3", `${traceId}-${spanId}-${sampled ? "1" : "0"}`);
  } else if (format === "jaeger") {
    res.set("uber-trace-id", `${traceId}:${spanId}:0:${sampled ? "1" : "0"}`);
  }
}

/* ─── ID Generation ─── */

function generateTraceId() {
  return randomBytes(16).toString("hex");
}

function generateSpanId() {
  return randomBytes(8).toString("hex");
}

/* ─── Metrics Flush ─── */

function flushMetrics(exporter, serviceName, counters, histograms, statusCounts, methodCounts) {
  if (counters.requests === 0) return;

  const durations = histograms.duration;
  const sorted = durations.slice().sort((a, b) => a - b);
  const p50 = sorted[Math.floor(sorted.length * 0.5)] ?? 0;
  const p95 = sorted[Math.floor(sorted.length * 0.95)] ?? 0;
  const p99 = sorted[Math.floor(sorted.length * 0.99)] ?? 0;

  const metricsSpan = {
    traceId: generateTraceId(),
    spanId: generateSpanId(),
    operationName: "metrics.flush",
    serviceName,
    startTime: Date.now(),
    duration: 0,
    tags: {
      "metric.type": "summary",
      "http.request.count": counters.requests,
      "http.error.count": counters.errors,
      "http.request.duration.p50": Math.round(p50 * 1000) / 1000,
      "http.request.duration.p95": Math.round(p95 * 1000) / 1000,
      "http.request.duration.p99": Math.round(p99 * 1000) / 1000,
      "http.status_counts": { ...statusCounts },
      "http.method_counts": { ...methodCounts },
    },
    status: "OK",
  };

  exporter([metricsSpan]);

  /* Reset accumulators */
  counters.requests = 0;
  counters.errors = 0;
  histograms.duration.length = 0;
  for (const k in statusCounts) delete statusCounts[k];
  for (const k in methodCounts) delete methodCounts[k];
}
