/**
 * http-native circuit breaker
 *
 * Protects downstream services from cascading failures using the
 * closed → open → half-open state machine.
 *
 * Usage:
 *   import { circuitBreaker } from "@http-native/core/circuit-breaker";
 *
 *   const dbBreaker = circuitBreaker({ name: "database", threshold: 5, timeout: 30000 });
 *   const result = await dbBreaker.call(() => db.query("SELECT 1"));
 */

const STATE_CLOSED = "closed";
const STATE_OPEN = "open";
const STATE_HALF_OPEN = "half-open";

/**
 * @param {Object} options
 * @param {string} options.name                 - Circuit name (for logging/metrics)
 * @param {number} [options.threshold=5]        - Consecutive failures before opening
 * @param {number} [options.timeout=30000]      - ms in open state before half-open probe
 * @param {number} [options.halfOpenMax=1]      - Max concurrent requests in half-open state
 * @param {Function} [options.onOpen]           - Called when circuit opens
 * @param {Function} [options.onHalfOpen]       - Called when circuit transitions to half-open
 * @param {Function} [options.onClose]          - Called when circuit closes (healthy again)
 * @param {Function} [options.isFailure]        - Custom failure detection (default: any thrown error)
 */
export function circuitBreaker(options) {
  const {
    name,
    threshold = 5,
    timeout = 30000,
    halfOpenMax = 1,
    onOpen,
    onHalfOpen,
    onClose,
    isFailure = () => true,
  } = options;

  if (!name) throw new Error("Circuit breaker requires a name");

  let state = STATE_CLOSED;
  let failureCount = 0;
  let lastFailureTime = 0;
  let halfOpenActive = 0;

  function trip() {
    if (state === STATE_OPEN) return;
    state = STATE_OPEN;
    lastFailureTime = Date.now();
    if (typeof onOpen === "function") {
      try { onOpen(); } catch { /* lifecycle callback failure must not propagate */ }
    }
  }

  function reset() {
    failureCount = 0;
    halfOpenActive = 0;
    if (state !== STATE_CLOSED) {
      state = STATE_CLOSED;
      if (typeof onClose === "function") {
        try { onClose(); } catch { /* lifecycle callback failure must not propagate */ }
      }
    }
  }

  function tryHalfOpen() {
    if (state !== STATE_OPEN) return false;
    if (Date.now() - lastFailureTime < timeout) return false;
    if (halfOpenActive >= halfOpenMax) return false;

    if (state !== STATE_HALF_OPEN) {
      state = STATE_HALF_OPEN;
      if (typeof onHalfOpen === "function") {
        try { onHalfOpen(); } catch { /* lifecycle callback failure must not propagate */ }
      }
    }
    halfOpenActive++;
    return true;
  }

  return {
    get name() { return name; },
    get state() { return state; },
    get failureCount() { return failureCount; },

    /**
     * Execute a function through the circuit breaker.
     *
     * @template T
     * @param {() => Promise<T>} fn
     * @returns {Promise<T>}
     */
    async call(fn) {
      /* Closed — allow the call */
      if (state === STATE_CLOSED) {
        try {
          const result = await fn();
          failureCount = 0;
          return result;
        } catch (err) {
          if (isFailure(err)) {
            failureCount++;
            if (failureCount >= threshold) trip();
          }
          throw err;
        }
      }

      /* Open — check if we should probe */
      if (state === STATE_OPEN) {
        if (!tryHalfOpen()) {
          throw new CircuitOpenError(name);
        }
      }

      /* Half-open — probe the downstream */
      try {
        const result = await fn();
        reset();
        return result;
      } catch (err) {
        halfOpenActive--;
        trip();
        throw err;
      }
    },

    /** Manually reset the circuit to closed state */
    reset,

    /** Manually trip the circuit to open state */
    trip,
  };
}

export class CircuitOpenError extends Error {
  constructor(circuitName) {
    super(`Circuit "${circuitName}" is open — request rejected`);
    this.name = "CircuitOpenError";
    this.circuit = circuitName;
    this.status = 503;
    this.code = "CIRCUIT_OPEN";
  }
}
