/**
 * http-native structured error types.
 *
 * Provides a typed error system with error codes for programmatic handling.
 * HttpError instances are automatically serialized into structured JSON
 * responses by the framework's error handler.
 *
 * Usage:
 *   import { HttpError, BadRequest, NotFound, Unauthorized } from "@http-native/core/error";
 *
 *   throw new HttpError(422, "VALIDATION_FAILED", "Invalid input", { fields: errors });
 *   throw new BadRequest("Missing required field: name");
 *   throw new NotFound("User not found");
 *   throw new Unauthorized("Invalid token");
 */

// ─── Base Error Class ─────────────────────

/**
 * Structured HTTP error with status code, machine-readable error code,
 * human-readable message, and optional detail payload.
 *
 * @extends Error
 */
export class HttpError extends Error {
  /**
   * @param {number} status   - HTTP status code
   * @param {string} [code]   - Machine-readable error code (e.g. "VALIDATION_FAILED")
   * @param {string} [message] - Human-readable error message
   * @param {Object} [details] - Additional error details
   */
  constructor(status, code, message, details) {
    /* Support (status, message) shorthand — shift arguments */
    if (typeof code === "string" && message === undefined && details === undefined) {
      if (!code.includes("_") && code.length > 20) {
        /* Looks like a message, not a code */
        super(code);
        this.status = status;
        this.code = defaultCodeForStatus(status);
        this.details = undefined;
      } else {
        super(code);
        this.status = status;
        this.code = code;
        this.details = undefined;
      }
    } else {
      super(message ?? `HTTP ${status}`);
      this.status = status;
      this.code = code ?? defaultCodeForStatus(status);
      this.details = details;
    }

    this.name = "HttpError";
  }

  /**
   * Serialize to a plain object suitable for JSON response.
   *
   * @returns {{ status: number, code: string, message: string, details?: Object }}
   */
  toJSON() {
    const json = {
      status: this.status,
      code: this.code,
      message: this.message,
    };
    if (this.details !== undefined) {
      json.details = this.details;
    }
    return json;
  }
}

// ─── Common Error Factories ───────────────

/**
 * 400 Bad Request
 * @param {string} [message]
 * @param {Object} [details]
 */
export class BadRequest extends HttpError {
  constructor(message, details) {
    super(400, "BAD_REQUEST", message ?? "Bad Request", details);
    this.name = "BadRequest";
  }
}

/**
 * 401 Unauthorized
 * @param {string} [message]
 * @param {Object} [details]
 */
export class Unauthorized extends HttpError {
  constructor(message, details) {
    super(401, "UNAUTHORIZED", message ?? "Unauthorized", details);
    this.name = "Unauthorized";
  }
}

/**
 * 403 Forbidden
 * @param {string} [message]
 * @param {Object} [details]
 */
export class Forbidden extends HttpError {
  constructor(message, details) {
    super(403, "FORBIDDEN", message ?? "Forbidden", details);
    this.name = "Forbidden";
  }
}

/**
 * 404 Not Found
 * @param {string} [message]
 * @param {Object} [details]
 */
export class NotFound extends HttpError {
  constructor(message, details) {
    super(404, "NOT_FOUND", message ?? "Not Found", details);
    this.name = "NotFound";
  }
}

/**
 * 409 Conflict
 * @param {string} [message]
 * @param {Object} [details]
 */
export class Conflict extends HttpError {
  constructor(message, details) {
    super(409, "CONFLICT", message ?? "Conflict", details);
    this.name = "Conflict";
  }
}

/**
 * 422 Unprocessable Entity
 * @param {string} [message]
 * @param {Object} [details]
 */
export class UnprocessableEntity extends HttpError {
  constructor(message, details) {
    super(422, "UNPROCESSABLE_ENTITY", message ?? "Unprocessable Entity", details);
    this.name = "UnprocessableEntity";
  }
}

/**
 * 429 Too Many Requests
 * @param {string} [message]
 * @param {Object} [details]
 */
export class TooManyRequests extends HttpError {
  constructor(message, details) {
    super(429, "TOO_MANY_REQUESTS", message ?? "Too Many Requests", details);
    this.name = "TooManyRequests";
  }
}

/**
 * 500 Internal Server Error
 * @param {string} [message]
 * @param {Object} [details]
 */
export class InternalServerError extends HttpError {
  constructor(message, details) {
    super(500, "INTERNAL_SERVER_ERROR", message ?? "Internal Server Error", details);
    this.name = "InternalServerError";
  }
}

/**
 * 502 Bad Gateway
 * @param {string} [message]
 * @param {Object} [details]
 */
export class BadGateway extends HttpError {
  constructor(message, details) {
    super(502, "BAD_GATEWAY", message ?? "Bad Gateway", details);
    this.name = "BadGateway";
  }
}

/**
 * 503 Service Unavailable
 * @param {string} [message]
 * @param {Object} [details]
 */
export class ServiceUnavailable extends HttpError {
  constructor(message, details) {
    super(503, "SERVICE_UNAVAILABLE", message ?? "Service Unavailable", details);
    this.name = "ServiceUnavailable";
  }
}

// ─── Helpers ──────────────────────────────

/**
 * Map common HTTP status codes to default error code strings.
 *
 * @param {number} status
 * @returns {string}
 */
function defaultCodeForStatus(status) {
  switch (status) {
    case 400: return "BAD_REQUEST";
    case 401: return "UNAUTHORIZED";
    case 403: return "FORBIDDEN";
    case 404: return "NOT_FOUND";
    case 405: return "METHOD_NOT_ALLOWED";
    case 409: return "CONFLICT";
    case 413: return "PAYLOAD_TOO_LARGE";
    case 422: return "UNPROCESSABLE_ENTITY";
    case 429: return "TOO_MANY_REQUESTS";
    case 500: return "INTERNAL_SERVER_ERROR";
    case 502: return "BAD_GATEWAY";
    case 503: return "SERVICE_UNAVAILABLE";
    case 504: return "GATEWAY_TIMEOUT";
    default: return `HTTP_${status}`;
  }
}
