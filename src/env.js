/**
 * http-native environment configuration (DX-6.4)
 *
 * Type-safe .env loading with validation and coercion. Reads from
 * process.env and an optional .env file (via Bun's built-in support).
 *
 * Usage:
 *   import { loadEnv } from "@http-native/core/env";
 *
 *   const env = loadEnv({
 *     PORT:         { type: "number", default: 3000 },
 *     DATABASE_URL: { type: "string", required: true },
 *     DEBUG:        { type: "boolean", default: false },
 *   });
 *   console.log(env.PORT); // 3000
 */

/**
 * @param {Record<string, EnvVarSpec>} schema
 * @param {{ prefix?: string, envFile?: string }} [options]
 * @returns {Record<string, unknown>}
 */
export function loadEnv(schema, options = {}) {
  const prefix = options.prefix ?? "";
  const env = Object.create(null);
  const errors = [];

  for (const [key, spec] of Object.entries(schema)) {
    const envKey = prefix + key;
    const raw = process.env[envKey];

    if (raw === undefined || raw === "") {
      if (spec.required) {
        errors.push(`Missing required env var: ${envKey}`);
        continue;
      }
      env[key] = spec.default ?? undefined;
      continue;
    }

    try {
      env[key] = coerce(raw, spec.type ?? "string", envKey);
    } catch (err) {
      errors.push(err.message);
    }
  }

  if (errors.length > 0) {
    throw new EnvValidationError(errors);
  }

  return Object.freeze(env);
}

/**
 * @param {string} value
 * @param {"string"|"number"|"boolean"|"json"} type
 * @param {string} key
 */
function coerce(value, type, key) {
  switch (type) {
    case "string":
      return value;
    case "number": {
      const n = Number(value);
      if (Number.isNaN(n)) throw new Error(`Env var ${key} must be a number, got "${value}"`);
      return n;
    }
    case "boolean":
      if (value === "true" || value === "1" || value === "yes") return true;
      if (value === "false" || value === "0" || value === "no" || value === "") return false;
      throw new Error(`Env var ${key} must be a boolean, got "${value}"`);
    case "json":
      try {
        return JSON.parse(value);
      } catch {
        throw new Error(`Env var ${key} must be valid JSON, got "${value}"`);
      }
    default:
      return value;
  }
}

export class EnvValidationError extends Error {
  constructor(errors) {
    super(`Environment validation failed:\n  - ${errors.join("\n  - ")}`);
    this.name = "EnvValidationError";
    this.errors = errors;
  }
}
