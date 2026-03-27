/**
 * http-native Validation Middleware
 *
 * Schema-agnostic: works with Zod, TypeBox, Yup, Joi, or any object with .parse()
 *
 * Usage:
 *   import { validate } from "http-native/validate";
 *   import { z } from "zod";
 *
 *   app.post("/users", validate({
 *     body: z.object({ name: z.string(), email: z.string().email() }),
 *   }), async (req, res) => {
 *     const { name, email } = req.validatedBody;
 *     res.json({ ok: true, name, email });
 *   });
 */

/**
 * @param {Object} schema
 * @param {Object} [schema.body] - Schema to validate req.json() against
 * @param {Object} [schema.query] - Schema to validate req.query against
 * @param {Object} [schema.params] - Schema to validate req.params against
 */
export function validate(schema = {}) {
  const { body: bodySchema, query: querySchema, params: paramsSchema } = schema;

  return async function validationMiddleware(req, res, next) {
    try {
      // Validate params
      if (paramsSchema) {
        const result = parseSchema(paramsSchema, req.params, "params");
        if (result.error) {
          res.status(400).json({
            error: "Validation Error",
            field: "params",
            details: result.error,
          });
          return;
        }
        req.validatedParams = result.value;
      }

      // Validate query
      if (querySchema) {
        const result = parseSchema(querySchema, req.query, "query");
        if (result.error) {
          res.status(400).json({
            error: "Validation Error",
            field: "query",
            details: result.error,
          });
          return;
        }
        req.validatedQuery = result.value;
      }

      // Validate body
      if (bodySchema) {
        const bodyData = req.json();
        if (bodyData === null && bodySchema) {
          res.status(400).json({
            error: "Validation Error",
            field: "body",
            details: "Request body is required",
          });
          return;
        }

        const result = parseSchema(bodySchema, bodyData, "body");
        if (result.error) {
          res.status(400).json({
            error: "Validation Error",
            field: "body",
            details: result.error,
          });
          return;
        }
        req.validatedBody = result.value;
      }

      await next();
    } catch (error) {
      // JSON parse error or schema error
      res.status(400).json({
        error: "Validation Error",
        details: error instanceof Error ? error.message : String(error),
      });
    }
  };
}

/**
 * Schema-agnostic parser. Supports:
 * - Zod: schema.parse() throws ZodError
 * - Zod safe: schema.safeParse() returns { success, data, error }
 * - TypeBox/Ajv: schema.parse() or custom
 * - Any object with .parse(data) that returns the parsed value or throws
 */
function parseSchema(schema, data, _fieldName) {
  // Zod-style safeParse
  if (typeof schema.safeParse === "function") {
    const result = schema.safeParse(data);
    if (result.success) {
      return { value: result.data, error: null };
    }
    // Zod error format
    const details = result.error?.issues
      ? result.error.issues.map((issue) => ({
          path: issue.path?.join(".") ?? "",
          message: issue.message,
        }))
      : result.error?.message ?? "Validation failed";
    return { value: null, error: details };
  }

  // Standard .parse() — throws on error
  if (typeof schema.parse === "function") {
    try {
      const value = schema.parse(data);
      return { value, error: null };
    } catch (error) {
      // Zod throws ZodError with .issues
      if (error?.issues) {
        const details = error.issues.map((issue) => ({
          path: issue.path?.join(".") ?? "",
          message: issue.message,
        }));
        return { value: null, error: details };
      }
      return { value: null, error: error?.message ?? "Validation failed" };
    }
  }

  // Joi-style .validate()
  if (typeof schema.validate === "function") {
    const result = schema.validate(data);
    if (result.error) {
      const details = result.error.details
        ? result.error.details.map((detail) => ({
            path: detail.path?.join(".") ?? "",
            message: detail.message,
          }))
        : result.error.message ?? "Validation failed";
      return { value: null, error: details };
    }
    return { value: result.value, error: null };
  }

  throw new TypeError(
    "Schema must have a .parse(), .safeParse(), or .validate() method",
  );
}
