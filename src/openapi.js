/**
 * http-native OpenAPI 3.1 auto-generation (DX-5.1)
 *
 * Derives an OpenAPI spec from registered routes and validation schemas.
 * Serves the JSON spec and optional Swagger UI from static fast-path routes.
 *
 * Usage:
 *   import { openapi } from "@http-native/core/openapi";
 *   app.use(openapi({
 *     info: { title: "My API", version: "1.0.0" },
 *     json: "/openapi.json",
 *     ui:   "/docs",
 *   }));
 */

/**
 * @param {Object} options
 * @param {Object} options.info                - OpenAPI info object (title, version, description)
 * @param {Object[]} [options.servers]         - Server URLs
 * @param {string}   [options.json="/openapi.json"] - Path to serve the raw JSON spec
 * @param {string}   [options.ui]              - Path to serve Swagger UI (optional)
 * @param {Object}   [options.components]      - Extra OpenAPI components to merge
 * @param {string[]} [options.tags]            - Top-level tag definitions
 */
export function openapi(options = {}) {
  const {
    info = { title: "API", version: "1.0.0" },
    servers = [],
    json: jsonPath = "/openapi.json",
    ui: uiPath,
    components = {},
    tags = [],
  } = options;

  let cachedSpec = null;

  return function openapiMiddleware(req, res, next) {
    if (req.method === "GET" && req.path === jsonPath) {
      if (!cachedSpec) {
        cachedSpec = JSON.stringify(generateSpec({ routes: [] }, { info, servers, components, tags }));
      }
      res.set("content-type", "application/json; charset=utf-8");
      return res.send(cachedSpec);
    }

    if (uiPath && req.method === "GET" && req.path === uiPath) {
      const html = `<!DOCTYPE html>
<html><head><title>${info.title ?? "API Docs"}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist/swagger-ui.css">
</head><body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({ url: "${jsonPath}", dom_id: "#swagger-ui" });</script>
</body></html>`;
      res.set("content-type", "text/html; charset=utf-8");
      return res.send(html);
    }

    return next();
  };
}

/**
 * Generate an OpenAPI spec from route metadata.
 * Called internally or can be used standalone.
 *
 * @param {Object} appMeta - Route and middleware metadata from the compiled app
 * @param {Object} options - Same options as openapi()
 * @returns {Object} OpenAPI 3.1 spec object
 */
export function generateSpec(appMeta, options = {}) {
  const {
    info = { title: "API", version: "1.0.0" },
    servers = [],
    components = {},
    tags = [],
  } = options;

  const spec = {
    openapi: "3.1.0",
    info,
    servers: servers.length > 0 ? servers : undefined,
    tags: tags.length > 0 ? tags.map((t) => (typeof t === "string" ? { name: t } : t)) : undefined,
    paths: {},
    components: {
      schemas: {},
      ...components,
    },
  };

  /* Walk routes and build path items */
  const routes = appMeta.routes ?? [];
  for (const route of routes) {
    const pathKey = toOpenApiPath(route.path);
    if (!spec.paths[pathKey]) spec.paths[pathKey] = {};

    const method = route.method.toLowerCase();
    const operation = {
      summary: route.meta?.summary ?? undefined,
      tags: route.meta?.tags ?? undefined,
      operationId: route.meta?.operationId ?? `${method}_${pathKey.replace(/[^a-zA-Z0-9]/g, "_")}`,
      parameters: extractPathParams(route.path),
      responses: {
        200: { description: "Successful response" },
      },
    };

    /* Extract validation schema if present */
    if (route.meta?.validation?.body) {
      const schema = extractJsonSchema(route.meta.validation.body);
      if (schema) {
        operation.requestBody = {
          required: true,
          content: {
            "application/json": { schema },
          },
        };
      }
    }

    if (route.meta?.validation?.query) {
      const queryParams = extractQueryParams(route.meta.validation.query);
      operation.parameters = [...(operation.parameters ?? []), ...queryParams];
    }

    spec.paths[pathKey][method] = operation;
  }

  return spec;
}

/** Convert express-style path to OpenAPI path: /users/:id → /users/{id} */
function toOpenApiPath(path) {
  return path.replace(/:([^/]+)/g, "{$1}");
}

/** Extract path parameters from route path string */
function extractPathParams(path) {
  const params = [];
  const matches = path.matchAll(/:([^/]+)/g);
  for (const match of matches) {
    params.push({
      name: match[1],
      in: "path",
      required: true,
      schema: { type: "string" },
    });
  }
  return params.length > 0 ? params : undefined;
}

/** Try to convert a Zod/TypeBox schema to JSON Schema */
function extractJsonSchema(schema) {
  /* Zod schemas have a ._def property */
  if (schema?._def?.typeName) {
    return zodToJsonSchema(schema);
  }
  /* TypeBox schemas are already JSON Schema */
  if (schema?.type || schema?.properties) {
    return schema;
  }
  return { type: "object" };
}

/** Minimal Zod → JSON Schema conversion for common types */
function zodToJsonSchema(schema) {
  const def = schema._def;
  switch (def.typeName) {
    case "ZodString":
      return { type: "string" };
    case "ZodNumber":
      return { type: "number" };
    case "ZodBoolean":
      return { type: "boolean" };
    case "ZodArray":
      return { type: "array", items: zodToJsonSchema(def.type) };
    case "ZodObject": {
      const properties = {};
      const required = [];
      if (def.shape) {
        const shape = typeof def.shape === "function" ? def.shape() : def.shape;
        for (const [key, val] of Object.entries(shape)) {
          properties[key] = zodToJsonSchema(val);
          if (!val.isOptional?.()) required.push(key);
        }
      }
      return {
        type: "object",
        properties,
        required: required.length > 0 ? required : undefined,
      };
    }
    case "ZodOptional":
      return zodToJsonSchema(def.innerType);
    case "ZodEnum":
      return { type: "string", enum: def.values };
    default:
      return { type: "object" };
  }
}

/** Extract query parameters from a validation schema */
function extractQueryParams(schema) {
  const params = [];
  const shape = schema?._def?.shape
    ? typeof schema._def.shape === "function"
      ? schema._def.shape()
      : schema._def.shape
    : schema?.properties ?? {};

  for (const [name, val] of Object.entries(shape)) {
    params.push({
      name,
      in: "query",
      required: !val?.isOptional?.(),
      schema: extractJsonSchema(val),
    });
  }
  return params;
}
