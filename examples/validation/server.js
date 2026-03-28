import { createApp } from "http-native";
import { validate } from "http-native/validate";

const app = createApp();

// ─── Manual Schema (no external deps) ───
//
// Works with any object that has .parse() or .safeParse().
// Below is a minimal hand-rolled schema — in production, use Zod:
//
//   import { z } from "zod";
//   const CreateUserSchema = z.object({
//     name: z.string().min(1).max(100),
//     email: z.string().email(),
//     age: z.number().int().min(0).max(150).optional(),
//   });

// Minimal schema with .parse() compatible API
function createSchema(validator) {
  return {
    parse(data) {
      const errors = validator(data);
      if (errors.length > 0) {
        const err = new Error("Validation failed");
        err.issues = errors.map((msg) => ({ path: [], message: msg }));
        throw err;
      }
      return data;
    },
  };
}

const CreateUserSchema = createSchema((data) => {
  const errors = [];
  if (!data || typeof data !== "object") {
    errors.push("Body must be an object");
    return errors;
  }
  if (typeof data.name !== "string" || data.name.length === 0) {
    errors.push("name is required and must be a non-empty string");
  }
  if (typeof data.email !== "string" || !data.email.includes("@")) {
    errors.push("email is required and must be a valid email");
  }
  if (data.age !== undefined && (typeof data.age !== "number" || data.age < 0)) {
    errors.push("age must be a non-negative number");
  }
  return errors;
});

const QuerySchema = createSchema((data) => {
  const errors = [];
  if (data.page && isNaN(Number(data.page))) {
    errors.push("page must be a number");
  }
  if (data.limit && isNaN(Number(data.limit))) {
    errors.push("limit must be a number");
  }
  return errors;
});

// ─── Error Handler ──────────────────────

app.onError((err, req, res) => {
  console.error(`Error: ${err.message}`);
  res.status(500).json({ error: "Internal server error" });
});

// ─── Routes with Validation ────────────

// Validates body against CreateUserSchema
app.post(
  "/users",
  validate({ body: CreateUserSchema }),
  (req, res) => {
    // req.validatedBody is the parsed & validated data
    const user = {
      id: crypto.randomUUID(),
      ...req.validatedBody,
      createdAt: new Date().toISOString(),
    };

    res.status(201).json(user);
  },
);

// Validates query params
app.get(
  "/users",
  validate({ query: QuerySchema }),
  (req, res) => {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;

    res.json({
      users: [],
      pagination: { page, limit, total: 0 },
    });
  },
);

const server = await app.listen({ port: 3000 });
console.log(`✅ Validation example running at ${server.url}`);
console.log(`
Try these:
  # Valid user
  curl -X POST -H "Content-Type: application/json" \\
    -d '{"name":"Alice","email":"alice@example.com","age":30}' \\
    ${server.url}/users

  # Missing name (400 error)
  curl -X POST -H "Content-Type: application/json" \\
    -d '{"email":"bob@example.com"}' \\
    ${server.url}/users

  # Invalid email (400 error)
  curl -X POST -H "Content-Type: application/json" \\
    -d '{"name":"Charlie","email":"not-an-email"}' \\
    ${server.url}/users

  # Valid query
  curl "${server.url}/users?page=2&limit=20"

  # Invalid query (400 error)
  curl "${server.url}/users?page=abc"
`);
