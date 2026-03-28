import { createApp } from "http-native";

const app = createApp();


class AppError extends Error {
  constructor(message, statusCode = 500, code = "INTERNAL_ERROR") {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

class NotFoundError extends AppError {
  constructor(resource = "Resource") {
    super(`${resource} not found`, 404, "NOT_FOUND");
  }
}

class ValidationError extends AppError {
  constructor(message) {
    super(message, 400, "VALIDATION_ERROR");
  }
}

class UnauthorizedError extends AppError {
  constructor(message = "Authentication required") {
    super(message, 401, "UNAUTHORIZED");
  }
}

// Global error handler

app.onError((err, req, res) => {
  // Known application errors
  if (err instanceof AppError) {
    console.error(`[${err.code}] ${req.method} ${req.path}: ${err.message}`);
    res.status(err.statusCode).json({
      error: {
        code: err.code,
        message: err.message,
      },
    });
    return;
  }

  // Unexpected errors — log full stack, return generic message
  console.error(`[UNHANDLED] ${req.method} ${req.path}:`, err);
  res.status(500).json({
    error: {
      code: "INTERNAL_ERROR",
      message:
        process.env.NODE_ENV === "production"
          ? "An unexpected error occurred"
          : err.message,
    },
  });
});

// Routes.

app.get("/", (req, res) => {
  res.json({ status: "ok" });
});

// Throws a custom NotFoundError
app.get("/users/:id", (req, res) => {
  const id = Number(req.params.id);
  if (id !== 1) {
    throw new NotFoundError("User");
  }
  res.json({ id: 1, name: "Alice" });
});

// Throws a ValidationError
app.post("/users", (req, res) => {
  const body = req.json();
  if (!body?.name) {
    throw new ValidationError("Name is required");
  }
  if (body.name.length < 2) {
    throw new ValidationError("Name must be at least 2 characters");
  }
  res.status(201).json({ id: 2, name: body.name });
});

// Throws an UnauthorizedError
app.get("/admin", (req, res) => {
  const token = req.header("authorization");
  if (!token) {
    throw new UnauthorizedError();
  }
  res.json({ admin: true });
});

// Throws an unhandled error (caught by generic handler)
app.get("/crash", (req, res) => {
  throw new TypeError("Cannot read property 'foo' of undefined");
});

// Async error (also caught!)
app.get("/async-crash", async (req, res) => {
  await new Promise((resolve) => setTimeout(resolve, 10));
  throw new Error("Async failure");
});

const server = await app.listen({ port: 3000 });
console.log(`🛡️  Error handling example running at ${server.url}`);
console.log(`
Try these:
  # OK
  curl ${server.url}/users/1

  # 404 NotFoundError
  curl ${server.url}/users/999

  # 400 ValidationError
  curl -X POST -H "Content-Type: application/json" \\
    -d '{}' ${server.url}/users

  # 401 UnauthorizedError
  curl ${server.url}/admin

  # 500 Unhandled error
  curl ${server.url}/crash

  # 500 Async error
  curl ${server.url}/async-crash
`);
