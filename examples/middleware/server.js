import { createApp } from "http-native";

const app = createApp();

// ─── Logging Middleware (global) ────────

app.use(async (req, res, next) => {
  const start = performance.now();
  console.log(`→ ${req.method} ${req.path}`);

  await next();

  const duration = (performance.now() - start).toFixed(2);
  console.log(`← ${req.method} ${req.path} [${duration}ms]`);
});

// ─── Auth Middleware (scoped to /api) ───

app.use("/api", async (req, res, next) => {
  const token = req.header("authorization");

  if (!token || !token.startsWith("Bearer ")) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Missing or invalid Bearer token",
    });
    return;
  }

  // Simulate token validation
  const payload = token.slice(7);
  if (payload === "invalid") {
    res.status(403).json({ error: "Forbidden", message: "Token is invalid" });
    return;
  }

  // Attach user info to response locals for downstream handlers
  res.locals.user = { id: 1, name: "John Doe", token: payload };
  await next();
});

// ─── Request ID Middleware (global) ──────

app.use(async (req, res, next) => {
  const requestId = crypto.randomUUID();
  res.set("X-Request-Id", requestId);
  res.locals.requestId = requestId;
  await next();
});

// ─── Routes ─────────────────────────────

// Public route (only logging + request ID middlewares run)
app.get("/", (req, res) => {
  res.json({ message: "Public endpoint", requestId: res.locals.requestId });
});

// Protected route (logging + request ID + auth middlewares run)
app.get("/api/profile", (req, res) => {
  res.json({
    user: res.locals.user,
    requestId: res.locals.requestId,
  });
});

app.get("/api/secret", (req, res) => {
  res.json({
    secret: "The cake is a lie",
    accessedBy: res.locals.user.name,
  });
});

// ─── Error Handler ──────────────────────

app.onError((err, req, res) => {
  console.error(`❌ Error on ${req.method} ${req.path}:`, err.message);
  res.status(500).json({
    error: "Something went wrong",
    requestId: res.locals.requestId,
  });
});

// Route that deliberately throws
app.get("/api/crash", (req, res) => {
  throw new Error("Simulated server error");
});

const server = await app.listen({ port: 3000 });
console.log(`🔐 Middleware example running at ${server.url}`);
console.log(`
Try these routes:
  # Public (no auth needed)
  curl ${server.url}/

  # Protected (will fail - no token)
  curl ${server.url}/api/profile

  # Protected (with valid token)
  curl -H "Authorization: Bearer mytoken123" ${server.url}/api/profile

  # Protected (with invalid token)
  curl -H "Authorization: Bearer invalid" ${server.url}/api/profile

  # Error handler test
  curl -H "Authorization: Bearer mytoken123" ${server.url}/api/crash
`);
