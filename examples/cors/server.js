import { createApp } from "http-native";
import { cors } from "http-native/cors";

const app = createApp();

// ─── Example 1: Allow all origins ───────
// app.use(cors());

// ─── Example 2: Allow specific origin ───
// app.use(cors({ origin: "https://myapp.com" }));

// ─── Example 3: Allow multiple origins ──
// app.use(cors({ origin: ["https://myapp.com", "https://admin.myapp.com"] }));

// ─── Example 4: Dynamic origin with credentials ──────────────────────────────
const ALLOWED_ORIGINS = new Set([
  "http://localhost:3000",
  "http://localhost:5173",
  "https://myapp.com",
]);

app.use(
  cors({
    origin: (requestOrigin) => ALLOWED_ORIGINS.has(requestOrigin),
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "X-Request-Id"],
    exposedHeaders: ["X-Request-Id", "X-RateLimit-Remaining"],
    maxAge: 86400, // Cache preflight for 24 hours
  }),
);

// ─── Routes ─────────────────────────────

app.get("/api/data", (req, res) => {
  res.set("X-Request-Id", crypto.randomUUID()).json({
    data: [
      { id: 1, name: "Item 1" },
      { id: 2, name: "Item 2" },
    ],
  });
});

app.post("/api/data", (req, res) => {
  const body = req.json();
  res.status(201).json({ created: true, item: body });
});

app.options("/api/data", (req, res) => {
  // CORS middleware handles this automatically via preflight
  res.status(204).send();
});

const server = await app.listen({ port: 3000 });
console.log(`🌐 CORS example running at ${server.url}`);
console.log(`
Test with:
  # Simple GET (no CORS headers without Origin)
  curl -v ${server.url}/api/data

  # CORS preflight
  curl -v -X OPTIONS \\
    -H "Origin: http://localhost:5173" \\
    -H "Access-Control-Request-Method: POST" \\
    -H "Access-Control-Request-Headers: Content-Type" \\
    ${server.url}/api/data

  # CORS GET
  curl -v -H "Origin: http://localhost:5173" ${server.url}/api/data

  # Disallowed origin (no CORS headers)
  curl -v -H "Origin: https://evil.com" ${server.url}/api/data
`);
