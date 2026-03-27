import { createApp } from "http-native";

const app = createApp();

// Simple GET route
app.get("/", (req, res) => {
  res.json({ message: "Hello, World!", timestamp: Date.now() });
});

// Route with params
app.get("/hello/:name", (req, res) => {
  res.json({ greeting: `Hello, ${req.params.name}!` });
});

// Multiple params
app.get("/users/:userId/posts/:postId", (req, res) => {
  res.json({
    userId: req.params.userId,
    postId: req.params.postId,
  });
});

// Query string parsing
app.get("/search", (req, res) => {
  const { q, page, limit } = req.query;
  res.json({
    query: q ?? "",
    page: Number(page) || 1,
    limit: Number(limit) || 10,
  });
});

// Different status codes
app.get("/not-found", (req, res) => {
  res.status(404).json({ error: "Resource not found" });
});

// Custom headers
app.get("/custom-headers", (req, res) => {
  res.set("X-Custom-Header", "http-native")
    .set("X-Request-Id", crypto.randomUUID())
    .json({ headers: "set!" });
});

const server = await app.listen({ port: 3000 });
console.log(`🚀 Basic server running at ${server.url}`);
console.log(`
Try these routes:
  curl ${server.url}/
  curl ${server.url}/hello/world
  curl ${server.url}/users/42/posts/7
  curl ${server.url}/search?q=http-native&page=2&limit=20
  curl -v ${server.url}/custom-headers
`);
