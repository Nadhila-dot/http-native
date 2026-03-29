import { resolve } from "node:path";

process.env.HTTP_NATIVE_NODE_PATH ??= resolve(process.cwd(), "http-native.release.node");

const { createApp } = await import("../../src/index.js");

const db = {
  async getUser(id) {
    return {
      id,
      name: "Ada Lovelace",
      role: "admin",
    };
  },
};

const app = createApp();

app.get("/", (req, res) => {
  res.json({
    ok: true,
    engine: "http-native",
    mode: "static",
  });
});

app.get("/users/:id", async (req, res) => {
  const user = await db.getUser(req.params.id);
  res.json(user);
});

const server = await app.listen({
  port: 3001,
});

console.log(`Server running at ${server.url}`);

// Keep the process alive (Bun doesn't ref-count napi threads)
setInterval(() => {}, 1 << 30);
