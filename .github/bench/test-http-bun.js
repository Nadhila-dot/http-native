const db = {
  async getUser(id) {
    return {
      id,
      name: "Ada Lovelace",
      role: "admin",
    };
  },
};

const server = Bun.serve({
  port: 3000,
  fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/") {
      return Response.json({
        ok: true,
        engine: "bun",
        mode: "static",
      });
    }

    if (url.pathname.startsWith("/users/")) {
      const id = url.pathname.slice("/users/".length);
      return db.getUser(id).then((user) => Response.json(user));
    }

    return Response.json(
      {
        error: "Route not found",
      },
      { status: 404 },
    );
  },
});

console.log(`Listening on ${server.url}`);
