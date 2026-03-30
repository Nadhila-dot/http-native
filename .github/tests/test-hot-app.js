import { createApp } from "../../src/index.js";

const app = createApp();

app.get("/", (req, res) => {
  res.json({ hello: "world", time: Date.now() });
});

const server = await app.listen().port(3000).opt({ devComments: false });
console.log("Server running at " + server.url);
