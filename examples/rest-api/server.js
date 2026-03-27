import { createApp } from "http-native";

const app = createApp();

// In-memory store
const todos = new Map();
let nextId = 1;

// Seed data
todos.set(1, { id: 1, title: "Learn http-native", completed: true });
todos.set(2, { id: 2, title: "Build something awesome", completed: false });
todos.set(3, { id: 3, title: "Deploy to production", completed: false });
nextId = 4;

// ─── Error Handler ────────────────────────────────────────────────────────────

app.onError((err, req, res) => {
  console.error(`Error: ${err.message}`);
  res.status(500).json({ error: "Internal server error" });
});

// ─── List all todos ───────────────────────────────────────────────────────────

app.get("/todos", (req, res) => {
  const { completed } = req.query;
  let items = [...todos.values()];

  if (completed === "true") {
    items = items.filter((t) => t.completed);
  } else if (completed === "false") {
    items = items.filter((t) => !t.completed);
  }

  res.json({ todos: items, count: items.length });
});

// ─── Get single todo ──────────────────────────────────────────────────────────

app.get("/todos/:id", (req, res) => {
  const id = Number(req.params.id);
  const todo = todos.get(id);

  if (!todo) {
    res.status(404).json({ error: `Todo #${id} not found` });
    return;
  }

  res.json(todo);
});

// ─── Create todo ──────────────────────────────────────────────────────────────

app.post("/todos", (req, res) => {
  const body = req.json();

  if (!body || !body.title) {
    res.status(400).json({ error: "Title is required" });
    return;
  }

  const todo = {
    id: nextId++,
    title: String(body.title),
    completed: Boolean(body.completed ?? false),
  };

  todos.set(todo.id, todo);
  res.status(201).json(todo);
});

// ─── Update todo ──────────────────────────────────────────────────────────────

app.put("/todos/:id", (req, res) => {
  const id = Number(req.params.id);
  const existing = todos.get(id);

  if (!existing) {
    res.status(404).json({ error: `Todo #${id} not found` });
    return;
  }

  const body = req.json();
  const updated = {
    ...existing,
    title: body?.title ?? existing.title,
    completed: body?.completed ?? existing.completed,
  };

  todos.set(id, updated);
  res.json(updated);
});

// ─── Delete todo ──────────────────────────────────────────────────────────────

app.delete("/todos/:id", (req, res) => {
  const id = Number(req.params.id);

  if (!todos.has(id)) {
    res.status(404).json({ error: `Todo #${id} not found` });
    return;
  }

  todos.delete(id);
  res.sendStatus(204);
});

// ─── Toggle completion ────────────────────────────────────────────────────────

app.patch("/todos/:id/toggle", (req, res) => {
  const id = Number(req.params.id);
  const todo = todos.get(id);

  if (!todo) {
    res.status(404).json({ error: `Todo #${id} not found` });
    return;
  }

  todo.completed = !todo.completed;
  res.json(todo);
});

const server = await app.listen({ port: 3000 });
console.log(`📝 REST API running at ${server.url}`);
console.log(`
CRUD operations:
  # List all
  curl ${server.url}/todos

  # Filter completed
  curl "${server.url}/todos?completed=false"

  # Get one
  curl ${server.url}/todos/1

  # Create
  curl -X POST -H "Content-Type: application/json" \\
    -d '{"title":"New todo"}' ${server.url}/todos

  # Update
  curl -X PUT -H "Content-Type: application/json" \\
    -d '{"title":"Updated","completed":true}' ${server.url}/todos/1

  # Toggle
  curl -X PATCH ${server.url}/todos/2/toggle

  # Delete
  curl -X DELETE ${server.url}/todos/3
`);
