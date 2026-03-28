import { resolve } from "node:path";

process.env.HTTP_NATIVE_NODE_PATH ??= resolve(process.cwd(), "http-native.release.node");
process.env.HTTP_NATIVE_NATIVE_PATH ??= process.env.HTTP_NATIVE_NODE_PATH;

const { createApp: createHttpNativeApp } = await import("../src/index.js");

const [, , engine, scenario, portArg] = process.argv;
const port = Number(portArg ?? 0);
const OPT_REPORT_INTERVAL_MS = 5000;

function buildStaticPayload(label) {
  return {
    ok: true,
    engine: label,
    mode: "static",
  };
}

function buildOptimizedPayload(label) {
  return {
    ok: true,
    engine: label,
    mode: "opt",
    optimization: "runtime",
  };
}

function buildDynamicApp(createApp, label) {
  const app = createApp();

  app.get("/users/:id", async (req, res) => {
    res.json({
      id: req.params.id,
      engine: label,
      mode: "dynamic",
    });
  });

  return app;
}

function buildStaticApp(createApp, label) {
  const app = createApp();

  if (label === "http-native") {
    app.get("/", (req, res) => {
      res.json({
        ok: true,
        engine: "http-native",
        mode: "static",
      });
    });

    return app;
  }

  app.get("/", (req, res) => {
    res.json({
      ok: true,
      engine: label,
      mode: "static",
    });
  });

  return app;
}

function buildOptimizedApp(createApp, label) {
  const app = createApp();
  const stablePayload = buildOptimizedPayload(label);

  app.get("/stable", (req, res) => {
    res.json(stablePayload);
  });

  return app;
}

function startBunServer(label, activeScenario) {
  const server = Bun.serve({
    port,
    hostname: "127.0.0.1",
    fetch(request) {
      const url = new URL(request.url);

      if (activeScenario === "static" && url.pathname === "/") {
        return Response.json(buildStaticPayload(label));
      }

      if (activeScenario === "dynamic" && url.pathname.startsWith("/users/")) {
        const id = url.pathname.split("/").pop();
        return Response.json({
          id,
          engine: label,
          mode: "dynamic",
        });
      }

      if (activeScenario === "opt" && url.pathname === "/stable") {
        return Response.json(buildOptimizedPayload(label));
      }

      return Response.json({ error: "Route not found" }, { status: 404 });
    },
  });

  console.log(`READY ${server.url}`);

  process.on("SIGTERM", () => {
    server.stop(true);
    process.exit(0);
  });
}

async function startFrameworkServer(createApp, label, activeScenario) {
  const app =
    activeScenario === "static"
      ? buildStaticApp(createApp, label)
      : activeScenario === "dynamic"
        ? buildDynamicApp(createApp, label)
        : buildOptimizedApp(createApp, label);

  const server = await app.listen({
    port,
    opt:
      label === "http-native" && activeScenario === "opt"
        ? { notify: true, cache: true }
        : undefined,
  });

  let optimizationReporter = null;
  if (label === "http-native" && activeScenario === "opt") {
    optimizationReporter = setInterval(() => {
      console.log("[http-native][bench-opt] summary");
      console.log(server.optimizations.summary());
    }, OPT_REPORT_INTERVAL_MS);
    optimizationReporter.unref();
  }

  console.log(`READY ${server.url}`);

  process.on("SIGTERM", async () => {
    if (optimizationReporter) {
      clearInterval(optimizationReporter);
    }
    if (label === "http-native" && activeScenario === "opt") {
      console.log("[http-native][bench-opt] final summary");
      console.log(server.optimizations.summary());
      console.log("[http-native][bench-opt] final snapshot");
      console.log(JSON.stringify(server.optimizations.snapshot(), null, 2));
    }
    await Promise.resolve(server.close());
    process.exit(0);
  });
}

if (engine === "bun") {
  startBunServer("bun", scenario);
} else if (engine === "http-native") {
  await startFrameworkServer(createHttpNativeApp, "http-native", scenario);
} else if (engine === "old") {
  const { createApp: createOldApp } = await import("../old/src/index.js");
  await startFrameworkServer(createOldApp, "old", scenario);
} else {
  throw new Error(`Unsupported benchmark engine: ${engine}`);
}
