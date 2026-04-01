import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { resolve } from "node:path";
import { homedir } from "node:os";

const DEFAULT_ENGINES = ["http-native", "bun", "express"];
const DEFAULT_SCENARIOS = ["static", "dynamic", "opt"];
const DEFAULT_CONNECTIONS = 200;
const DEFAULT_DURATION = "10s";
const DEFAULT_TIMEOUT = "2s";
const DEFAULT_OUTPUT_DIR = ".github/bench/results";
const DEFAULT_HTTP_NATIVE_RUNTIME = "bun";
const DEFAULT_BOMBARDIER_BIN = resolveBombardierBin();
const SUPPORTED_HTTP_NATIVE_RUNTIMES = new Set(["bun", "node"]);

const SERVER_PORTS = Object.freeze({
  bun: { static: 3000, dynamic: 3010, opt: 3020 },
  "http-native": { static: 3001, dynamic: 3011, opt: 3021 },
  old: { static: 3002, dynamic: 3012, opt: 3022 },
  xitca: { static: 3003, dynamic: 3013, opt: 3023 },
  monoio: { static: 3004, dynamic: 3014, opt: 3024 },
  zig: { static: 3005, dynamic: 3015, opt: 3025 },
  express: { static: 3008, dynamic: 3018, opt: 3028 },
  fiber: { static: 3009, dynamic: 3019, opt: 3029 },
});

const SUPPORTED_SCENARIOS = new Set(DEFAULT_SCENARIOS);
const SUPPORTED_ENGINES = new Set(Object.keys(SERVER_PORTS));

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const cases = buildBenchmarkCases(options.engines, options.scenarios);
  const outputDir = resolve(process.cwd(), options.outputDir);

  await mkdir(outputDir, { recursive: true });

  if (options.engines.includes("http-native")) {
    await runCommand("bun", ["run", "build:release"], {
      label: "build http-native release addon",
    });
  }

  const results = [];
  for (const testCase of cases) {
    const result = await runBenchmarkCase(testCase, options);
    results.push(result);
  }

  const payload = {
    generatedAt: new Date().toISOString(),
    environment: {
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      bun: Bun.version,
    },
    config: {
      engines: options.engines,
      scenarios: options.scenarios,
      connections: options.connections,
      duration: options.duration,
      timeout: options.timeout,
      httpNativeRuntime: options.httpNativeRuntime,
    },
    results,
  };

  const summary = renderSummary(payload);
  const jsonPath = resolve(outputDir, "results.json");
  const markdownPath = resolve(outputDir, "summary.md");

  await writeFile(jsonPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  await writeFile(markdownPath, summary, "utf8");

  if (process.env.GITHUB_STEP_SUMMARY) {
    await writeFile(process.env.GITHUB_STEP_SUMMARY, summary, {
      encoding: "utf8",
      flag: "a",
    });
  }

  console.log(summary);
  console.log(`[http-native][bench] wrote ${jsonPath}`);
  console.log(`[http-native][bench] wrote ${markdownPath}`);
  process.exit(0);
}

function parseArgs(argv) {
  const values = new Map();

  for (const arg of argv) {
    if (!arg.startsWith("--")) {
      throw new Error(`Unexpected argument: ${arg}`);
    }

    const [rawKey, ...rest] = arg.slice(2).split("=");
    const key = rawKey.trim();
    const value = rest.length > 0 ? rest.join("=") : "true";
    values.set(key, value);
  }

  if (values.has("help")) {
    printUsage();
    process.exit(0);
  }

  const engines = parseCsv(values.get("engines"), DEFAULT_ENGINES).map((engine) => {
    if (!SUPPORTED_ENGINES.has(engine)) {
      throw new Error(
        `Unsupported engine "${engine}". Supported engines: ${[...SUPPORTED_ENGINES].join(", ")}`,
      );
    }

    return engine;
  });

  const scenarios = parseCsv(values.get("scenarios"), DEFAULT_SCENARIOS).map((scenario) => {
    if (!SUPPORTED_SCENARIOS.has(scenario)) {
      throw new Error(
        `Unsupported scenario "${scenario}". Supported scenarios: ${[...SUPPORTED_SCENARIOS].join(", ")}`,
      );
    }

    return scenario;
  });

  const connections = Number(values.get("connections") ?? DEFAULT_CONNECTIONS);
  if (!Number.isInteger(connections) || connections <= 0) {
    throw new Error(`--connections must be a positive integer, received ${connections}`);
  }

  const duration = values.get("duration") ?? DEFAULT_DURATION;
  const timeout = values.get("timeout") ?? DEFAULT_TIMEOUT;
  const outputDir = values.get("output-dir") ?? DEFAULT_OUTPUT_DIR;
  const httpNativeRuntime = (values.get("http-native-runtime") ?? DEFAULT_HTTP_NATIVE_RUNTIME).trim();

  if (!SUPPORTED_HTTP_NATIVE_RUNTIMES.has(httpNativeRuntime)) {
    throw new Error(
      `Unsupported --http-native-runtime \"${httpNativeRuntime}\". Supported runtimes: ${[
        ...SUPPORTED_HTTP_NATIVE_RUNTIMES,
      ].join(", ")}`,
    );
  }

  return {
    engines,
    scenarios,
    connections,
    duration,
    timeout,
    outputDir,
    httpNativeRuntime,
  };
}

function printUsage() {
  console.log("Usage: bun .github/bench/ci.js [options]");
  console.log("");
  console.log("Options:");
  console.log(`  --engines=http-native,bun   Comma-separated list. Default: ${DEFAULT_ENGINES.join(",")}`);
  console.log(`  --scenarios=static,dynamic,opt   Comma-separated list. Default: ${DEFAULT_SCENARIOS.join(",")}`);
  console.log(`  --connections=${DEFAULT_CONNECTIONS}   Bombardier concurrency`);
  console.log(`  --duration=${DEFAULT_DURATION}   Bombardier duration`);
  console.log(`  --timeout=${DEFAULT_TIMEOUT}   Bombardier timeout`);
  console.log(
    `  --http-native-runtime=${DEFAULT_HTTP_NATIVE_RUNTIME}   Runtime for http-native/old: bun | node`,
  );
  console.log(`  --output-dir=${DEFAULT_OUTPUT_DIR}   Where to write results.json and summary.md`);
}

function parseCsv(value, fallback) {
  if (!value) {
    return [...fallback];
  }

  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function buildBenchmarkCases(engines, scenarios) {
  return engines.flatMap((engine) =>
    scenarios.map((scenario) => ({
      engine,
      scenario,
      port: portFor(engine, scenario),
      path: benchmarkPathForScenario(scenario),
    })),
  );
}

function resolveBombardierBin() {
  if (process.env.BOMBARDIER_BIN) {
    return process.env.BOMBARDIER_BIN;
  }

  const homeBin = resolve(homedir(), "go/bin/bombardier");
  if (existsSync(homeBin)) {
    return homeBin;
  }

  return "bombardier";
}

function benchmarkPathForScenario(scenario) {
  if (scenario === "static") {
    return "/";
  }

  if (scenario === "dynamic") {
    return "/users/42";
  }

  return "/stable";
}

function portFor(engine, scenario) {
  const port = SERVER_PORTS[engine]?.[scenario];
  if (!port) {
    throw new Error(`No benchmark port configured for ${engine}/${scenario}`);
  }

  return port;
}

async function runBenchmarkCase(testCase, options) {
  console.log(`[http-native][bench] starting ${testCase.engine}/${testCase.scenario} on :${testCase.port}`);

  const server = spawnServer(testCase, options);
  const serverLogs = [];
  let readyResolve;
  const ready = new Promise((resolve) => {
    readyResolve = resolve;
  });

  let stdoutBuffer = "";
  server.stdout.setEncoding("utf8");
  server.stdout.on("data", (chunk) => {
    stdoutBuffer += chunk;
    const lines = stdoutBuffer.split(/\r?\n/);
    stdoutBuffer = lines.pop() ?? "";

    for (const line of lines) {
      if (!line) {
        continue;
      }

      serverLogs.push(line);
      if (line.startsWith("READY ")) {
        readyResolve(line.slice("READY ".length).trim());
        continue;
      }

      console.log(`[${testCase.engine}/${testCase.scenario}] ${line}`);
    }
  });

  let stderrBuffer = "";
  server.stderr?.setEncoding("utf8");
  server.stderr?.on("data", (chunk) => {
    stderrBuffer += chunk;
    const lines = stderrBuffer.split(/\r?\n/);
    stderrBuffer = lines.pop() ?? "";

    for (const line of lines) {
      if (!line) {
        continue;
      }

      serverLogs.push(line);
      console.error(`[${testCase.engine}/${testCase.scenario}][stderr] ${line}`);
    }
  });

  const exitPromise = once(server, "exit").then(([code, signal]) => {
    throw new Error(
      `Benchmark target ${testCase.engine}/${testCase.scenario} exited early (code=${code}, signal=${signal})`,
    );
  });

  let url;
  try {
    url = await Promise.race([ready, exitPromise]);
    const benchmarkUrl = new URL(testCase.path, url).toString();
    const bombardier = await runCommand(
      DEFAULT_BOMBARDIER_BIN,
      [
        "-c",
        String(options.connections),
        "-d",
        options.duration,
        "-t",
        options.timeout,
        "-l",
        "-p",
        "result",
        "-o",
        "json",
        benchmarkUrl,
      ],
      {
        label: `${testCase.engine}/${testCase.scenario} bombardier`,
        capture: true,
      },
    );

    const parsed = JSON.parse(bombardier.stdout.trim());
    validateBombardierResult(parsed, testCase, benchmarkUrl);

    return {
      engine: testCase.engine,
      scenario: testCase.scenario,
      port: testCase.port,
      url: benchmarkUrl,
      serverLogs,
      spec: parsed.spec,
      result: parsed.result,
      derived: deriveMetrics(parsed.result),
    };
  } finally {
    await stopServer(server, `${testCase.engine}/${testCase.scenario}`);
  }
}

function spawnServer(testCase, options) {
  if (
    testCase.engine === "bun" ||
    testCase.engine === "http-native" ||
    testCase.engine === "old" ||
    testCase.engine === "express"
  ) {
    const runtime =
      testCase.engine === "bun"
        ? "bun"
        : testCase.engine === "express"
          ? "node"
          : options.httpNativeRuntime;
    return spawn(runtime, [".github/bench/target.js", testCase.engine, testCase.scenario, String(testCase.port)], {
      cwd: process.cwd(),
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
  }

  if (testCase.engine === "fiber") {
    const cwd = resolve(process.cwd(), ".github/bench/fiber-server");
    if (!existsSync(resolve(cwd, "go.mod"))) {
      throw new Error(`Missing Fiber benchmark target at ${cwd}`);
    }

    return spawn("go", ["run", ".", testCase.scenario, String(testCase.port)], {
      cwd,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
  }

  if (testCase.engine === "zig") {
    const cwd = resolve(process.cwd(), ".github/bench/zig-httpz");
    if (!existsSync(cwd)) {
      throw new Error(`Missing Zig benchmark target at ${cwd}`);
    }

    return spawn("zig", ["build", "run", "-Doptimize=ReleaseFast", "--", testCase.scenario, String(testCase.port)], {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });
  }

  if (testCase.engine === "xitca" || testCase.engine === "monoio") {
    const manifestPath =
      testCase.engine === "xitca"
        ? resolve(process.cwd(), ".github/bench/xitca-server/Cargo.toml")
        : resolve(process.cwd(), ".github/bench/monoio-server/Cargo.toml");

    if (!existsSync(manifestPath)) {
      throw new Error(`Missing Rust benchmark target at ${manifestPath}`);
    }

    return spawn(
      "cargo",
      ["run", "--release", "--manifest-path", manifestPath, "--", testCase.scenario, String(testCase.port)],
      {
        cwd: process.cwd(),
        detached: process.platform !== "win32",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
  }

  throw new Error(`Unsupported engine ${testCase.engine}`);
}

async function stopServer(server, label) {
  if (!server) {
    return;
  }

  if (server.exitCode !== null) {
    cleanupServerStreams(server);
    return;
  }

  const waitForExit = once(server, "exit");
  const gracefulSignal = "SIGTERM";

  try {
    if (server.pid && process.platform !== "win32") {
      process.kill(-server.pid, gracefulSignal);
    } else {
      server.kill(gracefulSignal);
    }
  } catch {
    cleanupServerStreams(server);
    return;
  }

  const gracefulExit = await Promise.race([
    waitForExit.then(() => true).catch(() => false),
    delay(5000).then(() => false),
  ]);

  if (!gracefulExit && server.exitCode === null) {
    console.warn(`[http-native][bench] forcing ${label} to exit`);
    try {
      if (server.pid && process.platform !== "win32") {
        process.kill(-server.pid, "SIGKILL");
      } else {
        server.kill("SIGKILL");
      }
      await once(server, "exit").catch(() => {});
    } catch {
      // Ignore kill failures during cleanup
    }
  }

  cleanupServerStreams(server);
}

function cleanupServerStreams(server) {
  server.stdout?.destroy();
  server.stderr?.destroy();
}

function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function runCommand(command, args, options = {}) {
  const label = options.label ?? `${command} ${args.join(" ")}`;
  const child = spawn(command, args, {
    cwd: process.cwd(),
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit",
    env: process.env,
  });

  let stdout = "";
  let stderr = "";

  if (options.capture) {
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr?.on("data", (chunk) => {
      stderr += chunk;
    });
  }

  const [code, signal] = await once(child, "exit");
  if (code !== 0) {
    throw new Error(
      `${label} failed (code=${code}, signal=${signal})${stderr ? `\n${stderr.trim()}` : ""}`,
    );
  }

  return { stdout, stderr };
}

function validateBombardierResult(payload, testCase, benchmarkUrl) {
  if (!payload?.result || !payload?.spec) {
    throw new Error(`Bombardier returned an unexpected payload for ${testCase.engine}/${testCase.scenario}`);
  }

  if (payload.spec.url !== benchmarkUrl) {
    throw new Error(
      `Bombardier benchmarked ${payload.spec.url} but expected ${benchmarkUrl}`,
    );
  }

  if (payload.result.req4xx > 0 || payload.result.req5xx > 0 || payload.result.others > 0) {
    throw new Error(
      `${testCase.engine}/${testCase.scenario} produced non-success responses: ${JSON.stringify(
        {
          req4xx: payload.result.req4xx,
          req5xx: payload.result.req5xx,
          others: payload.result.others,
        },
      )}`,
    );
  }
}

function deriveMetrics(result) {
  return {
    throughputMBps: result.bytesRead / result.timeTakenSeconds / (1024 * 1024),
    latencyMeanMs: result.latency.mean / 1000,
    latencyMaxMs: result.latency.max / 1000,
  };
}

function renderSummary(payload) {
  const lines = [
    "# Benchmark Summary",
    "",
    `Generated: ${payload.generatedAt}`,
    "",
    `Connections: ${payload.config.connections}`,
    `Duration: ${payload.config.duration}`,
    `Timeout: ${payload.config.timeout}`,
    "",
    "| Engine | Scenario | RPS Mean | Latency Mean (ms) | Latency Max (ms) | Throughput (MB/s) |",
    "| --- | --- | ---: | ---: | ---: | ---: |",
  ];

  for (const entry of payload.results) {
    lines.push(
      `| ${entry.engine} | ${entry.scenario} | ${formatNumber(entry.result.rps.mean)} | ${formatNumber(
        entry.derived.latencyMeanMs,
        2,
      )} | ${formatNumber(entry.derived.latencyMaxMs, 2)} | ${formatNumber(
        entry.derived.throughputMBps,
        2,
      )} |`,
    );
  }

  lines.push("");
  return `${lines.join("\n")}\n`;
}

function formatNumber(value, digits = 2) {
  return Number(value).toLocaleString("en-US", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

await main();
