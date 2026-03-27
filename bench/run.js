import { spawn } from "node:child_process";
import { once } from "node:events";

const [, , engineArg, scenarioArg, portArg] = process.argv;

const engine = engineArg ?? "http-native";
const scenario = scenarioArg ?? "static";
const port = Number(portArg ?? 3001);

function printUsage() {
  console.log("Usage: bun bench/run.js <engine> <scenario> <port>");
  console.log("Engines: http-native | bun | xitca | monoio | zig");
  console.log("Scenarios: static | dynamic | opt");
  console.log("");
  console.log("Example:");
  console.log("  bun bench/run.js http-native static 3001");
  console.log("  bombardier -c 200 -d 10s http://127.0.0.1:3001/");
}

function benchmarkPathForScenario(activeScenario) {
  if (activeScenario === "static") {
    return "/";
  }

  if (activeScenario === "dynamic") {
    return "/users/42";
  }

  return "/stable";
}

async function main() {
  if (!["http-native", "bun", "xitca", "monoio", "zig"].includes(engine)) {
    printUsage();
    process.exit(1);
  }

  if (!["static", "dynamic", "opt"].includes(scenario)) {
    printUsage();
    process.exit(1);
  }

  const child =
    engine === "xitca" || engine === "monoio"
      ? spawn(
        "cargo",
        [
          "run",
          "--release",
          "--manifest-path",
          engine === "xitca"
            ? "bench/xitca-server/Cargo.toml"
            : "bench/monoio-server/Cargo.toml",
          "--",
          scenario,
          String(port),
        ],
        {
          cwd: process.cwd(),
          stdio: ["ignore", "pipe", "inherit"],
        },
      )
      : engine === "zig"
        ? spawn(
          "zig",
          ["build", "run", "-Doptimize=ReleaseFast", "--", scenario, String(port)],
          {
            cwd: `${process.cwd()}/bench/zig-httpz`,
            stdio: ["ignore", "pipe", "inherit"],
          },
        )
        : spawn("bun", ["bench/target.js", engine, scenario, String(port)], {
          cwd: process.cwd(),
          stdio: ["ignore", "pipe", "inherit"],
        });

  child.stdout.setEncoding("utf8");

  let ready = false;
  let stdoutBuffer = "";

  child.stdout.on("data", (chunk) => {
    stdoutBuffer += chunk;
    const lines = stdoutBuffer.split(/\r?\n/);
    stdoutBuffer = lines.pop() ?? "";

    for (const line of lines) {
      if (!line.startsWith("READY ")) {
        console.log(line);
        continue;
      }

      ready = true;
      const url = line.slice("READY ".length).trim();
      const benchmarkUrl = new URL(benchmarkPathForScenario(scenario), url).toString();

      console.log(`[http-native] benchmark target ready: ${benchmarkUrl}`);
      console.log(`[http-native] run: bombardier -c 200 -d 10s "${benchmarkUrl}"`);
      console.log("[http-native] press Ctrl+C when you are done.");
    }
  });

  const shutdown = () => {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
    }
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  const [code, signal] = await once(child, "exit");

  if (!ready) {
    throw new Error(
      `Benchmark target ${engine}/${scenario} exited before readiness (code=${code}, signal=${signal})`,
    );
  }
}

await main();
