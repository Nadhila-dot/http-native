import { copyFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

// unused right?
// need to double check and delete this

const release = process.argv.includes("--release");
const profile = release ? "release" : "debug";

const cargoArgs = ["build"];
if (release) {
  cargoArgs.push("--release");
}
cargoArgs.push("--manifest-path", "rust-native/Cargo.toml");

const result = Bun.spawnSync({
  cmd: ["cargo", ...cargoArgs],
  cwd: process.cwd(),
  stdin: "ignore",
  stdout: "inherit",
  stderr: "inherit",
});

if (result.exitCode !== 0) {
  process.exit(result.exitCode);
}

const platformArtifact =
  process.platform === "darwin"
    ? "libhttp_native_napi.dylib"
    : process.platform === "win32"
      ? "http_native_napi.dll"
      : "libhttp_native_napi.so";

const source = resolve(`rust-native/target/${profile}/${platformArtifact}`);
const profileTarget = resolve(`http-native.${profile}.node`);
const defaultTarget = resolve("http-native.node");

if (!existsSync(source)) {
  throw new Error(`Native artifact not found at ${source}`);
}

copyFileSync(source, profileTarget);
copyFileSync(source, defaultTarget);
console.log(`[http-native] wrote ${profileTarget}`);
console.log(`[http-native] wrote ${defaultTarget}`);
