import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function loadNativeModule() {
  const configuredPath = process.env.HTTP_NATIVE_NATIVE_PATH ?? process.env.HTTP_NATIVE_NODE_PATH;
  const nativeModulePath = configuredPath
    ? resolve(rootDir, configuredPath)
    : resolve(rootDir, "http-native.node");

  if (!existsSync(nativeModulePath)) {
    throw new Error(
      `Native module not found at ${nativeModulePath}. Build it first with "bun run build".`,
    );
  }

  return require(nativeModulePath);
}
