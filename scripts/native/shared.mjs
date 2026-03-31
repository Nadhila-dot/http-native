import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(THIS_DIR, "..", "..");
const PACKAGE_JSON_PATH = resolve(PACKAGE_ROOT, "package.json");
const DEFAULT_REPOSITORY = "Http-native/http-native";

function parseRepositoryPath(input) {
  if (!input) {
    return null;
  }

  const value = String(input).trim();
  if (!value) {
    return null;
  }

  const githubHttpMatch = value.match(
    /github\.com[/:]([^/\s]+)\/([^/\s]+?)(?:\.git)?$/i,
  );
  if (githubHttpMatch) {
    return `${githubHttpMatch[1]}/${githubHttpMatch[2]}`;
  }

  const ownerRepoMatch = value.match(/^([^/\s]+)\/([^/\s]+)$/);
  if (ownerRepoMatch) {
    return `${ownerRepoMatch[1]}/${ownerRepoMatch[2]}`;
  }

  return null;
}

function readPackageJson() {
  const raw = readFileSync(PACKAGE_JSON_PATH, "utf8");
  return JSON.parse(raw);
}

export function resolvePackageVersion(explicitVersion) {
  if (explicitVersion) {
    return String(explicitVersion);
  }

  if (process.env.HTTP_NATIVE_BINARY_VERSION) {
    return process.env.HTTP_NATIVE_BINARY_VERSION;
  }

  return String(readPackageJson().version);
}

export function resolveRepositoryPath() {
  const envRepository = parseRepositoryPath(
    process.env.HTTP_NATIVE_BINARY_REPOSITORY,
  );
  if (envRepository) {
    return envRepository;
  }

  const pkg = readPackageJson();
  const repositoryValue =
    typeof pkg.repository === "string"
      ? pkg.repository
      : pkg.repository?.url;
  const repositoryPath = parseRepositoryPath(repositoryValue);
  return repositoryPath ?? DEFAULT_REPOSITORY;
}

export function resolveReleaseTag(version, explicitTag) {
  if (explicitTag) {
    return String(explicitTag);
  }

  if (process.env.HTTP_NATIVE_BINARY_TAG) {
    return process.env.HTTP_NATIVE_BINARY_TAG;
  }

  return `v${version}`;
}

export function resolveBinaryDestination() {
  return resolve(PACKAGE_ROOT, "http-native.node");
}

export function resolvePlatform(platform = process.platform, arch = process.arch) {
  const supportedPlatform =
    platform === "darwin" || platform === "linux" || platform === "win32";
  if (!supportedPlatform) {
    throw new Error(
      `Unsupported platform "${platform}". Supported: darwin, linux, win32.`,
    );
  }

  const supportedArch = arch === "x64" || arch === "arm64";
  if (!supportedArch) {
    throw new Error(`Unsupported architecture "${arch}". Supported: x64, arm64.`);
  }

  return { platform, arch };
}

export function resolveAssetName(platform, arch) {
  return `http-native-${platform}-${arch}.node`;
}

export function resolveAssetUrl(tag, assetName, repositoryPath = resolveRepositoryPath()) {
  const explicitBase = process.env.HTTP_NATIVE_BINARY_BASE_URL;
  if (explicitBase) {
    return `${explicitBase.replace(/\/+$/, "")}/${tag}/${assetName}`;
  }

  return `https://github.com/${repositoryPath}/releases/download/${tag}/${assetName}`;
}

export { PACKAGE_ROOT };
