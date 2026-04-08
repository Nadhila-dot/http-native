import { readFileSync } from "node:fs";

/**
 * @typedef {Object} TlsConfig
 * @property {string}  cert     - Path to PEM certificate file, or PEM string
 * @property {string}  key      - Path to PEM private key file, or PEM string
 * @property {string}  [ca]     - Path to CA bundle file, or PEM string (optional)
 * @property {string}  [passphrase] - Passphrase for encrypted private key (optional)
 */

/**
 * @typedef {Object} HttpServerConfig
 * @property {string}  defaultHost                   - Bind address (default "127.0.0.1")
 * @property {number}  defaultBacklog                - TCP listen backlog (default 2048)
 * @property {number}  maxHeaderBytes                - Maximum header block size in bytes
 * @property {string}  hotGetRootHttp11              - Hot-path prefix for GET / HTTP/1.1
 * @property {string}  hotGetRootHttp10              - Hot-path prefix for GET / HTTP/1.0
 * @property {string}  headerConnectionPrefix        - Lowercase "connection:" for matching
 * @property {string}  headerContentLengthPrefix     - Lowercase "content-length:" for matching
 * @property {string}  headerTransferEncodingPrefix  - Lowercase "transfer-encoding:" for matching
 * @property {TlsConfig|null} tls                    - TLS/SSL configuration (null = plain HTTP)
 */

/** @type {HttpServerConfig} */
const httpServerConfig = {
  defaultHost: "127.0.0.1",
  defaultBacklog: 2048,
  maxHeaderBytes: 16 * 1024,
  hotGetRootHttp11: "GET / HTTP/1.1\r\n",
  hotGetRootHttp10: "GET / HTTP/1.0\r\n",
  headerConnectionPrefix: "connection:",
  headerContentLengthPrefix: "content-length:",
  headerTransferEncodingPrefix: "transfer-encoding:",
  tls: null,
};

/**
 * Resolve a PEM value: if it looks like a file path, read it; otherwise return as-is.
 * @param {string} value - PEM string or file path
 * @returns {string} PEM content
 */
function resolvePem(value) {
  if (!value) return null;
  if (value.includes("-----BEGIN ")) return value;
  try {
    return readFileSync(value, "utf8");
  } catch (err) {
    throw new Error(`Failed to read TLS file: ${value} (${err.message})`);
  }
}

/**
 * Normalize TLS config — resolve file paths to PEM content and validate.
 * @param {TlsConfig|null} tls
 * @returns {{ cert: string, key: string, ca: string|null, passphrase: string|null }|null}
 */
function normalizeTlsConfig(tls) {
  if (!tls) return null;

  const cert = resolvePem(tls.cert);
  const key = resolvePem(tls.key);

  if (!cert) throw new Error("tls.cert is required — provide a PEM string or file path");
  if (!key) throw new Error("tls.key is required — provide a PEM string or file path");

  return {
    cert,
    key,
    ca: tls.ca ? resolvePem(tls.ca) : null,
    passphrase: tls.passphrase ?? null,
  };
}

/**
 * Merge caller-provided overrides with built-in defaults, coercing
 * every field to the expected primitive type.
 *
 * @param {Partial<HttpServerConfig>} [overrides={}]
 * @returns {HttpServerConfig} Fully-populated, type-coerced config
 */
export function normalizeHttpServerConfig(overrides = {}) {
  return {
    defaultHost: String(overrides.defaultHost ?? httpServerConfig.defaultHost),
    defaultBacklog: Number(overrides.defaultBacklog ?? httpServerConfig.defaultBacklog),
    maxHeaderBytes: Number(overrides.maxHeaderBytes ?? httpServerConfig.maxHeaderBytes),
    hotGetRootHttp11: String(overrides.hotGetRootHttp11 ?? httpServerConfig.hotGetRootHttp11),
    hotGetRootHttp10: String(overrides.hotGetRootHttp10 ?? httpServerConfig.hotGetRootHttp10),
    headerConnectionPrefix: String(
      overrides.headerConnectionPrefix ?? httpServerConfig.headerConnectionPrefix,
    ),
    headerContentLengthPrefix: String(
      overrides.headerContentLengthPrefix ?? httpServerConfig.headerContentLengthPrefix,
    ),
    headerTransferEncodingPrefix: String(
      overrides.headerTransferEncodingPrefix ??
        httpServerConfig.headerTransferEncodingPrefix,
    ),
    tls: normalizeTlsConfig("tls" in overrides ? overrides.tls : httpServerConfig.tls),
  };
}

export default httpServerConfig;
