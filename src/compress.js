/**
 * http-native response compression middleware.
 *
 * All compression happens in the Rust native layer — this middleware
 * is a no-op that carries configuration to the manifest.
 *
 * Usage:
 *   import { compress } from "@http-native/core/compress";
 *   app.use(compress());
 *   app.use(compress({ minSize: 512, brotliQuality: 6 }));
 */

/**
 * Create a compression middleware.
 *
 * @param {Object} [options]
 * @param {number} [options.minSize=1024]       - Minimum body size in bytes to compress
 * @param {number} [options.brotliQuality=4]    - Brotli quality (0-11, default 4)
 * @param {number} [options.gzipLevel=6]        - Gzip compression level (0-9, default 6)
 * @param {Array}  [options.qualityMap]          - Per-content-type quality overrides
 * @returns {Function} Middleware function
 */
export function compress(options = {}) {
  const config = {
    minSize: options.minSize ?? 1024,
    brotliQuality: options.brotliQuality ?? 4,
    gzipLevel: options.gzipLevel ?? 6,
    qualityMap: options.qualityMap ?? [],
  };

  function compressionMiddleware(req, res, next) {
    return next();
  }

  compressionMiddleware._compressionConfig = config;
  return compressionMiddleware;
}
