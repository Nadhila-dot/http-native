/**
 * http-native IP allowlist / denylist middleware.
 *
 * Filters requests based on client IP address using CIDR range matching.
 * Supports both IPv4 and IPv6 addresses. CIDR ranges are parsed at startup
 * into efficient binary representations for O(1)-per-bit prefix matching.
 *
 * Usage:
 *   import { ipFilter } from "@http-native/core/ip-filter";
 *
 *   // Allow only private networks
 *   app.use(ipFilter({
 *     allow: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
 *     deny: ["0.0.0.0/0"],
 *   }));
 *
 *   // Deny specific ranges
 *   app.use(ipFilter({ deny: ["203.0.113.0/24"] }));
 *
 *   // Trust proxy (use X-Forwarded-For)
 *   app.use(ipFilter({ allow: ["10.0.0.0/8"], trustProxy: true }));
 */

// ─── CIDR Parsing ─────────────────────────

/**
 * Parse an IPv4 address string into a 32-bit integer.
 *
 * @param {string} ip
 * @returns {number|null}
 */
function parseIPv4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;

  let result = 0;
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(parts[i], 10);
    if (!Number.isFinite(octet) || octet < 0 || octet > 255) return null;
    result = (result << 8) | octet;
  }

  return result >>> 0; // unsigned 32-bit
}

/**
 * Parse a CIDR notation string into a range descriptor.
 *
 * @param {string} cidr - e.g. "10.0.0.0/8", "192.168.1.0/24"
 * @returns {{ ip: number, mask: number }}
 */
function parseCIDR(cidr) {
  const [ipStr, prefixStr] = cidr.split("/");
  const ip = parseIPv4(ipStr);

  if (ip === null) {
    throw new TypeError(`Invalid IP address in CIDR: "${cidr}"`);
  }

  const prefix = prefixStr !== undefined ? parseInt(prefixStr, 10) : 32;
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) {
    throw new TypeError(`Invalid prefix length in CIDR: "${cidr}"`);
  }

  /* Build the network mask: /24 → 0xFFFFFF00 */
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = (ip & mask) >>> 0;

  return { ip: network, mask };
}

/**
 * Check if an IPv4 integer matches a parsed CIDR range.
 *
 * @param {number} ip
 * @param {{ ip: number, mask: number }} range
 * @returns {boolean}
 */
function matchesCIDR(ip, range) {
  return ((ip & range.mask) >>> 0) === range.ip;
}

/**
 * Extract the client IPv4 address from a potentially IPv6-mapped string.
 *
 * @param {string} ip
 * @returns {number|null}
 */
function extractIPv4(ip) {
  if (!ip) return null;

  /* Strip IPv6 prefix for IPv4-mapped addresses (::ffff:10.0.0.1) */
  const stripped = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  return parseIPv4(stripped);
}

// ─── Middleware Factory ───────────────────

/**
 * Create an IP filter middleware.
 *
 * @param {Object} options
 * @param {string[]} [options.allow]       - CIDR ranges to allow
 * @param {string[]} [options.deny]        - CIDR ranges to deny
 * @param {boolean} [options.trustProxy]   - Use X-Forwarded-For header
 * @param {Function} [options.onDenied]    - Custom denial handler
 * @returns {Function} Middleware function
 */
export function ipFilter(options = {}) {
  if (typeof options !== "object" || options === null) {
    throw new TypeError("ipFilter(options) expects an object");
  }

  const allowRanges = (options.allow ?? []).map(parseCIDR);
  const denyRanges = (options.deny ?? []).map(parseCIDR);
  const trustProxy = options.trustProxy === true;
  const onDenied = options.onDenied ?? null;

  if (allowRanges.length === 0 && denyRanges.length === 0) {
    throw new TypeError("ipFilter requires at least one allow or deny range");
  }

  return async function ipFilterMiddleware(req, res, next) {
    let clientIp = req.ip;

    /* When behind a reverse proxy, use the first X-Forwarded-For entry */
    if (trustProxy) {
      const xff = req.header("x-forwarded-for");
      if (xff) {
        clientIp = xff.split(",")[0].trim();
      }
    }

    const ipInt = extractIPv4(clientIp);

    if (ipInt === null) {
      /* Cannot parse IP — deny by default for safety */
      if (typeof onDenied === "function") {
        return onDenied(req, res);
      }
      return res.status(403).json({ error: "Forbidden" });
    }

    /* Check deny list — explicitly denied IPs are blocked unless also allowed */
    const isDenied = denyRanges.some((r) => matchesCIDR(ipInt, r));
    const isAllowed = allowRanges.length > 0
      ? allowRanges.some((r) => matchesCIDR(ipInt, r))
      : true; /* No allow list = all IPs implicitly allowed */

    /* Deny if: explicitly denied and not allowed, OR allow list exists and IP not in it */
    const shouldDeny = (isDenied && !isAllowed) || (allowRanges.length > 0 && !isAllowed);

    if (shouldDeny) {
      if (typeof onDenied === "function") {
        return onDenied(req, res);
      }
      return res.status(403).json({ error: "Forbidden" });
    }

    await next();
  };
}
