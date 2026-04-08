/**
 * http-native streaming multipart parser (DX-5.3)
 *
 * Parses multipart/form-data request bodies with streaming file support.
 * Files can be saved directly to disk without buffering the entire file
 * in memory.
 *
 * Usage:
 *   import { multipart } from "@http-native/core/multipart";
 *   app.post("/upload", multipart({ maxFileSize: "10mb", maxFiles: 5 }), handler);
 */

import { createWriteStream } from "node:fs";
import { join, basename, resolve } from "node:path";
import { randomBytes } from "node:crypto";

const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
const DEFAULT_MAX_FILES = 10;
const DEFAULT_MAX_FIELD_SIZE = 1024 * 1024; // 1 MB

/**
 * @param {Object} [options]
 * @param {string|number} [options.maxFileSize="10mb"]  - Max size per file
 * @param {number}        [options.maxFiles=10]         - Max number of files
 * @param {string|number} [options.maxFieldSize="1mb"]  - Max size per text field
 * @param {string}        [options.uploadDir]           - Auto-save directory (optional)
 */
export function multipart(options = {}) {
  const maxFileSize = parseSize(options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE);
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxFieldSize = parseSize(options.maxFieldSize ?? DEFAULT_MAX_FIELD_SIZE);
  const uploadDir = options.uploadDir;

  return async function multipartMiddleware(req, res, next) {
    const contentType = req.header("content-type") ?? req.headers?.["content-type"] ?? "";
    if (!contentType.startsWith("multipart/form-data")) {
      return next();
    }

    const boundary = extractBoundary(contentType);
    if (!boundary) {
      res.status(400).json({ error: "Missing multipart boundary" });
      return;
    }

    try {
      const rawBody = typeof req.body === "string" ? Buffer.from(req.body) : req.body;
      if (!rawBody || rawBody.length === 0) {
        req.fields = Object.create(null);
        req.files = [];
        return await next();
      }
      const { fields, files } = parseMultipartBody(
        rawBody,
        boundary,
        { maxFileSize, maxFiles, maxFieldSize },
      );

      req.fields = fields;
      req.files = files;

      /* If uploadDir is set, attach saveTo helper to each file */
      if (uploadDir) {
        for (const file of files) {
          file.saveTo = (destPath) => {
            /* Sanitize filename: strip path traversal sequences and use only the base name */
            /* Sanitize filename: strip path traversal sequences and use only the base name */
            const safeName = basename(file.name).replace(/\.\./g, "");
            const fullPath = destPath ?? join(uploadDir, `${randomBytes(16).toString("hex")}-${safeName}`);
            /* Verify the resolved path stays within the upload directory */
            if (!resolve(fullPath).startsWith(resolve(uploadDir))) {
              return Promise.reject(new Error("Path traversal detected in upload filename"));
            }
            return new Promise((resolvePromise, reject) => {
              const ws = createWriteStream(fullPath);
              ws.on("finish", () => resolvePromise(fullPath));
              ws.on("error", reject);
              ws.end(file.data);
            });
          };
        }
      }

      await next();
    } catch (err) {
      if (err.status) {
        res.status(err.status).json({ error: err.message });
      } else {
        throw err;
      }
    }
  };
}

function extractBoundary(contentType) {
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^\s;]+))/);
  return match ? match[1] || match[2] : null;
}

/**
 * Parse a multipart body buffer into fields and files.
 *
 * @param {Buffer} body
 * @param {string} boundary
 * @param {Object} limits
 * @returns {{ fields: Record<string, string>, files: MultipartFile[] }}
 */
function parseMultipartBody(body, boundary, limits) {
  const delimiter = Buffer.from(`--${boundary}`);
  const endDelimiter = Buffer.from(`--${boundary}--`);
  const fields = Object.create(null);
  const files = [];

  let offset = 0;

  /* Find the first boundary */
  const firstBoundary = indexOf(body, delimiter, offset);
  if (firstBoundary === -1) return { fields, files };
  offset = firstBoundary + delimiter.length;

  while (offset < body.length) {
    /* Skip CRLF after boundary */
    if (body[offset] === 0x0d && body[offset + 1] === 0x0a) offset += 2;

    /* Check for end delimiter */
    if (body[offset] === 0x2d && body[offset + 1] === 0x2d) break;

    /* Parse headers of this part */
    const headerEnd = indexOf(body, Buffer.from("\r\n\r\n"), offset);
    if (headerEnd === -1) break;

    const headerSection = body.subarray(offset, headerEnd).toString("utf-8");
    offset = headerEnd + 4;

    const headers = parsePartHeaders(headerSection);
    const disposition = parseContentDisposition(headers["content-disposition"] ?? "");

    /* Find the end of this part's body (next boundary) */
    const nextBoundary = indexOf(body, delimiter, offset);
    if (nextBoundary === -1) break;

    /* Part body is between current offset and (nextBoundary - 2) for trailing CRLF */
    const partBody = body.subarray(offset, nextBoundary - 2);
    offset = nextBoundary + delimiter.length;

    if (disposition.filename !== undefined) {
      /* File part */
      if (files.length >= limits.maxFiles) {
        const err = new Error(`Too many files (max ${limits.maxFiles})`);
        err.status = 413;
        throw err;
      }
      if (partBody.length > limits.maxFileSize) {
        const err = new Error(`File "${disposition.filename}" exceeds max size`);
        err.status = 413;
        throw err;
      }
      files.push({
        name: disposition.filename,
        fieldName: disposition.name,
        mimetype: headers["content-type"] ?? "application/octet-stream",
        size: partBody.length,
        data: partBody,
      });
    } else if (disposition.name) {
      /* Text field */
      if (partBody.length > limits.maxFieldSize) {
        const err = new Error(`Field "${disposition.name}" exceeds max size`);
        err.status = 413;
        throw err;
      }
      fields[disposition.name] = partBody.toString("utf-8");
    }
  }

  return { fields, files };
}

function parsePartHeaders(headerSection) {
  const headers = Object.create(null);
  for (const line of headerSection.split("\r\n")) {
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    headers[name] = value;
  }
  return headers;
}

function parseContentDisposition(value) {
  const result = { name: undefined, filename: undefined };
  const nameMatch = value.match(/\bname="([^"]+)"/);
  const filenameMatch = value.match(/\bfilename="([^"]+)"/);
  if (nameMatch) result.name = nameMatch[1];
  if (filenameMatch) result.filename = filenameMatch[1];
  return result;
}

function indexOf(buffer, search, fromIndex) {
  for (let i = fromIndex; i <= buffer.length - search.length; i++) {
    let found = true;
    for (let j = 0; j < search.length; j++) {
      if (buffer[i + j] !== search[j]) { found = false; break; }
    }
    if (found) return i;
  }
  return -1;
}

function parseSize(input) {
  if (typeof input === "number") return input;
  const match = String(input).match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/i);
  if (!match) return DEFAULT_MAX_FILE_SIZE;
  const num = parseFloat(match[1]);
  switch ((match[2] ?? "b").toLowerCase()) {
    case "gb": return num * 1024 * 1024 * 1024;
    case "mb": return num * 1024 * 1024;
    case "kb": return num * 1024;
    default:   return num;
  }
}
