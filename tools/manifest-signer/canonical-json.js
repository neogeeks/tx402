/**
 * tx402 canonical JSON — signing-tool copy.
 *
 * This is a deliberate third implementation of the format frozen in ADR-012, alongside
 * `packages/tx402/src/core/canonical-json.ts` and
 * `packages/tx402-python/src/tx402/canonical_json.py`.
 *
 * Duplicating it is safe here for a specific reason: this copy produces the bytes that get
 * *signed*, and both SDK copies produce the bytes that get *verified*. If any of the three
 * disagreed by even one byte, the `manifest.verify` conformance vectors over the real
 * bundled manifest would fail immediately in that language. The signature is itself the
 * cross-check, and it is a far stronger one than a shared import would be.
 *
 * The rules are documented in full in the TypeScript copy; they are not restated here so
 * that there is one place to read them.
 */

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

const SHORT_ESCAPES = new Map([
  [0x08, "\\b"],
  [0x09, "\\t"],
  [0x0a, "\\n"],
  [0x0c, "\\f"],
  [0x0d, "\\r"],
  [0x22, '\\"'],
  [0x5c, "\\\\"],
]);

/**
 * @param {string} value
 * @returns {string} an ASCII JSON string literal, quotes included
 */
function encodeString(value) {
  let out = '"';
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    const short = SHORT_ESCAPES.get(unit);
    if (short !== undefined) {
      out += short;
    } else if (unit >= 0x20 && unit <= 0x7e) {
      out += value[index];
    } else {
      out += `\\u${unit.toString(16).padStart(4, "0")}`;
    }
  }
  return `${out}"`;
}

/**
 * @param {string} key
 * @returns {boolean}
 */
function isPrintableAscii(key) {
  for (let index = 0; index < key.length; index += 1) {
    const unit = key.charCodeAt(index);
    if (unit < 0x20 || unit > 0x7e) return false;
  }
  return true;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @returns {string}
 */
function encodeValue(value, path) {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isInteger(value)) {
        throw new Error(`canonical-json: non-integer number at ${path || "/"}`);
      }
      if (Math.abs(value) > MAX_SAFE) {
        throw new Error(`canonical-json: integer out of safe range at ${path || "/"}`);
      }
      return String(value === 0 ? 0 : value);
    case "string":
      return encodeString(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((item, index) => encodeValue(item, `${path}/${index}`)).join(",")}]`;
      }
      if (Object.getPrototypeOf(value) !== Object.prototype) {
        throw new Error(`canonical-json: non-plain object at ${path || "/"}`);
      }
      const parts = [];
      for (const key of Object.keys(value).sort()) {
        if (!isPrintableAscii(key)) {
          throw new Error(`canonical-json: non-ASCII object key at ${path}/${key}`);
        }
        parts.push(`${encodeString(key)}:${encodeValue(value[key], `${path}/${key}`)}`);
      }
      return `{${parts.join(",")}}`;
    }
    default:
      throw new Error(`canonical-json: unsupported type ${typeof value} at ${path || "/"}`);
  }
}

/**
 * @param {unknown} value
 * @returns {string} canonical JSON, always pure ASCII
 */
export function canonicalizeJson(value) {
  return encodeValue(value, "");
}

/**
 * @param {unknown} value
 * @returns {Buffer}
 */
export function canonicalJsonBytes(value) {
  return Buffer.from(canonicalizeJson(value), "ascii");
}
