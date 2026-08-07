/**
 * tx402 canonical JSON — the deterministic byte form used for signing and hashing.
 *
 * Frozen at M0 (ADR-012). Two independent implementations must produce identical bytes for
 * identical input, or a manifest signed by the release tooling will not verify inside the
 * Python SDK. The `canonical-json.*` conformance vectors pin the output byte for byte.
 *
 * Rules, in full:
 *
 *  1. Permitted types are object, array, string, integer, boolean, and null. Anything else
 *     — a float, `NaN`, `Infinity`, `undefined`, a `bigint`, a `Date`, a class instance —
 *     is rejected rather than coerced.
 *  2. Integers must be exactly representable as a JS number (|n| <= 2^53 - 1). Python's
 *     integers are unbounded, so the *narrower* language sets the limit; without this a
 *     document could canonicalize in Python and silently round in TypeScript.
 *  3. Object keys must be printable ASCII (U+0020 – U+007E) and are sorted ascending.
 *     Restricting keys to ASCII is what makes the sort unambiguous: JavaScript compares
 *     strings by UTF-16 code unit and Python by code point, which disagree above the BMP.
 *  4. Strings escape `"` and `\`, use the short forms for `\b \t \n \f \r`, and escape
 *     every other character outside U+0020 – U+007E as lowercase `\uXXXX` per UTF-16 code
 *     unit. Output is therefore always pure ASCII, which removes any encoding ambiguity
 *     before the bytes reach a hash or a signature.
 *  5. No insignificant whitespace: `,` and `:` are bare separators.
 *
 * Rule 4 also means this is exactly `json.dumps(obj, sort_keys=True, ensure_ascii=True,
 * separators=(",", ":"), allow_nan=False)` on the Python side — which is how that
 * implementation is written, giving the two languages genuinely independent code paths
 * over the same frozen contract.
 */

/** Why a value could not be canonicalized. Stable identifiers, shared with Python. */
export type CanonicalJsonErrorReason =
  "non-integer-number" | "number-out-of-safe-range" | "non-ascii-key" | "unsupported-type";

/** Raised when a value cannot be canonically serialized. */
export class CanonicalJsonError extends Error {
  readonly reason: CanonicalJsonErrorReason;
  /** JSON-Pointer-ish path to the offending value, for diagnostics. */
  readonly path: string;

  constructor(reason: CanonicalJsonErrorReason, path: string, message: string) {
    super(message);
    this.name = "CanonicalJsonError";
    this.reason = reason;
    this.path = path;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Any value canonical JSON accepts. */
export type CanonicalValue =
  | null
  | boolean
  | number
  | string
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue };

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

const SHORT_ESCAPES = new Map<number, string>([
  [0x08, "\\b"],
  [0x09, "\\t"],
  [0x0a, "\\n"],
  [0x0c, "\\f"],
  [0x0d, "\\r"],
  [0x22, '\\"'],
  [0x5c, "\\\\"],
]);

/**
 * Escapes a string to a pure-ASCII JSON string literal, including the surrounding quotes.
 *
 * Iterates by UTF-16 code unit deliberately: a lone or paired surrogate is emitted as its
 * own `\uXXXX`, matching Python's `ensure_ascii` behavior exactly.
 */
function encodeString(value: string): string {
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

function isPrintableAscii(key: string): boolean {
  for (let index = 0; index < key.length; index += 1) {
    const unit = key.charCodeAt(index);
    if (unit < 0x20 || unit > 0x7e) return false;
  }
  return true;
}

function encodeValue(value: unknown, path: string): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number": {
      if (!Number.isFinite(value)) {
        throw new CanonicalJsonError(
          "non-integer-number",
          path,
          `Canonical JSON rejects non-finite numbers at ${path}`,
        );
      }
      if (!Number.isInteger(value)) {
        throw new CanonicalJsonError(
          "non-integer-number",
          path,
          `Canonical JSON rejects fractional numbers at ${path}; money is atomic-unit strings (ADR-006)`,
        );
      }
      if (Math.abs(value) > MAX_SAFE) {
        throw new CanonicalJsonError(
          "number-out-of-safe-range",
          path,
          `Integer at ${path} exceeds the safe range shared with Python`,
        );
      }
      // `-0` stringifies to "0" here, matching Python.
      return String(value === 0 ? 0 : value);
    }

    case "string":
      return encodeString(value);

    case "object": {
      if (Array.isArray(value)) {
        const items = value.map((item, index) => encodeValue(item, `${path}/${index}`));
        return `[${items.join(",")}]`;
      }

      // Reject anything with a non-plain prototype: Date, Map, Set, class instances, and
      // null-prototype objects all serialize inconsistently or lose information.
      const prototype = Object.getPrototypeOf(value) as unknown;
      if (prototype !== Object.prototype) {
        throw new CanonicalJsonError(
          "unsupported-type",
          path,
          `Canonical JSON accepts plain objects only; got a non-plain object at ${path}`,
        );
      }

      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      const parts: string[] = [];

      for (const key of keys) {
        if (!isPrintableAscii(key)) {
          throw new CanonicalJsonError(
            "non-ascii-key",
            `${path}/${key}`,
            `Object keys must be printable ASCII so that key ordering is language-independent; got ${JSON.stringify(key)}`,
          );
        }
        parts.push(`${encodeString(key)}:${encodeValue(record[key], `${path}/${key}`)}`);
      }

      return `{${parts.join(",")}}`;
    }

    default:
      // undefined, bigint, symbol, function
      throw new CanonicalJsonError(
        "unsupported-type",
        path,
        `Canonical JSON does not accept ${typeof value} at ${path}`,
      );
  }
}

/**
 * Serializes a value to its canonical JSON string. The result is always pure ASCII.
 *
 * @throws {CanonicalJsonError} when the value contains anything the format rejects.
 */
export function canonicalizeJson(value: unknown): string {
  return encodeValue(value, "");
}

/** Canonical JSON as bytes, ready for hashing or signing. ASCII, so UTF-8 is a no-op. */
export function canonicalJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalizeJson(value));
}
