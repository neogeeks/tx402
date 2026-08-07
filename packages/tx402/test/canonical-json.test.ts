/**
 * Canonical JSON cases the shared vectors cannot express.
 *
 * The `canonical-json.*` vectors are JSON documents, so they can only carry values JSON has.
 * Several of the format's rules are about values that reach the serializer from *code* —
 * `undefined`, a `bigint`, a `Date`, a `Map` — and those need a TypeScript test to exercise.
 */

import { describe, expect, it } from "vitest";

import {
  CanonicalJsonError,
  canonicalJsonBytes,
  canonicalizeJson,
} from "../src/core/canonical-json.js";

/** Asserts the value is rejected, and rejected for the stated reason. */
function expectRejection(value: unknown, reason: string): void {
  try {
    canonicalizeJson(value);
  } catch (error) {
    expect(error).toBeInstanceOf(CanonicalJsonError);
    expect((error as CanonicalJsonError).reason).toBe(reason);
    return;
  }
  throw new Error(`Expected rejection with ${reason}, but serialization succeeded`);
}

describe("canonicalizeJson — non-JSON inputs", () => {
  it("rejects undefined, functions, symbols, and bigints", () => {
    // JSON.stringify silently drops the first three inside objects and throws on bigint.
    // Silent dropping is the dangerous behavior: a field would vanish from the signed
    // bytes while remaining visible in the document a reviewer reads.
    expectRejection(undefined, "unsupported-type");
    expectRejection({ fn: () => 1 }, "unsupported-type");
    expectRejection({ sym: Symbol("x") }, "unsupported-type");
    expectRejection({ big: 1n }, "unsupported-type");
  });

  it("rejects objects with a non-plain prototype", () => {
    // Each of these has a JSON.stringify representation, and each of them loses
    // information: a Date becomes a string, a Map becomes `{}`.
    expectRejection({ when: new Date(0) }, "unsupported-type");
    expectRejection({ map: new Map([["a", 1]]) }, "unsupported-type");
    expectRejection({ set: new Set([1]) }, "unsupported-type");
    expectRejection(Object.create(null) as object, "unsupported-type");

    class Custom {
      value = 1;
    }
    expectRejection({ instance: new Custom() }, "unsupported-type");
  });

  it("rejects NaN and Infinity as non-integer numbers", () => {
    expectRejection({ nan: Number.NaN }, "non-integer-number");
    expectRejection({ infinite: Number.POSITIVE_INFINITY }, "non-integer-number");
    expectRejection({ negative: Number.NEGATIVE_INFINITY }, "non-integer-number");
  });

  it("reports the path to the offending value", () => {
    try {
      canonicalizeJson({ networks: { "eip155:8453": { assets: [{ decimals: 6.5 }] } } });
    } catch (error) {
      expect((error as CanonicalJsonError).path).toBe(
        "/networks/eip155:8453/assets/0/decimals",
      );
      return;
    }
    throw new Error("Expected a rejection");
  });

  it("rejects a non-ASCII key nested inside an array", () => {
    expectRejection([{ é: 1 }], "non-ascii-key");
  });
});

describe("canonicalizeJson — accepted values", () => {
  it("serializes bare scalars, not only objects", () => {
    expect(canonicalizeJson(null)).toBe("null");
    expect(canonicalizeJson(true)).toBe("true");
    expect(canonicalizeJson(false)).toBe("false");
    expect(canonicalizeJson(42)).toBe("42");
    expect(canonicalizeJson("hi")).toBe('"hi"');
    expect(canonicalizeJson([])).toBe("[]");
  });

  it("preserves array order while sorting object keys", () => {
    expect(canonicalizeJson({ b: [3, 1, 2], a: 1 })).toBe('{"a":1,"b":[3,1,2]}');
  });
});

describe("canonicalJsonBytes", () => {
  it("produces ASCII bytes, so UTF-8 encoding is a no-op", () => {
    const bytes = canonicalJsonBytes({ latin: "café", astral: "😀" });
    expect(bytes.every((byte) => byte < 0x80)).toBe(true);

    // Round-trips to the same string the serializer returned.
    expect(new TextDecoder().decode(bytes)).toBe(
      canonicalizeJson({ latin: "café", astral: "😀" }),
    );
  });

  it("propagates rejection rather than emitting partial bytes", () => {
    expect(() => canonicalJsonBytes({ bad: 1.5 })).toThrow(CanonicalJsonError);
  });
});
