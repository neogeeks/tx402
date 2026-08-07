import { encodePaymentRequiredHeader } from "@x402/core/http";
import { describe, expect, it } from "vitest";

import { MAX_PAYMENT_REQUIRED_DEPTH, decodePaymentRequired } from "../src/core/protocol.js";
import {
  InvalidPaymentRequiredError,
  UnsupportedProtocolError,
} from "../src/core/errors.js";

const REQUEST = {
  requestUrl: "https://api.example.com/resource",
  requestMethod: "post",
  requestId: "protocol-test",
  clockEpochMs: 1_785_711_360_000,
} as const;

const requirement = {
  scheme: "exact",
  network: "eip155:8453" as `${string}:${string}`,
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  amount: "50000",
  payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
  maxTimeoutSeconds: 60,
  extra: {},
};

function rawHeader(json: string): string {
  return Buffer.from(json).toString("base64");
}

function expectInvalidReason(operation: () => unknown, reason: string): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidPaymentRequiredError);
    expect((error as InvalidPaymentRequiredError).details.reason).toBe(reason);
    return;
  }
  throw new Error(`Expected InvalidPaymentRequiredError with reason ${reason}`);
}

describe("strict PaymentRequired decoding", () => {
  it("normalizes upstream fields and locally binds the method", () => {
    const header = encodePaymentRequiredHeader({
      x402Version: 2,
      resource: { url: REQUEST.requestUrl },
      accepts: [requirement],
    });
    const result = decodePaymentRequired(header, REQUEST);
    expect(result.resource).toEqual({ url: REQUEST.requestUrl, method: "POST" });
    expect(result.requirements[0]).toMatchObject({
      index: 0,
      amountAtomic: "50000",
      scheme: "exact",
    });
    expect(result.headerHash).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(result.requirements[0]?.rawHash).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("rejects duplicate object keys before JSON.parse can collapse them", () => {
    const header = rawHeader(
      '{"x402Version":2,"x402Version":2,"resource":{"url":"https://api.example.com/resource"},"accepts":[]}',
    );
    expectInvalidReason(() => decodePaymentRequired(header, REQUEST), "duplicate-json-key");
  });

  it("rejects nesting beyond depth 16", () => {
    const nested =
      "[".repeat(MAX_PAYMENT_REQUIRED_DEPTH + 1) +
      "0" +
      "]".repeat(MAX_PAYMENT_REQUIRED_DEPTH + 1);
    expectInvalidReason(
      () => decodePaymentRequired(rawHeader(nested), REQUEST),
      "json-depth-exceeded",
    );
  });

  it("distinguishes an unsupported version from malformed v2", () => {
    const header = rawHeader('{"x402Version":3,"resource":{},"accepts":[]}');
    expect(() => decodePaymentRequired(header, REQUEST)).toThrow(UnsupportedProtocolError);
  });

  it("rejects malformed schema fields without exposing the header", () => {
    const header = rawHeader(
      '{"x402Version":2,"resource":{"url":"https://api.example.com/resource"},"accepts":[{"scheme":"exact"}]}',
    );
    try {
      decodePaymentRequired(header, REQUEST);
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidPaymentRequiredError);
      expect(JSON.stringify(error)).not.toContain(header);
      return;
    }
    throw new Error("Expected malformed requirement to fail");
  });

  it.each([
    ["trailing input", '{"x402Version":2}x'],
    ["unterminated string", '"unterminated'],
    ["missing colon", '{"x402Version" 2}'],
    ["missing comma", "[true false]"],
    ["invalid token", "@"],
  ])("rejects invalid JSON grammar: %s", (_name, json) => {
    expectInvalidReason(
      () => decodePaymentRequired(rawHeader(json), REQUEST),
      "invalid-json",
    );
  });

  it("accepts the explicit localhost exception and preserves an optional error", () => {
    const header = encodePaymentRequiredHeader({
      x402Version: 2,
      error: "merchant diagnostic",
      resource: { url: "http://127.0.0.1:4321/resource" },
      accepts: [requirement],
    });
    const result = decodePaymentRequired(header, {
      ...REQUEST,
      requestUrl: "http://127.0.0.1:4321/requested",
      allowInsecureLocalhost: true,
    });
    expect(result.error).toBe("merchant diagnostic");
  });

  it("rejects invalid resource URLs and non-canonical scheme extra data", () => {
    const invalidUrl = rawHeader(
      JSON.stringify({
        x402Version: 2,
        resource: { url: "not a URL" },
        accepts: [requirement],
      }),
    );
    expectInvalidReason(
      () => decodePaymentRequired(invalidUrl, REQUEST),
      "resource-url-invalid",
    );

    const fractionalExtra = encodePaymentRequiredHeader({
      x402Version: 2,
      resource: { url: REQUEST.requestUrl },
      accepts: [{ ...requirement, extra: { ratio: 1.5 } }],
    });
    expectInvalidReason(
      () => decodePaymentRequired(fractionalExtra, REQUEST),
      "upstream-schema-invalid",
    );
  });
});
