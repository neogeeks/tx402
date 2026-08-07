import { describe, expect, it } from "vitest";

import {
  digestRequestBody,
  fingerprintRequest,
  normalizeFingerprintUrl,
} from "../src/core/fingerprint.js";

const CHALLENGE = `sha256:${"a".repeat(64)}`;

describe("SEC-009 request fingerprint", () => {
  it("binds method, normalized URL, body bytes, and challenge hash", () => {
    const base = {
      method: "post",
      url: "HTTPS://Example.COM:443/a/../pay?b=2&a=1#ignored",
      body: "hello",
      challengeHash: CHALLENGE,
    } as const;
    const fingerprint = fingerprintRequest(base);
    expect(fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(normalizeFingerprintUrl(base.url)).toBe("https://example.com/pay?b=2&a=1");
    expect(fingerprintRequest({ ...base, method: "POST" })).toBe(fingerprint);
    expect(fingerprintRequest({ ...base, body: "hello!" })).not.toBe(fingerprint);
    expect(
      fingerprintRequest({ ...base, challengeHash: `sha256:${"b".repeat(64)}` }),
    ).not.toBe(fingerprint);
  });

  it("excludes URL credentials and treats null as an empty byte body", () => {
    const withSecret = fingerprintRequest({
      method: "GET",
      url: "https://user:seeded-secret@example.com/data",
      body: null,
      challengeHash: CHALLENGE,
    });
    const withoutSecret = fingerprintRequest({
      method: "GET",
      url: "https://example.com/data",
      body: new Uint8Array(),
      challengeHash: CHALLENGE,
    });
    expect(withSecret).toBe(withoutSecret);
    expect(digestRequestBody(null)).toBe(digestRequestBody(""));
  });
});
