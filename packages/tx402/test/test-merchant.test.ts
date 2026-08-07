/**
 * The test merchant is test infrastructure, so it needs tests of its own.
 *
 * Everything from M1 onward is validated against this server. If it silently accepted an
 * invalid retry, or emitted a challenge tx402 could not decode, every integration test built
 * on it would be measuring the wrong thing — and would still be green.
 *
 * These tests use raw `fetch`, deliberately. Exercising the merchant through the SDK would
 * make the two mutually reinforcing: a shared misunderstanding of the envelope would pass.
 */

import { afterEach, describe, expect, it } from "vitest";

import { decodePaymentRequiredHeader, encodePaymentSignatureHeader } from "@x402/core/http";
import { createTestMerchant, DEFAULT_REQUIREMENTS } from "@tx402-dev/test-merchant";

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let merchant: Merchant | undefined;

afterEach(async () => {
  await merchant?.close();
  merchant = undefined;
});

/** A well-formed PAYMENT-SIGNATURE for a requirement the merchant offered. */
function signatureFor(requirement: Record<string, unknown>): string {
  return encodePaymentSignatureHeader({
    x402Version: 2,
    accepted: requirement as never,
    payload: { signature: "0xnotarealsignature", authorization: { nonce: "0x00" } },
  });
}

describe("test merchant — challenge", () => {
  it("emits a decodable v2 challenge on the first request", async () => {
    merchant = await createTestMerchant({ scenario: "pay-once" });

    const response = await fetch(`${merchant.url}/resource`);
    expect(response.status).toBe(402);

    const header = response.headers.get("payment-required");
    expect(header).toBeTruthy();

    // Decoded with upstream's own decoder: this is what proves the merchant speaks the
    // real envelope rather than a shape tx402 and it happen to agree on.
    const challenge = decodePaymentRequiredHeader(header as string);
    expect(challenge.x402Version).toBe(2);
    expect(challenge.accepts).toHaveLength(1);
    expect(challenge.accepts[0]?.network).toBe("eip155:8453");
    expect(challenge.accepts[0]?.amount).toBe("50000");
  });

  it("binds the challenge's resource URL to the request that produced it", async () => {
    merchant = await createTestMerchant({ scenario: "pay-once" });

    const response = await fetch(`${merchant.url}/v1/completions`);
    const challenge = decodePaymentRequiredHeader(
      response.headers.get("payment-required") as string,
    );
    expect(challenge.resource.url).toBe(`${merchant.url}/v1/completions`);
  });

  it("offers every configured requirement, in order", async () => {
    merchant = await createTestMerchant({
      requirements: [DEFAULT_REQUIREMENTS.base, DEFAULT_REQUIREMENTS.solana],
    });

    const response = await fetch(`${merchant.url}/resource`);
    const challenge = decodePaymentRequiredHeader(
      response.headers.get("payment-required") as string,
    );
    expect(challenge.accepts.map((entry) => entry.network)).toEqual([
      "eip155:8453",
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    ]);
  });
});

describe("test merchant — paid retry", () => {
  it("delivers with a PAYMENT-RESPONSE once a valid signature arrives", async () => {
    merchant = await createTestMerchant({ scenario: "pay-once" });

    await fetch(`${merchant.url}/resource`);
    const paid = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": signatureFor(DEFAULT_REQUIREMENTS.base) },
    });

    expect(paid.status).toBe(200);
    expect(paid.headers.get("payment-response")).toBeTruthy();
    expect(merchant.violations).toEqual([]);
  });

  it("rejects a signature naming a requirement it never offered", async () => {
    merchant = await createTestMerchant({ requirements: [DEFAULT_REQUIREMENTS.base] });

    await fetch(`${merchant.url}/resource`);
    const paid = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": signatureFor(DEFAULT_REQUIREMENTS.solana) },
    });

    expect(paid.status).toBe(400);
    expect(merchant.violations).toEqual(["accepted-requirement-was-not-offered"]);
  });

  it("rejects a signature that alters the amount", async () => {
    merchant = await createTestMerchant();

    await fetch(`${merchant.url}/resource`);
    const paid = await fetch(`${merchant.url}/resource`, {
      headers: {
        "payment-signature": signatureFor({ ...DEFAULT_REQUIREMENTS.base, amount: "1" }),
      },
    });

    expect(paid.status).toBe(400);
    expect(merchant.violations).toEqual(["accepted-amount-does-not-match-offer"]);
  });

  it("rejects two PAYMENT-SIGNATURE headers on one attempt (ADR-003)", async () => {
    merchant = await createTestMerchant();
    const value = signatureFor(DEFAULT_REQUIREMENTS.base);

    await fetch(`${merchant.url}/resource`);
    // fetch joins repeated header values with ", " — exactly how a duplicate would arrive.
    const paid = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": `${value}, ${value}` },
    });

    expect(paid.status).toBe(400);
    expect(merchant.violations).toEqual(["duplicate-payment-signature-header"]);
  });

  it("rejects an undecodable signature", async () => {
    merchant = await createTestMerchant();

    await fetch(`${merchant.url}/resource`);
    const paid = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": "not-base64-at-all!!!" },
    });

    expect(paid.status).toBe(400);
    expect(merchant.violations).toEqual(["payment-signature-not-decodable"]);
  });
});

describe("test merchant — scenarios", () => {
  it("unpaid-200 never challenges (T-001)", async () => {
    merchant = await createTestMerchant({ scenario: "unpaid-200" });

    const response = await fetch(`${merchant.url}/free`);
    expect(response.status).toBe(200);
    expect(response.headers.get("payment-required")).toBeNull();
    expect(merchant.paidRequests).toHaveLength(0);
  });

  it("rechallenge-once issues a fresh 402 to the first paid attempt (T-010)", async () => {
    merchant = await createTestMerchant({ scenario: "rechallenge-once" });
    const signature = signatureFor(DEFAULT_REQUIREMENTS.base);

    await fetch(`${merchant.url}/resource`);

    const first = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": signature },
    });
    expect(first.status).toBe(402);
    expect(first.headers.get("payment-required")).toBeTruthy();

    const second = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": signature },
    });
    expect(second.status).toBe(200);
  });

  it("malformed-challenge emits a header upstream cannot decode (T-009)", async () => {
    merchant = await createTestMerchant({ scenario: "malformed-challenge" });

    const response = await fetch(`${merchant.url}/resource`);
    expect(response.status).toBe(402);
    expect(() =>
      decodePaymentRequiredHeader(response.headers.get("payment-required") as string),
    ).toThrow();
  });

  it("error-after-signature returns 503 only once payment was transmitted (T-011)", async () => {
    merchant = await createTestMerchant({ scenario: "error-after-signature" });

    expect((await fetch(`${merchant.url}/resource`)).status).toBe(402);
    const paid = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": signatureFor(DEFAULT_REQUIREMENTS.base) },
    });
    expect(paid.status).toBe(503);
  });

  it("cross-origin-redirect points the paid retry at another origin (T-012)", async () => {
    merchant = await createTestMerchant({ scenario: "cross-origin-redirect" });

    await fetch(`${merchant.url}/resource`);
    const paid = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": signatureFor(DEFAULT_REQUIREMENTS.base) },
      redirect: "manual",
    });

    expect(paid.status).toBe(307);
    expect(paid.headers.get("location")).toBe("https://elsewhere.example.net/paid");
  });

  it("missing-payment-response delivers 200 with no settlement metadata", async () => {
    merchant = await createTestMerchant({ scenario: "missing-payment-response" });

    await fetch(`${merchant.url}/resource`);
    const paid = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": signatureFor(DEFAULT_REQUIREMENTS.base) },
    });

    expect(paid.status).toBe(200);
    expect(paid.headers.get("payment-response")).toBeNull();
  });

  it("server-error fails before any challenge is issued (T-017)", async () => {
    merchant = await createTestMerchant({ scenario: "server-error" });

    const response = await fetch(`${merchant.url}/resource`);
    expect(response.status).toBe(500);
    expect(response.headers.get("payment-required")).toBeNull();
  });
});

describe("test merchant — request log", () => {
  it("redacts the PAYMENT-SIGNATURE value while recording its presence (SEC-003)", async () => {
    merchant = await createTestMerchant();
    const signature = signatureFor(DEFAULT_REQUIREMENTS.base);

    await fetch(`${merchant.url}/resource`);
    await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": signature },
    });

    const paid = merchant.paidRequests;
    expect(paid).toHaveLength(1);
    expect(paid[0]?.hasSignature).toBe(true);
    expect(paid[0]?.headers["payment-signature"]).toBe("<redacted>");
    expect(JSON.stringify(merchant.requests)).not.toContain(signature);
  });

  it("records method, path, and body for assertions about request equivalence", async () => {
    merchant = await createTestMerchant({ scenario: "unpaid-200" });

    await fetch(`${merchant.url}/v1/completions`, {
      method: "POST",
      body: JSON.stringify({ prompt: "Hello" }),
      headers: { "content-type": "application/json" },
    });

    expect(merchant.requests[0]).toMatchObject({
      method: "POST",
      path: "/v1/completions",
      body: '{"prompt":"Hello"}',
    });
  });

  it("is deterministic — the same sequence twice yields the same statuses", async () => {
    merchant = await createTestMerchant({ scenario: "rechallenge-once" });
    const signature = signatureFor(DEFAULT_REQUIREMENTS.base);

    const run = async () => {
      await fetch(`${merchant!.url}/resource`);
      const a = await fetch(`${merchant!.url}/resource`, {
        headers: { "payment-signature": signature },
      });
      const b = await fetch(`${merchant!.url}/resource`, {
        headers: { "payment-signature": signature },
      });
      return [a.status, b.status];
    };

    const first = await run();
    merchant.reset();
    const second = await run();

    expect(first).toEqual([402, 200]);
    expect(second).toEqual(first);
  });
});

describe("test merchant — failed settlement (PLAN.md O40)", () => {
  /**
   * A facilitator that verifies anything and settles nothing.
   *
   * Real settlement failures are the interesting ones and are hard to provoke on demand:
   * `transaction_simulation_failed` from a recipient with no associated token account is
   * what actually happened at S13. This reproduces the shape of that answer locally.
   */
  async function refusingFacilitator(errorReason: string): Promise<{
    url: string;
    close: () => Promise<void>;
  }> {
    const { createServer } = await import("node:http");
    const server = createServer((request, response) => {
      let payload = "";
      request.on("data", (chunk) => (payload += chunk));
      request.on("end", () => {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(
          request.url === "/verify"
            ? JSON.stringify({ isValid: true })
            : JSON.stringify({ success: false, errorReason, transaction: "" }),
        );
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("no port");
    return {
      url: `http://127.0.0.1:${String(address.port)}`,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  }

  it("answers 402 with BOTH PAYMENT-RESPONSE and a fresh PAYMENT-REQUIRED", async () => {
    const facilitator = await refusingFacilitator("transaction_simulation_failed");
    try {
      merchant = await createTestMerchant({
        scenario: "pay-once",
        facilitatorUrl: facilitator.url,
        requirements: [DEFAULT_REQUIREMENTS.base],
      });

      const response = await fetch(`${merchant.url}/resource`, {
        headers: { "payment-signature": signatureFor(DEFAULT_REQUIREMENTS.base) },
      });

      expect(response.status).toBe(402);

      // The defect this test exists for: a 402 carrying only PAYMENT-RESPONSE is not a
      // challenge, so the buyer classified it as `missing-header` and the operator never
      // saw the facilitator's actual reason.
      const challenge = response.headers.get("payment-required");
      expect(challenge).not.toBeNull();
      expect(decodePaymentRequiredHeader(challenge as string).accepts).toHaveLength(1);

      // And the real cause is still carried, which is the whole point of answering at all.
      expect(response.headers.get("payment-response")).not.toBeNull();
      expect(merchant.requests.at(-1)?.settlement).toMatchObject({
        success: false,
        errorReason: "transaction_simulation_failed",
      });
    } finally {
      await facilitator.close();
    }
  });

  it("reports an unreachable facilitator as a settlement failure, not as a delivery", async () => {
    // Port 1 on loopback refuses immediately, so this needs no fixture and cannot hang.
    merchant = await createTestMerchant({
      scenario: "pay-once",
      facilitatorUrl: "http://127.0.0.1:1",
      requirements: [DEFAULT_REQUIREMENTS.base],
    });

    const response = await fetch(`${merchant.url}/resource`, {
      headers: { "payment-signature": signatureFor(DEFAULT_REQUIREMENTS.base) },
    });

    expect(response.status).toBe(402);
    expect(response.headers.get("payment-required")).not.toBeNull();
    expect(merchant.requests.at(-1)?.settlement).toMatchObject({
      success: false,
      errorReason: "facilitator-unreachable",
    });
  });
});
