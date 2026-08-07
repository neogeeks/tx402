/**
 * The re-challenge loop, end to end (T-010, T-011, T-012 — SPEC §6.7).
 *
 * These are the tests that claim M6. They run the shipped request path against a real test
 * merchant and a real local JSON-RPC stub; only name resolution is faked, exactly as in
 * `evm-payment.test.ts`.
 *
 * What each test is really pinning:
 *
 *  - **T-010** — a repeated 402 is parsed from scratch, re-planned, re-reserved, and
 *    re-signed. The re-priced re-challenge is the load-bearing part: if any implementation
 *    carried the first normalized challenge forward, it would pay the *old* price and the
 *    merchant's own retry validator would reject it as `accepted-amount-does-not-match-offer`.
 *  - **T-011** — an outcome that is unknown after transmission ends the loop. It is not one
 *    of the attempts `maxPaidAttempts` grants: retrying there would risk paying twice, which
 *    is precisely what SPEC §6.7 forbids without an idempotency strategy.
 *  - **T-012** — a cross-origin redirect is refused, and the reservation is held rather than
 *    released, because the signature already reached the merchant.
 */

import { randomBytes } from "node:crypto";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client, type Tx402Logger } from "../src/core/client.js";
import { MemorySpendStore, type SpendStore } from "../src/core/ledger.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import type { EvmSigner } from "../src/core/signers.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";

const BASE = BUNDLED_MANIFEST.networks["eip155:8453"] as EvmManifestNetwork;
const USDC = BASE.assets[0] as EvmManifestAsset;
const RPC_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));
const PAY_TO = "0x1234567890AbcdEF1234567890aBcdef12345678";

const REQUIREMENT = {
  scheme: "exact",
  network: "eip155:8453",
  asset: USDC.address,
  amount: "50000",
  payTo: PAY_TO,
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

/** The same offer at a different price — what a merchant re-challenges with. */
const REPRICED = { ...REQUIREMENT, amount: "70000" };

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let merchant: Merchant | undefined;
let rpc: EvmRpcStub;
let signer: EvmSigner & { readonly nonces: string[] };
let payer: `0x${string}`;

/** Records every ledger transition in order, so the loop's disposition is observable. */
function recordingStore(log: string[]): SpendStore {
  const inner = new MemorySpendStore();
  return {
    kind: inner.kind,
    reserve: async (input) => {
      const reservation = await inner.reserve(input);
      log.push("reserve");
      return reservation;
    },
    commit: async (input) => {
      const entry = await inner.commit(input);
      log.push("commit");
      return entry;
    },
    release: async (id, now) => {
      const released = await inner.release(id, now);
      log.push("release");
      return released;
    },
    getBudgetState: (query) => inner.getBudgetState(query),
  };
}

/**
 * A funded signer that keeps each authorization's nonce and nothing else.
 *
 * The nonce is what SPEC §6.6 requires to be fresh per authorization, and comparing two of
 * them is the most direct evidence that the second attempt signed something new rather than
 * re-sending the first. Nothing else from the message is retained (SEC-003).
 */
function noncedSigner(): EvmSigner & { readonly nonces: string[] } {
  const inner = privateKeyToEvmSigner(`0x${randomBytes(32).toString("hex")}`);
  const nonces: string[] = [];
  return {
    kind: "evm",
    nonces,
    getAddress: () => inner.getAddress(),
    signTypedData: (request) => {
      const message = request.message as { nonce?: unknown };
      if (typeof message.nonce === "string") nonces.push(message.nonce);
      return inner.signTypedData(request);
    },
  };
}

async function startMerchant(options: Parameters<typeof createTestMerchant>[0]) {
  if (merchant !== undefined) await merchant.close();
  merchant = await createTestMerchant(options);
  return merchant;
}

beforeEach(async () => {
  signer = noncedSigner();
  payer = await signer.getAddress();
  rpc = await createEvmRpcStub({
    chainId: 8453,
    token: USDC.address,
    balances: { [payer]: "5000000" },
  });

  const realFetch = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: Request | string | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (!RPC_HOSTS.has(url.host)) return realFetch(request);
    return realFetch(rpc.url, {
      method: request.method,
      headers: request.headers,
      body: await request.text(),
    });
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  if (merchant !== undefined) await merchant.close();
  merchant = undefined;
  await rpc.close();
});

function client(overrides: Parameters<typeof createTx402Client>[0] = {}) {
  const { policy, ...rest } = overrides;
  return createTx402Client({
    signers: { evm: signer },
    allowInsecureLocalhost: true,
    policy: {
      maxPerRequest: "0.50 USDC",
      maxPerHour: "10.00 USDC",
      allowedNetworks: ["eip155:8453"],
      ...policy,
    },
    ...rest,
  });
}

describe("T-010 repeated 402 with a fresh challenge", () => {
  it("re-plans, re-reserves, and re-signs against the new challenge", async () => {
    const server = await startMerchant({
      scenario: "rechallenge-once",
      requirements: [REQUIREMENT],
      rechallengeRequirements: [REPRICED],
      body: JSON.stringify({ ok: true, resource: "paid-on-second-attempt" }),
    });
    const log: string[] = [];
    const tx402 = client({ spendStore: recordingStore(log) });

    const response = await tx402.fetch(`${server.url}/resource`);
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      ok: true,
      resource: "paid-on-second-attempt",
    });

    // Two signed attempts, and the merchant's own retry validator accepted both — which it
    // only does when the second paid against the re-challenge's price, not the first's.
    expect(server.paidRequests).toHaveLength(2);
    expect(server.violations).toEqual([]);
    expect(server.paidRequests.map((entry) => entry.acceptedAmount)).toEqual([
      "50000",
      "70000",
    ]);

    // The old signature is never reused, and the authorization behind it is genuinely new.
    const hashes = server.paidRequests.map((entry) => entry.signatureHash);
    expect(hashes[0]).toBeTruthy();
    expect(hashes[0]).not.toBe(hashes[1]);
    expect(signer.nonces).toHaveLength(2);
    expect(signer.nonces[0]).not.toBe(signer.nonces[1]);

    // The disposition on each branch: released on the fresh challenge (no settlement can
    // have occurred if the merchant is still asking to be paid), committed on delivery.
    expect(log).toEqual(["reserve", "release", "reserve", "commit"]);

    // Only the second attempt's price is committed. The first reservation came back in full.
    const budget = tx402.getBudgetState();
    expect(budget.committedAtomic).toBe("70000");
    expect(budget.reservedAtomic).toBe("0");
    expect(budget.entries).toHaveLength(1);
  });

  it("keeps one request ID and the caller's idempotency key across both attempts", async () => {
    const server = await startMerchant({
      scenario: "rechallenge-once",
      requirements: [REQUIREMENT],
      rechallengeRequirements: [REPRICED],
    });

    await client().fetch(`${server.url}/resource`, {
      method: "POST",
      headers: { "idempotency-key": "caller-owned-key" },
      body: JSON.stringify({ prompt: "hello" }),
    });

    const [first, second] = server.paidRequests;
    // SPEC §6.7: the diagnostic ID identifies the caller's operation, so it is stable across
    // the attempts that operation took.
    expect(first?.headers["x-tx402-request-id"]).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
    expect(second?.headers["x-tx402-request-id"]).toBe(
      first?.headers["x-tx402-request-id"],
    );

    // The caller's key is preserved on every attempt and is never synthesized: the initial
    // unpaid request carried it too, and no attempt invented one of its own.
    expect(first?.headers["idempotency-key"]).toBe("caller-owned-key");
    expect(second?.headers["idempotency-key"]).toBe("caller-owned-key");
    // The body is replayed byte-for-byte on both signed attempts.
    expect(second?.body).toBe(JSON.stringify({ prompt: "hello" }));
    expect(first?.body).toBe(second?.body);
  });

  it("never synthesizes an idempotency key the caller did not supply", async () => {
    const server = await startMerchant({
      scenario: "rechallenge-once",
      requirements: [REQUIREMENT],
      rechallengeRequirements: [REPRICED],
    });

    await client().fetch(`${server.url}/resource`);

    for (const entry of server.requests) {
      expect(entry.headers["idempotency-key"]).toBeUndefined();
    }
  });

  it("exhausts the default two attempts and raises a typed terminal error", async () => {
    const server = await startMerchant({
      scenario: "always-402",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({ spendStore: recordingStore(log) });

    await expect(tx402.fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      context: { phase: "retry", paid: false },
      details: {
        status: 402,
        reason: "max-paid-attempts-exhausted",
        attempt: 2,
        maxPaidAttempts: 2,
      },
    });

    // Two signed attempts — the default counts signed retries, not the initial request,
    // which is why the merchant saw three requests in total.
    expect(server.paidRequests).toHaveLength(2);
    expect(server.requests).toHaveLength(3);
    expect(signer.nonces).toHaveLength(2);
    expect(signer.nonces[0]).not.toBe(signer.nonces[1]);
    expect(server.violations).toEqual([]);

    // Every attempt's reservation came back: a merchant still demanding payment is proof
    // that none of them settled.
    expect(log).toEqual(["reserve", "release", "reserve", "release"]);
    const budget = tx402.getBudgetState();
    expect(budget.committedAtomic).toBe("0");
    expect(budget.reservedAtomic).toBe("0");
  });

  it("honours the configured bound at each end of its 1–3 range", async () => {
    for (const maxPaidAttempts of [1, 3]) {
      const server = await startMerchant({
        scenario: "always-402",
        requirements: [REQUIREMENT],
      });
      signer = noncedSigner();
      rpc.setBalance(await signer.getAddress(), "5000000");

      await expect(
        client({ policy: { maxPaidAttempts } }).fetch(`${server.url}/resource`),
      ).rejects.toMatchObject({
        code: "TX402_RESOURCE_DELIVERY",
        details: { reason: "max-paid-attempts-exhausted", attempt: maxPaidAttempts },
      });
      expect(server.paidRequests).toHaveLength(maxPaidAttempts);
      expect(signer.nonces).toHaveLength(maxPaidAttempts);
      expect(new Set(signer.nonces).size).toBe(maxPaidAttempts);
    }
  });

  it("fails cleanly when the fresh challenge does not decode", async () => {
    const server = await startMerchant({
      scenario: "rechallenge-malformed",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({ spendStore: recordingStore(log) });

    // The re-challenge is parsed with the same strictness the first one got. The reservation
    // is released before the parse, so an undecodable challenge cannot strand budget.
    //
    // **The error class changed at ADR-022; the money disposition did not.** This asserted
    // `TX402_PAYMENT_REQUIRED_INVALID`, which maps to exit 5 — a band documented as "no
    // signature was ever produced", though one had already been transmitted. It is now the
    // post-transmission outcome it always was: exit 9 with `paid: false`. The three
    // assertions below are the ones that must not move, and none of them does.
    await expect(tx402.fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      details: { reason: "rechallenge-undecodable" },
      context: { paid: false },
    });
    expect(log).toEqual(["reserve", "release"]);
    expect(tx402.getBudgetState().reservedAtomic).toBe("0");
    expect(server.paidRequests).toHaveLength(1);
  });

  it("re-evaluates policy on the second attempt and can reject the new price", async () => {
    const server = await startMerchant({
      scenario: "rechallenge-once",
      requirements: [REQUIREMENT],
      // Re-priced above the caller's per-request cap.
      rechallengeRequirements: [{ ...REQUIREMENT, amount: "600000" }],
    });

    // SEC-002 holds on every attempt, not only the first: the second challenge goes through
    // the full policy gate before anything is planned, reserved, or signed.
    await expect(client().fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_POLICY_BUDGET",
      details: { requestedAtomic: "600000", capAtomic: "500000" },
    });
    expect(signer.nonces).toHaveLength(1);
    expect(server.paidRequests).toHaveLength(1);
  });

  it("reports each attempt in the diagnostic stream without leaking a signature", async () => {
    const server = await startMerchant({
      scenario: "rechallenge-once",
      requirements: [REQUIREMENT],
      rechallengeRequirements: [REPRICED],
    });
    const events: Record<string, unknown>[] = [];
    const record = (event: Readonly<Record<string, unknown>>) => events.push({ ...event });
    const logger: Tx402Logger = {
      debug: record,
      info: record,
      warn: record,
      error: record,
    };

    await client({ logger }).fetch(`${server.url}/resource`);

    expect(events.filter((event) => event.event === "request.retried")).toEqual([
      expect.objectContaining({ attempt: 1 }),
      expect.objectContaining({ attempt: 2 }),
    ]);
    // The fresh challenge is announced with its own hash, so the two are distinguishable.
    const challenges = events.filter((event) => event.event === "payment.required");
    expect(challenges).toHaveLength(2);
    expect(challenges[0]?.headerHash).not.toBe(challenges[1]?.headerHash);

    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain("signature");
    expect(serialized).not.toContain("nonce");
    for (const nonce of signer.nonces) expect(serialized).not.toContain(nonce);
  });
});

describe("T-011 unknown outcome after the signature is transmitted", () => {
  it("retains the reservation and does not spend a second attempt on a 5xx", async () => {
    const server = await startMerchant({
      scenario: "error-after-signature",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({ spendStore: recordingStore(log) });

    await expect(tx402.fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_PAYMENT_AMBIGUOUS",
      context: { phase: "retry", paid: "unknown" },
      details: { causeCategory: "server-error" },
    });

    // `maxPaidAttempts` is 2 here, and the loop deliberately does not use the second: the
    // merchant may already have settled, so retrying could pay twice (SPEC §6.7).
    expect(server.paidRequests).toHaveLength(1);
    expect(log).toEqual(["reserve"]);
    expect(tx402.getBudgetState().reservedAtomic).toBe("50000");
  });

  it("retains the reservation when the merchant never answers", async () => {
    const server = await startMerchant({
      scenario: "hang-after-signature",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({
      spendStore: recordingStore(log),
      timeouts: { paymentRetryMs: 1_000 },
    });

    const error = await tx402
      .fetch(`${server.url}/resource`)
      .catch((caught: unknown): unknown => caught);

    expect(error).toMatchObject({
      code: "TX402_PAYMENT_AMBIGUOUS",
      context: { paid: "unknown" },
      details: { causeCategory: "transport-after-signature" },
    });
    // The reservation's TTL is reported so a caller can decide when the ambiguity lapses.
    expect(
      (error as { details: { reservationExpiresAtEpochMs: number } }).details
        .reservationExpiresAtEpochMs,
    ).toBeGreaterThan(Date.now());
    expect(log).toEqual(["reserve"]);
    expect(server.paidRequests).toHaveLength(1);
  }, 15_000);

  it("holds the reservation on a same-origin redirect rather than releasing it", async () => {
    const server = await startMerchant({
      scenario: "same-origin-redirect",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({ spendStore: recordingStore(log) });

    // v0.1 does not follow the redirect, but a redirect is not a refusal — the merchant may
    // have settled and be pointing at the resource. Releasing would give back budget for
    // money that moved.
    await expect(tx402.fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_PAYMENT_AMBIGUOUS",
      details: { causeCategory: "redirect-not-followed" },
    });
    expect(log).toEqual(["reserve"]);
    expect(tx402.getBudgetState().reservedAtomic).toBe("50000");
  });
});

describe("T-012 cross-origin redirect on a paid retry", () => {
  it("blocks the redirect, raises PaidRedirectBlockedError, and holds the reservation", async () => {
    const server = await startMerchant({
      scenario: "cross-origin-redirect",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({ spendStore: recordingStore(log) });

    // SEC-005: the signature must not travel to another origin. It already reached this
    // merchant, so the outcome is unknown and the reservation is held to its TTL — but
    // SPEC §6.1 names `PaidRedirectBlockedError` for this case by class, and until S15b
    // the high-level client caught it and reported a generic ambiguity instead (O52).
    // The money disposition below is unchanged; only the identity moved.
    await expect(tx402.fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_REDIRECT_BLOCKED",
      retryable: false,
      context: { paid: "unknown" },
      details: { causeCategory: "redirect-blocked" },
    });
    expect(server.paidRequests).toHaveLength(1);
    expect(log).toEqual(["reserve"]);
    expect(tx402.getBudgetState().reservedAtomic).toBe("50000");
  });

  it("does not spend a further attempt after a blocked redirect", async () => {
    const server = await startMerchant({
      scenario: "cross-origin-redirect",
      requirements: [REQUIREMENT],
    });

    await client({ policy: { maxPaidAttempts: 3 } })
      .fetch(`${server.url}/resource`)
      .catch(() => undefined);

    // Three attempts were permitted; one was used. An ambiguous outcome ends the loop.
    expect(server.paidRequests).toHaveLength(1);
    expect(signer.nonces).toHaveLength(1);
  });
});
