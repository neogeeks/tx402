/**
 * The Base paid call, end to end (T-002, SPEC §6, SEC-002).
 *
 * A real test merchant and a real local JSON-RPC stub, both over HTTP. The only thing faked
 * is name resolution: the signed manifest names `mainnet.base.org`, and a `fetch` shim routes
 * that host to the stub. Nothing inside tx402 is mocked, so the assertions are about the
 * shipped code path — decode, policy, plan, reserve, sign, retry, commit.
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

/** The merchant's offer: Base USDC, 0.05, with the EIP-712 domain the exact scheme needs. */
const REQUIREMENT = {
  scheme: "exact",
  network: "eip155:8453",
  asset: USDC.address,
  amount: "50000",
  payTo: PAY_TO,
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let merchant: Merchant;
let rpc: EvmRpcStub;
let signer: EvmSigner & { signCount: number };
let payer: `0x${string}`;

/** Wraps a store so the order of ledger writes relative to signing is observable. */
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

/** Counts signatures without ever retaining one. */
function countingSigner(): EvmSigner & { signCount: number } {
  const inner = privateKeyToEvmSigner(`0x${randomBytes(32).toString("hex")}`);
  const wrapper: EvmSigner & { signCount: number } = {
    kind: "evm",
    signCount: 0,
    getAddress: () => inner.getAddress(),
    signTypedData: (request) => {
      wrapper.signCount += 1;
      return inner.signTypedData(request);
    },
  };
  return wrapper;
}

/** The same funded signer, with its invocation recorded in the ledger's ordering log. */
function withLog(log: string[]): EvmSigner {
  return {
    kind: "evm",
    getAddress: () => signer.getAddress(),
    signTypedData: (request) => {
      log.push("sign");
      return signer.signTypedData(request);
    },
  };
}

beforeEach(async () => {
  merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
    body: JSON.stringify({ ok: true, resource: "paid" }),
  });
  signer = countingSigner();
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
    // Manifest-declared RPC host, routed to the local stub. Everything else is untouched.
    return realFetch(rpc.url, {
      method: request.method,
      headers: request.headers,
      body: await request.text(),
    });
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await merchant.close();
  await rpc.close();
});

function client(overrides: Parameters<typeof createTx402Client>[0] = {}) {
  return createTx402Client({
    signers: { evm: signer },
    allowInsecureLocalhost: true,
    policy: {
      maxPerRequest: "0.50 USDC",
      maxPerHour: "10.00 USDC",
      allowedNetworks: ["eip155:8453"],
    },
    ...overrides,
  });
}

describe("M3 Base paid call", () => {
  it("T-002 makes one reservation, one signature, and one paid retry", async () => {
    const log: string[] = [];
    const tx402 = client({
      spendStore: recordingStore(log),
      signers: { evm: withLog(log) },
    });
    const response = await tx402.fetch(`${merchant.url}/resource`);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true, resource: "paid" });

    // Exactly one signature and exactly one signature-bearing request (ADR-003).
    expect(signer.signCount).toBe(1);
    expect(merchant.paidRequests).toHaveLength(1);
    expect(merchant.requests).toHaveLength(2);
    expect(merchant.violations).toEqual([]);

    // SEC-002 and SPEC §6.6: the reservation is written before the signer is invoked, and
    // the commit only happens after the resource is delivered.
    expect(log).toEqual(["reserve", "sign", "commit"]);

    const budget = tx402.getBudgetState();
    expect(budget.committedAtomic).toBe("50000");
    expect(budget.reservedAtomic).toBe("0");
    expect(budget.entries).toHaveLength(1);
    expect(budget.entries[0]?.settlementId).toBe(
      "0xtestmerchantsettlement000000000000000000000000000000000000000000",
    );

    // Chain identity was verified before the balance was trusted (SPEC §7.1).
    expect(rpc.calls.map((call) => call.method)).toEqual(["eth_chainId", "eth_call"]);
  });

  it("attaches exactly one PAYMENT-SIGNATURE, a request ID, and the caller's headers", async () => {
    const response = await client().fetch(`${merchant.url}/resource`, {
      method: "POST",
      headers: { "idempotency-key": "caller-owned-key", "x-caller": "keep-me" },
      body: JSON.stringify({ prompt: "hello" }),
    });
    expect(response.status).toBe(200);

    const paid = merchant.paidRequests[0];
    expect(paid?.method).toBe("POST");
    // SPEC §6.7: the caller's idempotency key is preserved and never synthesized.
    expect(paid?.headers["idempotency-key"]).toBe("caller-owned-key");
    expect(paid?.headers["x-caller"]).toBe("keep-me");
    expect(paid?.headers["x-tx402-request-id"]).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
    // The body is replayed byte-for-byte on the paid attempt.
    expect(paid?.body).toBe(JSON.stringify({ prompt: "hello" }));
    expect(merchant.requests[0]?.body).toBe(paid?.body);
  });

  it("omits the diagnostic request ID header when the caller disables it", async () => {
    await client({ disableRequestIdHeader: true }).fetch(`${merchant.url}/resource`);
    expect(merchant.paidRequests[0]?.headers["x-tx402-request-id"]).toBeUndefined();
  });

  it("refuses to sign when the balance cannot cover the price", async () => {
    rpc.setBalance(payer, "49999");

    await expect(client().fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_LIQUIDITY",
      details: {
        deficits: [
          {
            network: "eip155:8453",
            required: "50000",
            available: "49999",
          },
        ],
      },
    });
    expect(signer.signCount).toBe(0);
    expect(merchant.paidRequests).toHaveLength(0);
  });

  it("refuses to sign when the only RPC reports the wrong chain", async () => {
    rpc.setMode("wrong-chain");

    await expect(client().fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_TRANSPORT",
      details: { causeCategory: "chain-id-mismatch" },
    });
    // SPEC §9.1: a provider answering for another chain must not be able to induce a
    // signature, and it never gets asked for a balance.
    expect(signer.signCount).toBe(0);
    expect(rpc.calls.every((call) => call.method === "eth_chainId")).toBe(true);
  });

  it("declines a merchant offer that omits the EIP-712 token domain", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "pay-once",
      requirements: [{ ...REQUIREMENT, extra: {} }],
    });

    await expect(client().fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_PAYMENT_REQUIRED_INVALID",
      details: { reason: "eip712-domain-missing" },
    });
    expect(signer.signCount).toBe(0);
  });

  it("releases the reservation when the merchant refuses the paid request", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "refused-after-signature",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({
      spendStore: recordingStore(log),
      signers: { evm: withLog(log) },
    });

    // A 4xx is the merchant declining outright. There is no settlement to be ambiguous
    // about, so the budget comes back rather than being held for the TTL.
    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      context: { paid: false },
      details: { status: 403, reason: "paid-request-rejected" },
    });
    expect(log).toEqual(["reserve", "sign", "release"]);
    expect(tx402.getBudgetState().committedAtomic).toBe("0");
  });

  it("retains the reservation when the outcome after transmission is unknown", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "error-after-signature",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({
      spendStore: recordingStore(log),
      signers: { evm: withLog(log) },
    });

    const error = await tx402
      .fetch(`${merchant.url}/resource`)
      .catch((caught: unknown) => caught);

    // SPEC §6.7: a 5xx after the signature was transmitted is ambiguous. Releasing here
    // would let the same money be spent twice against the hourly cap.
    expect(error).toMatchObject({
      code: "TX402_PAYMENT_AMBIGUOUS",
      context: { paid: "unknown" },
      details: { causeCategory: "server-error" },
    });
    expect(log).toEqual(["reserve", "sign"]);
    expect(tx402.getBudgetState().reservedAtomic).toBe("50000");
  });

  it("makes exactly one signed attempt when the policy permits only one", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "always-402",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({
      spendStore: recordingStore(log),
      signers: { evm: withLog(log) },
      policy: {
        maxPerRequest: "0.50 USDC",
        maxPerHour: "10.00 USDC",
        allowedNetworks: ["eip155:8453"],
        maxPaidAttempts: 1,
      },
    });

    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      details: { reason: "max-paid-attempts-exhausted", attempt: 1, maxPaidAttempts: 1 },
    });
    // The full re-challenge loop is exercised in `test/completion.test.ts`; what this pins
    // is that the *bound* is the configured one and that it counts signed retries only.
    expect(signer.signCount).toBe(1);
    expect(merchant.paidRequests).toHaveLength(1);
    expect(log).toEqual(["reserve", "sign", "release"]);
  });

  it("accepts delivery when the merchant omits PAYMENT-RESPONSE and warns", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "missing-payment-response",
      requirements: [REQUIREMENT],
    });
    const events: Record<string, unknown>[] = [];
    const record = (event: Readonly<Record<string, unknown>>) => events.push({ ...event });
    const logger: Tx402Logger = {
      debug: record,
      info: record,
      warn: record,
      error: record,
    };

    const tx402 = client({ logger });
    await expect(tx402.fetch(`${merchant.url}/resource`)).resolves.toHaveProperty(
      "status",
      200,
    );

    expect(tx402.getBudgetState().committedAtomic).toBe("50000");
    expect(events).toContainEqual(
      expect.objectContaining({ reason: "payment-response-absent" }),
    );
  });

  it("keeps signatures and authorization payloads out of diagnostics", async () => {
    const events: Record<string, unknown>[] = [];
    const record = (event: Readonly<Record<string, unknown>>) => events.push({ ...event });
    const logger: Tx402Logger = {
      debug: record,
      info: record,
      warn: record,
      error: record,
    };

    await client({ logger }).fetch(`${merchant.url}/resource`, {
      headers: { authorization: "Bearer seeded-secret" },
    });

    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain("seeded-secret");
    // No signature, no EIP-3009 authorization member, and no encoded header value. The
    // manifest's public token address does appear inside `assetId`, which is intended —
    // SPEC §10 requires it and it is not secret.
    expect(serialized).not.toContain("signature");
    expect(serialized).not.toContain("nonce");
    expect(serialized).not.toContain("validBefore");
    expect(serialized).not.toContain("authorization");
    expect(await signer.getAddress()).toBeTruthy();
    expect(serialized).not.toContain(await signer.getAddress());
    expect(events.map((event) => event.event)).toEqual([
      "request.started",
      "payment.required",
      "policy.checked",
      "route.planned",
      "budget.reserved",
      "sign.started",
      "sign.completed",
      "request.retried",
      "payment.completed",
    ]);
  });
});

describe("M3 payment path edge cases", () => {
  it("rejects a settlement the merchant itself reports as unsuccessful", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "unsuccessful-settlement",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({ spendStore: recordingStore(log) });

    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      context: { paid: false },
      details: { reason: "settlement-unsuccessful" },
    });
    expect(log).toEqual(["reserve", "release"]);
    expect(tx402.getBudgetState().committedAtomic).toBe("0");
  });

  it("refuses delivery when PAYMENT-RESPONSE is present and cannot be decoded", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "corrupt-payment-response",
      requirements: [REQUIREMENT],
    });
    const events: Record<string, unknown>[] = [];
    const record = (event: Readonly<Record<string, unknown>>) => events.push({ ...event });
    const logger: Tx402Logger = {
      debug: record,
      info: record,
      warn: record,
      error: record,
    };

    const tx402 = client({ logger });

    // SPEC §6.7 makes a 2xx paid-success "only when any required upstream PAYMENT-RESPONSE
    // parses successfully". A header that is present and does not decode is a protocol
    // violation and is evidence in neither direction — so it cannot commit, and it cannot
    // release either (ADR-016, O53). Until S15b this returned the resource as paid success.
    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_PAYMENT_AMBIGUOUS",
      context: { paid: "unknown" },
      details: { causeCategory: "settlement-metadata-unparseable" },
    });
    expect(events).toContainEqual(
      expect.objectContaining({ reason: "payment-response-unparseable" }),
    );
    // Retained, not committed and not released: the reservation still counts against the
    // hourly cap until its TTL, because a corrupt header is no evidence that nothing moved.
    expect(tx402.getBudgetState().committedAtomic).toBe("0");
    expect(tx402.getBudgetState().reservedAtomic).toBe("50000");
  });

  it("raises PaidRedirectBlockedError for a cross-origin redirect after signing", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "cross-origin-redirect",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const tx402 = client({ spendStore: recordingStore(log) });

    // SEC-005 stops the signature from travelling onward, but it already reached this
    // merchant, so the outcome is unknown and the reservation is held (SPEC §6.7). The
    // class is the one SPEC §6.1 names, not a generic ambiguity (O52).
    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_REDIRECT_BLOCKED",
      details: { causeCategory: "redirect-blocked" },
    });
    expect(log).toEqual(["reserve"]);
  });

  it("treats a timeout after signing as ambiguous", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "hang-after-signature",
      requirements: [REQUIREMENT],
    });
    const tx402 = client({ timeouts: { paymentRetryMs: 1_000 } });

    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_PAYMENT_AMBIGUOUS",
      details: { causeCategory: "transport-after-signature" },
    });
  }, 15_000);

  it("replays a bodyFactory body on the paid attempt and types its failure", async () => {
    let calls = 0;
    const response = await client().fetch(`${merchant.url}/resource`, {
      method: "POST",
      bodyFactory: () => {
        calls += 1;
        return `attempt-${calls}`;
      },
    });

    expect(response.status).toBe(200);
    // The caller owns replay, so the factory is asked again rather than a buffer replayed.
    expect(calls).toBe(2);
    expect(merchant.requests[0]?.body).toBe("attempt-1");
    expect(merchant.paidRequests[0]?.body).toBe("attempt-2");

    await expect(
      client().fetch(`${merchant.url}/resource`, {
        method: "POST",
        bodyFactory: () => {
          calls += 1;
          if (calls > 3) throw new Error("seeded retry factory failure");
          return "first";
        },
      }),
    ).rejects.toMatchObject({
      code: "TX402_NON_REPLAYABLE",
      details: { reason: "body-factory-failed" },
    });
  });

  it("releases the reservation when the signer refuses", async () => {
    const log: string[] = [];
    const refusing: EvmSigner = {
      kind: "evm",
      getAddress: () => signer.getAddress(),
      signTypedData: () => Promise.reject(new Error("seeded refusal")),
    };
    const tx402 = client({ spendStore: recordingStore(log), signers: { evm: refusing } });

    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_SIGNER",
      details: { causeCategory: "signer-rejected" },
    });
    expect(log).toEqual(["reserve", "release"]);
    expect(merchant.paidRequests).toHaveLength(0);
  });

  it("clears adapter health without touching the ledger", async () => {
    const tx402 = client();
    await tx402.fetch(`${merchant.url}/resource`);

    tx402.resetHealth();
    // Awaiting a turn lets the adapter's reset settle; the ledger is untouched either way.
    await Promise.resolve();
    expect(tx402.getBudgetState().committedAtomic).toBe("50000");

    // The second call re-verifies chain identity on a freshly reset pool.
    rpc.reset();
    await createTestMerchantScopedCall(tx402);
    expect(rpc.calls.map((call) => call.method)).toEqual(["eth_chainId", "eth_call"]);
  });

  it("wraps a spend-store failure as a typed transport error", async () => {
    const broken: SpendStore = {
      kind: "broken",
      reserve: () => Promise.reject(new Error("seeded store failure")),
      commit: () => Promise.reject(new Error("unused")),
      release: () => Promise.reject(new Error("unused")),
      getBudgetState: () =>
        new MemorySpendStore().getBudgetState({
          policyScope: "scope",
          assetId: "asset",
          nowEpochMs: Date.now(),
        }),
    };

    // A reserve that fails is pre-transmission, so it is genuinely retryable — but the
    // category now names the spend store rather than reporting the generic "runtime" that
    // any unclassified throw produced (O46).
    await expect(
      client({ spendStore: broken }).fetch(`${merchant.url}/resource`),
    ).rejects.toMatchObject({
      code: "TX402_TRANSPORT",
      retryable: true,
      context: { phase: "policy" },
      details: { causeCategory: "spend-store-unavailable", storeKind: "broken" },
    });
    expect(signer.signCount).toBe(0);
  });
});

/** A second paid call against the same merchant, which re-challenges every request. */
async function createTestMerchantScopedCall(tx402: ReturnType<typeof client>) {
  merchant.reset();
  await tx402.fetch(`${merchant.url}/resource`).catch(() => undefined);
}
