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
import { normalizePolicyHost } from "../src/core/policy.js";
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
    capabilities: inner.capabilities,
    reserve: async (input) => {
      const result = await inner.reserve(input);
      log.push("reserve");
      return result;
    },
    commit: async (input) => {
      const entry = await inner.commit(input);
      log.push("commit");
      return entry;
    },
    release: async (ref, now) => {
      const released = await inner.release(ref, now);
      log.push("release");
      return released;
    },
    expose: (ref, now) => inner.expose(ref, now),
    getBudgetState: (query) => inner.getBudgetState(query),
    listExposed: (query) => inner.listExposed(query),
    isFrozen: (scope) => inner.isFrozen(scope),
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

  it("holds the reservation as exposed when the outcome after transmission is unknown", async () => {
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

    // SPEC §6.7/§7: a 5xx after the signature was transmitted is ambiguous. The
    // pre-transmission fence already moved the reservation to `exposed`, and neither commit
    // nor release runs — so it stays exposed (durable, non-expiring), not reserved. Releasing
    // it would let the same money be spent twice against the cap.
    expect(error).toMatchObject({
      code: "TX402_PAYMENT_AMBIGUOUS",
      context: { paid: "unknown" },
      details: { causeCategory: "server-error" },
    });
    // The fence's `expose` is not recorded by `recordingStore` (only reserve/commit/release
    // are), so the ordering log stays reserve → sign; the exposed budget is asserted below.
    expect(log).toEqual(["reserve", "sign"]);
    const budget = tx402.getBudgetState();
    expect(budget.reservedAtomic).toBe("0");
    expect(budget.exposedAtomic).toBe("50000");
    expect(budget.cumulativeConsumedAtomic).toBe("50000");
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
      "payment.exposed",
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
    // Held as exposed, not committed and not released: the fence ran before transmission, so
    // the reservation counts against both caps until an operator reconciles it, because a
    // corrupt header is no evidence that nothing moved (SPEC §7, ADR-026).
    const budget = tx402.getBudgetState();
    expect(budget.committedAtomic).toBe("0");
    expect(budget.reservedAtomic).toBe("0");
    expect(budget.exposedAtomic).toBe("50000");
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
      capabilities: { atomicGlobalFreeze: true },
      reserve: () => Promise.reject(new Error("seeded store failure")),
      commit: () => Promise.reject(new Error("unused")),
      release: () => Promise.reject(new Error("unused")),
      expose: () => Promise.reject(new Error("unused")),
      listExposed: () => Promise.reject(new Error("unused")),
      isFrozen: () => Promise.resolve(false),
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

/* ------------------------------------------------------------------------------------- */
/* SPEC §7 / ADR-026 — the pre-transmission exposure fence                                 */
/* ------------------------------------------------------------------------------------- */

/** A store that records every lifecycle write, including `expose`, in call order. */
function fenceLoggingStore(log: string[]): SpendStore {
  const inner = new MemorySpendStore();
  return {
    kind: inner.kind,
    capabilities: inner.capabilities,
    reserve: async (input) => {
      const result = await inner.reserve(input);
      log.push("reserve");
      return result;
    },
    commit: async (input) => {
      const entry = await inner.commit(input);
      log.push("commit");
      return entry;
    },
    release: async (ref, now) => {
      const released = await inner.release(ref, now);
      log.push("release");
      return released;
    },
    expose: async (ref, now) => {
      const exposed = await inner.expose(ref, now);
      log.push("expose");
      return exposed;
    },
    getBudgetState: (query) => inner.getBudgetState(query),
    listExposed: (query) => inner.listExposed(query),
    isFrozen: (scope) => inner.isFrozen(scope),
  };
}

describe("SPEC §7 exposure fence", () => {
  it("fences after signing and resolves exposed → committed on a delivered payment", async () => {
    const log: string[] = [];
    const events: { level: string; event: Record<string, unknown> }[] = [];
    const record = (level: string) => (event: Readonly<Record<string, unknown>>) =>
      events.push({ level, event: { ...event } });
    const logger: Tx402Logger = {
      debug: record("debug"),
      info: record("info"),
      warn: record("warn"),
      error: record("error"),
    };
    const store = fenceLoggingStore(log);
    const tx402 = client({ spendStore: store, signers: { evm: withLog(log) }, logger });

    const response = await tx402.fetch(`${merchant.url}/resource`);
    expect(response.status).toBe(200);

    // The fence sits between the signature and the wire, and the successful completion
    // resolves the exposed reservation with commit — so the amount ends in cumulativeCommitted
    // with nothing stranded in exposedTotal.
    expect(log).toEqual(["reserve", "sign", "expose", "commit"]);
    const budget = tx402.getBudgetState();
    expect(budget.committedAtomic).toBe("50000");
    expect(budget.exposedAtomic).toBe("0");
    expect(budget.reservedAtomic).toBe("0");

    // Exactly one `payment.exposed`, at info, carrying redaction-safe identifiers only.
    const exposed = events.filter((entry) => entry.event.event === "payment.exposed");
    expect(exposed).toHaveLength(1);
    expect(exposed[0]?.level).toBe("info");
    expect(exposed[0]?.event).toMatchObject({ amountAtomic: "50000" });
  });

  it("resolves exposed → released when the merchant refuses after the signature", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "refused-after-signature",
      requirements: [REQUIREMENT],
    });
    const log: string[] = [];
    const store = fenceLoggingStore(log);
    const tx402 = client({ spendStore: store, signers: { evm: withLog(log) } });

    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      details: { reason: "paid-request-rejected" },
    });

    // A definitive refusal is evidence nothing settled, so the exposed reservation is released
    // and the budget comes fully back — no term retains the amount.
    expect(log).toEqual(["reserve", "sign", "expose", "release"]);
    const budget = tx402.getBudgetState();
    expect(budget.committedAtomic).toBe("0");
    expect(budget.reservedAtomic).toBe("0");
    expect(budget.exposedAtomic).toBe("0");
  });

  it("aborts the transmission and releases when the fence write fails", async () => {
    const inner = new MemorySpendStore();
    const store: SpendStore = {
      kind: "expose-explodes",
      capabilities: inner.capabilities,
      reserve: (input) => inner.reserve(input),
      commit: (input) => inner.commit(input),
      release: (ref, now) => inner.release(ref, now),
      expose: () => Promise.reject(new Error("fence backend unreachable")),
      getBudgetState: (query) => inner.getBudgetState(query),
      listExposed: (query) => inner.listExposed(query),
      isFrozen: (scope) => inner.isFrozen(scope),
    };
    const events: { level: string; event: Record<string, unknown> }[] = [];
    const record = (level: string) => (event: Readonly<Record<string, unknown>>) =>
      events.push({ level, event: { ...event } });
    const logger: Tx402Logger = {
      debug: record("debug"),
      info: record("info"),
      warn: record("warn"),
      error: record("error"),
    };
    const tx402 = client({ spendStore: store, logger });

    // A failed fence is a clean pre-transmission failure: retryable, categorized, and — because
    // SEC-002 keeps the signature in-process until the fence records — nothing reached the wire.
    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_TRANSPORT",
      retryable: true,
      details: { causeCategory: "exposure-fence-failed", storeKind: "expose-explodes" },
    });

    // The signature was produced (the fence is after signing) but never transmitted, and the
    // reservation was released, so no budget is held.
    expect(signer.signCount).toBe(1);
    expect(merchant.paidRequests).toHaveLength(0);
    const budget = tx402.getBudgetState();
    expect(budget.reservedAtomic).toBe("0");
    expect(budget.exposedAtomic).toBe("0");
    expect(budget.committedAtomic).toBe("0");

    // The failure emits `payment.exposed` at error, not info.
    const exposed = events.filter((entry) => entry.event.event === "payment.exposed");
    expect(exposed).toHaveLength(1);
    expect(exposed[0]?.level).toBe("error");
    expect(exposed[0]?.event).toMatchObject({ reason: "exposure-fence-failed" });
  });
});

/** A second paid call against the same merchant, which re-challenges every request. */
async function createTestMerchantScopedCall(tx402: ReturnType<typeof client>) {
  merchant.reset();
  await tx402.fetch(`${merchant.url}/resource`).catch(() => undefined);
}

describe("SPEC §5 kill switch", () => {
  it("denies a paid call on a frozen store, before the signer, and emits spend.frozen", async () => {
    const store = new MemorySpendStore();
    // Whole-store freeze: `capabilities.atomicGlobalFreeze` is true for the in-process store,
    // so `"*"` is a permitted scope and blocks every reserve (SPEC §5.2, ADR-027).
    await store.freeze("*");

    const events: { level: string; event: Record<string, unknown> }[] = [];
    const record = (level: string) => (event: Readonly<Record<string, unknown>>) =>
      events.push({ level, event: { ...event } });
    const logger: Tx402Logger = {
      debug: record("debug"),
      info: record("info"),
      warn: record("warn"),
      error: record("error"),
    };
    const tx402 = client({ spendStore: store, logger });

    // The freeze check is reserve step 2 — reached before any signer exists in scope (SEC-002),
    // so the refusal is a non-retryable policy error and nothing is signed.
    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_SPEND_FROZEN",
      retryable: false,
      retryability: "no",
    });
    expect(signer.signCount).toBe(0);
    expect(merchant.paidRequests).toHaveLength(0);

    // Exactly one `spend.frozen`, at warn, carrying redaction-safe scope identifiers only.
    const frozen = events.filter((entry) => entry.event.event === "spend.frozen");
    expect(frozen).toHaveLength(1);
    expect(frozen[0]?.level).toBe("warn");
    expect(frozen[0]?.event).toMatchObject({ frozenScope: "*" });
  });

  it("admits the call again once the store is unfrozen (KS-7)", async () => {
    const store = new MemorySpendStore();
    await store.freeze("*");
    await store.unfreeze("*");
    const tx402 = client({ spendStore: store });

    const response = await tx402.fetch(`${merchant.url}/resource`);
    expect(response.status).toBe(200);
    expect(signer.signCount).toBe(1);
  });
});

describe("SPEC §6 recipient pinning", () => {
  const recordingLogger = () => {
    const events: { level: string; event: Record<string, unknown> }[] = [];
    const record = (level: string) => (event: Readonly<Record<string, unknown>>) =>
      events.push({ level, event: { ...event } });
    const logger: Tx402Logger = {
      debug: record("debug"),
      info: record("info"),
      warn: record("warn"),
      error: record("error"),
    };
    return { events, logger };
  };

  it("TOFU establishes a first-use pin inside reserve and emits recipient.pinned once", async () => {
    const store = new MemorySpendStore();
    const scope = normalizePolicyHost(merchant.url);
    await store.setTofuEnabled(scope, true);
    const { events, logger } = recordingLogger();
    const tx402 = client({ spendStore: store, logger, recipientPolicy: { mode: "tofu" } });

    const response = await tx402.fetch(`${merchant.url}/resource`);
    expect(response.status).toBe(200);
    expect(signer.signCount).toBe(1);
    // The claim happened in the reserve atom; the store now pins the merchant's payTo,
    // canonicalized to lowercase hex (SPEC §6.4).
    expect(await store.getRecipientPins(scope, "eip155:8453")).toEqual([
      PAY_TO.toLowerCase(),
    ]);
    // Exactly one recipient.pinned, at info, carrying the redaction-safe recipient identifiers.
    const pinned = events.filter((entry) => entry.event.event === "recipient.pinned");
    expect(pinned).toHaveLength(1);
    expect(pinned[0]?.level).toBe("info");
    expect(pinned[0]?.event).toMatchObject({
      network: "eip155:8453",
      recipient: PAY_TO.toLowerCase(),
    });
  });

  it("a second paid call to the same recipient re-emits nothing (replay-safe)", async () => {
    const store = new MemorySpendStore();
    const scope = normalizePolicyHost(merchant.url);
    await store.setTofuEnabled(scope, true);
    const { events, logger } = recordingLogger();
    const tx402 = client({ spendStore: store, logger, recipientPolicy: { mode: "tofu" } });

    await tx402.fetch(`${merchant.url}/resource`);
    await tx402.fetch(`${merchant.url}/resource`);
    // The pin was claimed once; the second reserve matched it, so only one recipient.pinned.
    expect(events.filter((entry) => entry.event.event === "recipient.pinned")).toHaveLength(
      1,
    );
  });

  it("O17 — a recipient-store outage in the advisory read fails closed as a retryable recipient-store-unavailable TransportError (0 signs, one request.failed)", async () => {
    const scope = normalizePolicyHost(merchant.url);
    const inner = new MemorySpendStore();
    await inner.setTofuEnabled(scope, true);
    // A store whose advisory recipient read is DOWN — an infrastructure outage, not a refusal.
    const store = new Proxy(inner, {
      get(target, prop, receiver): unknown {
        if (prop === "getRecipientPins") {
          return () => Promise.reject(new Error("recipient pin store is down"));
        }
        const value: unknown = Reflect.get(target, prop, receiver);
        return typeof value === "function"
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    });
    const { events, logger } = recordingLogger();
    const tx402 = client({ spendStore: store, logger, recipientPolicy: { mode: "tofu" } });

    const error = await tx402
      .fetch(`${merchant.url}/resource`)
      .catch((caught: unknown) => caught);
    // §6.3: an advisory recipient-store outage is a retryable TransportError, never a refusal.
    expect(error).toMatchObject({
      code: "TX402_TRANSPORT",
      details: { causeCategory: "recipient-store-unavailable" },
    });
    expect((error as { retryable: boolean }).retryable).toBe(true);
    // Fail-closed: the advisory read is pre-signature, so nothing was signed…
    expect(signer.signCount).toBe(0);
    // …and the terminal event fired exactly once (SPEC §11 once-per-request).
    expect(events.filter((entry) => entry.event.event === "request.failed")).toHaveLength(
      1,
    );
  });

  it("O18 — a post-settlement commit failure emits request.failed exactly once", async () => {
    // The merchant settles (delivers), then the store's commit fails — money moved but was not
    // recorded. The terminal event must fire ONCE, not once inside commitOrFail and again outside.
    const inner = new MemorySpendStore();
    const store = new Proxy(inner, {
      get(target, prop, receiver): unknown {
        if (prop === "commit") {
          return () => Promise.reject(new Error("store down after settlement"));
        }
        const value: unknown = Reflect.get(target, prop, receiver);
        return typeof value === "function"
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    });
    const { events, logger } = recordingLogger();
    const tx402 = client({ spendStore: store, logger });

    const error = await tx402
      .fetch(`${merchant.url}/resource`)
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      context: { paid: true },
    });
    expect(events.filter((entry) => entry.event.event === "request.failed")).toHaveLength(
      1,
    );
  });

  it("an administered allowlist that excludes payTo refuses the call before the signer and emits recipient.rejected", async () => {
    const store = new MemorySpendStore();
    const scope = normalizePolicyHost(merchant.url);
    // An operator pins a DIFFERENT recipient; the client always sends its payTo, so the
    // authoritative reserve assertion (SPEC §3.4 step 3) refuses it regardless of the caller's
    // mode — the store's source drives the refusal.
    await store.setRecipientPins(scope, "eip155:8453", [
      "0x000000000000000000000000000000000000dead",
    ]);
    const { events, logger } = recordingLogger();
    const tx402 = client({ spendStore: store, logger });

    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RECIPIENT_UNPINNED",
      retryable: false,
      retryability: "no",
    });
    // Pre-signature policy refusal (SEC-002): nothing signed, nothing paid.
    expect(signer.signCount).toBe(0);
    expect(merchant.paidRequests).toHaveLength(0);
    // Exactly one recipient.rejected, at warn, with the RP-8 details for a known-set mismatch.
    const rejected = events.filter((entry) => entry.event.event === "recipient.rejected");
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.level).toBe("warn");
    expect(rejected[0]?.event).toMatchObject({
      reason: "not-allowlisted",
      network: "eip155:8453",
      presentedRecipient: PAY_TO.toLowerCase(),
    });
  });

  it("a client-side allowlist that lists payTo admits the call without claiming a TOFU pin", async () => {
    const store = new MemorySpendStore();
    const scope = normalizePolicyHost(merchant.url);
    const { events, logger } = recordingLogger();
    const tx402 = client({
      spendStore: store,
      logger,
      recipientPolicy: {
        mode: "allowlist",
        allow: [{ host: scope, network: "eip155:8453", recipients: [PAY_TO] }],
      },
    });

    const response = await tx402.fetch(`${merchant.url}/resource`);
    expect(response.status).toBe(200);
    expect(signer.signCount).toBe(1);
    // Allowlist mode never claims a pin (SPEC §6.2 "allowlist wins, TOFU fills gaps").
    expect(await store.getRecipientPins(scope, "eip155:8453")).toEqual([]);
    expect(events.filter((entry) => entry.event.event === "recipient.pinned")).toHaveLength(
      0,
    );
  });

  it("fails closed at construction when mode:'tofu' is given a store without a pin interface", () => {
    // A store missing getRecipientPins/getRecipientPolicy cannot back TOFU (SPEC §6.1).
    const dataOnly: SpendStore = recordingStore([]);
    let caught: unknown;
    try {
      client({ spendStore: dataOnly, recipientPolicy: { mode: "tofu" } });
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { reason: "recipient-tofu-needs-pin-store" },
    });
  });
});
