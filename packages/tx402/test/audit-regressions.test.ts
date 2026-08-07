/**
 * Regressions for the S15 pre-publication audit findings O44–O46 and O52–O53.
 *
 * Every case here was written from the governing text — SPEC §5.3, §6.1, §6.7, §4.3, and
 * ADR-016/017/018 — and *then* run against the S15 commit to confirm it failed there. That
 * ordering matters more than usual for this file: the audit's central complaint was that
 * the existing green suite asserted what the implementation did rather than what the
 * specification required, so a regression derived from the implementation would have been
 * worth nothing.
 *
 * A real test merchant and a real local JSON-RPC stub, both over HTTP, exactly as
 * `evm-payment.test.ts` uses them — the assertions are about the shipped path, not a mock
 * of it. The Python counterpart is
 * `packages/tx402-python/tests/test_audit_regressions.py`, and the two are deliberately
 * close: an asymmetric fix is how the languages drift.
 */

import { randomBytes } from "node:crypto";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import {
  createTx402Client,
  SPEND_STORE_COMMIT_FAILED_REASON,
  SPEND_STORE_UNAVAILABLE_CAUSE,
} from "../src/core/client.js";
import { MemorySpendStore, type SpendEntry, type SpendStore } from "../src/core/ledger.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import { normalizePolicyHost } from "../src/core/policy.js";
import type { EvmSigner } from "../src/core/signers.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";

const BASE = BUNDLED_MANIFEST.networks["eip155:8453"] as EvmManifestNetwork;
const USDC = BASE.assets[0] as EvmManifestAsset;
const RPC_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));
const PAY_TO = "0x1234567890AbcdEF1234567890aBcdef12345678";
const AMOUNT = "50000";
const ASSET_ID = `eip155:8453/erc20:${USDC.address}`;

const REQUIREMENT = {
  scheme: "exact",
  network: "eip155:8453",
  asset: USDC.address,
  amount: AMOUNT,
  payTo: PAY_TO,
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let rpc: EvmRpcStub;
let signer: EvmSigner & { signCount: number };
const servers: Merchant[] = [];

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

async function merchantFor(scenario: string): Promise<Merchant> {
  const server = await createTestMerchant({
    scenario,
    requirements: [REQUIREMENT],
    body: JSON.stringify({ ok: true }),
  });
  servers.push(server);
  return server;
}

beforeEach(async () => {
  signer = countingSigner();
  const payer = await signer.getAddress();
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
  await Promise.all(servers.splice(0).map((server) => server.close()));
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

async function totals(store: SpendStore, policyScope: string) {
  const state = await store.getBudgetState({
    policyScope,
    assetId: ASSET_ID,
    nowEpochMs: Date.now(),
  });
  return { committed: state.committedAtomic, reserved: state.reservedAtomic };
}

/* ------------------------------------------------------------------------------------- */
/* O44 — settlement evidence outranks the status line (SPEC §5.3)                          */
/* ------------------------------------------------------------------------------------- */

describe("O44 settlement precedence", () => {
  it("keeps a settled-but-undelivered 403 committed and reports paid: true", async () => {
    // SPEC §5.3, verbatim: "If payment settlement is reported successful but resource
    // response is unusable, the spend remains committed and the SDK raises
    // ResourceDeliveryError with paid=true." Nothing in that sentence mentions the status
    // line, and consulting the status line first is exactly what the audit found.
    const server = await merchantFor("settled-but-refused");
    const store = new MemorySpendStore();
    const tx402 = client({ spendStore: store });

    await expect(tx402.fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      retryable: false,
      context: { paid: true, phase: "complete" },
      details: { status: 403, reason: "settlement-succeeded-resource-unusable" },
    });

    const scope = normalizePolicyHost(`${server.url}/resource`);
    expect(await totals(store, scope)).toEqual({ committed: AMOUNT, reserved: "0" });
  });

  it("does not re-challenge into a second payment when a 402 reports a settlement", async () => {
    // The sharpest case, and the one that costs real money. A repeated 402 is normally the
    // strongest possible evidence that nothing settled, so it releases and the loop signs
    // again. A 402 that *also* reports a successful settlement is a merchant contradicting
    // itself, and re-signing on it pays twice for one resource.
    const server = await merchantFor("settled-but-rechallenged");
    const store = new MemorySpendStore();
    const tx402 = client({ spendStore: store, policy: { maxPaidAttempts: 3 } });

    await expect(tx402.fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      context: { paid: true },
    });

    expect(signer.signCount).toBe(1);
    expect(server.paidRequests).toHaveLength(1);
    const scope = normalizePolicyHost(`${server.url}/resource`);
    expect((await totals(store, scope)).committed).toBe(AMOUNT);
  });

  it("still releases when a refusal claims no settlement", async () => {
    // The other half of the rule, so the fix cannot be "always commit". A merchant that
    // refuses *and* claims no settlement has told us nothing moved, and holding the budget
    // would be a silent overcharge against the hourly cap.
    const server = await merchantFor("refused-after-signature");
    const store = new MemorySpendStore();
    const tx402 = client({ spendStore: store });

    await expect(tx402.fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      context: { paid: false },
      details: { reason: "paid-request-rejected" },
    });

    const scope = normalizePolicyHost(`${server.url}/resource`);
    expect(await totals(store, scope)).toEqual({ committed: "0", reserved: "0" });
  });

  it("consumes the hourly cap it charged, so the next call is refused by budget", async () => {
    // The consequence the finding names: an autonomous caller paying twice. The cap admits
    // exactly one payment; the first is settled and undelivered. The second must be refused
    // by the *budget*, which only happens if the first committed — and it must be refused
    // before a signer is reached, which is what `signCount` pins.
    const store = new MemorySpendStore();
    const policy = { maxPerRequest: "0.05 USDC", maxPerHour: "0.05 USDC" };
    const server = await merchantFor("settled-but-refused");

    await expect(
      client({ spendStore: store, policy }).fetch(`${server.url}/resource`),
    ).rejects.toMatchObject({ code: "TX402_RESOURCE_DELIVERY" });
    expect(signer.signCount).toBe(1);

    await expect(
      client({ spendStore: store, policy }).fetch(`${server.url}/resource`),
    ).rejects.toMatchObject({ code: "TX402_POLICY_BUDGET" });
    expect(signer.signCount).toBe(1);
  });
});

/* ------------------------------------------------------------------------------------- */
/* O45 — the ledger scope is the merchant host, and the snapshot is real                   */
/* ------------------------------------------------------------------------------------- */

describe("O45 policy scope", () => {
  it("shares one host's cap between two independently constructed clients", async () => {
    // SPEC §4.3 makes `spendStore` the way to hold one budget across processes. A shared
    // store is only shareable if two clients agree on the key; a per-client UUID meant two
    // clients saw two ledgers for one merchant, and the fleet-wide cap the README promises
    // was silently per-client.
    const store = new MemorySpendStore();
    const policy = { maxPerRequest: "0.05 USDC", maxPerHour: "0.05 USDC" };
    const server = await merchantFor("pay-once");

    await expect(
      client({ spendStore: store, policy }).fetch(`${server.url}/resource`),
    ).resolves.toHaveProperty("status", 200);

    // A *different* client object, the same store, the same merchant host.
    await expect(
      client({ spendStore: store, policy }).fetch(`${server.url}/resource`),
    ).rejects.toMatchObject({ code: "TX402_POLICY_BUDGET" });
  });

  it("keeps two hosts on two ledgers within one store", async () => {
    // The same defect in the other direction: one scope across unrelated merchants. A
    // per-host cap that is actually per-client refuses a second merchant because the first
    // had spent, which is not what maxPerHour promises. Asserted against the store rather
    // than through two servers because every local server shares one host.
    const store = new MemorySpendStore();
    const now = Date.now();
    for (const [index, host] of ["a.example", "b.example"].entries()) {
      await store.reserve({
        requestId: `r${index}`,
        reservationId: `r${index}`,
        policyScope: host,
        requestFingerprint: `sha256:${"0".repeat(64)}`,
        assetId: ASSET_ID,
        amountAtomic: AMOUNT,
        maxPerHourAtomic: AMOUNT,
        nowEpochMs: now,
      });
      await store.commit({ reservationId: `r${index}`, committedAtEpochMs: now });
    }
    expect((await totals(store, "a.example")).committed).toBe(AMOUNT);
    expect((await totals(store, "b.example")).committed).toBe(AMOUNT);
    expect(normalizePolicyHost("https://a.example/x")).not.toBe(
      normalizePolicyHost("https://b.example/x"),
    );
  });

  it("returns a snapshot that names its own scope and asset, read from the store", async () => {
    // The audit seeded a store with committed 7 / reserved 3, called getBudgetState(), and
    // got hard-coded zeros with no read reaching the store at all.
    const store = new MemorySpendStore();
    const server = await merchantFor("pay-once");
    const tx402 = client({ spendStore: store });
    await tx402.fetch(`${server.url}/resource`);

    const scope = normalizePolicyHost(server.url);
    const snapshot = tx402.getBudgetState();
    expect(snapshot.policyScope).toBe(scope);
    expect(snapshot.assetId).toBe(ASSET_ID);
    expect(snapshot.committedAtomic).toBe(AMOUNT);

    const queried = await tx402.queryBudgetState({ policyScope: scope, assetId: ASSET_ID });
    expect(queried.committedAtomic).toBe(AMOUNT);
  });

  it("reads a scope written by something other than this client", async () => {
    // The fleet-wide case, without needing a second process: another writer's committed
    // spend must be visible through the client's own query.
    const store = new MemorySpendStore();
    await store.reserve({
      requestId: "external",
      policyScope: "elsewhere.example",
      requestFingerprint: `sha256:${"0".repeat(64)}`,
      assetId: ASSET_ID,
      amountAtomic: "7",
      maxPerHourAtomic: "1000",
      nowEpochMs: Date.now(),
      reservationId: "external-1",
    });
    await store.commit({ reservationId: "external-1", committedAtEpochMs: Date.now() });

    const state = await client({ spendStore: store }).queryBudgetState({
      policyScope: "elsewhere.example",
      assetId: ASSET_ID,
    });
    expect(state.committedAtomic).toBe("7");
  });
});

/* ------------------------------------------------------------------------------------- */
/* O46 — a store failure after settlement (ADR-017)                                        */
/* ------------------------------------------------------------------------------------- */

/** A store whose `commit` fails the way a database outage does. */
function commitFails(): SpendStore & { commitCalls: number } {
  const inner = new MemorySpendStore();
  const store: SpendStore & { commitCalls: number } = {
    kind: "failing-commit",
    commitCalls: 0,
    reserve: (input) => inner.reserve(input),
    commit: (): Promise<SpendEntry> => {
      store.commitCalls += 1;
      return Promise.reject(new Error("ledger backend unreachable"));
    },
    release: (id, now) => inner.release(id, now),
    getBudgetState: (query) => inner.getBudgetState(query),
  };
  return store;
}

describe("O46 spend-store failure semantics", () => {
  it("reports a post-settlement commit outage as typed, paid, and not retryable", async () => {
    const server = await merchantFor("pay-once");
    const store = commitFails();

    await expect(
      client({ spendStore: store }).fetch(`${server.url}/resource`),
    ).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      retryable: false,
      context: { paid: true, phase: "complete" },
      details: { reason: SPEND_STORE_COMMIT_FAILED_REASON, storeKind: "failing-commit" },
    });
    expect(store.commitCalls).toBe(1);
  });

  it("does not release the reservation when the commit failed", async () => {
    // Money moved. Handing the budget straight back would be the worst of both.
    const server = await merchantFor("pay-once");
    const store = commitFails();
    await client({ spendStore: store })
      .fetch(`${server.url}/resource`)
      .catch(() => undefined);

    const scope = normalizePolicyHost(server.url);
    expect(await totals(store, scope)).toEqual({ committed: "0", reserved: AMOUNT });
  });

  it("classifies a reserve outage the other way, and never reaches the signer", async () => {
    // The mirror image. Nothing has been signed, so no money can have moved and a retry is
    // genuinely safe — which is why this one is the retryable code and the commit one is not.
    const server = await merchantFor("pay-once");
    const broken: SpendStore = {
      kind: "failing-reserve",
      reserve: () => Promise.reject(new Error("ledger backend unreachable")),
      commit: () => Promise.reject(new Error("unused")),
      release: () => Promise.reject(new Error("unused")),
      getBudgetState: (query) => new MemorySpendStore().getBudgetState(query),
    };

    await expect(
      client({ spendStore: broken }).fetch(`${server.url}/resource`),
    ).rejects.toMatchObject({
      code: "TX402_TRANSPORT",
      retryable: true,
      context: { phase: "policy" },
      details: { causeCategory: SPEND_STORE_UNAVAILABLE_CAUSE },
    });
    expect(signer.signCount).toBe(0);
  });

  it("does not let a failing release mask the original refusal", async () => {
    const server = await merchantFor("refused-after-signature");
    const inner = new MemorySpendStore();
    const store: SpendStore = {
      kind: "release-explodes",
      reserve: (input) => inner.reserve(input),
      commit: (input) => inner.commit(input),
      release: () => Promise.reject(new Error("cleanup path is not the error path")),
      getBudgetState: (query) => inner.getBudgetState(query),
    };

    await expect(
      client({ spendStore: store }).fetch(`${server.url}/resource`),
    ).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      details: { reason: "paid-request-rejected" },
    });
  });
});

/* ------------------------------------------------------------------------------------- */
/* O52 / O53 — public error identity and malformed settlement metadata                     */
/* ------------------------------------------------------------------------------------- */

describe("O52 cross-origin redirect identity", () => {
  it("raises PaidRedirectBlockedError with its origins and a retained reservation", async () => {
    // SPEC §6.1: "Cross-origin redirect raises PaidRedirectBlockedError." Two facts, and
    // only one of them held. The money fact — retained, because the signature already
    // reached the merchant — is unchanged; the class the specification promises was
    // unreachable from the only entry point callers use.
    const server = await merchantFor("cross-origin-redirect");
    const store = new MemorySpendStore();

    await expect(
      client({ spendStore: store }).fetch(`${server.url}/resource`),
    ).rejects.toMatchObject({
      code: "TX402_REDIRECT_BLOCKED",
      retryable: false,
      context: { paid: "unknown" },
      details: {
        fromOrigin: server.origin,
        toOrigin: "https://elsewhere.example.net",
        causeCategory: "redirect-blocked",
      },
    });

    const scope = normalizePolicyHost(server.url);
    expect(await totals(store, scope)).toEqual({ committed: "0", reserved: AMOUNT });
  });
});

describe("O53 malformed settlement metadata", () => {
  it("refuses to call a corrupt PAYMENT-RESPONSE a delivery", async () => {
    // SPEC §6.7: a 2xx is paid-success "only when any required upstream PAYMENT-RESPONSE
    // parses successfully". A present header that does not decode is a protocol violation,
    // and it is evidence in neither direction — so it neither commits nor releases.
    const server = await merchantFor("corrupt-payment-response");
    const store = new MemorySpendStore();

    await expect(
      client({ spendStore: store }).fetch(`${server.url}/resource`),
    ).rejects.toMatchObject({
      code: "TX402_PAYMENT_AMBIGUOUS",
      context: { paid: "unknown" },
      details: { causeCategory: "settlement-metadata-unparseable" },
    });

    const scope = normalizePolicyHost(server.url);
    expect(await totals(store, scope)).toEqual({ committed: "0", reserved: AMOUNT });
  });

  it("still delivers when the header is absent altogether", async () => {
    // The distinction the fix rests on: absent is forgiven because upstream marks the
    // header optional, malformed is not.
    const server = await merchantFor("missing-payment-response");
    const store = new MemorySpendStore();
    const response = await client({ spendStore: store }).fetch(`${server.url}/resource`);
    expect(response.status).toBe(200);

    const scope = normalizePolicyHost(server.url);
    expect((await totals(store, scope)).committed).toBe(AMOUNT);
  });
});
