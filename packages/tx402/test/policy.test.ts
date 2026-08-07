import { describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import type { SpendStore } from "../src/core/ledger.js";
import { MemorySpendStore } from "../src/core/ledger.js";
import { PolicyEngine } from "../src/core/policy.js";
import type { NormalizedPaymentRequired } from "../src/core/protocol.js";

const NOW = 1_785_715_200_000;
const BASE_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

function required(
  overrides: Partial<NormalizedPaymentRequired["requirements"][number]> = {},
  url = "https://api.example.com/pay",
): NormalizedPaymentRequired {
  return Object.freeze({
    protocolVersion: 2,
    resource: Object.freeze({ url, method: "POST" }),
    requirements: Object.freeze([
      Object.freeze({
        index: 0,
        scheme: "exact",
        network: "eip155:8453",
        asset: BASE_ASSET,
        amountAtomic: "1",
        payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
        maxTimeoutSeconds: 60,
        extra: Object.freeze({}),
        rawHash: `sha256:${"1".repeat(64)}`,
        ...overrides,
      }),
    ]),
    receivedAt: new Date(NOW).toISOString(),
    headerHash: `sha256:${"2".repeat(64)}`,
  });
}

function evaluate(
  engine: PolicyEngine,
  paymentRequired: NormalizedPaymentRequired,
  store: SpendStore = new MemorySpendStore(),
) {
  return engine.evaluate(paymentRequired, {
    requestId: "policy-test",
    policyScope: "scope",
    nowEpochMs: NOW,
    spendStore: store,
  });
}

describe("PolicyEngine", () => {
  it("normalizes exact and wildcard domain rules", async () => {
    const exact = new PolicyEngine(BUNDLED_MANIFEST, {
      allowedDomains: ["API.Example.COM."],
    });
    await expect(evaluate(exact, required())).resolves.toMatchObject({
      normalizedHost: "api.example.com",
    });

    const wildcard = new PolicyEngine(BUNDLED_MANIFEST, {
      allowedDomains: ["*.example.com"],
    });
    await expect(evaluate(wildcard, required())).resolves.toBeDefined();
    await expect(
      evaluate(wildcard, required({}, "https://example.com/pay")),
    ).rejects.toMatchObject({
      code: "TX402_POLICY_DOMAIN",
      details: { normalizedHost: "example.com" },
    });
  });

  it("resolves allowed network aliases and rejects disallowed networks before scheme", async () => {
    const solana = new PolicyEngine(BUNDLED_MANIFEST, {
      allowedNetworks: ["solana:mainnet"],
    });
    await expect(
      evaluate(
        solana,
        required({
          network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
          asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        }),
      ),
    ).resolves.toHaveProperty(
      "requirements.0.assetId",
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    );

    await expect(
      evaluate(
        new PolicyEngine(BUNDLED_MANIFEST),
        required({ network: "eip155:84532", scheme: "mystery" }),
      ),
    ).rejects.toMatchObject({
      code: "TX402_SCHEME_UNSUPPORTED",
      details: { offeredNetworks: ["eip155:84532"] },
    });
  });

  it("enforces manifest schemes/assets before monetary limits", async () => {
    const engine = new PolicyEngine(BUNDLED_MANIFEST, {
      maxPerRequest: "0.000001 USDC",
      maxPerHour: "0.000001 USDC",
    });
    await expect(
      evaluate(
        engine,
        required({
          asset: "0x0000000000000000000000000000000000000001",
          amountAtomic: "2",
        }),
      ),
    ).rejects.toHaveProperty("code", "TX402_SCHEME_UNSUPPORTED");
  });

  it("T-006 rejects above maxPerRequest locally in under 2 ms p95 without store/signer work", async () => {
    const getBudgetState = vi.fn();
    const forbidden = vi.fn(() => Promise.reject(new Error("must not run")));
    const store: SpendStore = {
      kind: "spy",
      reserve: forbidden,
      commit: forbidden,
      release: forbidden,
      getBudgetState,
    };
    const engine = new PolicyEngine(BUNDLED_MANIFEST, {
      maxPerRequest: "0.000001 USDC",
      maxPerHour: "1 USDC",
    });
    const quote = required({ amountAtomic: "2", extra: { timestamp: "invalid-later" } });
    const durations: number[] = [];
    for (let index = 0; index < 500; index += 1) {
      const started = performance.now();
      await expect(evaluate(engine, quote, store)).rejects.toHaveProperty(
        "code",
        "TX402_POLICY_BUDGET",
      );
      durations.push(performance.now() - started);
    }
    durations.sort((left, right) => left - right);
    expect(durations[Math.floor(durations.length * 0.95)]).toBeLessThan(2);
    expect(getBudgetState).not.toHaveBeenCalled();
    expect(forbidden).not.toHaveBeenCalled();
  });

  it("counts committed and active reservations in the rolling-hour precheck", async () => {
    const store = new MemorySpendStore();
    const engine = new PolicyEngine(BUNDLED_MANIFEST, {
      maxPerRequest: "0.000004 USDC",
      maxPerHour: "0.000004 USDC",
    });
    await store.reserve({
      reservationId: "00000000-0000-7000-8000-000000000001",
      requestId: "existing",
      policyScope: "scope",
      requestFingerprint: `sha256:${"3".repeat(64)}`,
      assetId: `eip155:8453/erc20:${BASE_ASSET}`,
      amountAtomic: "3",
      maxPerHourAtomic: "4",
      nowEpochMs: NOW,
    });
    await expect(
      evaluate(
        engine,
        required({ amountAtomic: "2", extra: { timestamp: "invalid-later" } }),
        store,
      ),
    ).rejects.toMatchObject({
      code: "TX402_POLICY_BUDGET",
      details: { capKind: "per-hour", reservedAtomic: "3" },
    });
  });

  it("conditionally enforces maxQuoteAge after the budget check", async () => {
    const engine = new PolicyEngine(BUNDLED_MANIFEST, {}, { maxQuoteAgeMs: 5_000 });
    await expect(evaluate(engine, required())).resolves.toBeDefined();
    await expect(
      evaluate(
        engine,
        required({ extra: { timestamp: new Date(NOW - 5_001).toISOString() } }),
      ),
    ).rejects.toMatchObject({
      code: "TX402_PAYMENT_REQUIRED_INVALID",
      details: { reason: "quote-expired" },
    });
    await expect(
      evaluate(
        engine,
        required({ extra: { timestamp: new Date(NOW + 15_001).toISOString() } }),
      ),
    ).rejects.toMatchObject({
      code: "TX402_CLOCK_SKEW",
      details: { thresholdMs: 15_000 },
    });
  });

  it("validates every policy field synchronously and rejects monetary numbers", () => {
    try {
      new PolicyEngine(BUNDLED_MANIFEST, { maxPerRequest: 0.5 });
      throw new Error("Expected numeric money config to fail");
    } catch (error) {
      expect(error).toMatchObject({
        code: "TX402_CONFIG_INVALID",
        details: { configPath: "policy.maxPerRequest", reason: "number-not-allowed" },
      });
    }
    expect(
      () =>
        new PolicyEngine(BUNDLED_MANIFEST, {
          maxPerRequest: "2 USDC",
          maxPerHour: "1 USDC",
        }),
    ).toThrowError(/below-max-per-request/u);
    expect(() => new PolicyEngine(BUNDLED_MANIFEST, { allowedNetworks: [] })).toThrow();
    expect(
      () => new PolicyEngine(BUNDLED_MANIFEST, { allowedDomains: ["https://bad"] }),
    ).toThrow();
    expect(() => new PolicyEngine(BUNDLED_MANIFEST, { maxPaidAttempts: 4 })).toThrow();
    expect(() => new PolicyEngine(BUNDLED_MANIFEST, {}, { maxQuoteAgeMs: -1 })).toThrow();
  });
});

describe("routing.rpcOverrides (ADR-015)", () => {
  const engine = (rpcOverrides: Record<string, readonly string[]>) =>
    new PolicyEngine(
      BUNDLED_MANIFEST,
      { allowedNetworks: ["eip155:84532"] },
      {
        rpcOverrides,
      },
    );

  it("resolves an aliased key to canonical CAIP-2", () => {
    // `solana:devnet` is an alias; the adapter is handed the genesis-hash id, so an
    // override keyed by the alias has to land under the canonical name or it silently
    // never applies — which is the failure this resolution exists to prevent.
    const resolved = new PolicyEngine(
      BUNDLED_MANIFEST,
      {},
      {
        rpcOverrides: { "solana:devnet": ["https://rpc.example.com/k"] },
      },
    ).rpcOverrides;

    expect(Object.keys(resolved)).toEqual(["solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"]);
  });

  it("defaults to no overrides, so the manifest decides", () => {
    expect(new PolicyEngine(BUNDLED_MANIFEST).rpcOverrides).toEqual({});
  });

  it("rejects an unknown network rather than never applying", () => {
    expect(() => engine({ "eip155:999999": ["https://rpc.example.com"] })).toThrow(
      /eip155:999999|unknown-network|routing.rpcOverrides/u,
    );
  });

  it("rejects an empty list", () => {
    expect(() => engine({ "eip155:84532": [] })).toThrow(/empty-list/u);
  });

  it("rejects plaintext http off localhost, because the key is in the URL", () => {
    expect(() => engine({ "eip155:84532": ["http://rpc.example.com/k"] })).toThrow(
      /insecure-scheme/u,
    );
    // A local validator has no transport to intercept.
    expect(() => engine({ "eip155:84532": ["http://127.0.0.1:8899"] })).not.toThrow();
    expect(() => engine({ "eip155:84532": ["http://localhost:8899"] })).not.toThrow();
  });

  it("rejects a value that is not a URL", () => {
    expect(() => engine({ "eip155:84532": ["not a url"] })).toThrow(/invalid-url/u);
  });
});
