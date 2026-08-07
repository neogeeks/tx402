/**
 * The RoutePlanner (SPEC §6.4).
 *
 * Ordering itself is pinned by the shared `routing.candidate-order` vectors, so these tests
 * cover what a vector cannot express: that the probes actually run concurrently, that a
 * network/asset/owner is queried once no matter how many requirements name it, and that
 * step 20's three failure cases stay distinguishable — an unreachable RPC must not be
 * reported as an empty wallet.
 */

import { describe, expect, it } from "vitest";

import type { ChainRoute } from "../src/core/chain.js";
import { InsufficientLiquidityError, TransportError } from "../src/core/errors.js";
import { HealthIndex } from "../src/core/health.js";
import type { ManifestAsset } from "../src/core/manifest.js";
import type { PolicyRequirement } from "../src/core/policy.js";
import {
  createBalanceProbeCache,
  orderRouteCandidates,
  planRoutes,
  type RouteCandidate,
  type RouteProbeOutcome,
} from "../src/core/routing.js";

const T = 1_785_715_200_000;
const BASE = "eip155:8453";
const SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const BASE_ASSET = `${BASE}/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`;
const SOLANA_ASSET = `${SOLANA}/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`;
const CONTEXT = { requestId: "req-1", phase: "route" } as const;

function requirement(index: number, network: string, assetId: string): PolicyRequirement {
  return {
    index,
    scheme: "exact",
    network,
    asset: assetId.slice(assetId.indexOf("/") + 1).split(":")[1] as string,
    amountAtomic: "50000",
    payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
    maxTimeoutSeconds: 60,
    extra: {},
    rawHash: `sha256:${"0".repeat(64)}`,
    assetId,
    manifestAsset: {} as ManifestAsset,
    maxPerRequestAtomic: "500000",
    maxPerHourAtomic: "10000000",
  };
}

function route(
  requirementIndex: number,
  networkId: string,
  assetId: string,
  overrides: Partial<ChainRoute> = {},
): ChainRoute {
  return {
    requirementIndex,
    networkId,
    scheme: "exact",
    assetId,
    amountAtomic: "50000",
    signerId: "evm:0x1111111111111111111111111111111111111111",
    balanceAtomic: "5000000",
    viable: true,
    rejectionReasons: [],
    estimatedFeeAtomic: "0",
    ...overrides,
  };
}

function candidate(overrides: Partial<RouteCandidate>): RouteCandidate {
  return {
    requirementIndex: 0,
    network: BASE,
    scheme: "exact",
    assetId: BASE_ASSET,
    amountAtomic: "50000",
    estimatedFeeAtomic: "0",
    healthScore: 0.8,
    circuitState: "closed",
    rank: 0,
    viable: true,
    rejectionReasons: [],
    ...overrides,
  };
}

describe("route ordering", () => {
  it("ranks every candidate, viable or not, from 1 upward", () => {
    const ordered = orderRouteCandidates(
      [
        candidate({
          requirementIndex: 0,
          viable: false,
          rejectionReasons: ["insufficient-balance"],
        }),
        candidate({ requirementIndex: 1 }),
      ],
      [],
    );
    expect(ordered.map((entry) => [entry.requirementIndex, entry.rank])).toEqual([
      [1, 1],
      [0, 2],
    ]);
  });

  it("ignores a preference for a network no candidate offers", () => {
    const ordered = orderRouteCandidates(
      [candidate({ requirementIndex: 1 }), candidate({ requirementIndex: 0 })],
      ["eip155:84532"],
    );
    // Preference is a tie-break, never a filter: with nothing to prefer, the index decides.
    expect(ordered.map((entry) => entry.requirementIndex)).toEqual([0, 1]);
  });

  it("treats a repeated preference entry as its first position", () => {
    const ordered = orderRouteCandidates(
      [
        candidate({ requirementIndex: 0, network: SOLANA, assetId: SOLANA_ASSET }),
        candidate({ requirementIndex: 1 }),
      ],
      [BASE, SOLANA, BASE],
    );
    expect(ordered.map((entry) => entry.requirementIndex)).toEqual([1, 0]);
  });

  /**
   * SPEC §6.4 step 19 requires identical output for identical inputs *and health state*.
   * That is a property of `orderRouteCandidates` alone, so it is asserted here on fixed
   * inputs — not through a live client, whose probes re-measure the wall clock on every
   * pass and so present a different health state each time (PLAN.md open item O34). The
   * mirror of this assertion lives in `packages/tx402-python/tests/test_routing.py`.
   */
  it("decides an exact tie on every key above it by requirement index", () => {
    const ordered = orderRouteCandidates(
      [
        candidate({
          requirementIndex: 1,
          network: SOLANA,
          assetId: SOLANA_ASSET,
          observedLatencyMs: 41,
        }),
        candidate({ requirementIndex: 0, observedLatencyMs: 41 }),
      ],
      [],
    );
    // The merchant's own ordering wins, not whichever RPC happened to answer first.
    expect(ordered.map((entry) => entry.requirementIndex)).toEqual([0, 1]);
  });

  it("produces identical output for identical input regardless of array order", () => {
    const set = [
      candidate({ requirementIndex: 0, healthScore: 0.7, observedLatencyMs: 30 }),
      candidate({ requirementIndex: 1, healthScore: 0.9, observedLatencyMs: 300 }),
      candidate({ requirementIndex: 2, healthScore: 0.9, observedLatencyMs: 20 }),
    ];
    const forward = orderRouteCandidates(set, []).map((entry) => entry.requirementIndex);
    const reversed = orderRouteCandidates([...set].reverse(), []).map(
      (entry) => entry.requirementIndex,
    );
    expect(forward).toEqual([2, 1, 0]);
    // SPEC §6.4 step 19: the order is a property of the candidates, not of how they arrived.
    expect(reversed).toEqual(forward);
  });

  it("does not mutate the candidates it was given", () => {
    const input = [candidate({ requirementIndex: 3 })];
    orderRouteCandidates(input, []);
    expect(input[0]?.rank).toBe(0);
  });
});

describe("balance probe cache", () => {
  it("joins concurrent readers of the same key onto one load", async () => {
    const cache = createBalanceProbeCache();
    let loads = 0;
    const load = async (): Promise<number> => {
      loads += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return 7;
    };

    const [first, second] = await Promise.all([
      cache.read("k", load),
      cache.read("k", load),
    ]);
    expect([first, second]).toEqual([7, 7]);
    expect(loads).toBe(1);
    // A different key is a different balance and must not be served from the first.
    await cache.read("other", load);
    expect(loads).toBe(2);
  });
});

describe("planRoutes", () => {
  const health = new HealthIndex();

  it("probes every requirement concurrently and deduplicates the balance read", async () => {
    const requirements = [
      requirement(0, BASE, BASE_ASSET),
      requirement(1, BASE, BASE_ASSET),
      requirement(2, SOLANA, SOLANA_ASSET),
    ];
    let inFlight = 0;
    let peak = 0;
    let reads = 0;

    const plan = await planRoutes({
      requirements,
      preferNetworks: [SOLANA],
      health,
      nowEpochMs: T,
      context: CONTEXT,
      probe: async (item, balances): Promise<RouteProbeOutcome> => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        const balance = await balances.read(`${item.network} owner`, async () => {
          reads += 1;
          await new Promise((resolve) => setTimeout(resolve, 10));
          return "5000000";
        });
        inFlight -= 1;
        return {
          kind: "route",
          route: route(item.index, item.network, item.assetId, { balanceAtomic: balance }),
        };
      },
    });

    expect(peak).toBe(3);
    // Two Base requirements share one query; Solana is a second network, so a second.
    expect(reads).toBe(2);
    expect(plan.candidates).toHaveLength(3);
    expect(plan.selected.requirementIndex).toBe(2);
    expect(plan.selectedRequirement.network).toBe(SOLANA);
  });

  it("waits for every probe before selecting, so a slow winner still wins", async () => {
    const plan = await planRoutes({
      requirements: [
        requirement(0, BASE, BASE_ASSET),
        requirement(1, SOLANA, SOLANA_ASSET),
      ],
      preferNetworks: [SOLANA],
      health,
      nowEpochMs: T,
      context: CONTEXT,
      probe: async (item): Promise<RouteProbeOutcome> => {
        // The preferred network answers last. A "first viable wins" planner would pick Base.
        if (item.network === SOLANA)
          await new Promise((resolve) => setTimeout(resolve, 25));
        return { kind: "route", route: route(item.index, item.network, item.assetId) };
      },
    });
    expect(plan.selected.network).toBe(SOLANA);
  });

  it("reports unsupported when nothing could be attempted", async () => {
    await expect(
      planRoutes({
        requirements: [requirement(0, BASE, BASE_ASSET)],
        preferNetworks: [],
        health,
        nowEpochMs: T,
        context: CONTEXT,
        probe: () => Promise.resolve({ kind: "rejected", reason: "no-signer-configured" }),
      }),
    ).rejects.toMatchObject({ code: "TX402_SCHEME_UNSUPPORTED" });
  });

  it("reports the transport failure, not empty funds, when no balance was ever read", async () => {
    const failure = new TransportError("RPC unreachable", {
      context: CONTEXT,
      details: { causeCategory: "timeout" },
    });
    await expect(
      planRoutes({
        requirements: [requirement(0, BASE, BASE_ASSET)],
        preferNetworks: [],
        health,
        nowEpochMs: T,
        context: CONTEXT,
        probe: () =>
          Promise.resolve({
            kind: "failed",
            reason: "balance-unavailable",
            error: failure,
            fatal: false,
          }),
      }),
    ).rejects.toBe(failure);
  });

  it("reports per-network deficits when balances were read and none sufficed", async () => {
    const error = await planRoutes({
      requirements: [
        requirement(0, BASE, BASE_ASSET),
        requirement(1, SOLANA, SOLANA_ASSET),
      ],
      preferNetworks: [],
      health,
      nowEpochMs: T,
      context: CONTEXT,
      probe: (item): Promise<RouteProbeOutcome> =>
        Promise.resolve({
          kind: "route",
          route: route(item.index, item.network, item.assetId, {
            balanceAtomic: "10000",
            viable: false,
            rejectionReasons: ["insufficient-balance"],
          }),
        }),
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(InsufficientLiquidityError);
    expect((error as InsufficientLiquidityError).details.deficits).toEqual([
      { network: BASE, assetId: BASE_ASSET, required: "50000", available: "10000" },
      { network: SOLANA, assetId: SOLANA_ASSET, required: "50000", available: "10000" },
    ]);
  });

  it("prefers a deficit report over a transport error when at least one balance was read", async () => {
    await expect(
      planRoutes({
        requirements: [
          requirement(0, BASE, BASE_ASSET),
          requirement(1, SOLANA, SOLANA_ASSET),
        ],
        preferNetworks: [],
        health,
        nowEpochMs: T,
        context: CONTEXT,
        probe: (item): Promise<RouteProbeOutcome> =>
          Promise.resolve(
            item.network === BASE
              ? {
                  kind: "failed",
                  reason: "chain-identity-mismatch",
                  error: new Error("wrong chain"),
                  fatal: false,
                }
              : {
                  kind: "route",
                  route: route(item.index, item.network, item.assetId, {
                    balanceAtomic: "1",
                    viable: false,
                    rejectionReasons: ["insufficient-balance"],
                  }),
                },
          ),
      }),
    ).rejects.toBeInstanceOf(InsufficientLiquidityError);
  });

  it("turns a probe that throws into a fatal failure rather than losing it", async () => {
    const thrown = new Error("probe exploded");
    await expect(
      planRoutes({
        requirements: [requirement(0, BASE, BASE_ASSET)],
        preferNetworks: [],
        health,
        nowEpochMs: T,
        context: CONTEXT,
        probe: () => Promise.reject(thrown),
      }),
    ).rejects.toBe(thrown);
  });

  it("scores a candidate from the endpoint that answered", async () => {
    const scored = new HealthIndex();
    const endpointId = HealthIndex.endpointId(BASE, "slow.example.com");
    scored.recordSuccess(endpointId, 600, T);

    const plan = await planRoutes({
      requirements: [requirement(0, BASE, BASE_ASSET)],
      preferNetworks: [],
      health: scored,
      nowEpochMs: T,
      context: CONTEXT,
      probe: (item): Promise<RouteProbeOutcome> =>
        Promise.resolve({
          kind: "route",
          route: route(item.index, item.network, item.assetId, { endpointId }),
        }),
    });

    // 0.84 success EWMA less the full 0.20 latency penalty at the 600 ms budget.
    expect(plan.selected.healthScore).toBe(0.64);
    expect(plan.selected.observedLatencyMs).toBe(600);
    expect(plan.selected.circuitState).toBe("closed");
  });

  it("falls back to the new-endpoint score when no endpoint is reported", async () => {
    const plan = await planRoutes({
      requirements: [requirement(0, BASE, BASE_ASSET)],
      preferNetworks: [],
      health,
      nowEpochMs: T,
      context: CONTEXT,
      probe: (item): Promise<RouteProbeOutcome> =>
        Promise.resolve({
          kind: "route",
          route: route(item.index, item.network, item.assetId),
        }),
    });
    expect(plan.selected.healthScore).toBe(0.8);
    expect(plan.selected.observedLatencyMs).toBeUndefined();
    expect(plan.selected.estimatedFeeAtomic).toBe("0");
  });
});
