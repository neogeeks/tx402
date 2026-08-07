/**
 * Deterministic route planning (SPEC §6.4, §5.2).
 *
 * The planner is reached only after the policy engine has approved a set of requirements —
 * SPEC §6.3 step 13 makes that ordering a MUST, because this is the first place that talks to
 * a network, and a balance query against a merchant-named chain is already an observable side
 * effect of a request policy might have refused.
 *
 * Three properties shape the code:
 *
 *  1. **Ordering is a pure function of the candidates.** SPEC §6.4 step 19 requires identical
 *     output for identical inputs and health state, so every comparison key is either carried
 *     on the candidate or read once from the health index before sorting. `requirementIndex`
 *     is the final key and is unique per challenge, which makes the order a total one — the
 *     result does not depend on the sort being stable, or on which probe finished first.
 *  2. **Balances are fetched concurrently, once per unique network/asset/owner.** Step 15
 *     says concurrently; the deduplication is what keeps a challenge offering the same
 *     network twice from spending two round trips out of the 150 ms decision budget.
 *  3. **Nothing is dropped.** A requirement with no signer, an unreadable balance, and an
 *     insufficient balance all become candidates carrying their `rejectionReasons`, because
 *     SPEC §6.4 step 20's per-network deficits and the SPEC §10 diagnostics both need the
 *     full considered set rather than the survivors.
 */

import type { ChainRoute } from "./chain.js";
import { InsufficientLiquidityError, UnsupportedSchemeError } from "./errors.js";
import type { Tx402ErrorContext } from "./errors.js";
import {
  HEALTH_NEW_ENDPOINT_SCORE,
  type CircuitState,
  type HealthIndex,
} from "./health.js";
import type { PolicyRequirement } from "./policy.js";

/** The closed set from `core-spec/schemas/route-candidate.schema.json`. */
export type RouteRejectionReason =
  | "no-signer-configured"
  | "scheme-unsupported"
  | "network-not-in-manifest"
  | "network-not-allowed-by-policy"
  | "asset-unsupported"
  | "environment-mismatch"
  | "insufficient-balance"
  | "balance-unavailable"
  | "chain-identity-mismatch"
  | "circuit-open";

/** One scored route (SPEC §5.2). Every field here is redaction-safe. */
export interface RouteCandidate {
  readonly requirementIndex: number;
  readonly network: string;
  readonly scheme: string;
  readonly assetId: string;
  readonly amountAtomic: string;
  readonly signerId?: string;
  readonly balanceAtomic?: string;
  readonly estimatedFeeAtomic: string;
  readonly healthScore: number;
  readonly observedLatencyMs?: number;
  readonly circuitState: CircuitState;
  readonly rank: number;
  readonly viable: boolean;
  readonly rejectionReasons: readonly RouteRejectionReason[];
}

/**
 * Separates the parts of a balance-cache key.
 *
 * A NUL cannot appear in a CAIP-2 identifier, a token address, or an account address, so
 * joining on it makes the key unambiguous — the same reason `core/policy.ts` uses it for its
 * network/asset index. It is written as an escape rather than as a literal character: a raw
 * NUL byte in a source file makes git classify the file as binary and stop diffing it.
 */
export const BALANCE_KEY_SEPARATOR = "\u0000";

/**
 * Memoizes an in-flight read so requirements sharing a network/asset/owner share one query.
 *
 * Keyed on the promise rather than on the result, so concurrent callers join the same request
 * instead of racing two. The cache lives for exactly one planning pass: a balance is a
 * snapshot, and reusing it across requests would be reusing a stale one.
 */
export interface BalanceProbeCache {
  read<T>(key: string, load: () => Promise<T>): Promise<T>;
}

export function createBalanceProbeCache(): BalanceProbeCache {
  const inFlight = new Map<string, Promise<unknown>>();
  return {
    read<T>(key: string, load: () => Promise<T>): Promise<T> {
      const existing = inFlight.get(key);
      if (existing !== undefined) return existing as Promise<T>;
      const started = load();
      inFlight.set(key, started);
      return started;
    },
  };
}

/** What a probe can report back about one requirement. */
export type RouteProbeOutcome =
  /** The adapter scored the requirement against the chain. */
  | { readonly kind: "route"; readonly route: ChainRoute }
  /** Nothing was attempted — no signer, no adapter, no manifest entry. */
  | { readonly kind: "rejected"; readonly reason: RouteRejectionReason }
  /** An attempt was made and failed. `fatal` errors outrank a liquidity report. */
  | {
      readonly kind: "failed";
      readonly reason: RouteRejectionReason;
      readonly error: unknown;
      readonly fatal: boolean;
    };

export interface RoutePlanRequest {
  readonly requirements: readonly PolicyRequirement[];
  /** `routing.preferNetworks`, already normalized to canonical CAIP-2 (SPEC §4.3). */
  readonly preferNetworks: readonly string[];
  readonly health: HealthIndex;
  readonly nowEpochMs: number;
  readonly context: Tx402ErrorContext;
  readonly probe: (
    requirement: PolicyRequirement,
    balances: BalanceProbeCache,
  ) => Promise<RouteProbeOutcome>;
}

export interface RoutePlan {
  /** Every requirement considered, ranked. Non-viable candidates are retained. */
  readonly candidates: readonly RouteCandidate[];
  readonly selected: RouteCandidate;
  readonly selectedRequirement: PolicyRequirement;
  readonly selectedRoute: ChainRoute;
}

/**
 * Orders candidates by SPEC §6.4 step 18, with SPEC §6.5's open-circuit rule layered on top.
 *
 * Step 18's list is *viable, preference, fee, health, latency, index*. SPEC §6.5 adds a
 * stronger statement about one of those inputs — "an open endpoint may be used only when
 * every compatible endpoint is open, and it is ranked **last**" — which cannot be expressed as
 * a health-score adjustment, because a large enough preference bonus would outrank it. It is
 * therefore its own key, immediately below viability, and above preference.
 *
 * Every key is a total or near-total order and the last one is unique per challenge, so the
 * result does not depend on sort stability.
 */
export function orderRouteCandidates(
  candidates: readonly RouteCandidate[],
  preferNetworks: readonly string[],
): RouteCandidate[] {
  const preference = new Map<string, number>();
  for (const network of preferNetworks) {
    if (!preference.has(network)) preference.set(network, preference.size);
  }
  const unpreferred = preference.size;

  const ordered = [...candidates].sort((a, b) => {
    if (a.viable !== b.viable) return a.viable ? -1 : 1;

    const aOpen = a.circuitState === "open" ? 1 : 0;
    const bOpen = b.circuitState === "open" ? 1 : 0;
    if (aOpen !== bOpen) return aOpen - bOpen;

    const aRank = preference.get(a.network) ?? unpreferred;
    const bRank = preference.get(b.network) ?? unpreferred;
    if (aRank !== bRank) return aRank - bRank;

    const aFee = BigInt(a.estimatedFeeAtomic);
    const bFee = BigInt(b.estimatedFeeAtomic);
    if (aFee !== bFee) return aFee < bFee ? -1 : 1;

    if (a.healthScore !== b.healthScore) return b.healthScore - a.healthScore;

    // An endpoint with no observation is not slow, it is unmeasured; treating it as 0 keeps
    // this key from silently doing the work of the health score above it.
    const aLatency = a.observedLatencyMs ?? 0;
    const bLatency = b.observedLatencyMs ?? 0;
    if (aLatency !== bLatency) return aLatency - bLatency;

    return a.requirementIndex - b.requirementIndex;
  });

  return ordered.map((candidate, index) =>
    Object.freeze({ ...candidate, rank: index + 1 }),
  );
}

function healthOf(
  health: HealthIndex,
  endpointId: string | undefined,
  nowEpochMs: number,
): { healthScore: number; circuitState: CircuitState; observedLatencyMs?: number } {
  if (endpointId === undefined) {
    return { healthScore: HEALTH_NEW_ENDPOINT_SCORE, circuitState: "closed" };
  }
  const observed = health.inspect(endpointId, nowEpochMs);
  return {
    healthScore: observed.healthScore,
    circuitState: observed.circuitState,
    ...(observed.observedLatencyMs === undefined
      ? {}
      : { observedLatencyMs: observed.observedLatencyMs }),
  };
}

function candidateFromOutcome(
  requirement: PolicyRequirement,
  outcome: RouteProbeOutcome,
  health: HealthIndex,
  nowEpochMs: number,
): RouteCandidate {
  const base = {
    requirementIndex: requirement.index,
    network: requirement.network,
    scheme: requirement.scheme,
    assetId: requirement.assetId,
    amountAtomic: requirement.amountAtomic,
    rank: 0,
  };

  if (outcome.kind === "route") {
    const route = outcome.route;
    return {
      ...base,
      ...healthOf(health, route.endpointId, nowEpochMs),
      signerId: route.signerId,
      balanceAtomic: route.balanceAtomic,
      estimatedFeeAtomic: route.estimatedFeeAtomic ?? "0",
      viable: route.viable,
      rejectionReasons: route.viable
        ? []
        : (route.rejectionReasons as readonly RouteRejectionReason[]),
    };
  }

  return {
    ...base,
    healthScore: HEALTH_NEW_ENDPOINT_SCORE,
    circuitState: "closed",
    estimatedFeeAtomic: "0",
    viable: false,
    rejectionReasons: [outcome.reason],
  };
}

/**
 * Runs every probe concurrently, then applies steps 16 through 20.
 *
 * The probes are raced together rather than in requirement order, and every one of them is
 * awaited before anything is ordered — a "first viable candidate wins" shortcut would make
 * the selection depend on which RPC answered first, which is precisely what step 19 forbids.
 */
export async function planRoutes(request: RoutePlanRequest): Promise<RoutePlan> {
  const balances = createBalanceProbeCache();
  const outcomes = await Promise.all(
    request.requirements.map(async (requirement): Promise<RouteProbeOutcome> => {
      try {
        return await request.probe(requirement, balances);
      } catch (error) {
        return { kind: "failed", reason: "balance-unavailable", error, fatal: true };
      }
    }),
  );

  const candidates = orderRouteCandidates(
    request.requirements.map((requirement, index) =>
      candidateFromOutcome(
        requirement,
        outcomes[index] as RouteProbeOutcome,
        request.health,
        request.nowEpochMs,
      ),
    ),
    request.preferNetworks,
  );

  const selected = candidates.find((candidate) => candidate.viable);
  if (selected !== undefined) {
    const index = request.requirements.findIndex(
      (requirement) => requirement.index === selected.requirementIndex,
    );
    const outcome = outcomes[index] as RouteProbeOutcome;
    /* istanbul ignore next -- a viable candidate can only come from a `route` outcome. */
    if (outcome.kind !== "route") throw new Error("Selected candidate has no route");
    return {
      candidates,
      selected,
      selectedRequirement: request.requirements[index] as PolicyRequirement,
      selectedRoute: outcome.route,
    };
  }

  /* Step 20, in three cases that must not be conflated. */
  const attempted = outcomes.filter((outcome) => outcome.kind !== "rejected");
  if (attempted.length === 0) {
    throw new UnsupportedSchemeError(
      "No offered network has a configured signer and chain adapter",
      {
        context: request.context,
        details: {
          offeredSchemes: [...new Set(request.requirements.map((item) => item.scheme))],
          offeredNetworks: [...new Set(request.requirements.map((item) => item.network))],
        },
      },
    );
  }

  // Reported in the merchant's own requirement order rather than in rank order: a deficit
  // report answers "what was offered and what was short", and ranking it by measured health
  // would make the same wallet against the same challenge produce a different-looking error.
  const deficits = candidates
    .filter((candidate) => candidate.balanceAtomic !== undefined)
    .sort((a, b) => a.requirementIndex - b.requirementIndex)
    .map((candidate) => ({
      network: candidate.network,
      assetId: candidate.assetId,
      required: candidate.amountAtomic,
      available: candidate.balanceAtomic as string,
    }));

  if (deficits.length === 0) {
    // Every attempt failed before a balance was observed. Reporting insufficient liquidity
    // here would blame the caller's funds for what is an unreachable RPC.
    const failure = outcomes.find((outcome) => outcome.kind === "failed");
    if (failure !== undefined && failure.kind === "failed") throw failure.error;
  }

  throw new InsufficientLiquidityError("No offered route has sufficient balance", {
    context: request.context,
    details: { deficits },
  });
}
