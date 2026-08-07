/**
 * Stage B handlers — the TypeScript SDK executed against the shared vectors.
 *
 * One handler per vector `kind`. Registering a handler is what claims the kind; the runner
 * fails if a vector at or below {@link IMPLEMENTED_THROUGH} has none, so this file and
 * `IMPLEMENTED_THROUGH` move together.
 *
 * Handlers throw on mismatch rather than returning false, because the diff is the only
 * genuinely useful part of a conformance failure.
 */

import { expect } from "vitest";

import { BUNDLED_MANIFEST } from "../../src/core/bundled-manifest.js";
import { canonicalizeJson, CanonicalJsonError } from "../../src/core/canonical-json.js";
import { classifyPaidAttempt, type PaidAttemptResult } from "../../src/core/completion.js";
import { TX402_ERROR_TAXONOMY } from "../../src/core/errors.js";
import { isTx402Error } from "../../src/core/errors.js";
import {
  digestRequestBody,
  fingerprintRequest,
  normalizeFingerprintUrl,
} from "../../src/core/fingerprint.js";
import { HealthIndex } from "../../src/core/health.js";
import { MemorySpendStore } from "../../src/core/ledger.js";
import {
  resolveNetwork,
  verifyReleaseManifest,
  type EvmManifestNetwork,
  type ReleaseManifest,
  type SvmManifestAsset,
  type SvmManifestNetwork,
} from "../../src/core/manifest.js";
import { normalizePolicyHost } from "../../src/core/policy.js";
import { decodePaymentRequired } from "../../src/core/protocol.js";
import { orderRouteCandidates, type RouteCandidate } from "../../src/core/routing.js";
import {
  planExactEvmAuthorization,
  type ExactEvmRequirementInput,
} from "../../src/evm/plan.js";
import {
  planExactSvmAuthorization,
  type ExactSvmRequirementInput,
} from "../../src/solana/plan.js";
import { registerHandler, type ConformanceVector } from "./runner.js";

/** Manifest failures all surface to callers as ConfigurationError (SPEC §5.4). */
const MANIFEST_ERROR_CODE = "TX402_CONFIG_INVALID";

registerHandler("errors.taxonomy", (vector: ConformanceVector) => {
  const expected = vector.expected as {
    entries: {
      code: string;
      className: string;
      retryability: string;
      retryable: boolean;
      requiredDetails: string[];
    }[];
  };

  // Compared as whole arrays, in order: the taxonomy's ordering is part of what is frozen,
  // and an entry-by-entry loop would let a reordering pass.
  const actual = TX402_ERROR_TAXONOMY.map((entry) => ({
    code: entry.code,
    className: entry.className,
    retryability: entry.retryability,
    retryable: entry.retryable,
    requiredDetails: [...entry.requiredDetails],
  }));

  expect(actual).toEqual(expected.entries);
});

registerHandler("canonical-json", (vector: ConformanceVector) => {
  const { document } = vector.input as { document: unknown };
  const expected = vector.expected as
    { canonical: string; sha256: string } | { error: string };

  if ("error" in expected) {
    try {
      canonicalizeJson(document);
    } catch (error) {
      expect(error).toBeInstanceOf(CanonicalJsonError);
      expect((error as CanonicalJsonError).reason).toBe(expected.error);
      return;
    }
    throw new Error(
      `Expected canonicalization to fail with ${expected.error}, but it succeeded`,
    );
  }

  expect(canonicalizeJson(document)).toBe(expected.canonical);
});

registerHandler("manifest.verify", (vector: ConformanceVector) => {
  const input = vector.input as {
    manifest: unknown;
    nowEpochMs: number;
    trustedKeys?: Record<string, string>;
  };
  const expected = vector.expected as
    { outcome: "valid" } | { outcome: "invalid"; errorCode: string; reason: string };

  const result = verifyReleaseManifest(input.manifest, {
    nowEpochMs: input.nowEpochMs,
    ...(input.trustedKeys ? { trustedKeys: input.trustedKeys } : {}),
  });

  if (expected.outcome === "valid") {
    if (!result.valid) {
      throw new Error(
        `Expected the manifest to verify, but it failed: ${result.reason} — ${result.message}`,
      );
    }
    return;
  }

  if (result.valid) {
    throw new Error(
      `Expected the manifest to be rejected with ${expected.reason}, but it verified`,
    );
  }

  expect(result.reason).toBe(expected.reason);
  expect(MANIFEST_ERROR_CODE).toBe(expected.errorCode);
});

registerHandler("manifest.network-resolution", (vector: ConformanceVector) => {
  const input = vector.input as { manifest: ReleaseManifest; query: string };
  const expected = vector.expected as
    { resolved: string; wasAlias: boolean } | { errorCode: string; reason: string };

  const result = resolveNetwork(input.manifest, input.query);

  if ("resolved" in expected) {
    if (!("resolved" in result)) {
      throw new Error(
        `Expected ${input.query} to resolve to ${expected.resolved}, but it failed: ${result.message}`,
      );
    }
    expect(result.resolved).toBe(expected.resolved);
    expect(result.wasAlias).toBe(expected.wasAlias);
    return;
  }

  if ("resolved" in result) {
    throw new Error(
      `Expected ${input.query} to be rejected, but it resolved to ${result.resolved}`,
    );
  }
  expect(result.reason).toBe(expected.reason);
  expect(MANIFEST_ERROR_CODE).toBe(expected.errorCode);
});

registerHandler("protocol.decode-payment-required", (vector: ConformanceVector) => {
  const input = vector.input as {
    requestUrl: string;
    requestMethod: string;
    header?: string;
    generatedHeader?: { kind: "repeated-ascii"; decodedBytes: number };
    clockEpochMs: number;
  };
  const expected = vector.expected as
    | { outcome: "valid"; normalized: unknown }
    | { outcome: "invalid"; errorCode: string; reason: string };

  try {
    const header = input.generatedHeader
      ? Buffer.alloc(input.generatedHeader.decodedBytes, 0x78).toString("base64")
      : input.header;
    const normalized = decodePaymentRequired(header, {
      requestUrl: input.requestUrl,
      requestMethod: input.requestMethod,
      requestId: vector.id,
      clockEpochMs: input.clockEpochMs,
    });
    if (expected.outcome === "invalid") {
      throw new Error(`Expected decode to fail with ${expected.reason}, but it succeeded`);
    }
    expect(normalized).toEqual(expected.normalized);
  } catch (error) {
    if (expected.outcome === "valid") throw error;
    if (!isTx402Error(error)) throw error;
    expect(error.code).toBe(expected.errorCode);
    expect(error.details.reason).toBe(expected.reason);
  }
});

registerHandler("request.fingerprint", (vector: ConformanceVector) => {
  const input = vector.input as {
    method: string;
    url: string;
    body: string | null;
    challengeHash: string;
  };
  const expected = vector.expected as {
    normalizedUrl: string;
    bodyHash: string;
    fingerprint: string;
  };
  expect(normalizeFingerprintUrl(input.url)).toBe(expected.normalizedUrl);
  expect(digestRequestBody(input.body)).toBe(expected.bodyHash);
  expect(
    fingerprintRequest({
      method: input.method,
      url: input.url,
      body: input.body,
      challengeHash: input.challengeHash,
    }),
  ).toBe(expected.fingerprint);
});

registerHandler("spend-ledger.behavior", async (vector: ConformanceVector) => {
  const input = vector.input as { operations: Record<string, unknown>[] };
  const expected = vector.expected as { outcomes: unknown[] };
  const store = new MemorySpendStore();
  const outcomes: Record<string, unknown>[] = [];
  for (const operation of input.operations) {
    try {
      switch (operation.action) {
        case "reserve": {
          const reservation = await store.reserve(operation as never);
          outcomes.push({ outcome: "reserved", state: reservation.state });
          break;
        }
        case "commit": {
          await store.commit(operation as never);
          outcomes.push({ outcome: "committed" });
          break;
        }
        case "release": {
          const reservation = await store.release(
            operation.reservationId as string,
            operation.nowEpochMs as number,
          );
          outcomes.push({ outcome: "released", state: reservation.state });
          break;
        }
        case "snapshot": {
          const state = await store.getBudgetState(operation as never);
          outcomes.push({
            outcome: "snapshot",
            committedAtomic: state.committedAtomic,
            reservedAtomic: state.reservedAtomic,
            reservationStates: state.reservations.map((item) => item.state),
            entryCount: state.entries.length,
          });
          break;
        }
        default:
          throw new Error(`Unknown ledger operation ${String(operation.action)}`);
      }
    } catch (error) {
      if (!isTx402Error(error)) throw error;
      outcomes.push({ outcome: "error", errorCode: error.code });
    }
  }
  expect(outcomes).toEqual(expected.outcomes);
});

registerHandler("evm.authorization-plan", (vector: ConformanceVector) => {
  const input = vector.input as {
    networkId: string;
    requirement: ExactEvmRequirementInput;
    payer: string;
    nowEpochMs: number;
    maxAuthorizationSeconds?: number;
  };
  const expected = vector.expected as {
    outcome: "valid" | "invalid";
    plan?: Record<string, unknown>;
    errorCode?: string;
    reason?: string;
  };

  // The network and asset are resolved from the bundled manifest rather than carried in the
  // vector, so the fixture pins that lookup too — SPEC §0 admits chain and token data through
  // the signed manifest and nowhere else.
  const network = BUNDLED_MANIFEST.networks[input.networkId] as EvmManifestNetwork;
  const asset =
    network.assets.find(
      (candidate) =>
        candidate.address.toLowerCase() === input.requirement.asset.toLowerCase(),
    ) ?? network.assets[0];
  // Vectors that name an off-manifest token still need an asset to be rejected against.
  if (asset === undefined) throw new Error(`${input.networkId} declares no assets`);

  const run = () =>
    planExactEvmAuthorization({
      requirement: input.requirement,
      networkId: input.networkId,
      network,
      asset,
      payer: input.payer,
      nowEpochMs: input.nowEpochMs,
      maxAuthorizationSeconds: input.maxAuthorizationSeconds ?? 60,
      context: { requestId: vector.id, phase: "route" },
    });

  if (expected.outcome === "valid") {
    expect({ ...run() }).toEqual(expected.plan);
    return;
  }
  try {
    run();
    expect.unreachable(`${vector.id} should have been rejected`);
  } catch (error) {
    if (!isTx402Error(error)) throw error;
    expect({ errorCode: error.code, reason: error.details.reason }).toEqual({
      errorCode: expected.errorCode,
      reason: expected.reason,
    });
  }
});

registerHandler("svm.authorization-plan", async (vector: ConformanceVector) => {
  const input = vector.input as {
    networkId: string;
    requirement: ExactSvmRequirementInput;
    payer: string;
    assetTokenProgram?: string;
  };
  const expected = vector.expected as {
    outcome: "valid" | "invalid";
    plan?: Record<string, unknown>;
    errorCode?: string;
    reason?: string;
  };
  const network = BUNDLED_MANIFEST.networks[input.networkId] as SvmManifestNetwork;
  const manifestAsset =
    network.assets.find((candidate) => candidate.mint === input.requirement.asset) ??
    network.assets[0];
  if (manifestAsset === undefined) throw new Error(`${input.networkId} declares no assets`);
  const asset = {
    ...manifestAsset,
    ...(input.assetTokenProgram === undefined
      ? {}
      : { tokenProgram: input.assetTokenProgram }),
  } as unknown as SvmManifestAsset;
  const run = () =>
    planExactSvmAuthorization({
      requirement: input.requirement,
      networkId: input.networkId,
      network,
      asset,
      payer: input.payer,
      maxAuthorizationSeconds: 60,
      context: { requestId: vector.id, phase: "route" },
    });

  if (expected.outcome === "valid") {
    expect({ ...(await run()) }).toEqual(expected.plan);
    return;
  }
  try {
    await run();
    expect.unreachable(`${vector.id} should have been rejected`);
  } catch (error) {
    if (!isTx402Error(error)) throw error;
    expect({ errorCode: error.code, reason: error.details.reason }).toEqual({
      errorCode: expected.errorCode,
      reason: expected.reason,
    });
  }
});

/* M5 — route ordering and endpoint health (SPEC §6.4, §6.5). ---------------------------- */

registerHandler("routing.candidate-order", (vector: ConformanceVector) => {
  const input = vector.input as {
    preferNetworks?: string[];
    candidates: Omit<RouteCandidate, "rank">[];
  };
  const expected = vector.expected as { order: number[]; selected?: number | null };

  // `rank` is what the ordering assigns, so the fixture supplies candidates without one and
  // a placeholder goes in only to satisfy the type.
  const ordered = orderRouteCandidates(
    input.candidates.map((candidate) => ({ ...candidate, rank: 0 })),
    input.preferNetworks ?? [],
  );

  expect(ordered.map((candidate) => candidate.requirementIndex)).toEqual(expected.order);
  // Ranks are 1-based and dense: every considered candidate is ranked, viable or not.
  expect(ordered.map((candidate) => candidate.rank)).toEqual(
    ordered.map((_candidate, index) => index + 1),
  );
  if (expected.selected !== undefined) {
    const selected = ordered.find((candidate) => candidate.viable);
    expect(selected?.requirementIndex ?? null).toEqual(expected.selected);
  }
});

/* M0 — policy scope identity (SPEC §6.3, ADR-018). --------------------------------------- */

registerHandler("policy.host-normalization", (vector: ConformanceVector) => {
  const { url } = vector.input as { url: string };
  const { host } = vector.expected as { host: string };
  expect(normalizePolicyHost(url)).toBe(host);
});

/* M6 — completion semantics (SPEC §6.7). ------------------------------------------------ */

registerHandler("completion.paid-attempt", (vector: ConformanceVector) => {
  const input = vector.input as {
    maxPaidAttempts: number;
    attempts: { attempt: number; result: PaidAttemptResult }[];
  };
  const expected = vector.expected as { dispositions: Record<string, unknown>[] };

  // Compared as whole objects rather than field by field: `reservation` is the field that
  // decides what happens to money, and an assertion that only checked `kind` would pass an
  // implementation that released where it should have retained.
  const observed = input.attempts.map((entry) => ({
    ...classifyPaidAttempt({
      attempt: entry.attempt,
      maxPaidAttempts: input.maxPaidAttempts,
      result: entry.result,
    }),
  }));

  expect(observed).toEqual(expected.dispositions);
});

registerHandler("health.circuit", (vector: ConformanceVector) => {
  const input = vector.input as {
    endpointId: string;
    operations: { action: string; latencyMs?: number; nowEpochMs: number }[];
  };
  const expected = vector.expected as { observations: Record<string, unknown>[] };
  const health = new HealthIndex();

  const observed = input.operations.map((operation) => {
    let admission: string | undefined;
    if (operation.action === "success") {
      health.recordSuccess(
        input.endpointId,
        operation.latencyMs ?? 0,
        operation.nowEpochMs,
      );
    } else if (operation.action === "failure") {
      health.recordFailure(input.endpointId, operation.nowEpochMs);
    } else if (operation.action === "open") {
      health.open(input.endpointId, operation.nowEpochMs);
    } else if (operation.action === "admit") {
      admission = health.admit(input.endpointId, operation.nowEpochMs);
    }
    const state = health.inspect(input.endpointId, operation.nowEpochMs);
    return {
      circuitState: state.circuitState,
      healthScore: state.healthScore,
      consecutiveFailures: state.consecutiveFailures,
      sampleCount: state.sampleCount,
      ...(admission === undefined ? {} : { admission }),
    };
  });

  expect(observed).toEqual(expected.observations);
});
