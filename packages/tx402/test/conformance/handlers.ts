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

/** Manifest failures all surface to callers as ConfigurationError. */
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
  // The v2 lifecycle ops take the full `{policyScope, assetId, reservationId}` ref (SPEC §3.1),
  // but a vector's commit/release op carries only the id — so the driver reconstructs the ref
  // from the reserve that created it (falling back to any ref fields a vector supplies
  // directly, which the S5 extended vectors will). No frozen vector changes.
  const refs = new Map<string, { policyScope: string; assetId: string }>();
  const outcomes: Record<string, unknown>[] = [];
  for (const operation of input.operations) {
    const refFor = (): { policyScope: string; assetId: string } =>
      refs.get(operation.reservationId as string) ?? {
        policyScope: operation.policyScope as string,
        assetId: operation.assetId as string,
      };
    try {
      switch (operation.action) {
        case "reserve": {
          const { reservation } = await store.reserve(operation as never);
          refs.set(reservation.reservationId, {
            policyScope: reservation.policyScope,
            assetId: reservation.assetId,
          });
          outcomes.push({ outcome: "reserved", state: reservation.state });
          break;
        }
        case "commit": {
          const ref = refFor();
          await store.commit({
            reservationId: operation.reservationId as string,
            policyScope: ref.policyScope,
            assetId: ref.assetId,
            committedAtEpochMs: operation.committedAtEpochMs as number,
            ...(operation.settlementId === undefined
              ? {}
              : { settlementId: operation.settlementId as string }),
          });
          outcomes.push({ outcome: "committed" });
          break;
        }
        case "release": {
          const ref = refFor();
          const reservation = await store.release(
            { reservationId: operation.reservationId as string, ...ref },
            operation.nowEpochMs as number,
          );
          outcomes.push({ outcome: "released", state: reservation.state });
          break;
        }
        case "expose": {
          // The pre-transmission fence (SPEC §7, ADR-026), driven at the store level exactly
          // as the client's `store.expose(ref, now)` call does it.
          const ref = refFor();
          const reservation = await store.expose(
            { reservationId: operation.reservationId as string, ...ref },
            operation.nowEpochMs as number,
          );
          outcomes.push({ outcome: "exposed", state: reservation.state });
          break;
        }
        case "snapshot": {
          const state = await store.getBudgetState(operation as never);
          outcomes.push({
            outcome: "snapshot",
            committedAtomic: state.committedAtomic,
            reservedAtomic: state.reservedAtomic,
            // The exposure/cumulative counters are the headline figures SPEC §7 pins, but they
            // are opt-in so the pre-0.2.0 ledger vectors keep their exact four-field snapshot.
            ...(operation.exposure === true
              ? {
                  exposedAtomic: state.exposedAtomic,
                  cumulativeCommittedAtomic: state.cumulativeCommittedAtomic,
                  cumulativeConsumedAtomic: state.cumulativeConsumedAtomic,
                }
              : {}),
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
      // A BudgetExceededError carries `capKind` (per-request/per-hour/cumulative); surface it so
      // a cumulative refusal is distinguishable from a per-hour one, which share an error code.
      const capKind = (error.details as { capKind?: unknown }).capKind;
      outcomes.push({
        outcome: "error",
        errorCode: error.code,
        ...(typeof capKind === "string" ? { capKind } : {}),
      });
    }
  }
  expect(outcomes).toEqual(expected.outcomes);
});

registerHandler("spend-freeze.behavior", async (vector: ConformanceVector) => {
  const input = vector.input as { operations: Record<string, unknown>[] };
  const expected = vector.expected as {
    outcomes: unknown[];
    incapableOutcomes?: unknown[];
  };
  const store = new MemorySpendStore();
  // Parameterized by the store's declared global-freeze capability (SPEC §5.2, §13). The
  // reference store is `atomicGlobalFreeze: true`, so it runs the `outcomes` arm; a durable
  // store that declares `false` (Redis Cluster, id-per-scope DO — S7/S8) runs
  // `incapableOutcomes`, where `freeze("*")` fails closed instead of freezing. A per-scope
  // vector omits `incapableOutcomes`, so both arms use `outcomes`.
  const arm =
    store.capabilities.atomicGlobalFreeze || expected.incapableOutcomes === undefined
      ? expected.outcomes
      : expected.incapableOutcomes;
  const refs = new Map<string, { policyScope: string; assetId: string }>();
  const outcomes: Record<string, unknown>[] = [];
  for (const operation of input.operations) {
    const refFor = (): { policyScope: string; assetId: string } =>
      refs.get(operation.reservationId as string) ?? {
        policyScope: operation.policyScope as string,
        assetId: operation.assetId as string,
      };
    try {
      switch (operation.action) {
        case "reserve": {
          const { reservation } = await store.reserve(operation as never);
          refs.set(reservation.reservationId, {
            policyScope: reservation.policyScope,
            assetId: reservation.assetId,
          });
          outcomes.push({ outcome: "reserved", state: reservation.state });
          break;
        }
        case "commit": {
          const ref = refFor();
          await store.commit({
            reservationId: operation.reservationId as string,
            policyScope: ref.policyScope,
            assetId: ref.assetId,
            committedAtEpochMs: operation.committedAtEpochMs as number,
            ...(operation.settlementId === undefined
              ? {}
              : { settlementId: operation.settlementId as string }),
          });
          outcomes.push({ outcome: "committed" });
          break;
        }
        case "release": {
          const ref = refFor();
          const reservation = await store.release(
            { reservationId: operation.reservationId as string, ...ref },
            operation.nowEpochMs as number,
          );
          outcomes.push({ outcome: "released", state: reservation.state });
          break;
        }
        case "expose": {
          const ref = refFor();
          const reservation = await store.expose(
            { reservationId: operation.reservationId as string, ...ref },
            operation.nowEpochMs as number,
          );
          outcomes.push({ outcome: "exposed", state: reservation.state });
          break;
        }
        case "freeze": {
          await store.freeze(operation.scope as string, operation.nowEpochMs as number);
          outcomes.push({ outcome: "frozen" });
          break;
        }
        case "unfreeze": {
          await store.unfreeze(operation.scope as string, operation.nowEpochMs as number);
          outcomes.push({ outcome: "unfrozen" });
          break;
        }
        case "snapshot": {
          const state = await store.getBudgetState(operation as never);
          outcomes.push({
            outcome: "snapshot",
            committedAtomic: state.committedAtomic,
            reservedAtomic: state.reservedAtomic,
            // `frozen` is the headline freeze signal; the exposure/cumulative counters stay
            // opt-in so a freeze vector only asserts what it cares about.
            frozen: state.frozen,
            ...(operation.exposure === true
              ? {
                  exposedAtomic: state.exposedAtomic,
                  cumulativeCommittedAtomic: state.cumulativeCommittedAtomic,
                  cumulativeConsumedAtomic: state.cumulativeConsumedAtomic,
                }
              : {}),
            reservationStates: state.reservations.map((item) => item.state),
            entryCount: state.entries.length,
          });
          break;
        }
        default:
          throw new Error(`Unknown freeze operation ${String(operation.action)}`);
      }
    } catch (error) {
      if (!isTx402Error(error)) throw error;
      outcomes.push({ outcome: "error", errorCode: error.code });
    }
  }
  expect(outcomes).toEqual(arm);
});

registerHandler("recipient-pin.behavior", async (vector: ConformanceVector) => {
  const input = vector.input as { operations: Record<string, unknown>[] };
  const expected = vector.expected as { outcomes: unknown[] };
  const store = new MemorySpendStore();
  const outcomes: Record<string, unknown>[] = [];
  for (const operation of input.operations) {
    try {
      switch (operation.action) {
        case "set-recipient-pins": {
          await store.setRecipientPins(
            operation.scope as string,
            operation.network as string,
            operation.recipients as string[],
            operation.nowEpochMs as number,
          );
          outcomes.push({ outcome: "pins-set" });
          break;
        }
        case "set-tofu-enabled": {
          await store.setTofuEnabled(
            operation.scope as string,
            operation.enabled as boolean,
            operation.nowEpochMs as number,
          );
          outcomes.push({ outcome: "tofu-set" });
          break;
        }
        case "set-recipient-assertion-required": {
          await store.setRecipientAssertionRequired(
            operation.scope as string,
            operation.required as boolean,
            operation.nowEpochMs as number,
          );
          outcomes.push({ outcome: "assertion-set" });
          break;
        }
        case "reserve": {
          // The authoritative assert/claim (SPEC §3.4 step 3): the recipient fields are
          // asserted against the store's administered set in the same atom as the budget.
          const { recipientPinEstablished } = await store.reserve(operation as never);
          outcomes.push({ outcome: "reserved", pinEstablished: recipientPinEstablished });
          break;
        }
        case "snapshot-pins": {
          const recipients = await store.getRecipientPins(
            operation.scope as string,
            operation.network as string,
          );
          outcomes.push({ outcome: "pins", recipients: [...recipients] });
          break;
        }
        default:
          throw new Error(`Unknown recipient-pin operation ${String(operation.action)}`);
      }
    } catch (error) {
      if (!isTx402Error(error)) throw error;
      // Surface the RP-8 conditional details verbatim: `reason` always, and
      // `network`/`presentedRecipient`/`expectedRecipients` only when the error carries them
      // (present for not-allowlisted/pin-mismatch, absent for assertion-required — SPEC §6.5).
      const details = error.details as Record<string, unknown>;
      outcomes.push({
        outcome: "error",
        errorCode: error.code,
        ...(details.reason === undefined ? {} : { reason: details.reason }),
        ...(details.network === undefined ? {} : { network: details.network }),
        ...(details.presentedRecipient === undefined
          ? {}
          : { presentedRecipient: details.presentedRecipient }),
        ...(details.expectedRecipients === undefined
          ? {}
          : { expectedRecipients: details.expectedRecipients }),
      });
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
