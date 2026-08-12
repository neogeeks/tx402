/**
 * `Tx402SpendStoreDO` against a LOCAL Cloudflare Workers runtime (workerd via
 * `@cloudflare/vitest-pool-workers` — SPEC §12.3/§12.4, ADR-023 — tests that RUN the behaviour). No
 * Cloudflare account: the DO + its SQLite storage run entirely in the local runtime (O2/O8). Runs
 * via `vitest.durable-object.config.ts`, not the default node config (which EXCLUDES this file).
 *
 * The whole `checkDurableSpendStore` (the S7b harness — plane separation, skew, locator, cumulative,
 * exposure, true-parallel atomicity, freeze incl. the capability-parameterized global arm, pins,
 * administered limits, and restart via the eviction hook) runs on BOTH topologies:
 *
 *  - **id-per-scope** (`SPEND_DO`, `idFromName(scope)`) declares `atomicGlobalFreeze:false`, so the
 *    freeze check's INCAPABLE arm runs: `freeze("*")` → `global-freeze-unsupported`.
 *  - **single-coordinator** (`COORDINATOR_DO`, one fixed id) declares `atomicGlobalFreeze:true`, so
 *    the CAPABLE arm runs: `freeze("*")` blocks a distinct scope atomically.
 *
 * Plus DO-specific properties: the admin token is verified INSIDE the DO (a wrong/absent token
 * cannot mutate admin state), a reserve whose DO is unreachable is fail-closed (`TransportError`,
 * no signature), and a local reserve-throughput baseline (a real deployed-coordinator acceptance is
 * S14/S15, NOT claimed here).
 */

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { TransportError } from "../src/core/errors.js";
import {
  checkDurableSpendStore,
  checkSpendStore,
  type DurableSpendStoreHarness,
} from "../src/core/spend-store-contract.js";
import {
  DurableObjectSpendStore,
  durableObjectSpendStore,
  type DurableObjectLocator,
} from "../src/durable-object/index.js";
import type { Tx402SpendStoreDOStub } from "../src/durable-object/index.js";

declare module "cloudflare:test" {
  interface ProvidedEnv {
    SPEND_DO: DurableObjectNamespace;
    COORDINATOR_DO: DurableObjectNamespace;
    TX402_DO_ADMIN_SECRET: string;
    TX402_DO_TEST_MODE: string;
  }
}

const SECRET = env.TX402_DO_ADMIN_SECRET;
const ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const FP = `sha256:${"0".repeat(64)}`;
const NOW = 1_800_000_000_000;
const TIMEOUT = 60_000;
// The scopes the contract harness touches (spend-store-contract.ts SCOPE/OTHER_SCOPE). In the
// id-per-scope topology each is its own DO, so reset/setBackendClock must reach both.
const CONTRACT_SCOPES = ["merchant.example", "other.example"];

// id-per-scope: each scope routes to its own DO.
function spendStub(scope: string): Tx402SpendStoreDOStub {
  return env.SPEND_DO.get(
    env.SPEND_DO.idFromName(scope),
  ) as unknown as Tx402SpendStoreDOStub;
}
// single-coordinator: every scope routes to one DO, so a "*" freeze shares the reserve's domain.
const COORDINATOR_ID = "tx402-coordinator";
function coordinatorStub(): Tx402SpendStoreDOStub {
  return env.COORDINATOR_DO.get(
    env.COORDINATOR_DO.idFromName(COORDINATOR_ID),
  ) as unknown as Tx402SpendStoreDOStub;
}
const coordinatorLocate: DurableObjectLocator = () => coordinatorStub();

const idPerScope: DurableSpendStoreHarness = {
  connectData: () =>
    durableObjectSpendStore({ locate: spendStub, atomicGlobalFreeze: false }),
  connectAdmin: () =>
    new DurableObjectSpendStore({
      locate: spendStub,
      atomicGlobalFreeze: false,
      adminToken: SECRET,
    }),
  connectAdminWithDataCredential: () =>
    new DurableObjectSpendStore({ locate: spendStub, atomicGlobalFreeze: false }),
  reset: async () => {
    for (const scope of CONTRACT_SCOPES) await spendStub(scope).reset();
  },
  setBackendClock: async (nowEpochMs) => {
    for (const scope of CONTRACT_SCOPES) await spendStub(scope).setBackendClock(nowEpochMs);
  },
  // The DO analog of the Redis AOF restart: evict the primary scope's instance; its SQLite persists.
  restart: async () => {
    await spendStub("merchant.example")
      .__evict()
      .catch(() => undefined);
  },
};

const coordinator: DurableSpendStoreHarness = {
  connectData: () =>
    durableObjectSpendStore({ locate: coordinatorLocate, atomicGlobalFreeze: true }),
  connectAdmin: () =>
    new DurableObjectSpendStore({
      locate: coordinatorLocate,
      atomicGlobalFreeze: true,
      adminToken: SECRET,
    }),
  connectAdminWithDataCredential: () =>
    new DurableObjectSpendStore({ locate: coordinatorLocate, atomicGlobalFreeze: true }),
  reset: async () => {
    await coordinatorStub().reset();
  },
  setBackendClock: async (nowEpochMs) => {
    await coordinatorStub().setBackendClock(nowEpochMs);
  },
  restart: async () => {
    await coordinatorStub()
      .__evict()
      .catch(() => undefined);
  },
};

describe("Tx402SpendStoreDO (local Workers runtime, SPEC §12.3/§12.4)", () => {
  it(
    "passes the single-plane contract twin (checkSpendStore)",
    async () => {
      let counter = 0;
      await checkSpendStore(() => {
        // Each factory call gets a FRESH, empty DO id (checkSpendStore needs independent stores).
        const id = `contract-${counter++}`;
        return durableObjectSpendStore({
          locate: () =>
            env.SPEND_DO.get(
              env.SPEND_DO.idFromName(id),
            ) as unknown as Tx402SpendStoreDOStub,
          atomicGlobalFreeze: false,
        });
      });
    },
    TIMEOUT,
  );

  it(
    "passes the whole durable harness on id-per-scope (atomicGlobalFreeze:false → incapable global-freeze arm)",
    async () => {
      await checkDurableSpendStore(idPerScope);
    },
    TIMEOUT,
  );

  it(
    "passes the whole durable harness on single-coordinator (atomicGlobalFreeze:true → capable global-freeze arm)",
    async () => {
      await checkDurableSpendStore(coordinator);
    },
    TIMEOUT,
  );

  it(
    "verifies the admin token inside the DO — a wrong token (any length) or absent token cannot mutate admin state (O62)",
    async () => {
      await idPerScope.reset();
      const scope = "merchant.example";
      // A wrong token of a DIFFERENT length than the secret.
      const wrong = new DurableObjectSpendStore({
        locate: spendStub,
        atomicGlobalFreeze: false,
        adminToken: "not-the-secret",
      });
      // O62: a wrong token of the SAME length as the secret (differs only in the final char). This
      // exercises the content path of the DO's length-folding constant-time compare — the pre-O62
      // early-return-on-length form never reached the loop for a mismatched-length token. A
      // same-length wrong token must be denied identically to a different-length one.
      const sameLengthWrongToken = `${SECRET.slice(0, -1)}${SECRET.endsWith("x") ? "y" : "x"}`;
      expect(sameLengthWrongToken).toHaveLength(SECRET.length);
      expect(sameLengthWrongToken).not.toBe(SECRET);
      const sameLengthWrong = new DurableObjectSpendStore({
        locate: spendStub,
        atomicGlobalFreeze: false,
        adminToken: sameLengthWrongToken,
      });
      const none = new DurableObjectSpendStore({
        locate: spendStub,
        atomicGlobalFreeze: false,
      });
      for (const bad of [wrong, sameLengthWrong, none]) {
        await expect(bad.freeze(scope)).rejects.toMatchObject({
          details: { reason: "admin-credential-required" },
        });
        await expect(
          bad.setRecipientPins(scope, "eip155:8453", ["0x0"]),
        ).rejects.toMatchObject({
          details: { reason: "admin-credential-required" },
        });
        await expect(
          bad.setBudgetLimits(scope, ASSET, { maxPerHourAtomic: "1" }),
        ).rejects.toMatchObject({ details: { reason: "admin-credential-required" } });
      }
      // A denied freeze left the scope unfrozen; the correct secret then freezes it.
      const data = durableObjectSpendStore({
        locate: spendStub,
        atomicGlobalFreeze: false,
      });
      expect(await data.isFrozen(scope)).toBe(false);
      const admin = new DurableObjectSpendStore({
        locate: spendStub,
        atomicGlobalFreeze: false,
        adminToken: SECRET,
      });
      await admin.freeze(scope);
      expect(await data.isFrozen(scope)).toBe(true);
      await admin.unfreeze(scope);
    },
    TIMEOUT,
  );

  it(
    "U13 — the concrete DO admin methods accept the trailing nowEpochMs an operator would pass",
    async () => {
      // Mirrors the RedisSpendStore U13 guard (ux-regressions-s14i.test.ts) on the DO's concrete
      // type: each admin method carries the optional trailing `_nowEpochMs?`, so a DO-Worker
      // operator can call it with `Date.now()` and it type-checks (under the DO tsconfig) AND runs.
      // Dropping the optional param would make each call below "Expected N, got N+1" — the guard.
      await idPerScope.reset();
      const scope = "u13.example";
      const admin = new DurableObjectSpendStore({
        locate: spendStub,
        atomicGlobalFreeze: false,
        adminToken: SECRET,
      });
      const now = Date.now();
      await admin.freeze(scope, now);
      await admin.unfreeze(scope, now);
      await admin.setBudgetLimits(scope, ASSET, { maxPerHourAtomic: "5000000" }, now);
      await admin.setRecipientPins(scope, "eip155:8453", ["0xabc"], now);
      await admin.setTofuEnabled(scope, true, now);
      await admin.setRecipientAssertionRequired(scope, true, now);
      await admin.resetCumulative(scope, ASSET, now);
    },
    TIMEOUT,
  );

  it("is fail-closed when the DO is unreachable — reserve raises a retryable TransportError, no signature", async () => {
    const unreachable = durableObjectSpendStore({
      locate: () =>
        ({
          reserve: () => Promise.reject(new Error("DO unreachable / overloaded")),
        }) as unknown as Tx402SpendStoreDOStub,
      atomicGlobalFreeze: false,
    });
    let error: unknown;
    try {
      await unreachable.reserve({
        reservationId: "ov-1",
        requestId: "ov-1",
        policyScope: "merchant.example",
        requestFingerprint: FP,
        assetId: ASSET,
        amountAtomic: "1",
        maxPerHourAtomic: "100",
        nowEpochMs: NOW,
      });
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(TransportError);
    expect((error as TransportError).retryable).toBe(true);
    expect((error as TransportError).details.causeCategory).toBe(
      "durable-object-unreachable",
    );
  });

  it(
    "records a local reserve-throughput baseline on the coordinator (a deployed acceptance is S14/S15)",
    async () => {
      await coordinator.reset();
      await coordinator.setBackendClock(NOW);
      const store = durableObjectSpendStore({
        locate: coordinatorLocate,
        atomicGlobalFreeze: true,
      });
      const attempts = 100;
      const start = Date.now();
      for (let index = 0; index < attempts; index += 1) {
        await store.reserve({
          reservationId: `tp-${index}`,
          requestId: `tp-${index}`,
          policyScope: "merchant.example",
          requestFingerprint: FP,
          assetId: ASSET,
          amountAtomic: "1",
          maxPerHourAtomic: "100000000",
          nowEpochMs: NOW,
        });
      }
      const elapsedMs = Math.max(1, Date.now() - start);
      const perSecond = (attempts / elapsedMs) * 1000;
      // A LOCAL regression floor only — deliberately conservative to avoid CI flakiness. The real
      // deployed-coordinator throughput acceptance threshold is validated at S14/S15 (SPEC §12.3),
      // never asserted here against the local runtime.
      console.log(
        `tx402 DO coordinator local baseline: ${attempts} reserves in ${elapsedMs}ms (${perSecond.toFixed(0)}/s)`,
      );
      expect(perSecond).toBeGreaterThan(10);
    },
    TIMEOUT,
  );
});
