import { describe, expect, it } from "vitest";

import { MemorySpendStore, type ReserveSpendResult } from "../src/core/ledger.js";
import {
  SpendStoreContractError,
  checkSpendStore,
} from "../src/core/spend-store-contract.js";

describe("checkSpendStore (the TS contract twin, SPEC §3.6)", () => {
  it("passes for the built-in MemorySpendStore v2", async () => {
    await checkSpendStore(() => new MemorySpendStore());
  });

  it("catches a store that is not atomic under contention", async () => {
    // The naive adapter: read the total, decide, THEN insert, with a turn of the event loop
    // in between. It passes every other rule and loses money only here.
    class RaceyStore extends MemorySpendStore {
      override async reserve(
        input: Parameters<MemorySpendStore["reserve"]>[0],
      ): Promise<ReserveSpendResult> {
        const state = await this.getBudgetState({
          policyScope: input.policyScope,
          assetId: input.assetId,
          nowEpochMs: input.nowEpochMs,
        });
        const used = BigInt(state.committedAtomic) + BigInt(state.reservedAtomic);
        await Promise.resolve(); // the window a real adapter leaves open
        if (used + BigInt(input.amountAtomic) > BigInt(input.maxPerHourAtomic)) {
          return super.reserve(input); // let the parent raise BudgetExceededError
        }
        // Skip the cap on the insert so only the racey check above decides.
        return super.reserve({ ...input, maxPerHourAtomic: "1000000000" });
      }
    }
    await expect(checkSpendStore(() => new RaceyStore())).rejects.toBeInstanceOf(
      SpendStoreContractError,
    );
  });

  it("rejects a malformed atomic amount before insert (O58 TS↔Py parity)", async () => {
    // The reference store guards `amountAtomic` with ^[1-9][0-9]*$ and throws TypeError BEFORE the
    // reservation is written. The Python twin now matches (bare int() used to accept these — and a
    // negative even LOWERED the cap-consumption sum). Unreachable on the validated payment path, but
    // the reference/default store must not be the permissive one at its API boundary.
    const ASSET = "eip155:8453/erc20:0x0000000000000000000000000000000000000001";
    const SCOPE = "o58.example";
    const NOW = 1_800_000_000_000;
    for (const bad of ["-5", "0", "007", " 5 ", "5.0", ""]) {
      const store = new MemorySpendStore();
      await expect(
        store.reserve({
          reservationId: "o58",
          requestId: "o58",
          policyScope: SCOPE,
          requestFingerprint: `sha256:${"0".repeat(64)}`,
          assetId: ASSET,
          amountAtomic: bad,
          maxPerHourAtomic: "1000",
          nowEpochMs: NOW,
        }),
      ).rejects.toBeInstanceOf(TypeError);
      const state = await store.getBudgetState({
        policyScope: SCOPE,
        assetId: ASSET,
        nowEpochMs: NOW,
      });
      expect(state.reservedAtomic).toBe("0"); // the guard fired before any insert
    }
  });

  it("catches a store missing a v2 data-plane method", async () => {
    const lookalike = {
      kind: "lookalike",
      capabilities: { atomicGlobalFreeze: true },
      reserve: () => Promise.reject(new Error("unused")),
      commit: () => Promise.reject(new Error("unused")),
      release: () => Promise.reject(new Error("unused")),
      getBudgetState: () => Promise.reject(new Error("unused")),
      // expose / listExposed / isFrozen deliberately absent
    };
    await expect(checkSpendStore(() => lookalike as never)).rejects.toBeInstanceOf(
      SpendStoreContractError,
    );
  });
});
