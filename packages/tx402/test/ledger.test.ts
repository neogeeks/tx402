import { describe, expect, it } from "vitest";

import {
  MemorySpendStore,
  RESERVATION_TTL_MS,
  ROLLING_WINDOW_MS,
} from "../src/core/ledger.js";

const NOW = 1_785_715_200_000;
const ASSET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const FINGERPRINT = `sha256:${"1".repeat(64)}`;

function reservationId(index: number): string {
  return `00000000-0000-7000-8000-${String(index).padStart(12, "0")}`;
}

function reserve(
  store: MemorySpendStore,
  index: number,
  overrides: Partial<Parameters<MemorySpendStore["reserve"]>[0]> = {},
) {
  return store.reserve({
    reservationId: reservationId(index),
    requestId: `request-${index}`,
    policyScope: "client-1",
    requestFingerprint: FINGERPRINT,
    assetId: ASSET,
    amountAtomic: "2",
    maxPerHourAtomic: "6",
    nowEpochMs: NOW,
    ...overrides,
  });
}

describe("MemorySpendStore", () => {
  it("T-007 atomically admits exactly the reservations within the cap", async () => {
    const store = new MemorySpendStore();
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, (_, index) => reserve(store, index)),
    );
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(3);
    const rejected = results.filter((result) => result.status === "rejected");
    expect(rejected).toHaveLength(17);
    expect(rejected[0]).toMatchObject({
      reason: { code: "TX402_POLICY_BUDGET", details: { reservedAtomic: "6" } },
    });
    await expect(
      store.getBudgetState({ policyScope: "client-1", assetId: ASSET, nowEpochMs: NOW }),
    ).resolves.toMatchObject({ committedAtomic: "0", reservedAtomic: "6" });
  });

  it("expires at 120 seconds and allows the capacity to be reused", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1, { amountAtomic: "6" });
    await expect(
      reserve(store, 2, { nowEpochMs: NOW + RESERVATION_TTL_MS - 1 }),
    ).rejects.toHaveProperty("code", "TX402_POLICY_BUDGET");
    await expect(
      reserve(store, 2, { nowEpochMs: NOW + RESERVATION_TTL_MS, amountAtomic: "6" }),
    ).resolves.toHaveProperty("state", "reserved");
    const state = await store.getBudgetState({
      policyScope: "client-1",
      assetId: ASSET,
      nowEpochMs: NOW + RESERVATION_TTL_MS,
    });
    expect(state.reservedAtomic).toBe("6");
    expect(
      state.reservations.find((item) => item.reservationId === reservationId(1))?.state,
    ).toBe("expired");
  });

  it("commits idempotently, releases terminal failures, and never releases committed spend", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    const first = await store.commit({
      reservationId: reservationId(1),
      committedAtEpochMs: NOW + 10,
      settlementId: "settlement-1",
    });
    const replay = await store.commit({
      reservationId: reservationId(1),
      committedAtEpochMs: NOW + 20,
      settlementId: "different",
    });
    expect(replay).toBe(first);
    expect(await store.release(reservationId(1), NOW + 30)).toHaveProperty(
      "state",
      "committed",
    );

    await reserve(store, 2);
    expect(await store.release(reservationId(2), NOW + 30)).toHaveProperty(
      "state",
      "released",
    );
    const state = await store.getBudgetState({
      policyScope: "client-1",
      assetId: ASSET,
      nowEpochMs: NOW + 30,
    });
    expect(state).toMatchObject({ committedAtomic: "2", reservedAtomic: "0" });
    expect(state.entries).toHaveLength(1);
  });

  it("includes the exact rolling-hour boundary, then prunes committed spend", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.commit({ reservationId: reservationId(1), committedAtEpochMs: NOW });
    expect(
      await store.getBudgetState({
        policyScope: "client-1",
        assetId: ASSET,
        nowEpochMs: NOW + ROLLING_WINDOW_MS,
      }),
    ).toMatchObject({ committedAtomic: "2" });
    expect(
      await store.getBudgetState({
        policyScope: "client-1",
        assetId: ASSET,
        nowEpochMs: NOW + ROLLING_WINDOW_MS + 1,
      }),
    ).toMatchObject({ committedAtomic: "0", entries: [] });
  });

  it("retains scope metadata while a late-committed entry remains in the window", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.commit({
      reservationId: reservationId(1),
      committedAtEpochMs: NOW + ROLLING_WINDOW_MS - 1,
    });
    expect(
      await store.getBudgetState({
        policyScope: "client-1",
        assetId: ASSET,
        nowEpochMs: NOW + ROLLING_WINDOW_MS + 1,
      }),
    ).toMatchObject({ committedAtomic: "2", entries: [{ amountAtomic: "2" }] });
  });

  it("partitions totals by policy scope and asset", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await reserve(store, 2, { policyScope: "client-2", amountAtomic: "6" });
    await reserve(store, 3, {
      assetId: "eip155:8453/erc20:0x0000000000000000000000000000000000000001",
      amountAtomic: "6",
    });
    expect(
      await store.getBudgetState({
        policyScope: "client-1",
        assetId: ASSET,
        nowEpochMs: NOW,
      }),
    ).toMatchObject({ reservedAtomic: "2" });
  });

  it("can commit late payment evidence after reservation expiry", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.getBudgetState({
      policyScope: "client-1",
      assetId: ASSET,
      nowEpochMs: NOW + RESERVATION_TTL_MS,
    });
    await expect(
      store.commit({
        reservationId: reservationId(1),
        committedAtEpochMs: NOW + RESERVATION_TTL_MS + 1,
      }),
    ).resolves.toHaveProperty("amountAtomic", "2");
  });

  it("property: every admitted randomized reservation preserves the atomic cap invariant", async () => {
    const store = new MemorySpendStore();
    let state = 0x7_402;
    let admitted = 0n;
    const cap = 10_000n;
    for (let index = 100; index < 1_100; index += 1) {
      state = (Math.imul(state, 1_103_515_245) + 12_345) >>> 0;
      const amount = BigInt((state % 97) + 1);
      try {
        await reserve(store, index, {
          amountAtomic: amount.toString(),
          maxPerHourAtomic: cap.toString(),
        });
        admitted += amount;
      } catch (error) {
        expect(error).toHaveProperty("code", "TX402_POLICY_BUDGET");
      }
      const snapshot = await store.getBudgetState({
        policyScope: "client-1",
        assetId: ASSET,
        nowEpochMs: NOW,
      });
      expect(BigInt(snapshot.reservedAtomic)).toBe(admitted);
      expect(admitted).toBeLessThanOrEqual(cap);
    }
  });
});
