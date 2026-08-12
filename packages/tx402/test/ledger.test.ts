import { describe, expect, it } from "vitest";

import {
  MemorySpendStore,
  RESERVATION_TTL_MS,
  ROLLING_WINDOW_MS,
  type ReservationRef,
} from "../src/core/ledger.js";

const NOW = 1_785_715_200_000;
const ASSET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const FINGERPRINT = `sha256:${"1".repeat(64)}`;

function reservationId(index: number): string {
  return `00000000-0000-7000-8000-${String(index).padStart(12, "0")}`;
}

function ref(index: number, overrides: Partial<ReservationRef> = {}): ReservationRef {
  return {
    reservationId: reservationId(index),
    policyScope: "client-1",
    assetId: ASSET,
    ...overrides,
  };
}

// Unwraps the ReserveSpendResult (SPEC §3.2) so the existing behavioural assertions read the
// reservation directly. `recipientPinEstablished` is asserted in its own v2 tests below.
async function reserve(
  store: MemorySpendStore,
  index: number,
  overrides: Partial<Parameters<MemorySpendStore["reserve"]>[0]> = {},
) {
  const result = await store.reserve({
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
  return result.reservation;
}

function snapshot(store: MemorySpendStore, nowEpochMs = NOW) {
  return store.getBudgetState({ policyScope: "client-1", assetId: ASSET, nowEpochMs });
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
    await expect(snapshot(store)).resolves.toMatchObject({
      committedAtomic: "0",
      reservedAtomic: "6",
    });
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
    const state = await snapshot(store, NOW + RESERVATION_TTL_MS);
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
      policyScope: "client-1",
      assetId: ASSET,
      committedAtEpochMs: NOW + 10,
      settlementId: "settlement-1",
    });
    const replay = await store.commit({
      reservationId: reservationId(1),
      policyScope: "client-1",
      assetId: ASSET,
      committedAtEpochMs: NOW + 20,
      settlementId: "different",
    });
    expect(replay).toBe(first);
    expect(await store.release(ref(1), NOW + 30)).toHaveProperty("state", "committed");

    await reserve(store, 2);
    expect(await store.release(ref(2), NOW + 30)).toHaveProperty("state", "released");
    const state = await snapshot(store, NOW + 30);
    expect(state).toMatchObject({ committedAtomic: "2", reservedAtomic: "0" });
    expect(state.entries).toHaveLength(1);
  });

  it("includes the exact rolling-hour boundary, then prunes committed spend", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.commit({
      reservationId: reservationId(1),
      policyScope: "client-1",
      assetId: ASSET,
      committedAtEpochMs: NOW,
    });
    expect(await snapshot(store, NOW + ROLLING_WINDOW_MS)).toMatchObject({
      committedAtomic: "2",
    });
    expect(await snapshot(store, NOW + ROLLING_WINDOW_MS + 1)).toMatchObject({
      committedAtomic: "0",
      entries: [],
    });
  });

  it("retains scope metadata while a late-committed exposed entry remains in the window", async () => {
    // In v2 a late commit only happens through the exposure fence: expose clears the TTL, and
    // the maybe-settled payment is resolved to committed later. Window membership is by
    // committedAtEpochMs, so the entry is still counted just inside the boundary.
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.expose(ref(1), NOW + 5);
    await store.commit({
      reservationId: reservationId(1),
      policyScope: "client-1",
      assetId: ASSET,
      committedAtEpochMs: NOW + ROLLING_WINDOW_MS - 1,
    });
    expect(await snapshot(store, NOW + ROLLING_WINDOW_MS + 1)).toMatchObject({
      committedAtomic: "2",
      entries: [{ amountAtomic: "2" }],
    });
  });

  it("partitions totals by policy scope and asset", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await reserve(store, 2, { policyScope: "client-2", amountAtomic: "6" });
    await reserve(store, 3, {
      assetId: "eip155:8453/erc20:0x0000000000000000000000000000000000000001",
      amountAtomic: "6",
    });
    expect(await snapshot(store)).toMatchObject({ reservedAtomic: "2" });
  });

  it("refuses to commit a reservation that has expired (SPEC §3.4 named break)", async () => {
    // v0.1 permitted this. v0.2 refuses it: the pre-transmission fence means a legitimate
    // payment is `exposed` before it settles, so an `expired` reservation can never
    // legitimately commit, and permitting it would breach the cumulative cap.
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await snapshot(store, NOW + RESERVATION_TTL_MS); // maintain: reservation 1 -> expired
    await expect(
      store.commit({
        reservationId: reservationId(1),
        policyScope: "client-1",
        assetId: ASSET,
        committedAtEpochMs: NOW + RESERVATION_TTL_MS + 1,
      }),
    ).rejects.toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { configPath: "reservation.lifecycle", reason: "expired-cannot-commit" },
    });
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
      const shot = await snapshot(store);
      expect(BigInt(shot.reservedAtomic)).toBe(admitted);
      expect(admitted).toBeLessThanOrEqual(cap);
    }
  });
});

describe("MemorySpendStore v2 — exposure, cumulative counters, freeze, pins (SPEC §3)", () => {
  it("declares the atomicGlobalFreeze capability (single process)", () => {
    expect(new MemorySpendStore().capabilities.atomicGlobalFreeze).toBe(true);
  });

  it("reserve returns a result with recipientPinEstablished false (pins are S6)", async () => {
    const store = new MemorySpendStore();
    const result = await store.reserve({
      reservationId: reservationId(1),
      requestId: "request-1",
      policyScope: "client-1",
      requestFingerprint: FINGERPRINT,
      assetId: ASSET,
      amountAtomic: "2",
      maxPerHourAtomic: "6",
      nowEpochMs: NOW,
    });
    expect(result.recipientPinEstablished).toBe(false);
    expect(result.reservation.state).toBe("reserved");
    // A replay returns the same reservation and never re-claims a pin.
    const replay = await store.reserve({
      reservationId: reservationId(1),
      requestId: "request-1",
      policyScope: "client-1",
      requestFingerprint: FINGERPRINT,
      assetId: ASSET,
      amountAtomic: "2",
      maxPerHourAtomic: "6",
      nowEpochMs: NOW,
    });
    expect(replay.recipientPinEstablished).toBe(false);
    expect(replay.reservation.reservationId).toBe(reservationId(1));
  });

  it("exposes a reserved reservation, keeps it counting past its TTL, and lists it", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    const exposed = await store.expose(ref(1), NOW + 5);
    expect(exposed.state).toBe("exposed");

    // Exposed money is counted through exposedAtomic, not reservedAtomic, and folds into the
    // lifetime cumulative-consumed figure.
    const now = await snapshot(store);
    expect(now).toMatchObject({
      reservedAtomic: "0",
      exposedAtomic: "2",
      cumulativeCommittedAtomic: "0",
      cumulativeConsumedAtomic: "2",
    });

    // Non-expiring: still exposed and still counted a full hour later.
    const later = await snapshot(store, NOW + ROLLING_WINDOW_MS + 1);
    expect(later.exposedAtomic).toBe("2");
    const listed = await store.listExposed({
      policyScope: "client-1",
      assetId: ASSET,
      nowEpochMs: NOW + ROLLING_WINDOW_MS + 1,
    });
    expect(listed.map((item) => item.reservationId)).toEqual([reservationId(1)]);
  });

  it("expose is idempotent and the exposed total matches what listExposed reports", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1, { amountAtomic: "2" });
    await reserve(store, 2, { amountAtomic: "3", maxPerHourAtomic: "6" });
    await store.expose(ref(1), NOW);
    const replay = await store.expose(ref(1), NOW); // replay, no double-count
    expect(replay.state).toBe("exposed");
    await store.expose(ref(2), NOW);

    const state = await snapshot(store);
    const listed = await store.listExposed({
      policyScope: "client-1",
      assetId: ASSET,
      nowEpochMs: NOW,
    });
    const listedSum = listed.reduce((sum, item) => sum + BigInt(item.amountAtomic), 0n);
    expect(BigInt(state.exposedAtomic ?? "0")).toBe(listedSum);
    expect(state.exposedAtomic).toBe("5");
  });

  it("exposed reservations still count against the per-hour cap", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1, { amountAtomic: "2" }); // cap 6
    await store.expose(ref(1), NOW);
    await reserve(store, 2, { amountAtomic: "2" });
    await reserve(store, 3, { amountAtomic: "2" }); // 2 exposed + 2 + 2 = 6, at cap
    await expect(reserve(store, 4, { amountAtomic: "2" })).rejects.toHaveProperty(
      "code",
      "TX402_POLICY_BUDGET",
    );
  });

  it("commit(exposed) moves the amount from exposed to cumulative committed", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.expose(ref(1), NOW);
    await store.commit({
      reservationId: reservationId(1),
      policyScope: "client-1",
      assetId: ASSET,
      committedAtEpochMs: NOW + 10,
      settlementId: "s1",
    });
    expect(await snapshot(store, NOW + 10)).toMatchObject({
      exposedAtomic: "0",
      cumulativeCommittedAtomic: "2",
      cumulativeConsumedAtomic: "2",
      committedAtomic: "2",
    });
  });

  it("release(exposed) frees the exposed budget", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.expose(ref(1), NOW);
    const released = await store.release(ref(1), NOW + 10);
    expect(released.state).toBe("released");
    expect(await snapshot(store, NOW + 10)).toMatchObject({
      exposedAtomic: "0",
      cumulativeConsumedAtomic: "0",
    });
  });

  it("resolveExposed(committed) is exactly commit(exposed)", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.expose(ref(1), NOW);
    await store.resolveExposed(ref(1), "committed", NOW + 10);
    expect(await snapshot(store, NOW + 10)).toMatchObject({
      exposedAtomic: "0",
      cumulativeCommittedAtomic: "2",
    });
  });

  it("resolveExposed on a still-reserved record is reservation-not-exposed", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await expect(store.resolveExposed(ref(1), "committed", NOW)).rejects.toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { configPath: "reservation.lifecycle", reason: "reservation-not-exposed" },
    });
  });

  it("expose on a committed record is reservation-already-terminal", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.commit({
      reservationId: reservationId(1),
      policyScope: "client-1",
      assetId: ASSET,
      committedAtEpochMs: NOW,
    });
    await expect(store.expose(ref(1), NOW)).rejects.toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: {
        configPath: "reservation.lifecycle",
        reason: "reservation-already-terminal",
      },
    });
  });

  it("commit on a released record is released-cannot-commit", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.release(ref(1), NOW);
    await expect(
      store.commit({
        reservationId: reservationId(1),
        policyScope: "client-1",
        assetId: ASSET,
        committedAtEpochMs: NOW + 10,
      }),
    ).rejects.toMatchObject({
      details: { configPath: "reservation.lifecycle", reason: "released-cannot-commit" },
    });
  });

  it("a ref whose scope names no record is reservation-not-found, identically per op", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    const wrong = ref(1, { policyScope: "someone-else" });
    for (const op of [
      () => store.release(wrong, NOW),
      () => store.expose(wrong, NOW),
      () => store.resolveExposed(wrong, "committed", NOW),
      () =>
        store.commit({
          reservationId: wrong.reservationId,
          policyScope: wrong.policyScope,
          assetId: wrong.assetId,
          committedAtEpochMs: NOW,
        }),
    ]) {
      await expect(op()).rejects.toMatchObject({
        code: "TX402_CONFIG_INVALID",
        details: { configPath: "reservationRef", reason: "reservation-not-found" },
      });
    }
  });

  it("reports and reconciles administered limits and freeze state", async () => {
    const store = new MemorySpendStore();
    await store.setBudgetLimits("client-1", ASSET, {
      maxPerHourAtomic: "100",
      maxTotalAtomic: "1000",
    });
    await reserve(store, 1); // 2 reserved
    const state = await snapshot(store);
    expect(state).toMatchObject({
      perHourLimitAtomic: "100",
      cumulativeLimitAtomic: "1000",
      availablePerHourAtomic: "98",
      availableCumulativeAtomic: "998",
      frozen: false,
    });
    expect(await store.getBudgetLimits("client-1", ASSET)).toMatchObject({
      maxPerHourAtomic: "100",
      maxTotalAtomic: "1000",
    });

    await store.freeze("client-1", NOW);
    expect(await store.isFrozen("client-1")).toBe(true);
    expect((await snapshot(store)).frozen).toBe(true);
    // A global freeze covers a distinct scope (single-process atomic-global-freeze).
    await store.unfreeze("client-1", NOW);
    await store.freeze("*", NOW);
    expect(await store.isFrozen("client-1")).toBe(true);
  });

  it("stores admin recipient pins and policy flags with their source", async () => {
    const store = new MemorySpendStore();
    expect(await store.getRecipientPolicy("client-1")).toEqual({
      tofuEnabled: false,
      recipientAssertionRequired: false,
    });
    await store.setRecipientPins("client-1", "eip155:8453", ["0xabc"], NOW);
    expect(await store.getRecipientPins("client-1", "eip155:8453")).toEqual(["0xabc"]);
    await store.setTofuEnabled("client-1", true, NOW);
    await store.setRecipientAssertionRequired("client-1", true, NOW);
    expect(await store.getRecipientPolicy("client-1")).toEqual({
      tofuEnabled: true,
      recipientAssertionRequired: true,
    });
  });

  it("fails closed on an empty recipient when assertion is required (O56 parity)", async () => {
    // The reference/default store must NOT be the permissive one on a safety gate: a
    // defined-but-empty recipientCanonical is NOT a presented recipient, so an assertion-required
    // scope refuses it — matching the durable Redis (`recipientCanonical ~= ''`) and DO stores.
    const store = new MemorySpendStore();
    await store.setRecipientAssertionRequired("client-1", true, NOW);
    await expect(
      reserve(store, 1, { recipientNetwork: "eip155:8453", recipientCanonical: "" }),
    ).rejects.toMatchObject({
      code: "TX402_RECIPIENT_UNPINNED",
      details: { reason: "assertion-required" },
    });
    // And nothing was reserved (the refusal is pre-insert).
    expect((await snapshot(store)).reservedAtomic).toBe("0");
  });

  it("resetCumulative clears the lifetime committed figure", async () => {
    const store = new MemorySpendStore();
    await reserve(store, 1);
    await store.commit({
      reservationId: reservationId(1),
      policyScope: "client-1",
      assetId: ASSET,
      committedAtEpochMs: NOW,
    });
    expect((await snapshot(store, NOW)).cumulativeCommittedAtomic).toBe("2");
    await store.resetCumulative("client-1", ASSET, NOW);
    expect((await snapshot(store, NOW)).cumulativeCommittedAtomic).toBe("0");
  });
});

// The cumulative-cap conformance vectors drive the caller-cap path cross-language; the
// administered-limit precedence (SPEC §4.3) is not expressible in a ledger vector — the vector
// op set has no admin verbs — so it is proven here against MemorySpendStore directly (ADR-023).
describe("MemorySpendStore v2 — cumulative cap + administered limits (SPEC §4, §3.4 steps 4/6)", () => {
  async function commit(store: MemorySpendStore, index: number): Promise<void> {
    await store.commit({
      reservationId: reservationId(index),
      policyScope: "client-1",
      assetId: ASSET,
      committedAtEpochMs: NOW,
    });
  }

  it("refuses a caller cumulative cap the per-hour cap would admit (capKind cumulative)", async () => {
    const store = new MemorySpendStore();
    // Per-hour has headroom (100); the cumulative cap (10) is the only dimension that binds.
    await reserve(store, 1, {
      amountAtomic: "6",
      maxPerHourAtomic: "100",
      maxTotalAtomic: "10",
    });
    await commit(store, 1);
    await expect(
      reserve(store, 2, {
        amountAtomic: "6",
        maxPerHourAtomic: "100",
        maxTotalAtomic: "10",
      }),
    ).rejects.toMatchObject({
      code: "TX402_POLICY_BUDGET",
      details: { capKind: "cumulative", capAtomic: "10", committedAtomic: "6" },
    });
  });

  it("binds the administered cumulative cap even with no caller cap (§4.3)", async () => {
    const store = new MemorySpendStore();
    await store.setBudgetLimits("client-1", ASSET, { maxTotalAtomic: "10" });
    await reserve(store, 1, { amountAtomic: "6", maxPerHourAtomic: "100" }); // no maxTotal
    await commit(store, 1);
    await expect(
      reserve(store, 2, { amountAtomic: "6", maxPerHourAtomic: "100" }),
    ).rejects.toMatchObject({
      code: "TX402_POLICY_BUDGET",
      details: { capKind: "cumulative", capAtomic: "10" },
    });
  });

  it("rejects a caller cumulative cap above the administered one (config, not budget)", async () => {
    const store = new MemorySpendStore();
    await store.setBudgetLimits("client-1", ASSET, { maxTotalAtomic: "10" });
    await expect(
      reserve(store, 1, {
        amountAtomic: "1",
        maxPerHourAtomic: "100",
        maxTotalAtomic: "20",
      }),
    ).rejects.toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { reason: "cap-exceeds-administered", configPath: "policy.maxTotal" },
    });
  });

  it("rejects a caller per-hour cap above the administered one (config, not budget)", async () => {
    const store = new MemorySpendStore();
    await store.setBudgetLimits("client-1", ASSET, { maxPerHourAtomic: "5" });
    await expect(
      reserve(store, 1, { amountAtomic: "1", maxPerHourAtomic: "10" }),
    ).rejects.toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { reason: "cap-exceeds-administered", configPath: "policy.maxPerHour" },
    });
  });

  it("honours a stricter caller per-hour cap via the min", async () => {
    const store = new MemorySpendStore();
    await store.setBudgetLimits("client-1", ASSET, { maxPerHourAtomic: "100" });
    // The caller cap (5) is below the administered one (100); min = 5, so 6 is refused.
    await expect(
      reserve(store, 1, { amountAtomic: "6", maxPerHourAtomic: "5" }),
    ).rejects.toMatchObject({
      code: "TX402_POLICY_BUDGET",
      details: { capKind: "per-hour", capAtomic: "5" },
    });
  });

  it("lowered-cap precedence: old caller cap → config, re-fetched cap → budget (§4.3)", async () => {
    const store = new MemorySpendStore();
    await store.setBudgetLimits("client-1", ASSET, { maxTotalAtomic: "10" });
    await reserve(store, 1, {
      amountAtomic: "8",
      maxPerHourAtomic: "100",
      maxTotalAtomic: "10",
    });
    await commit(store, 1); // consume 8 under the original cap
    // Lower the administered cap below current consumption — permitted, no rollback (§4.3).
    await store.setBudgetLimits("client-1", ASSET, { maxTotalAtomic: "5" });
    // A worker still presenting its old, higher caller cap trips step 4 (configuration).
    await expect(
      reserve(store, 2, {
        amountAtomic: "1",
        maxPerHourAtomic: "100",
        maxTotalAtomic: "10",
      }),
    ).rejects.toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { reason: "cap-exceeds-administered" },
    });
    // A worker whose caller cap is now ≤ the administered cap gets a budget refusal (8 > 5).
    await expect(
      reserve(store, 3, {
        amountAtomic: "1",
        maxPerHourAtomic: "100",
        maxTotalAtomic: "5",
      }),
    ).rejects.toMatchObject({
      code: "TX402_POLICY_BUDGET",
      details: { capKind: "cumulative", capAtomic: "5" },
    });
  });

  it("never binds when neither a caller nor an administered cumulative cap is set", async () => {
    const store = new MemorySpendStore();
    const reservation = await reserve(store, 1, {
      amountAtomic: "1000000",
      maxPerHourAtomic: "1000000",
    });
    expect(reservation.state).toBe("reserved");
  });
});
