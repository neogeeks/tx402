/**
 * A runnable conformance suite for third-party {@link SpendStore} adapters — the TypeScript
 * twin of `tx402.spend_store_contract` (SPEC §3.6). Published from `tx402/spend-store-contract`
 * (off the size-gated core path, like the chain adapters) so an adapter author, who is not a
 * contributor to this repository, can import it.
 *
 * @example
 * ```ts
 * import { checkSpendStore } from "tx402/spend-store-contract";
 *
 * await checkSpendStore(() => new RedisSpendStore({ url: "redis://localhost/15" }));
 * ```
 *
 * `checkSpendStore` rejects with a {@link SpendStoreContractError} on the first violation, its
 * message naming the rule. The single-plane suite exercises what one process can check against
 * a data-plane store: money arithmetic, the rolling window, idempotency, the typed over-cap
 * refusal, scope/asset isolation, the exposure lifecycle, and — with concurrent calls — that
 * reserve is atomic. Cross-machine atomicity, the operator/agent credential split, restart
 * durability, and backend-authoritative time need a durable backend and both planes: that is
 * {@link checkDurableSpendStore} (run against the Redis and DO adapters).
 */

import {
  BudgetExceededError,
  ConfigurationError,
  RecipientUnpinnedError,
  SpendScopeFrozenError,
} from "./errors.js";
import {
  RESERVATION_TTL_MS,
  ROLLING_WINDOW_MS,
  type BudgetLimits,
  type BudgetState,
  type RecipientPinStore,
  type ReservationRef,
  type ReserveSpendResult,
  type SpendReservation,
  type SpendStore,
  type SpendStoreAdmin,
} from "./ledger.js";

/** A fixed instant, so every check is deterministic and never reads a real clock. */
const NOW = 1_800_000_000_000;
const ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
// The EIP-55 CHECKSUMMED form of the SAME erc20 contract as ASSET — the casing the signed manifest
// carries. The store MUST key both on the canonical (lowercased) asset (U16), so a cap/reservation
// under one casing addresses the same ledger as the other.
const ASSET_CHECKSUMMED = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const OTHER_ASSET = "solana:mainnet/spl:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SCOPE = "merchant.example";
const OTHER_SCOPE = "other.example";
const CANON_SCOPE = "canon.example";
const FINGERPRINT = `sha256:${"0".repeat(64)}`;

/** A spend store violated the contract. The message names the rule. */
export class SpendStoreContractError extends Error {
  constructor(rule: string) {
    super(rule);
    this.name = "SpendStoreContractError";
  }
}

function mustHold(condition: boolean, rule: string): void {
  if (!condition) throw new SpendStoreContractError(rule);
}

function ref(reservation: SpendReservation): ReservationRef {
  return {
    reservationId: reservation.reservationId,
    policyScope: reservation.policyScope,
    assetId: reservation.assetId,
  };
}

async function reserve(
  store: SpendStore,
  options: {
    reservationId: string;
    amount: string;
    cap?: string;
    scope?: string;
    asset?: string;
    now?: number;
  },
): Promise<SpendReservation> {
  const result = await store.reserve({
    reservationId: options.reservationId,
    requestId: `contract-${options.reservationId}`,
    policyScope: options.scope ?? SCOPE,
    requestFingerprint: FINGERPRINT,
    assetId: options.asset ?? ASSET,
    amountAtomic: options.amount,
    maxPerHourAtomic: options.cap ?? "1000000",
    nowEpochMs: options.now ?? NOW,
  });
  return result.reservation;
}

async function totals(
  store: SpendStore,
  options: { scope?: string; asset?: string; now?: number } = {},
): Promise<[bigint, bigint]> {
  const state = await store.getBudgetState({
    policyScope: options.scope ?? SCOPE,
    assetId: options.asset ?? ASSET,
    nowEpochMs: options.now ?? NOW,
  });
  return [BigInt(state.committedAtomic), BigInt(state.reservedAtomic)];
}

// eslint-disable-next-line @typescript-eslint/require-await -- shape check is synchronous but shares the async check signature
async function checkShape(makeStore: () => SpendStore): Promise<void> {
  const store = makeStore();
  mustHold(
    typeof store.kind === "string" && store.kind.length > 0,
    "kind must be a non-empty string identifying the store in diagnostics",
  );
  mustHold(
    typeof store.capabilities?.atomicGlobalFreeze === "boolean",
    "capabilities.atomicGlobalFreeze must be a boolean (SPEC §3.1)",
  );
  for (const method of [
    "reserve",
    "commit",
    "release",
    "expose",
    "getBudgetState",
    "listExposed",
    "isFrozen",
  ] as const) {
    mustHold(
      typeof store[method] === "function",
      `a SpendStore must implement ${method} (SPEC §3.1)`,
    );
  }
}

async function checkReserveAndTotals(makeStore: () => SpendStore): Promise<void> {
  const store = makeStore();
  const [committed, reserved] = await totals(store);
  mustHold(
    committed === 0n && reserved === 0n,
    "a fresh scope/asset pair must report committed 0 and reserved 0",
  );
  const result = await store.reserve({
    reservationId: "r1",
    requestId: "contract-r1",
    policyScope: SCOPE,
    requestFingerprint: FINGERPRINT,
    assetId: ASSET,
    amountAtomic: "1500",
    maxPerHourAtomic: "1000000",
    nowEpochMs: NOW,
  });
  mustHold(
    result.recipientPinEstablished === false,
    "reserve must return a ReserveSpendResult with recipientPinEstablished false by default",
  );
  const reservation = result.reservation;
  mustHold(
    reservation.state === "reserved",
    "reserve must return a reservation in state 'reserved'",
  );
  mustHold(
    reservation.amountAtomic === "1500",
    "reserve must echo amountAtomic back unchanged, as an atomic string",
  );
  mustHold(
    reservation.expiresAtEpochMs === NOW + RESERVATION_TTL_MS,
    `a reservation must expire ${RESERVATION_TTL_MS} ms after it was created`,
  );
  const [c2, r2] = await totals(store);
  mustHold(
    c2 === 0n && r2 === 1500n,
    "an open reservation must count toward reserved, not committed",
  );
}

async function checkScopeAndAssetIsolation(makeStore: () => SpendStore): Promise<void> {
  const store = makeStore();
  await reserve(store, { reservationId: "s1", amount: "700" });
  const [oc, or] = await totals(store, { scope: OTHER_SCOPE });
  mustHold(
    oc === 0n && or === 0n,
    "reservations must not leak between policy scopes — a scope is a separate ledger",
  );
  const [ac, ar] = await totals(store, { asset: OTHER_ASSET });
  mustHold(
    ac === 0n && ar === 0n,
    "reservations must not leak between assets — atomic units are asset-specific",
  );
}

async function checkCommitAndRelease(makeStore: () => SpendStore): Promise<void> {
  let store = makeStore();
  const reserved = await reserve(store, { reservationId: "c1", amount: "900" });
  const entry = await store.commit({
    reservationId: reserved.reservationId,
    policyScope: reserved.policyScope,
    assetId: reserved.assetId,
    committedAtEpochMs: NOW + 10,
    settlementId: "0xabc",
  });
  mustHold(
    entry.amountAtomic === "900",
    "commit must record the reserved amount unchanged",
  );
  mustHold(
    entry.settlementId === "0xabc",
    "commit must retain the settlement id it was given",
  );
  const [committed, reservedTotal] = await totals(store, { now: NOW + 10 });
  mustHold(
    committed === 900n && reservedTotal === 0n,
    "a committed reservation moves from reserved to committed, not both",
  );
  const again = await store.commit({
    reservationId: reserved.reservationId,
    policyScope: reserved.policyScope,
    assetId: reserved.assetId,
    committedAtEpochMs: NOW + 20,
  });
  mustHold(
    again.committedAtEpochMs === entry.committedAtEpochMs,
    "commit must be idempotent: a second call returns the first entry unchanged",
  );

  // O27: an empty settlementId means "no settlement id" — EVERY adapter must round-trip it as
  // ABSENT, not as `""`. (Memory/DO used to keep `""`; Redis dropped it — a cross-adapter split.)
  const emptyStore = makeStore();
  const emptyReserved = await reserve(emptyStore, {
    reservationId: "c-empty",
    amount: "100",
  });
  const emptyEntry = await emptyStore.commit({
    reservationId: emptyReserved.reservationId,
    policyScope: emptyReserved.policyScope,
    assetId: emptyReserved.assetId,
    committedAtEpochMs: NOW + 10,
    settlementId: "",
  });
  mustHold(
    emptyEntry.settlementId === undefined,
    'commit with an empty settlementId must round-trip as absent, never ""',
  );
  const emptyReplay = await emptyStore.commit({
    reservationId: emptyReserved.reservationId,
    policyScope: emptyReserved.policyScope,
    assetId: emptyReserved.assetId,
    committedAtEpochMs: NOW + 20,
  });
  mustHold(
    emptyReplay.settlementId === undefined,
    "the stored entry read back on a replay must also show an empty settlementId as absent",
  );

  store = makeStore();
  const toRelease = await reserve(store, { reservationId: "c2", amount: "900" });
  const released = await store.release(ref(toRelease), NOW + 5);
  mustHold(
    released.state === "released",
    "release must return the reservation in state 'released'",
  );
  const [rc, rr] = await totals(store, { now: NOW + 5 });
  mustHold(
    rc === 0n && rr === 0n,
    "a released reservation must stop counting toward the cap immediately",
  );
  await store.release(ref(toRelease), NOW + 6);
  let raised = false;
  try {
    await store.commit({
      reservationId: toRelease.reservationId,
      policyScope: toRelease.policyScope,
      assetId: toRelease.assetId,
      committedAtEpochMs: NOW + 7,
    });
  } catch {
    raised = true;
  }
  mustHold(raised, "commit on a released reservation must raise, never silently succeed");
}

async function checkIdempotentReserve(makeStore: () => SpendStore): Promise<void> {
  const store = makeStore();
  const first = await reserve(store, { reservationId: "i1", amount: "400" });
  const second = await reserve(store, { reservationId: "i1", amount: "400" });
  mustHold(
    first.reservationId === second.reservationId,
    "a repeated reservationId with identical data must return the same reservation",
  );
  const [, reserved] = await totals(store);
  mustHold(
    reserved === 400n,
    "a repeated reservationId must not double-count against the cap",
  );
  let raised = false;
  try {
    await reserve(store, { reservationId: "i1", amount: "401" });
  } catch {
    raised = true;
  }
  mustHold(
    raised,
    "a reservationId reused with different spend data must raise, not overwrite",
  );
}

async function checkCapRefusal(makeStore: () => SpendStore): Promise<void> {
  const store = makeStore();
  await reserve(store, { reservationId: "b1", amount: "800", cap: "1000" });
  let refused = false;
  try {
    await reserve(store, { reservationId: "b2", amount: "300", cap: "1000" });
  } catch (error) {
    if (!(error instanceof BudgetExceededError)) {
      throw new SpendStoreContractError(
        `an over-cap reserve must raise BudgetExceededError, not ${String(error)}; any ` +
          "other exception is read as a store outage",
      );
    }
    for (const key of [
      "requestedAtomic",
      "capAtomic",
      "committedAtomic",
      "reservedAtomic",
      "capKind",
    ]) {
      mustHold(key in error.details, `BudgetExceededError must carry details[${key}] (§8)`);
    }
    refused = true;
  }
  mustHold(refused, "an over-cap reserve must be refused: 800 + 300 exceeds a cap of 1000");
  const [committed, reserved] = await totals(store);
  mustHold(
    committed === 0n && reserved === 800n,
    "a refused reserve must leave the ledger exactly as it was",
  );
}

async function checkRollingWindow(makeStore: () => SpendStore): Promise<void> {
  const inside = makeStore();
  const w1 = await reserve(inside, { reservationId: "w1", amount: "500" });
  await inside.commit({
    reservationId: w1.reservationId,
    policyScope: w1.policyScope,
    assetId: w1.assetId,
    committedAtEpochMs: NOW,
  });
  const [ci] = await totals(inside, { now: NOW + ROLLING_WINDOW_MS - 1 });
  mustHold(
    ci === 500n,
    "a commit must still count one millisecond before the window closes",
  );

  const outside = makeStore();
  const w1b = await reserve(outside, { reservationId: "w1", amount: "500" });
  await outside.commit({
    reservationId: w1b.reservationId,
    policyScope: w1b.policyScope,
    assetId: w1b.assetId,
    committedAtEpochMs: NOW,
  });
  const [co] = await totals(outside, { now: NOW + ROLLING_WINDOW_MS + 1 });
  mustHold(
    co === 0n,
    `a commit must leave the rolling window ${ROLLING_WINDOW_MS} ms after it happened`,
  );
}

async function checkExpiry(makeStore: () => SpendStore): Promise<void> {
  const store = makeStore();
  await reserve(store, { reservationId: "e1", amount: "600" });
  const [committed, reserved] = await totals(store, { now: NOW + RESERVATION_TTL_MS + 1 });
  mustHold(
    committed === 0n && reserved === 0n,
    "an expired reservation must stop counting toward the cap (SPEC §5.3)",
  );
}

async function checkExposureLifecycle(makeStore: () => SpendStore): Promise<void> {
  const store = makeStore();
  const reserved = await reserve(store, { reservationId: "x1", amount: "400" });
  const exposed = await store.expose(ref(reserved), NOW + 5);
  mustHold(
    exposed.state === "exposed",
    "expose must move a reserved reservation to state 'exposed'",
  );
  const state = await store.getBudgetState({
    policyScope: SCOPE,
    assetId: ASSET,
    nowEpochMs: NOW + 5,
  });
  mustHold(
    state.exposedAtomic === "400" && state.reservedAtomic === "0",
    "an exposed reservation must count as exposed, not reserved (SPEC §7)",
  );
  mustHold(
    state.cumulativeConsumedAtomic === "400",
    "exposed spend must fold into cumulativeConsumed (SPEC §3.4)",
  );
  const later = await store.getBudgetState({
    policyScope: SCOPE,
    assetId: ASSET,
    nowEpochMs: NOW + ROLLING_WINDOW_MS + 1,
  });
  mustHold(
    later.exposedAtomic === "400",
    "an exposed reservation must not expire — it stays counted until resolved (ADR-026)",
  );
  const listed = await store.listExposed({
    policyScope: SCOPE,
    assetId: ASSET,
    nowEpochMs: NOW + ROLLING_WINDOW_MS + 1,
  });
  mustHold(
    listed.length === 1 && listed[0]?.reservationId === "x1",
    "listExposed must enumerate the unresolved exposed reservation",
  );
  await store.commit({
    reservationId: reserved.reservationId,
    policyScope: reserved.policyScope,
    assetId: reserved.assetId,
    committedAtEpochMs: NOW + 20,
  });
  const resolved = await store.getBudgetState({
    policyScope: SCOPE,
    assetId: ASSET,
    nowEpochMs: NOW + 20,
  });
  mustHold(
    resolved.exposedAtomic === "0" && resolved.cumulativeCommittedAtomic === "400",
    "commit on an exposed reservation must move it from exposed to cumulative committed",
  );
}

async function checkAtomicity(makeStore: () => SpendStore): Promise<void> {
  // MemorySpendStore does its cap comparison and insert in one event-loop turn, so 20
  // concurrent reserves resolve deterministically. A store that awaits between the read and
  // the insert (the naive networked adapter) admits more than five here and nowhere else.
  const store = makeStore();
  const attempts = 20;
  const results = await Promise.allSettled(
    Array.from({ length: attempts }, (_unused, index) =>
      reserve(store, { reservationId: `a${index}`, amount: "1", cap: "5" }),
    ),
  );
  const admitted = results.filter((result) => result.status === "fulfilled").length;
  mustHold(
    admitted === 5,
    `reserve must be atomic: 20 concurrent one-unit reservations under a cap of 5 admitted ` +
      `${admitted}, not 5`,
  );
  const [, reserved] = await totals(store);
  mustHold(
    reserved === 5n,
    "after a contended run the ledger must total exactly the cap, never more",
  );
}

async function checkReservationIdAliasing(makeStore: () => SpendStore): Promise<void> {
  // O48/O54: a caller-supplied reservationId that aliases a reserved key MUST NEVER corrupt the
  // (scope, asset) ledger. The pathological ids are the reserved final-segment suffixes — the index
  // ZSET (`idx`) AND the per-asset counter/limits keys (`total`/`exposed`/`limits`, O54) — and any
  // id carrying the `:` key separator (which re-parses to a different (asset, id) pair). A store
  // that flattens its keys into one namespace (Redis) refuses each with a typed ConfigurationError;
  // a store immune by construction (Memory's NUL-joined map keys, the DO's parameterized SQLite
  // column) simply records it. What NO store may do is throw an untyped error, or leave the ledger
  // unreadable afterwards (the Redis WRONGTYPE brick this guards). Each id runs in its own scope so
  // the readability assertion is unambiguous.
  const pathological = ["idx", "total", "exposed", "limits", "a:idx"] as const;
  for (const reservationId of pathological) {
    const store = makeStore();
    const scope = `alias.${reservationId.replace(":", "_")}.example`;
    let accepted = false;
    try {
      await reserve(store, { reservationId, amount: "1", scope });
      accepted = true;
    } catch (error) {
      mustHold(
        error instanceof ConfigurationError &&
          error.details["reason"] === "reservation-id-aliases-index",
        `a reservationId (${reservationId}) that aliases a reserved index/counter key must be ` +
          "refused as a typed ConfigurationError (reason reservation-id-aliases-index), never an " +
          "untyped/WRONGTYPE error",
      );
    }
    // The (scope, asset) ledger must remain readable either way — the reserve must not brick it.
    const state = await store.getBudgetState({
      policyScope: scope,
      assetId: ASSET,
      nowEpochMs: NOW,
    });
    mustHold(
      typeof state.reservedAtomic === "string",
      `getBudgetState must still return after reservationId '${reservationId}' (no brick)`,
    );
    mustHold(
      BigInt(state.reservedAtomic) === (accepted ? 1n : 0n),
      accepted
        ? `a store that accepts reservationId '${reservationId}' must record its reservation`
        : `a store that refuses reservationId '${reservationId}' must not have reserved anything`,
    );
  }
}

async function checkAssetCanonicalization(makeStore: () => SpendStore): Promise<void> {
  // U16: the (scope, asset) ledger keys on the CANONICAL asset (an eip155 asset lowercased, §6.4),
  // so a reserve under the checksummed manifest asset and a read/second-reserve under its lowercase
  // form must address the SAME ledger. ASSET is already lowercase; ASSET_CHECKSUMMED is the EIP-55
  // form the signed manifest carries. Data-plane only, so EVERY store runs it (a lookalike that keys
  // on the raw asset string fails: the checksummed reserve is invisible under the lowercase read).
  const store = makeStore();
  await reserve(store, {
    reservationId: "u16-canon-1",
    amount: "700",
    cap: "1000",
    asset: ASSET_CHECKSUMMED,
  });
  const [committed, reserved] = await totals(store, { asset: ASSET });
  mustHold(
    committed === 0n && reserved === 700n,
    "a reserve under the checksummed asset must be visible under its lowercase form — the ledger " +
      "keys on the canonical asset (U16)",
  );
  let tripped: unknown;
  try {
    await reserve(store, {
      reservationId: "u16-canon-2",
      amount: "400",
      cap: "1000",
      asset: ASSET,
    });
  } catch (error) {
    tripped = error;
  }
  mustHold(
    tripped instanceof BudgetExceededError,
    "a reserve under the lowercase asset must share the checksummed ledger's per-hour cap, so " +
      "700 + 400 > 1000 is refused (U16 canonicalization)",
  );
}

const CHECKS: readonly ((makeStore: () => SpendStore) => Promise<void>)[] = [
  checkShape,
  checkReserveAndTotals,
  checkAssetCanonicalization,
  checkScopeAndAssetIsolation,
  checkCommitAndRelease,
  checkIdempotentReserve,
  checkCapRefusal,
  checkRollingWindow,
  checkExpiry,
  checkExposureLifecycle,
  checkAtomicity,
  checkReservationIdAliasing,
];

/**
 * Runs every single-plane contract check against stores produced by `makeStore`.
 *
 * `makeStore` is a factory rather than an instance because several checks need a store with no
 * history; a factory that hands back the same populated object will fail them. Each call should
 * produce an empty, independent ledger. Rejects with {@link SpendStoreContractError} on the
 * first violation.
 */
export async function checkSpendStore(makeStore: () => SpendStore): Promise<void> {
  for (const check of CHECKS) {
    await check(makeStore);
  }
}

/* v8 ignore start */
// Coverage from here down is EXCLUDED: the durable harness is verification tooling that only
// runs against a LIVE durable backend (the `redis-store` suite + the `durable-store` CI job,
// gated on `TX402_TEST_REDIS_URL`), never the no-backend unit matrix. Its correctness is proven
// behaviourally by those tests, not by line coverage here — the same reasoning that omits the
// `src/redis` adapter and the Python `stores/` from the coverage gate (ADR-008/§12.1).

// ── The durable harness (SPEC §3.6) ────────────────────────────────────────────────────
//
// A networked store cannot be checked through checkSpendStore alone: that factory hands back
// independent empty stores, so it cannot express a shared backend, a restart, the
// operator/agent credential split, or backend-authoritative time. checkDurableSpendStore takes
// BOTH security planes over one shared, resettable namespace plus a settable backend clock.
// The API and the two checks only the harness can express — plane separation and clock skew;
// freeze, cumulative, pins, administered limits and true-parallel atomicity run against the
// Redis and DO adapters.

export interface DurableSpendStoreHarness {
  /** Opens a DATA-plane store over the shared namespace. */
  connectData(): SpendStore;
  /** Opens an ADMIN store over the shared namespace. */
  connectAdmin(): SpendStoreAdmin;
  /** The admin method surface bound to the DATA credential, so plane separation is attemptable. */
  connectAdminWithDataCredential(): SpendStoreAdmin;
  /** Clears the shared namespace between checks. */
  reset(): Promise<void> | void;
  /** Drives the store's test-only backend clock (SPEC §3.4a). Production exposes no setter. */
  setBackendClock(nowEpochMs: number): Promise<void> | void;
  /**
   * OPTIONAL. Restarts the backend so the restart-durability check runs (SPEC §12.4
   * `_check_restart`). It MUST return only once the backend is reachable again, and the data
   * written before it MUST survive (Redis: AOF; DO: SQLite). When absent, `_check_restart` is
   * skipped — a store whose harness cannot control the process still runs every other check.
   */
  restart?(): Promise<void> | void;
}

const NO_LIMITS: BudgetLimits = Object.freeze({});

const ADMIN_METHOD_CALLS: readonly [
  string,
  (admin: SpendStoreAdmin) => Promise<unknown>,
][] = [
  ["freeze", (admin) => admin.freeze(SCOPE, NOW)],
  ["unfreeze", (admin) => admin.unfreeze(SCOPE, NOW)],
  [
    "setRecipientPins",
    (admin) => admin.setRecipientPins(SCOPE, "eip155:8453", ["0x0"], NOW),
  ],
  ["setBudgetLimits", (admin) => admin.setBudgetLimits(SCOPE, ASSET, NO_LIMITS, NOW)],
  [
    "setRecipientAssertionRequired",
    (admin) => admin.setRecipientAssertionRequired(SCOPE, true, NOW),
  ],
  ["setTofuEnabled", (admin) => admin.setTofuEnabled(SCOPE, true, NOW)],
  ["resetCumulative", (admin) => admin.resetCumulative(SCOPE, ASSET, NOW)],
];

/**
 * Every admin method invoked with a DATA credential is denied (SPEC §3.6, ADR-029): each
 * mutation must be refused with `admin-credential-required` so a compromised agent path cannot
 * freeze a scope, widen a cap, or rewrite a pin.
 */
async function checkPlaneSeparation(
  connectAdminWithDataCredential: () => SpendStoreAdmin,
): Promise<void> {
  const admin = connectAdminWithDataCredential();
  for (const [name, call] of ADMIN_METHOD_CALLS) {
    let denied: unknown;
    try {
      await call(admin);
    } catch (error) {
      denied = error;
    }
    if (denied === undefined) {
      throw new SpendStoreContractError(
        `${name} must be denied when invoked with a data credential (ADR-029)`,
      );
    }
    if (!(denied instanceof ConfigurationError)) {
      const kind = denied instanceof Error ? denied.name : typeof denied;
      throw new SpendStoreContractError(
        `${name} with a data credential must raise a typed admin-credential-required ` +
          `ConfigurationError, not ${kind}`,
      );
    }
    mustHold(
      denied.details.reason === "admin-credential-required",
      `${name} with a data credential must be denied with reason 'admin-credential-required'`,
    );
  }
}

/**
 * Backend time windows the cap, so fleet clock skew cannot double-spend it (SPEC §3.4a). Two
 * independent connections: A reserves the whole cap with a future-skewed caller clock, then B
 * reserves with an earlier one. A durable store windows on its own clock, so it still counts
 * A's reservation and caps B — the round-7 skew breach this closes.
 */
async function checkSkew(
  connectData: () => SpendStore,
  setBackendClock: (nowEpochMs: number) => Promise<void> | void,
): Promise<void> {
  await setBackendClock(NOW);
  const a = connectData();
  const b = connectData();
  await a.reserve({
    reservationId: "skew-a",
    requestId: "skew-a",
    policyScope: SCOPE,
    requestFingerprint: FINGERPRINT,
    assetId: ASSET,
    amountAtomic: "5",
    maxPerHourAtomic: "5",
    nowEpochMs: NOW + 20_000, // A's caller clock runs fast; the backend clock wins.
  });
  let refused = false;
  try {
    await b.reserve({
      reservationId: "skew-b",
      requestId: "skew-b",
      policyScope: SCOPE,
      requestFingerprint: FINGERPRINT,
      assetId: ASSET,
      amountAtomic: "1",
      maxPerHourAtomic: "5",
      nowEpochMs: NOW, // B's caller clock is earlier; it must not exclude A.
    });
  } catch (error) {
    if (error instanceof BudgetExceededError) refused = true;
    else throw error;
  }
  mustHold(
    refused,
    "a durable store must window on its own clock: B must not exceed a cap A already filled " +
      "just because B's caller clock is earlier (SPEC §3.4a)",
  );
}

/**
 * A ref resolves across connections (SPEC §12.4 `_check_locator`): a reservation opened on one
 * data connection is committed / released / exposed from a *different* one, by its ref alone — the
 * cross-machine addressing a bare reservation UUID cannot express in a sharded store (P0-1).
 */
async function checkLocator(connectData: () => SpendStore): Promise<void> {
  const a = connectData();
  const b = connectData();
  const toCommit = await reserve(a, { reservationId: "loc-commit", amount: "10" });
  const entry = await b.commit({
    reservationId: toCommit.reservationId,
    policyScope: toCommit.policyScope,
    assetId: toCommit.assetId,
    committedAtEpochMs: NOW + 1,
    settlementId: "0xloc",
  });
  mustHold(
    entry.amountAtomic === "10",
    "commit on connection B must resolve a reservation opened on connection A (SPEC §12.4)",
  );
  const toRelease = await reserve(a, { reservationId: "loc-release", amount: "10" });
  const released = await b.release(ref(toRelease), NOW + 2);
  mustHold(
    released.state === "released",
    "release on connection B must resolve a reservation opened on connection A",
  );
  const toExpose = await reserve(a, { reservationId: "loc-expose", amount: "10" });
  const exposed = await b.expose(ref(toExpose), NOW + 3);
  mustHold(
    exposed.state === "exposed",
    "expose on connection B must fence a reservation opened on connection A",
  );
}

/**
 * The cumulative cap binds first when it is the tighter limit and survives the rolling boundary
 * (SPEC §3.6 `_check_cumulative_cap`, §4): a lifetime ceiling still refuses after the per-hour
 * figure has aged out of the window.
 */
async function checkCumulativeCap(
  connectData: () => SpendStore,
  setBackendClock: (nowEpochMs: number) => Promise<void> | void,
): Promise<void> {
  await setBackendClock(NOW);
  const store = connectData();
  const first = await store.reserve({
    reservationId: "cum-1",
    requestId: "cum-1",
    policyScope: SCOPE,
    requestFingerprint: FINGERPRINT,
    assetId: ASSET,
    amountAtomic: "6",
    maxPerHourAtomic: "1000",
    maxTotalAtomic: "10",
    nowEpochMs: NOW,
  });
  await store.commit({
    reservationId: first.reservation.reservationId,
    policyScope: SCOPE,
    assetId: ASSET,
    committedAtEpochMs: NOW,
  });
  let capKind: unknown;
  try {
    await store.reserve({
      reservationId: "cum-2",
      requestId: "cum-2",
      policyScope: SCOPE,
      requestFingerprint: FINGERPRINT,
      assetId: ASSET,
      amountAtomic: "5",
      maxPerHourAtomic: "1000",
      maxTotalAtomic: "10",
      nowEpochMs: NOW,
    });
  } catch (error) {
    if (!(error instanceof BudgetExceededError)) throw error;
    capKind = error.details.capKind;
  }
  mustHold(
    capKind === "cumulative",
    "the cumulative cap must bind (capKind 'cumulative') where the per-hour cap still has room (SPEC §4)",
  );
  // Advance a full rolling window: the per-hour figure resets, the lifetime one does not.
  await setBackendClock(NOW + ROLLING_WINDOW_MS + 1);
  let stillRefused = false;
  try {
    await store.reserve({
      reservationId: "cum-3",
      requestId: "cum-3",
      policyScope: SCOPE,
      requestFingerprint: FINGERPRINT,
      assetId: ASSET,
      amountAtomic: "5",
      maxPerHourAtomic: "1000",
      maxTotalAtomic: "10",
      nowEpochMs: NOW + ROLLING_WINDOW_MS + 1,
    });
  } catch (error) {
    if (!(error instanceof BudgetExceededError)) throw error;
    stillRefused = true;
  }
  mustHold(
    stillRefused,
    "cumulative spend is lifetime: it must still bind after the rolling hour has reset the per-hour figure (SPEC §4.2)",
  );
}

/**
 * Exposure is durable and never escapes (SPEC §3.6 `_check_exposure`, §7): an exposed reservation
 * keeps counting past the 120 s TTL and the rolling hour, `listExposed` enumerates it across
 * connections, and the admin `resolveExposed` reconciles it (and refuses a second, terminal call).
 */
async function checkExposure(
  connectData: () => SpendStore,
  connectAdmin: () => SpendStoreAdmin,
  setBackendClock: (nowEpochMs: number) => Promise<void> | void,
): Promise<void> {
  await setBackendClock(NOW);
  const data = connectData();
  const admin = connectAdmin();
  const opened = await reserve(data, { reservationId: "exp-1", amount: "400" });
  const exposed = await data.expose(ref(opened), NOW + 5);
  mustHold(exposed.state === "exposed", "expose must fence a reserved reservation");
  await setBackendClock(NOW + ROLLING_WINDOW_MS + 1);
  const later = await data.getBudgetState({
    policyScope: SCOPE,
    assetId: ASSET,
    nowEpochMs: NOW + ROLLING_WINDOW_MS + 1,
  });
  mustHold(
    later.exposedAtomic === "400" && later.cumulativeConsumedAtomic === "400",
    "an exposed reservation must not expire — it keeps counting past 120 s and the rolling hour (ADR-026)",
  );
  const listed = await data.listExposed({
    policyScope: SCOPE,
    assetId: ASSET,
    nowEpochMs: NOW + ROLLING_WINDOW_MS + 1,
  });
  mustHold(
    listed.length === 1 && listed[0]?.reservationId === opened.reservationId,
    "listExposed must enumerate the unresolved exposed reservation across connections",
  );
  await admin.resolveExposed(ref(opened), "committed", NOW + ROLLING_WINDOW_MS + 2);
  const resolved = await data.getBudgetState({
    policyScope: SCOPE,
    assetId: ASSET,
    nowEpochMs: NOW + ROLLING_WINDOW_MS + 2,
  });
  mustHold(
    resolved.exposedAtomic === "0" && resolved.cumulativeCommittedAtomic === "400",
    "resolveExposed(committed) must move exposed spend into cumulative committed (SPEC §7)",
  );
  let terminal = false;
  try {
    await admin.resolveExposed(ref(opened), "committed", NOW + ROLLING_WINDOW_MS + 3);
  } catch (error) {
    if (
      error instanceof ConfigurationError &&
      error.details.reason === "reservation-already-terminal"
    )
      terminal = true;
    else throw error;
  }
  mustHold(
    terminal,
    "resolveExposed on an already-resolved reservation must refuse as reservation-already-terminal",
  );
}

/**
 * `reserve` is atomic under TRUE parallelism over independent connections (SPEC §3.6
 * `_check_atomicity`): exactly the cap is admitted of a burst that far exceeds it, and the ledger
 * totals exactly the cap — never more, however the reads and writes interleave across machines.
 */
async function checkAtomicityParallel(
  connectData: () => SpendStore,
  setBackendClock: (nowEpochMs: number) => Promise<void> | void,
): Promise<void> {
  await setBackendClock(NOW);
  const attempts = 20;
  const results = await Promise.allSettled(
    Array.from({ length: attempts }, (_unused, index) =>
      connectData().reserve({
        reservationId: `par-${index}`,
        requestId: `par-${index}`,
        policyScope: SCOPE,
        requestFingerprint: FINGERPRINT,
        assetId: ASSET,
        amountAtomic: "1",
        maxPerHourAtomic: "5",
        nowEpochMs: NOW,
      }),
    ),
  );
  const admitted = results.filter((result) => result.status === "fulfilled").length;
  mustHold(
    admitted === 5,
    `reserve must be atomic across independent connections: 20 concurrent one-unit reserves ` +
      `under a cap of 5 admitted ${admitted}, not 5 (SPEC §3.6)`,
  );
  const [, reserved] = await totals(connectData(), { now: NOW });
  mustHold(
    reserved === 5n,
    "after a contended parallel run the shared ledger must total exactly the cap, never more",
  );
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function reserveWithRecipient(
  store: SpendStore,
  options: {
    id: string;
    recipient: string;
    network: string;
    scope?: string;
    enforcement?: "off" | "allowlist" | "tofu";
    now?: number;
  },
): Promise<ReserveSpendResult> {
  return store.reserve({
    reservationId: options.id,
    requestId: `contract-${options.id}`,
    policyScope: options.scope ?? SCOPE,
    requestFingerprint: FINGERPRINT,
    assetId: ASSET,
    amountAtomic: "1",
    maxPerHourAtomic: "1000000",
    recipientNetwork: options.network,
    recipientCanonical: options.recipient,
    recipientEnforcement: options.enforcement ?? "tofu",
    nowEpochMs: options.now ?? NOW,
  });
}

/**
 * Freeze is an admin-plane control, atomic with reserve (SPEC §3.6 `_check_freeze`, §5). Freezing
 * a scope makes every reserve on it raise `SpendScopeFrozenError`; committed spend is preserved
 * across the freeze; unfreeze restores it. The global-`"*"` arm is parameterized by the declared
 * `capabilities.atomicGlobalFreeze` exactly as SPEC §5.2: a capable store asserts `"*"` blocks a
 * *distinct* scope, an incapable store (Redis Cluster / id-per-scope DO) asserts `freeze("*")`
 * fails closed with `global-freeze-unsupported`, so no adapter must implement a `"*"` atom it
 * structurally cannot.
 */
async function checkFreeze(
  connectData: () => SpendStore,
  connectAdmin: () => SpendStoreAdmin,
  setBackendClock: (nowEpochMs: number) => Promise<void> | void,
): Promise<void> {
  await setBackendClock(NOW);
  const data = connectData();
  const admin = connectAdmin();

  // Committed spend established before the freeze must survive it (KS-7, §5.4).
  const pre = await reserve(data, { reservationId: "fz-pre", amount: "100" });
  await data.commit({
    reservationId: pre.reservationId,
    policyScope: pre.policyScope,
    assetId: pre.assetId,
    committedAtEpochMs: NOW,
  });

  await admin.freeze(SCOPE, NOW);
  mustHold(await data.isFrozen(SCOPE), "isFrozen must report a scope the admin just froze");

  let frozenErr: unknown;
  try {
    await reserve(data, { reservationId: "fz-1", amount: "1" });
  } catch (error) {
    frozenErr = error;
  }
  if (!(frozenErr instanceof SpendScopeFrozenError)) {
    throw new SpendStoreContractError(
      `reserve on a frozen scope must raise SpendScopeFrozenError, not ${String(frozenErr)}`,
    );
  }
  mustHold(
    frozenErr.details.frozenScope === SCOPE && frozenErr.details.scope === SCOPE,
    "a per-scope freeze must carry details.frozenScope and details.scope = the scope (§5.3)",
  );

  const preserved = await data.getBudgetState({
    policyScope: SCOPE,
    assetId: ASSET,
    nowEpochMs: NOW,
  });
  mustHold(
    preserved.committedAtomic === "100" && preserved.frozen === true,
    "a freeze must preserve committed accounting and report frozen (KS-7, §5.4)",
  );

  await admin.unfreeze(SCOPE, NOW);
  mustHold(!(await data.isFrozen(SCOPE)), "unfreeze must clear the scope's freeze");
  const readmitted = await reserve(data, { reservationId: "fz-2", amount: "1" });
  mustHold(readmitted.state === "reserved", "unfreeze must restore reserves on the scope");

  // Global "*" arm, parameterized by the declared capability (SPEC §5.2).
  if (data.capabilities.atomicGlobalFreeze) {
    await admin.freeze("*", NOW);
    let globalErr: unknown;
    try {
      await reserve(data, { reservationId: "fz-g", amount: "1", scope: OTHER_SCOPE });
    } catch (error) {
      globalErr = error;
    }
    if (!(globalErr instanceof SpendScopeFrozenError)) {
      throw new SpendStoreContractError(
        `an atomicGlobalFreeze store must let freeze("*") block a distinct scope with ` +
          `SpendScopeFrozenError, not ${String(globalErr)}`,
      );
    }
    mustHold(
      globalErr.details.frozenScope === "*",
      'a global freeze must report frozenScope "*" (SPEC §5.2)',
    );
    await admin.unfreeze("*", NOW);
    const afterGlobal = await reserve(data, {
      reservationId: "fz-g2",
      amount: "1",
      scope: OTHER_SCOPE,
    });
    mustHold(
      afterGlobal.state === "reserved",
      "unfreeze(*) must restore reserves fleet-wide",
    );
  } else {
    let unsupported: unknown;
    try {
      await admin.freeze("*", NOW);
    } catch (error) {
      unsupported = error;
    }
    if (!(unsupported instanceof ConfigurationError)) {
      throw new SpendStoreContractError(
        `a store without atomicGlobalFreeze must refuse freeze("*") with a typed ` +
          `ConfigurationError, not ${String(unsupported)}`,
      );
    }
    mustHold(
      unsupported.details.reason === "global-freeze-unsupported" &&
        unsupported.details.configPath === "freeze.global",
      'freeze("*") on an incapable store must fail closed as global-freeze-unsupported (SPEC §5.2)',
    );
  }
}

/**
 * Recipient pinning under contention (SPEC §3.6 `_check_pins`, §6.2, §12.4). Two properties a
 * single-process store cannot demonstrate: a concurrent in-reserve TOFU claim converges to exactly
 * one pin (exactly one worker reports establishing it, and it is authoritative afterward), and a
 * recipient rotation racing a burst of reserves never tears — a reader sees the whole old pin or
 * the whole new one, never a transient empty/partial record.
 */
async function checkPins(
  connectData: () => SpendStore,
  connectAdmin: () => SpendStoreAdmin,
  setBackendClock: (nowEpochMs: number) => Promise<void> | void,
): Promise<void> {
  const NETWORK = "eip155:8453";
  const R1 = `0x${"1".repeat(40)}`;
  const R2 = `0x${"2".repeat(40)}`;

  // ── A: a concurrent in-reserve TOFU claim converges to exactly one pin. ──
  await setBackendClock(NOW);
  await connectAdmin().setTofuEnabled(SCOPE, true, NOW);
  const claims = await Promise.allSettled(
    Array.from({ length: 12 }, (_unused, index) =>
      reserveWithRecipient(connectData(), {
        id: `pin-${index}`,
        recipient: R1,
        network: NETWORK,
      }),
    ),
  );
  const admitted = claims.filter(
    (result): result is PromiseFulfilledResult<ReserveSpendResult> =>
      result.status === "fulfilled",
  );
  mustHold(
    admitted.length === claims.length,
    "every concurrent reserve presenting the same recipient under TOFU must be admitted",
  );
  const established = admitted.filter(
    (result) => result.value.recipientPinEstablished,
  ).length;
  mustHold(
    established === 1,
    `a contended TOFU claim must converge to one pin: ${established} workers reported ` +
      "establishing it, not 1 (SPEC §6.2)",
  );
  let mismatch: unknown;
  try {
    await reserveWithRecipient(connectData(), {
      id: "pin-r2",
      recipient: R2,
      network: NETWORK,
    });
  } catch (error) {
    mismatch = error;
  }
  if (!(mismatch instanceof RecipientUnpinnedError)) {
    throw new SpendStoreContractError(
      `after a TOFU claim a different recipient must raise RecipientUnpinnedError, not ` +
        `${String(mismatch)}`,
    );
  }
  mustHold(
    mismatch.details.reason === "pin-mismatch",
    "a recipient not matching the converged TOFU pin must be reason 'pin-mismatch' (SPEC §6.5)",
  );

  // ── B: a rotation racing reserves never tears. On a DISTINCT scope (fresh, tofu OFF) an admin
  // allowlist [R1] is rotated to [R2] while a burst of reserves present R2 under enforcement
  // "tofu". With an atomic pin write, each reserve sees the whole old pin ([R1] → not-allowlisted)
  // or the whole new one ([R2] → admit) — never a transient no-record, which under tofu-not-
  // provisioned would surface as a ConfigurationError. Any such error betrays a torn write. ──
  await connectAdmin().setRecipientPins(OTHER_SCOPE, NETWORK, [R1], NOW);
  const tasks: Array<() => Promise<unknown>> = [
    () => connectAdmin().setRecipientPins(OTHER_SCOPE, NETWORK, [R2], NOW),
  ];
  for (let index = 0; index < 12; index += 1) {
    tasks.push(() =>
      reserveWithRecipient(connectData(), {
        id: `rot-${index}`,
        recipient: R2,
        network: NETWORK,
        scope: OTHER_SCOPE,
      }),
    );
  }
  const outcomes = await Promise.allSettled(tasks.map((task) => task()));
  for (let index = 1; index < outcomes.length; index += 1) {
    const outcome = outcomes[index];
    if (outcome?.status === "rejected") {
      const error: unknown = outcome.reason;
      if (
        error instanceof RecipientUnpinnedError &&
        error.details.reason === "not-allowlisted"
      ) {
        continue;
      }
      throw new SpendStoreContractError(
        `a reserve racing a pin rotation must be cleanly admitted or refused not-allowlisted, ` +
          `never a torn read (${String(error)}) — the pin write must be atomic (SPEC §12.4)`,
      );
    }
  }
  const settled = await reserveWithRecipient(connectData(), {
    id: "rot-final",
    recipient: R2,
    network: NETWORK,
    scope: OTHER_SCOPE,
  });
  mustHold(
    settled.recipientPinEstablished === false,
    "a rotated admin allowlist must admit the new recipient without claiming a TOFU pin",
  );

  // ── C (O27): an administered EMPTY recipient set must read back as [] on EVERY adapter. The DO
  // stored "" and returned [""] (`"".split("\n")`), diverging from Memory/Redis which returned []. ──
  const EMPTY_NETWORK = "eip155:1";
  await connectAdmin().setRecipientPins(OTHER_SCOPE, EMPTY_NETWORK, [], NOW);
  // Every durable store passed to the harness is also a RecipientPinStore (Memory/Redis/DO).
  const pinReader = connectData() as SpendStore & RecipientPinStore;
  const emptyPins = await pinReader.getRecipientPins(OTHER_SCOPE, EMPTY_NETWORK);
  mustHold(
    emptyPins.length === 0,
    `an administered empty recipient set must read back as [], not [""] (got ${JSON.stringify(
      [...emptyPins],
    )}, O27)`,
  );
}

/**
 * Store-administered caps and their precedence (SPEC §3.6 `_check_administered_limits`, §4.3). A
 * caller cap ABOVE the administered one is rejected per dimension (`cap-exceeds-administered`), so a
 * drifted worker cannot widen the fleet cap; a stricter caller cap is honoured via `min`. Lowering
 * an administered cap below current consumption does not unspend — it clamps availability to 0 and
 * refuses new reserves whose caller cap is now within the lowered limit (`BudgetExceededError`).
 */
async function checkAdministeredLimits(
  connectData: () => SpendStore,
  connectAdmin: () => SpendStoreAdmin,
  setBackendClock: (nowEpochMs: number) => Promise<void> | void,
): Promise<void> {
  await setBackendClock(NOW);
  const data = connectData();
  const admin = connectAdmin();

  // U16: a cap administered under the LOWERCASE asset must bind a reserve under the CHECKSUMMED
  // manifest form of the SAME contract — both key on the canonical (lowercased) asset (§6.4). This
  // is the exact drifted-worker scenario the runbook teaches: without canonicalization the
  // copy-pasted lowercase cap would be inert and the over-cap reserve would proceed. Runs first in a
  // dedicated scope so it cannot perturb the assertions below.
  await admin.setBudgetLimits(CANON_SCOPE, ASSET, { maxPerHourAtomic: "100" }, NOW);
  let canonRejected: unknown;
  try {
    await data.reserve({
      reservationId: "u16-canon",
      requestId: "u16-canon",
      policyScope: CANON_SCOPE,
      requestFingerprint: FINGERPRINT,
      assetId: ASSET_CHECKSUMMED, // checksummed form of the lowercase-administered contract
      amountAtomic: "1",
      maxPerHourAtomic: "200", // caller cap ABOVE the administered 100 → cap-exceeds if it binds
      nowEpochMs: NOW,
    });
  } catch (error) {
    canonRejected = error;
  }
  if (
    !(canonRejected instanceof ConfigurationError) ||
    canonRejected.details.reason !== "cap-exceeds-administered"
  ) {
    throw new SpendStoreContractError(
      "an administered cap under the LOWERCASE asset must bind a reserve under the CHECKSUMMED " +
        `asset (U16 canonicalization), got ${String(canonRejected)}`,
    );
  }

  await admin.setBudgetLimits(
    SCOPE,
    ASSET,
    { maxPerHourAtomic: "100", maxTotalAtomic: "100" },
    NOW,
  );

  for (const [dimension, configPath] of [
    ["perHour", "policy.maxPerHour"],
    ["total", "policy.maxTotal"],
  ] as const) {
    let rejected: unknown;
    try {
      await data.reserve({
        reservationId: `adm-hi-${dimension}`,
        requestId: `adm-hi-${dimension}`,
        policyScope: SCOPE,
        requestFingerprint: FINGERPRINT,
        assetId: ASSET,
        amountAtomic: "1",
        maxPerHourAtomic: dimension === "perHour" ? "200" : "50",
        maxTotalAtomic: dimension === "total" ? "200" : "50",
        nowEpochMs: NOW,
      });
    } catch (error) {
      rejected = error;
    }
    if (!(rejected instanceof ConfigurationError)) {
      throw new SpendStoreContractError(
        `a caller ${dimension} cap above the administered one must raise ConfigurationError, ` +
          `not ${String(rejected)}`,
      );
    }
    mustHold(
      rejected.details.reason === "cap-exceeds-administered" &&
        rejected.details.configPath === configPath,
      `a caller cap above the administered one must be cap-exceeds-administered at ${configPath} (§4.3)`,
    );
  }

  // A stricter caller cap is honoured via min; the reservation is admitted and committed.
  const admittedResult = await data.reserve({
    reservationId: "adm-ok",
    requestId: "adm-ok",
    policyScope: SCOPE,
    requestFingerprint: FINGERPRINT,
    assetId: ASSET,
    amountAtomic: "10",
    maxPerHourAtomic: "50",
    maxTotalAtomic: "50",
    nowEpochMs: NOW,
  });
  await data.commit({
    reservationId: admittedResult.reservation.reservationId,
    policyScope: SCOPE,
    assetId: ASSET,
    committedAtEpochMs: NOW,
  });

  // Lower the administered cap below current consumption (10): it cannot unspend, clamps
  // availability to 0, and refuses a new reserve even when the caller cap is within it.
  await admin.setBudgetLimits(
    SCOPE,
    ASSET,
    { maxPerHourAtomic: "5", maxTotalAtomic: "5" },
    NOW,
  );
  const clamped = await data.getBudgetState({
    policyScope: SCOPE,
    assetId: ASSET,
    nowEpochMs: NOW,
  });
  mustHold(
    clamped.availablePerHourAtomic === "0" && clamped.availableCumulativeAtomic === "0",
    "a cap lowered below current consumption must clamp availability to 0, never negative (§4.3)",
  );
  let refused: unknown;
  try {
    await data.reserve({
      reservationId: "adm-over",
      requestId: "adm-over",
      policyScope: SCOPE,
      requestFingerprint: FINGERPRINT,
      assetId: ASSET,
      amountAtomic: "1",
      maxPerHourAtomic: "5",
      maxTotalAtomic: "5",
      nowEpochMs: NOW,
    });
  } catch (error) {
    refused = error;
  }
  mustHold(
    refused instanceof BudgetExceededError,
    "a reserve under a lowered administered cap whose consumption already exceeds it must raise " +
      "BudgetExceededError (§4.3)",
  );

  // O26: `setBudgetLimits` is ONE atom, so a reserve racing it sees the whole OLD cap or the whole
  // NEW cap, NEVER a transient "no administered cap" (the window the old client-side DEL-then-HSET
  // opened). On a fresh scope an administered maxPerHour "5" is rewritten to "6" while a burst of
  // reserves present a caller cap of "1000000" — far above BOTH low administered values — and an
  // amount "100". Under either cap the caller cap exceeds the administered one, so every reserve
  // MUST be refused `cap-exceeds-administered`; a single ADMIT betrays a torn no-cap read.
  await admin.setBudgetLimits(OTHER_SCOPE, ASSET, { maxPerHourAtomic: "5" }, NOW);
  const raceTasks: Array<() => Promise<unknown>> = [
    () =>
      connectAdmin().setBudgetLimits(OTHER_SCOPE, ASSET, { maxPerHourAtomic: "6" }, NOW),
  ];
  for (let index = 0; index < 12; index += 1) {
    raceTasks.push(() =>
      connectData().reserve({
        reservationId: `lim-race-${index}`,
        requestId: `lim-race-${index}`,
        policyScope: OTHER_SCOPE,
        requestFingerprint: FINGERPRINT,
        assetId: ASSET,
        amountAtomic: "100",
        maxPerHourAtomic: "1000000",
        maxTotalAtomic: "1000000",
        nowEpochMs: NOW,
      }),
    );
  }
  const raceOutcomes = await Promise.allSettled(raceTasks.map((task) => task()));
  for (let index = 1; index < raceOutcomes.length; index += 1) {
    const outcome = raceOutcomes[index];
    if (outcome?.status === "fulfilled") {
      throw new SpendStoreContractError(
        "a reserve racing setBudgetLimits was ADMITTED — it saw a torn 'no administered cap' " +
          "window; the replacement must be one atom (§4.3, O26)",
      );
    }
    const error: unknown = outcome?.reason;
    if (
      !(error instanceof ConfigurationError) ||
      error.details.reason !== "cap-exceeds-administered"
    ) {
      throw new SpendStoreContractError(
        "a reserve racing setBudgetLimits must be refused cap-exceeds-administered (old or new " +
          `cap), never ${String(error)} (§4.3, O26)`,
      );
    }
  }
}

/**
 * Restart durability (SPEC §3.6 `_check_restart`, §12.4). A reservation and a committed entry
 * written before a backend restart must both survive it, and the reservation must still be
 * committable by its ref (Redis proves AOF persistence; the DO its SQLite storage). Runs only when
 * the harness provides a `restart` hook.
 */
async function checkRestart(
  connectData: () => SpendStore,
  restart: () => Promise<void> | void,
  setBackendClock: (nowEpochMs: number) => Promise<void> | void,
): Promise<void> {
  await setBackendClock(NOW);
  const before = connectData();
  const held = await reserve(before, { reservationId: "rst-held", amount: "42" });
  const toCommit = await reserve(before, { reservationId: "rst-committed", amount: "8" });
  await before.commit({
    reservationId: toCommit.reservationId,
    policyScope: SCOPE,
    assetId: ASSET,
    committedAtEpochMs: NOW,
  });

  await restart();

  // A fresh connection; retry the first read so the client's reconnect after the restart settles.
  const after = connectData();
  let state: BudgetState | undefined;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      state = await after.getBudgetState({
        policyScope: SCOPE,
        assetId: ASSET,
        nowEpochMs: NOW,
      });
      break;
    } catch {
      await delay(250);
    }
  }
  if (state === undefined) {
    throw new SpendStoreContractError("the store was unreachable after a restart");
  }
  mustHold(
    state.reservedAtomic === "42" && state.committedAtomic === "8",
    "AOF durability: a reservation and a committed entry must survive a server restart (§12.4)",
  );
  const entry = await after.commit({
    reservationId: held.reservationId,
    policyScope: SCOPE,
    assetId: ASSET,
    committedAtEpochMs: NOW + 1,
  });
  mustHold(
    entry.amountAtomic === "42",
    "a reservation that survived a restart must remain committable by its ref (§12.4)",
  );
}

/**
 * Runs the durable-store checks that need both planes, a shared namespace, and a clock:
 * plane-separation and clock-skew; the locator, cumulative-cap, exposure, and true-parallel
 * atomicity checks; and the admin-STATE governance checks — freeze (with the capability-
 * parameterized global arm), pins (contended TOFU claim + rotation-vs-reserve), administered limits,
 * and — when the harness can restart the backend — restart durability (SPEC §3.6/§12.4).
 */
export async function checkDurableSpendStore(
  harness: DurableSpendStoreHarness,
): Promise<void> {
  // The connectors are wrapped in arrows so a method that reads `this` on the caller's harness
  // keeps its binding. `reset` runs before every check so each starts from an empty namespace.
  await harness.reset();
  await checkPlaneSeparation(() => harness.connectAdminWithDataCredential());
  await harness.reset();
  await checkSkew(
    () => harness.connectData(),
    (nowEpochMs) => harness.setBackendClock(nowEpochMs),
  );
  await harness.reset();
  await checkLocator(() => harness.connectData());
  await harness.reset();
  await checkCumulativeCap(
    () => harness.connectData(),
    (nowEpochMs) => harness.setBackendClock(nowEpochMs),
  );
  await harness.reset();
  await checkExposure(
    () => harness.connectData(),
    () => harness.connectAdmin(),
    (nowEpochMs) => harness.setBackendClock(nowEpochMs),
  );
  await harness.reset();
  await checkAtomicityParallel(
    () => harness.connectData(),
    (nowEpochMs) => harness.setBackendClock(nowEpochMs),
  );
  await harness.reset();
  await checkFreeze(
    () => harness.connectData(),
    () => harness.connectAdmin(),
    (nowEpochMs) => harness.setBackendClock(nowEpochMs),
  );
  await harness.reset();
  await checkPins(
    () => harness.connectData(),
    () => harness.connectAdmin(),
    (nowEpochMs) => harness.setBackendClock(nowEpochMs),
  );
  await harness.reset();
  await checkAdministeredLimits(
    () => harness.connectData(),
    () => harness.connectAdmin(),
    (nowEpochMs) => harness.setBackendClock(nowEpochMs),
  );
  // Restart durability runs last (it interrupts connections) and only when the harness can drive a
  // backend restart. A harness without the hook still runs every other check (SPEC §3.6/§12.4).
  if (harness.restart !== undefined) {
    const restart = harness.restart.bind(harness);
    await harness.reset();
    await checkRestart(
      () => harness.connectData(),
      () => restart(),
      (nowEpochMs) => harness.setBackendClock(nowEpochMs),
    );
  }
}

/* v8 ignore stop */
