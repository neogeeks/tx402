/**
 * Deterministic store seeds for the CLI operator-verb `--json` golden.
 *
 * The five verbs act on a shared store, so their `--json` is a function of the store's *state*.
 * To pin that output byte-for-byte across the TypeScript and Python CLIs, both languages drive
 * an identical store: this module builds the state, and it is the ONE source of truth — imported
 * by the TypeScript generator/pin (in-process) and by the Node gateway subprocess the Python pin
 * spawns (`tools/store-gateway/cli.js`). Because every verb output here is amounts, scopes, and
 * recipient sets — never a reservation id or a timestamp — the state is fully deterministic, and
 * the seeded spend is always fresh (well inside the rolling window), so windowing never bites.
 *
 * `applySeed` uses only the public data/admin methods, so it seeds a `MemorySpendStore` from
 * either the built dist or the TypeScript source, and (in principle) any conformant store.
 */

/** The scope every verb scenario targets (a normalized merchant host). */
export const SEED_SCOPE = "api.merchant.example";
/** The CAIP-2 network the recipient pins and the budget asset live under. */
export const SEED_NETWORK = "eip155:8453";
/** USDC on Base — the manifest's `eip155:8453` asset, so the default-asset path matches too. */
export const SEED_ASSET_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
/** The CAIP-19 asset id the store keys budget by. */
export const SEED_ASSET_ID = `${SEED_NETWORK}/erc20:${SEED_ASSET_ADDRESS}`;

/** The two admin-allowlist recipients the `governed` seed pins (SPEC §6). */
export const SEED_PINS = [
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
];

/** Administered caps set by the `governed` seed (atomic USDC: 1 / 5 USDC). */
const ADMIN_PER_HOUR = "1000000";
const ADMIN_TOTAL = "5000000";

/** The names `applySeed` understands; the scenarios manifest references these. */
export const SEED_NAMES = ["governed", "consumed-no-limits", "empty"];

/**
 * Applies one named seed to `store` at time `now`. `governed` = administered caps + an allowlist
 * + committed/exposed spend, unfrozen; `consumed-no-limits` = the same spend with NO caps;
 * `empty` = a pristine scope.
 */
export async function applySeed(store, name, now) {
  if (name === "empty") return;

  if (name === "governed") {
    await store.setBudgetLimits(
      SEED_SCOPE,
      SEED_ASSET_ID,
      { maxPerHourAtomic: ADMIN_PER_HOUR, maxTotalAtomic: ADMIN_TOTAL },
      now,
    );
  }

  // Same spend in both non-empty seeds: 0.30 USDC committed, 0.20 USDC exposed.
  await commitSpend(store, "300000", now);
  await exposeSpend(store, "200000", now);

  if (name === "governed") {
    await store.setRecipientPins(SEED_SCOPE, SEED_NETWORK, [...SEED_PINS], now);
    // O21: the `pins` verb reports these. Set non-default (true) values — AFTER the seed's own
    // recipient-less reserves, which an `recipientAssertionRequired` would otherwise refuse — so
    // the golden proves both flags propagate, not just the false/false default.
    await store.setTofuEnabled(SEED_SCOPE, true, now);
    await store.setRecipientAssertionRequired(SEED_SCOPE, true, now);
  }
}

/** Reserve then commit `amountAtomic`, so the scope carries committed (and cumulative) spend. */
async function commitSpend(store, amountAtomic, now) {
  const { reservation } = await store.reserve({
    requestId: `seed-commit-${amountAtomic}`,
    policyScope: SEED_SCOPE,
    requestFingerprint: `seed-commit-fp-${amountAtomic}`,
    assetId: SEED_ASSET_ID,
    amountAtomic,
    maxPerHourAtomic: ADMIN_PER_HOUR,
    maxTotalAtomic: ADMIN_TOTAL,
    nowEpochMs: now,
  });
  await store.commit({
    reservationId: reservation.reservationId,
    policyScope: SEED_SCOPE,
    assetId: SEED_ASSET_ID,
    committedAtEpochMs: now,
  });
}

/** Reserve then expose `amountAtomic` (a durable pre-transmission fence, SPEC §7). */
async function exposeSpend(store, amountAtomic, now) {
  const { reservation } = await store.reserve({
    requestId: `seed-expose-${amountAtomic}`,
    policyScope: SEED_SCOPE,
    requestFingerprint: `seed-expose-fp-${amountAtomic}`,
    assetId: SEED_ASSET_ID,
    amountAtomic,
    maxPerHourAtomic: ADMIN_PER_HOUR,
    maxTotalAtomic: ADMIN_TOTAL,
    nowEpochMs: now,
  });
  await store.expose(
    {
      reservationId: reservation.reservationId,
      policyScope: SEED_SCOPE,
      assetId: SEED_ASSET_ID,
    },
    now,
  );
}
