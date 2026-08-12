#!/usr/bin/env node
/**
 * The unified deterministic adversarial driver (PRD-phase1 §27).
 *
 *   pnpm build && pnpm adversarial
 *   TX402_ADVERSARIAL_SEED=123 pnpm adversarial   # only reorders the concurrency fan-out
 *
 * PRD-phase1 §27 asks for **one deterministic, offline run** that composes the adversarial
 * axes a fleet actually faces — concurrency, store failure, signer failure, budget
 * exhaustion, and freeze — rather than proving each in isolation. This is that run. It drives
 * the **shipped** buyer SDK (imported from `dist`, nothing mocked inside tx402) against the
 * real synthetic stack — `tools/test-merchant`, `tools/evm-rpc-stub`, and the new
 * `tools/mock-facilitator` (the offline `/verify`+`/settle` stub §27 also calls for) — and
 * asserts the Phase-1 product invariants (PRD §28, INV-1…INV-7) hold under each attack.
 *
 * Why a driver and not more unit tests: the unit and conformance suites pin each mechanism;
 * this proves they still hold when the mechanisms are stacked and money is on the line, and
 * it does so **offline** — no testnet, no funds, no network beyond three localhost servers —
 * so it is safe to run on every push. Determinism is deliberate: a fixed signer key, a
 * steppable clock, and a pure settlement stub mean a violation reproduces byte-for-byte.
 *
 * The invariant behind every scenario: **a governed payment is never silently converted into
 * an ungoverned one.** Every adversarial condition must end in either a correct settled
 * payment or a *typed* refusal with the budget conserved — never a signature the policy did
 * not authorize, never budget that leaked, never an exposed amount that escaped the cap.
 *
 * S12 adds no conformance vector and no error code (those stay 88 / 17): this is a driver
 * over behaviour the vectors already pin, composed the way an operator's fleet composes it.
 */

import { BUNDLED_MANIFEST } from "../../packages/tx402/dist/core/bundled-manifest.js";
import { createTx402Client } from "../../packages/tx402/dist/index.js";
import { isTx402Error } from "../../packages/tx402/dist/core/errors.js";
import { MemorySpendStore } from "../../packages/tx402/dist/core/ledger.js";
import { normalizePolicyHost } from "../../packages/tx402/dist/core/policy.js";
import { privateKeyToEvmSigner } from "../../packages/tx402/dist/signers/index.js";

import { createEvmRpcStub } from "../evm-rpc-stub/index.js";
import { createMockFacilitator } from "../mock-facilitator/index.js";
import { createTestMerchant } from "../test-merchant/index.js";

// --- the merchant's offer, and the manifest facts the buyer verifies against ------------

const BASE = BUNDLED_MANIFEST.networks["eip155:8453"];
const USDC = BASE.assets[0];
/** Manifest RPC hosts, redirected to the local stub by the fetch shim below. */
const RPC_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));
const PAY_TO = "0x1234567890AbcdEF1234567890aBcdef12345678";
const OTHER_RECIPIENT = "0x000000000000000000000000000000000000dEaD";

/** Base USDC, 0.05, with the EIP-712 domain the exact scheme needs. */
const REQUIREMENT = {
  scheme: "exact",
  network: "eip155:8453",
  asset: USDC.address,
  amount: "50000", // 0.05 USDC in atomic units
  payTo: PAY_TO,
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

/** A fixed key, so the signature — and therefore the whole run — is reproducible. */
const SIGNER_KEY = `0x${"42".repeat(32)}`;
const ONE_HOUR_MS = 3_600_000;

const SEED = Number(process.env["TX402_ADVERSARIAL_SEED"] ?? 0x7a402);

/** xorshift32, only used to fan the concurrency scenario out in a seeded order. */
function rng(seed) {
  let state = seed || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 2 ** 32;
  };
}
const random = rng(SEED);

/**
 * A clock whose wall time the caller advances by hand, so budget windows and the exposed-TTL
 * are exercised without waiting. `monotonic` stays real — it feeds only duration metrics.
 *
 * The fixed start (2026-09-01Z) sits inside the bundled release manifest's validity window
 * (`assertValidReleaseManifest` is checked against `clock.now()` at construction), and leaves
 * ample room ahead of it for the multi-hour advances the budget and exposure scenarios make.
 */
function steppableClock(startMs = 1_788_220_800_000) {
  let nowMs = startMs;
  return {
    clock: { now: () => nowMs, monotonic: () => performance.now() },
    advance: (ms) => {
      nowMs += ms;
    },
  };
}

/** A funded EVM signer that counts its signatures without ever retaining one. */
function countingSigner() {
  const inner = privateKeyToEvmSigner(SIGNER_KEY);
  const signer = {
    kind: "evm",
    signCount: 0,
    getAddress: () => inner.getAddress(),
    signTypedData: (request) => {
      signer.signCount += 1;
      return inner.signTypedData(request);
    },
  };
  return signer;
}

/** A signer that refuses. The client must release and classify, never leave budget reserved. */
function refusingSigner() {
  const inner = privateKeyToEvmSigner(SIGNER_KEY);
  return {
    kind: "evm",
    getAddress: () => inner.getAddress(),
    signTypedData: () => Promise.reject(new Error("seeded signer refusal")),
  };
}

/**
 * Wraps a real `MemorySpendStore`, logging each data-plane transition so a scenario can prove
 * the ordering — and, with `failOn`, that a store failure mid-flow is handled by releasing the
 * reservation rather than leaking it or committing anyway. `getBudgetState`/`isFrozen` delegate
 * untouched, so the wrapper is a faithful store the client can also read back through.
 */
function recordingStore({ failOn } = {}) {
  const inner = new MemorySpendStore();
  const log = [];
  const step =
    (name, run) =>
    (...args) => {
      log.push(name);
      if (failOn === name) return Promise.reject(new Error(`seeded ${name} failure`));
      return run(...args);
    };
  return {
    log,
    inner,
    store: {
      kind: failOn === undefined ? "recording" : `${failOn}-explodes`,
      capabilities: inner.capabilities,
      reserve: step("reserve", (input) => inner.reserve(input)),
      commit: step("commit", (input) => inner.commit(input)),
      release: step("release", (ref, now) => inner.release(ref, now)),
      expose: step("expose", (ref, now) => inner.expose(ref, now)),
      getBudgetState: (query) => inner.getBudgetState(query),
      listExposed: (query) => inner.listExposed(query),
      isFrozen: (scope) => inner.isFrozen(scope),
    },
  };
}

// --- the fetch shim: manifest RPC hosts to the active local stub, all else untouched -----

let activeRpcUrl = null;
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const request = new Request(input, init);
  const host = new URL(request.url).host;
  if (activeRpcUrl !== null && RPC_HOSTS.has(host)) {
    return realFetch(activeRpcUrl, {
      method: request.method,
      headers: request.headers,
      body: await request.text(),
    });
  }
  return realFetch(request);
};

/** Starts a local EVM stub funding `payer` and makes it the shim's target. */
async function startRpc(payer) {
  const rpc = await createEvmRpcStub({
    chainId: 8453,
    token: USDC.address,
    balances: { [payer]: "100000000" }, // 100 USDC, ample for any scenario
  });
  activeRpcUrl = rpc.url;
  return rpc;
}

const DEFAULT_POLICY = {
  maxPerRequest: "0.50 USDC",
  maxPerHour: "10.00 USDC",
  allowedNetworks: ["eip155:8453"],
};

function buildClient({ store, signer, policy, recipientPolicy, clock, logger }) {
  return createTx402Client({
    signers: { evm: signer },
    spendStore: store,
    allowInsecureLocalhost: true,
    clock,
    ...(logger === undefined ? {} : { logger }),
    ...(recipientPolicy === undefined ? {} : { recipientPolicy }),
    policy: { ...DEFAULT_POLICY, ...policy },
  });
}

/** Collects the warn/info events a scenario wants to assert on. */
function recordingLogger() {
  const events = [];
  const at = (level) => (event) => events.push({ level, event: { ...event } });
  return {
    events,
    logger: { debug: at("debug"), info: at("info"), warn: at("warn"), error: at("error") },
  };
}

const settle = (promise) =>
  promise.then(
    (value) => ({ value }),
    (error) => ({ error }),
  );

// --- assertion harness (fuzz-style: collect, summarize, exit 1 on any violation) --------

const failures = [];
let checks = 0;
let scenarioName = "";
function check(description, condition) {
  checks += 1;
  if (!condition) failures.push(`[${scenarioName}] ${description}`);
}

// --- scenario A: true in-process concurrency cannot exceed the shared cap (INV-2) --------

async function concurrency() {
  scenarioName = "concurrency / shared cap (INV-2)";
  const store = new MemorySpendStore();
  const signer = countingSigner();
  const merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
  });
  const rpc = await startRpc(await signer.getAddress());
  const { clock } = steppableClock();
  // A per-hour cap that admits exactly three 0.05 reservations. Eight workers race for it.
  const tx402 = buildClient({
    store,
    signer,
    clock,
    policy: { maxPerRequest: "0.05 USDC", maxPerHour: "0.15 USDC" },
  });

  const fanOut = Array.from({ length: 8 }, (_, index) => index).sort(() => random() - 0.5);
  const results = await Promise.all(
    fanOut.map(() => settle(tx402.fetch(`${merchant.url}/resource`))),
  );

  const admitted = results.filter((r) => r.value?.status === 200).length;
  const refused = results.filter(
    (r) =>
      r.error !== undefined &&
      isTx402Error(r.error) &&
      r.error.code === "TX402_POLICY_BUDGET",
  ).length;

  check("exactly three of eight workers are admitted", admitted === 3);
  check("the other five are refused with TX402_POLICY_BUDGET", refused === 5);
  check("exactly three signatures — no over-authorization", signer.signCount === 3);
  check(
    "exactly three paid requests reach the merchant",
    merchant.paidRequests.length === 3,
  );

  await merchant.close();
  await rpc.close();
}

// --- scenario B1: a store outage fails closed, before the signer (INV-7) -----------------

async function storeOutage() {
  scenarioName = "store outage / fail-closed (INV-7)";
  const signer = countingSigner();
  const merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
  });
  const rpc = await startRpc(await signer.getAddress());
  const { clock } = steppableClock();
  // A store whose *reserve* is out (SS-11 / O46): the pre-flight reads answer, so the failure
  // is classified as a reserve outage rather than a generic runtime fault.
  const broken = {
    kind: "broken",
    capabilities: { atomicGlobalFreeze: true },
    reserve: () => Promise.reject(new Error("seeded store failure")),
    commit: () => Promise.reject(new Error("unused")),
    release: () => Promise.reject(new Error("unused")),
    expose: () => Promise.reject(new Error("unused")),
    listExposed: () => Promise.reject(new Error("unused")),
    isFrozen: () => Promise.resolve(false),
    getBudgetState: () =>
      new MemorySpendStore().getBudgetState({
        policyScope: "scope",
        assetId: "asset",
        nowEpochMs: clock.now(),
      }),
  };
  const tx402 = buildClient({ store: broken, signer, clock });

  const { error } = await settle(tx402.fetch(`${merchant.url}/resource`));
  check(
    "a store that cannot reserve raises a retryable TX402_TRANSPORT",
    isTx402Error(error) && error.code === "TX402_TRANSPORT" && error.retryable === true,
  );
  check(
    "the cause is spend-store-unavailable, tagged with the store kind",
    error?.details?.causeCategory === "spend-store-unavailable" &&
      error?.details?.storeKind === "broken",
  );
  check("nothing was signed when the budget could not be reserved", signer.signCount === 0);
  check("nothing was transmitted", merchant.paidRequests.length === 0);

  await merchant.close();
  await rpc.close();
}

// --- scenario B2: an exposure-fence failure aborts with nothing sent (INV-7) -------------

async function fenceFailure() {
  scenarioName = "exposure-fence failure / fail-closed (INV-7)";
  const { store, log } = recordingStore({ failOn: "expose" });
  const signer = countingSigner();
  const merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
  });
  const rpc = await startRpc(await signer.getAddress());
  const { clock } = steppableClock();
  const tx402 = buildClient({ store, signer, clock });

  const { error } = await settle(tx402.fetch(`${merchant.url}/resource`));
  check(
    "a fence write that fails raises a retryable TX402_TRANSPORT",
    isTx402Error(error) && error.code === "TX402_TRANSPORT" && error.retryable === true,
  );
  check(
    "the cause is exposure-fence-failed",
    error?.details?.causeCategory === "exposure-fence-failed",
  );
  check(
    "the reservation is released, never committed",
    log.includes("release") && !log.includes("commit"),
  );
  check(
    "the signature was built but never transmitted",
    merchant.paidRequests.length === 0,
  );

  await merchant.close();
  await rpc.close();
}

// --- scenario C: a refusing signer releases and classifies (INV-1) -----------------------

async function signerFailure() {
  scenarioName = "signer refusal (INV-1)";
  const { store, log } = recordingStore();
  const merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
  });
  const signer = refusingSigner();
  const rpc = await startRpc(await signer.getAddress());
  const { clock } = steppableClock();
  const tx402 = buildClient({ store, signer, clock });

  const { error } = await settle(tx402.fetch(`${merchant.url}/resource`));
  check(
    "a signer that refuses surfaces as a signer-rejected transport error",
    isTx402Error(error) && error?.details?.causeCategory === "signer-rejected",
  );
  check("no paid request is transmitted", merchant.paidRequests.length === 0);
  check(
    "the reservation is released before the fence, never exposed or committed",
    log.includes("reserve") &&
      log.includes("release") &&
      !log.includes("expose") &&
      !log.includes("commit"),
  );

  await merchant.close();
  await rpc.close();
}

// --- scenario D: both caps bind; the per-hour one rolls, the cumulative one does not (INV-2)

async function budgetExhaustion() {
  scenarioName = "budget exhaustion, per-hour + cumulative (INV-2)";
  const store = new MemorySpendStore();
  const signer = countingSigner();
  const merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
  });
  const rpc = await startRpc(await signer.getAddress());
  const { clock, advance } = steppableClock();
  // Two 0.05 payments per rolling hour; three over the lifetime. After the window rolls the
  // per-hour term resets to zero but the lifetime total does not — so the cumulative cap can
  // bind while the per-hour cap still has headroom, isolating the two.
  const tx402 = buildClient({
    store,
    signer,
    clock,
    policy: { maxPerRequest: "0.05 USDC", maxPerHour: "0.10 USDC", maxTotal: "0.15 USDC" },
  });
  const call = () => settle(tx402.fetch(`${merchant.url}/resource`));

  const first = await call();
  const secondSameHour = await call();
  check(
    "two 0.05 payments fit the first hour",
    first.value?.status === 200 &&
      secondSameHour.value?.status === 200 &&
      signer.signCount === 2,
  );

  const perHour = await call();
  check(
    "a third call in the same hour is refused: capKind per-hour",
    isTx402Error(perHour.error) &&
      perHour.error.code === "TX402_POLICY_BUDGET" &&
      perHour.error.details?.capKind === "per-hour",
  );
  check("the refused per-hour call signs nothing", signer.signCount === 2);

  advance(ONE_HOUR_MS + 1); // the rolling window resets; the lifetime total does not
  const rolled = await call();
  check(
    "after the hour rolls, the third lifetime payment settles",
    rolled.value?.status === 200 && signer.signCount === 3,
  );

  const cumulative = await call();
  check(
    "the fourth lifetime call is refused with per-hour headroom to spare: capKind cumulative",
    isTx402Error(cumulative.error) &&
      cumulative.error.code === "TX402_POLICY_BUDGET" &&
      cumulative.error.details?.capKind === "cumulative",
  );
  check("the refused cumulative call signs nothing", signer.signCount === 3);

  await merchant.close();
  await rpc.close();
}

// --- scenario E: a frozen scope authorizes nothing; unfreeze restores it (INV-3) ---------

async function killSwitch() {
  scenarioName = "kill switch / freeze (INV-3)";
  const store = new MemorySpendStore();
  const signer = countingSigner();
  const merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
  });
  const rpc = await startRpc(await signer.getAddress());
  const { clock } = steppableClock();
  const { events, logger } = recordingLogger();
  const tx402 = buildClient({ store, signer, clock, logger });

  const before = await settle(tx402.fetch(`${merchant.url}/resource`));
  check(
    "spending is admitted before the freeze",
    before.value?.status === 200 && signer.signCount === 1,
  );

  await store.freeze("*"); // atomicGlobalFreeze is true for MemorySpendStore
  const frozen = await settle(tx402.fetch(`${merchant.url}/resource`));
  check(
    "a frozen scope refuses with a non-retryable TX402_SPEND_FROZEN",
    isTx402Error(frozen.error) &&
      frozen.error.code === "TX402_SPEND_FROZEN" &&
      frozen.error.retryable === false,
  );
  check("the freeze refusal precedes the signer — nothing signed", signer.signCount === 1);
  check("nothing is transmitted under freeze", merchant.paidRequests.length === 1);
  const frozenEvents = events.filter((e) => e.event.event === "spend.frozen");
  check(
    "exactly one spend.frozen event, at warn",
    frozenEvents.length === 1 && frozenEvents[0]?.level === "warn",
  );

  await store.unfreeze("*");
  const after = await settle(tx402.fetch(`${merchant.url}/resource`));
  check(
    "unfreeze readmits spending",
    after.value?.status === 200 && signer.signCount === 2,
  );

  await merchant.close();
  await rpc.close();
}

// --- scenario F: a recipient the store does not pin is refused before the signer (INV-4) --

async function recipientMismatch() {
  scenarioName = "recipient mismatch (INV-4)";
  const store = new MemorySpendStore();
  const signer = countingSigner();
  const merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
  });
  const rpc = await startRpc(await signer.getAddress());
  const { clock } = steppableClock();
  const { events, logger } = recordingLogger();
  // An operator pins a DIFFERENT recipient; the client always sends the merchant's payTo, so
  // the authoritative in-reserve assertion refuses it regardless of the caller's mode.
  await store.setRecipientPins(normalizePolicyHost(merchant.url), "eip155:8453", [
    OTHER_RECIPIENT,
  ]);
  const tx402 = buildClient({ store, signer, clock, logger });

  const { error } = await settle(tx402.fetch(`${merchant.url}/resource`));
  check(
    "a merchant whose payout is not pinned is refused with TX402_RECIPIENT_UNPINNED",
    isTx402Error(error) &&
      error.code === "TX402_RECIPIENT_UNPINNED" &&
      error.retryable === false,
  );
  check(
    "the recipient refusal precedes the signer — nothing signed",
    signer.signCount === 0,
  );
  check(
    "nothing is transmitted to an unpinned recipient",
    merchant.paidRequests.length === 0,
  );
  const rejected = events.filter((e) => e.event.event === "recipient.rejected");
  check(
    "exactly one recipient.rejected event, at warn",
    rejected.length === 1 && rejected[0]?.level === "warn",
  );

  await merchant.close();
  await rpc.close();
}

// --- scenario G: an exposed amount keeps consuming the cap and cannot escape by expiring (INV-2)

async function exposureNoEscape() {
  scenarioName = "exposure no-escape (INV-2)";
  const store = new MemorySpendStore();
  const signer = countingSigner();
  // A 5xx after the signature is transmitted: the outcome is unknown, the reservation is
  // fenced to `exposed`, and neither commit nor release runs.
  const merchant = await createTestMerchant({
    scenario: "error-after-signature",
    requirements: [REQUIREMENT],
  });
  const rpc = await startRpc(await signer.getAddress());
  const { clock, advance } = steppableClock();
  // A cumulative ceiling of exactly one 0.05 payment. The rolling hour would let an *expired*
  // reservation's slot be reused; the lifetime cap is what a maybe-settled payment must never
  // escape, so this is the cap the no-escape property is asserted against.
  const tx402 = buildClient({
    store,
    signer,
    clock,
    policy: { maxPerRequest: "0.05 USDC", maxPerHour: "0.05 USDC", maxTotal: "0.05 USDC" },
  });

  const { error } = await settle(tx402.fetch(`${merchant.url}/resource`));
  check(
    "an outcome unknown after transmission is TX402_PAYMENT_AMBIGUOUS",
    isTx402Error(error) && error.code === "TX402_PAYMENT_AMBIGUOUS",
  );

  // The self-describing snapshot reports the exposed amount for the scope+asset just paid.
  const exposed = tx402.getBudgetState();
  check(
    "the amount is held as exposed, counted once against the lifetime total",
    exposed.exposedAtomic === "50000" && exposed.cumulativeConsumedAtomic === "50000",
  );

  // Advance well past both the 120 s reservation TTL and the rolling hour. A never-transmitted
  // reservation would have freed its slot by now; the exposed one must not, because it is still
  // counted against the lifetime total — so a fresh reserve is refused on the cumulative cap.
  advance(2 * ONE_HOUR_MS);
  const followUp = await settle(tx402.fetch(`${merchant.url}/resource`));
  check(
    "a later payment is refused on the cumulative cap — the exposed amount never escaped by expiring",
    isTx402Error(followUp.error) &&
      followUp.error.code === "TX402_POLICY_BUDGET" &&
      followUp.error.details?.capKind === "cumulative",
  );
  check("the refused follow-up signs nothing", signer.signCount === 1);

  await merchant.close();
  await rpc.close();
}

// --- scenario H: the offline mock facilitator settles and declines deterministically ------

async function offlineFacilitator() {
  scenarioName = "offline mock facilitator (settle vs decline)";

  // H1 — a successful settle through the real /verify+/settle wire commits the payment.
  {
    const signer = countingSigner();
    const facilitator = await createMockFacilitator({ mode: "settle" });
    const merchant = await createTestMerchant({
      scenario: "pay-once",
      requirements: [REQUIREMENT],
      facilitatorUrl: facilitator.url,
    });
    const rpc = await startRpc(await signer.getAddress());
    const { clock } = steppableClock();
    const tx402 = buildClient({ store: new MemorySpendStore(), signer, clock });

    const { value } = await settle(tx402.fetch(`${merchant.url}/resource`));
    check("a facilitator-settled call delivers 200", value?.status === 200);
    check(
      "the offline facilitator ran the /verify then /settle wire",
      facilitator.calls.map((c) => c.path).join(",") === "/verify,/settle",
    );
    check(
      "a settled payment is committed",
      tx402.getBudgetState().committedAtomic === "50000",
    );

    await merchant.close();
    await rpc.close();
    await facilitator.close();
  }

  // H2 — a declined settlement leaves no committed budget behind.
  {
    const { store, log } = recordingStore();
    const signer = countingSigner();
    const facilitator = await createMockFacilitator({ mode: "decline" });
    const merchant = await createTestMerchant({
      scenario: "pay-once",
      requirements: [REQUIREMENT],
      facilitatorUrl: facilitator.url,
    });
    const rpc = await startRpc(await signer.getAddress());
    const { clock } = steppableClock();
    const tx402 = buildClient({ store, signer, clock, policy: { maxPaidAttempts: 1 } });

    const { error } = await settle(tx402.fetch(`${merchant.url}/resource`));
    check("a declined settlement ends in a typed refusal", isTx402Error(error));
    check(
      "the decline was seen at the /settle step, offline",
      facilitator.calls.some((c) => c.path === "/settle"),
    );
    check("a settlement the facilitator declined commits nothing", !log.includes("commit"));
    // The exposed reservation is RELEASED, not leaked: a no-op release would strand the exposure.
    check("a declined settlement releases the reservation", log.includes("release"));
    const budget = tx402.getBudgetState();
    check(
      "a declined settlement conserves budget: nothing committed, reserved, or exposed",
      budget.committedAtomic === "0" &&
        budget.reservedAtomic === "0" &&
        (budget.exposedAtomic ?? "0") === "0",
    );

    await merchant.close();
    await rpc.close();
    await facilitator.close();
  }
}

// --- mutation self-test: prove the guards can FAIL (falsifiability, O29) -----------------
//
// A green driver is only trustworthy if its assertions have teeth. This mode injects the two
// mutations S13 demonstrated used to false-pass — a one-byte `0x00` "signature", and a no-op
// release that leaks exposure — and asserts each is now CAUGHT: the mock-facilitator refuses the
// malformed/mis-bound authorization, and the strengthened H2 conservation check sees the leak.
async function selftest() {
  let broken = 0;
  const mustFail = (guardHolds, why) => {
    if (!guardHolds) {
      console.error(`  ✗ selftest: ${why}`);
      broken += 1;
    }
  };

  // (1) The facilitator's /verify settles a valid authorization and REFUSES a malformed / mis-bound
  //     one — the seam a one-byte signer or a mis-bound payload would otherwise sail through.
  const facilitator = await createMockFacilitator({ mode: "settle" });
  const verify = async (paymentPayload) => {
    const res = await fetch(`${facilitator.url}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        x402Version: 2,
        paymentPayload,
        paymentRequirements: REQUIREMENT,
      }),
    });
    return (await res.json()).isValid === true;
  };
  const auth = (over = {}) => ({
    from: `0x${"11".repeat(20)}`,
    to: REQUIREMENT.payTo,
    value: REQUIREMENT.amount,
    validAfter: "0",
    validBefore: "9999999999",
    nonce: `0x${"22".repeat(32)}`,
    ...over,
  });
  const payload = (sig = `0x${"ab".repeat(65)}`, over = {}) => ({
    x402Version: 2,
    accepted: {
      scheme: "exact",
      network: "eip155:8453",
      asset: REQUIREMENT.asset,
      amount: REQUIREMENT.amount,
      payTo: REQUIREMENT.payTo,
    },
    payload: { signature: sig, authorization: auth(over) },
  });
  mustFail(
    await verify(payload()),
    "a well-formed, correctly-bound authorization must verify",
  );
  mustFail(!(await verify(payload("0x00"))), "a one-byte signature must be refused");
  mustFail(
    !(await verify(payload(undefined, { to: OTHER_RECIPIENT }))),
    "a wrong-recipient authorization must be refused",
  );
  mustFail(
    !(await verify(payload(undefined, { value: "1" }))),
    "a wrong-amount authorization must be refused",
  );
  await facilitator.close();

  // (2) The H2 conservation check has teeth: an exposed hold that is NOT released leaves
  //     exposedAtomic non-zero — exactly the condition H2 now asserts is "0". A no-op release is
  //     therefore caught.
  const store = new MemorySpendStore();
  const assetId = "eip155:8453/erc20:" + REQUIREMENT.asset;
  const now = 1_788_220_800_000;
  const reserved = (
    await store.reserve({
      reservationId: "st-1",
      requestId: "st-1",
      policyScope: "merchant.example",
      requestFingerprint: `sha256:${"0".repeat(64)}`,
      assetId,
      amountAtomic: "50000",
      maxPerHourAtomic: "1000000",
      nowEpochMs: now,
    })
  ).reservation;
  await store.expose(
    { reservationId: reserved.reservationId, policyScope: reserved.policyScope, assetId },
    now,
  );
  const leaked = await store.getBudgetState({
    policyScope: "merchant.example",
    assetId,
    nowEpochMs: now,
  });
  mustFail(
    leaked.exposedAtomic === "50000",
    "an un-released exposed hold must leave exposedAtomic non-zero (so H2 catches a no-op release)",
  );

  if (broken > 0) {
    console.error(
      `\nadversarial selftest: ${broken} guard(s) could NOT fail — driver not trusted`,
    );
    process.exit(1);
  }
  console.log("OK    adversarial selftest green — every mutation guard can fail (O29)");
}

// --- run ---------------------------------------------------------------------------------

const SCENARIOS = [
  concurrency,
  storeOutage,
  fenceFailure,
  signerFailure,
  budgetExhaustion,
  killSwitch,
  recipientMismatch,
  exposureNoEscape,
  offlineFacilitator,
];

if (process.argv[2] === "selftest") {
  await selftest();
} else {
  const started = performance.now();
  console.log(`tx402 adversarial driver (PRD-phase1 §27) — seed ${SEED}\n`);
  for (const scenario of SCENARIOS) {
    const before = failures.length;
    await scenario();
    const ok = failures.length === before;
    console.log(`  ${ok ? "PASS" : "FAIL"}  ${scenarioName}`);
  }
  const elapsed = Math.round(performance.now() - started);

  console.log(`\n${SCENARIOS.length} scenarios, ${checks} assertions in ${elapsed} ms`);

  if (failures.length > 0) {
    console.error(`\n${failures.length} invariant violation(s). Reproduce with:`);
    console.error(`  TX402_ADVERSARIAL_SEED=${SEED} pnpm adversarial\n`);
    for (const failure of failures) console.error(`  ✗ ${failure}`);
    process.exit(1);
  }

  console.log(
    "adversarial: PASS — every attack ended in a settled payment or a typed refusal",
  );
}
