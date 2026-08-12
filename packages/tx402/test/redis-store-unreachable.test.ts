/**
 * U9 (S14e) / O53≡U12 (S14g/S14h): a store OUTAGE on the READ / operator-verb path must surface as
 * a typed, retryable `TransportError` — exactly as a `reserve` against the same dead store already
 * does — not an untyped ioredis `MaxRetriesPerRequestError`. This points a `RedisSpendStore` at a
 * port where nothing listens (no live Redis needed, so it runs in the default suite) and asserts
 * each read method classifies the outage as `TX402_TRANSPORT`. U9 covered `getBudgetState`/
 * `listExposed`/`isFrozen`; S14i adds the three sibling reads the S14f fix left unwrapped:
 * `getRecipientPins`/`getRecipientPolicy`/`getBudgetLimits`. Also checks O55 (the admin gate on
 * `getBudgetLimits`). (ADR-023 — a test that RUNS the behaviour.)
 */

import { Redis } from "ioredis";
import { afterEach, describe, expect, it } from "vitest";

import { ConfigurationError, TransportError, isTx402Error } from "../src/core/errors.js";
import { RedisSpendStore } from "../src/redis/store.js";

const DEAD = "redis://127.0.0.1:6399"; // nothing listens here
const NOW = 1_800_000_000_000;
const SCOPE = "outage.example";
const NETWORK = "eip155:8453";
const ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

let client: Redis | undefined;

function deadClient(): Redis {
  // Bound the retry so the test fails in ~0.5 s instead of ioredis's default ~10 s storm.
  client = new Redis(DEAD, {
    maxRetriesPerRequest: 1,
    retryStrategy: (times: number) => (times > 1 ? null : 100),
  });
  client.on("error", () => {}); // swallow connection 'error' events, as the CLI does
  return client;
}

function deadStore(): RedisSpendStore {
  return new RedisSpendStore({ client: deadClient() });
}

/** getBudgetLimits is admin-gated, so the outage test needs an admin store. */
function deadAdminStore(): RedisSpendStore {
  return new RedisSpendStore({ client: deadClient(), admin: true });
}

afterEach(() => {
  client?.disconnect();
  client = undefined;
});

function assertTypedTransport(error: unknown): void {
  expect(error).toBeInstanceOf(TransportError);
  expect(isTx402Error(error)).toBe(true);
  const tx = error as TransportError;
  expect(tx.code).toBe("TX402_TRANSPORT");
  expect(tx.retryable).toBe(true);
  // Redaction (SEC-003): the coarse category, never the DSN or the ioredis internal message.
  expect(tx.message).not.toContain("6399");
  expect(tx.message).not.toContain("ECONNREFUSED");
  expect(tx.details["causeCategory"]).toBe("spend-store-unavailable");
}

describe("RedisSpendStore read methods against an unreachable server (U9)", () => {
  it("getBudgetState throws a typed retryable TransportError", async () => {
    const store = deadStore();
    const error = await store
      .getBudgetState({ policyScope: SCOPE, assetId: ASSET, nowEpochMs: NOW })
      .then(() => undefined)
      .catch((e: unknown) => e);
    assertTypedTransport(error);
  });

  it("listExposed throws a typed retryable TransportError", async () => {
    const store = deadStore();
    const error = await store
      .listExposed({ policyScope: SCOPE, assetId: ASSET, nowEpochMs: NOW })
      .then(() => undefined)
      .catch((e: unknown) => e);
    assertTypedTransport(error);
  });

  it("isFrozen throws a typed retryable TransportError", async () => {
    const store = deadStore();
    const error = await store
      .isFrozen(SCOPE)
      .then(() => undefined)
      .catch((e: unknown) => e);
    assertTypedTransport(error);
  });

  // ── O53: the three sibling reads the S14f U9 fix left unwrapped ──────────────────────────────

  it("getRecipientPins throws a typed retryable TransportError (O53)", async () => {
    const store = deadStore();
    const error = await store
      .getRecipientPins(SCOPE, NETWORK)
      .then(() => undefined)
      .catch((e: unknown) => e);
    assertTypedTransport(error);
  });

  it("getRecipientPolicy throws a typed retryable TransportError (O53)", async () => {
    const store = deadStore();
    const error = await store
      .getRecipientPolicy(SCOPE)
      .then(() => undefined)
      .catch((e: unknown) => e);
    assertTypedTransport(error);
  });

  it("getBudgetLimits throws a typed retryable TransportError (O53, admin store)", async () => {
    const store = deadAdminStore();
    const error = await store
      .getBudgetLimits(SCOPE, ASSET)
      .then(() => undefined)
      .catch((e: unknown) => e);
    assertTypedTransport(error);
  });
});

describe("RedisSpendStore.getBudgetLimits requires an admin credential (O55)", () => {
  it("a data-plane store refuses getBudgetLimits with admin-credential-required, before connecting", async () => {
    // #requireAdmin fires before any Redis command, so this needs no live server and never
    // reaches the (dead) connection — the refusal is a typed ConfigurationError, not a transport
    // outage. Matches the DO (#verifyAdmin) and the gateway (403s a data token).
    const store = deadStore(); // admin: false
    const error = await store
      .getBudgetLimits(SCOPE, ASSET)
      .then(() => undefined)
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConfigurationError);
    expect((error as ConfigurationError).details["reason"]).toBe(
      "admin-credential-required",
    );
  });
});
