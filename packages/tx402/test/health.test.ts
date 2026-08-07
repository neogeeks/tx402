/**
 * The unified health index and circuit breaker (SPEC §6.5, §6.4 step 17).
 *
 * The conformance vectors in `core-spec/conformance/vectors/health/` pin the arithmetic and
 * the state machine for both languages. What is tested here is the behaviour that is not
 * expressible as a vector sequence: the LRU cap, the idle-retention sweep, endpoint
 * namespacing, and the interaction of `admit` with concurrent callers.
 */

import { describe, expect, it } from "vitest";

import {
  HEALTH_IDLE_RETENTION_MS,
  HEALTH_MAX_ENDPOINTS,
  HEALTH_NEW_ENDPOINT_SCORE,
  HEALTH_OPEN_MS,
  HealthIndex,
} from "../src/core/health.js";

const T = 1_785_715_200_000;
const A = "eip155:8453|a.example.com";
const B = "eip155:8453|b.example.com";

describe("HealthIndex scoring", () => {
  it("starts an unseen endpoint at 0.80 and reports it closed", () => {
    const health = new HealthIndex();
    expect(health.score(A, T)).toBe(HEALTH_NEW_ENDPOINT_SCORE);
    expect(health.state(A, T)).toBe("closed");
    expect(health.inspect(A, T)).toEqual({
      endpointId: A,
      circuitState: "closed",
      healthScore: 0.8,
      observedLatencyMs: undefined,
      consecutiveFailures: 0,
      sampleCount: 0,
    });
    // Reading an unknown endpoint must not create an entry — otherwise a diagnostics call
    // would consume LRU capacity that belongs to endpoints tx402 actually used.
    expect(health.size).toBe(0);
  });

  it("penalizes latency up to the cap and never leaves [0, 1]", () => {
    const fast = new HealthIndex();
    const slow = new HealthIndex();
    fast.recordSuccess(A, 0, T);
    slow.recordSuccess(A, 60_000, T);

    // Same success history, so the whole difference is the latency penalty, and the penalty
    // is capped at 0.20 no matter how far past the 600 ms budget the endpoint is.
    expect(fast.score(A, T)).toBe(0.84);
    expect(slow.score(A, T)).toBe(0.64);
    expect(slow.score(A, T)).toBeGreaterThanOrEqual(0);
  });

  it("scores each namespaced endpoint separately", () => {
    const health = new HealthIndex();
    const base = HealthIndex.endpointId("eip155:8453", "rpc.example.com");
    const solana = HealthIndex.endpointId(
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      "rpc.example.com",
    );
    expect(base).not.toBe(solana);

    for (let index = 0; index < 5; index += 1) health.recordFailure(base, T + index);
    // One provider serving two chains can be broken on one and healthy on the other.
    expect(health.state(base, T + 4)).toBe("open");
    expect(health.state(solana, T + 4)).toBe("closed");
  });
});

describe("HealthIndex circuit", () => {
  it("hands out exactly one half-open probe and re-opens when it fails", () => {
    const health = new HealthIndex();
    for (let index = 0; index < 5; index += 1) health.recordFailure(A, T);
    expect(health.state(A, T)).toBe("open");

    const halfOpenAt = T + HEALTH_OPEN_MS;
    expect(health.admit(A, halfOpenAt)).toBe("half-open");
    // The one probe is taken; a concurrent caller is refused rather than doubling up.
    expect(health.admit(A, halfOpenAt)).toBe("open");

    health.recordFailure(A, halfOpenAt);
    // A failed probe re-opens immediately, without waiting for another five failures.
    expect(health.state(A, halfOpenAt)).toBe("open");
    expect(health.state(A, halfOpenAt + HEALTH_OPEN_MS - 1)).toBe("open");
    expect(health.state(A, halfOpenAt + HEALTH_OPEN_MS)).toBe("half-open");
  });

  it("admits a closed endpoint without consuming a probe", () => {
    const health = new HealthIndex();
    expect(health.admit(A, T)).toBe("closed");
    health.recordSuccess(A, 10, T);
    expect(health.admit(A, T)).toBe("closed");
    expect(health.admit(A, T)).toBe("closed");
  });

  it("opens immediately on a chain-identity failure regardless of the window", () => {
    const health = new HealthIndex();
    // SPEC §7.1/§7.2: one wrong-chain answer is enough. This is the only caller of `open`.
    health.open(A, T);
    expect(health.state(A, T)).toBe("open");
    expect(health.inspect(A, T).consecutiveFailures).toBe(1);
  });

  it("clears the failure history when a probe closes the circuit", () => {
    const health = new HealthIndex();
    for (let index = 0; index < 5; index += 1) health.recordFailure(A, T);
    health.recordSuccess(A, 20, T + HEALTH_OPEN_MS);

    expect(health.state(A, T + HEALTH_OPEN_MS)).toBe("closed");
    expect(health.inspect(A, T + HEALTH_OPEN_MS).sampleCount).toBe(1);
    // The next single failure must not re-open a recovered endpoint.
    health.recordFailure(A, T + HEALTH_OPEN_MS + 1);
    expect(health.state(A, T + HEALTH_OPEN_MS + 1)).toBe("closed");
  });
});

describe("HealthIndex retention", () => {
  it("keeps at most 128 endpoints, evicting the least recently used", () => {
    const health = new HealthIndex();
    for (let index = 0; index < HEALTH_MAX_ENDPOINTS + 10; index += 1) {
      health.recordSuccess(`eip155:8453|host-${index}.example.com`, 5, T);
    }
    expect(health.size).toBe(HEALTH_MAX_ENDPOINTS);
    // The first ten are gone; the most recent survive.
    expect(health.score("eip155:8453|host-0.example.com", T)).toBe(
      HEALTH_NEW_ENDPOINT_SCORE,
    );
    expect(
      health.score(`eip155:8453|host-${HEALTH_MAX_ENDPOINTS + 9}.example.com`, T),
    ).not.toBe(HEALTH_NEW_ENDPOINT_SCORE);
  });

  it("respects recency rather than insertion order when evicting", () => {
    const health = new HealthIndex({ maxEndpoints: 2 });
    health.recordSuccess(A, 5, T);
    health.recordSuccess(B, 5, T);
    // Touch A so B becomes the least recently used.
    health.recordSuccess(A, 5, T + 1);
    health.recordSuccess("eip155:8453|c.example.com", 5, T + 2);

    expect(health.score(B, T + 2)).toBe(HEALTH_NEW_ENDPOINT_SCORE);
    expect(health.score(A, T + 2)).not.toBe(HEALTH_NEW_ENDPOINT_SCORE);
  });

  it("drops endpoints idle for 30 minutes", () => {
    const health = new HealthIndex();
    health.recordFailure(A, T);
    expect(health.size).toBe(1);

    // The sweep runs when the index is next written to, which is the only moment its size
    // can grow — so retention is bounded without a timer holding the process open.
    health.recordSuccess(B, 5, T + HEALTH_IDLE_RETENTION_MS);
    expect(health.size).toBe(1);
    expect(health.score(A, T + HEALTH_IDLE_RETENTION_MS)).toBe(HEALTH_NEW_ENDPOINT_SCORE);
  });

  it("forgets one endpoint and resets all of them", () => {
    const health = new HealthIndex();
    health.recordFailure(A, T);
    health.recordFailure(B, T);

    health.forget(A);
    expect(health.size).toBe(1);
    expect(health.score(A, T)).toBe(HEALTH_NEW_ENDPOINT_SCORE);

    health.reset();
    expect(health.size).toBe(0);
    expect(health.score(B, T)).toBe(HEALTH_NEW_ENDPOINT_SCORE);
  });
});
