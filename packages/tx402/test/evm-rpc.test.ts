/**
 * RPC contract tests against the local stub (SPEC §7.1, §6.5, §9.1).
 *
 * The rule under test is the one SPEC §7.1 states as a MUST: the chain ID an RPC reports has
 * to equal the candidate's before anything it says is trusted, and a mismatch opens that
 * endpoint's circuit and moves to the next RPC. SPEC §9.1 names the threat it defends
 * against — a provider answering for the wrong chain.
 */

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { afterEach, describe, expect, it } from "vitest";

import { CIRCUIT_OPEN_MS } from "../src/core/chain.js";
import { HealthIndex } from "../src/core/health.js";
import { EvmRpcError, EvmRpcPool } from "../src/evm/rpc.js";

const TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const OWNER = "0x1111111111111111111111111111111111111111";
const NOW = 1_785_000_000_000;

const open: EvmRpcStub[] = [];

async function stub(options: Parameters<typeof createEvmRpcStub>[0] = {}) {
  const instance = await createEvmRpcStub({ chainId: 8453, token: TOKEN, ...options });
  open.push(instance);
  return instance;
}

afterEach(async () => {
  await Promise.all(open.splice(0).map((instance) => instance.close()));
});

describe("EvmRpcPool", () => {
  it("verifies the chain ID before returning a balance", async () => {
    const rpc = await stub({ balances: { [OWNER]: "5000000" } });
    const pool = new EvmRpcPool([rpc.url]);

    const reading = await pool.readBalance({
      chainId: 8453,
      token: TOKEN,
      owner: OWNER,
      nowEpochMs: NOW,
    });

    expect(reading).toMatchObject({ balanceAtomic: 5_000_000n, chainId: 8453 });
    expect(reading.endpoint).toBe(`127.0.0.1:${rpc.port}`);
    // Chain identity is established on the same endpoint that serves the balance, and on
    // every read — a cached verification would only ever prove a previous answer.
    expect(rpc.calls.map((call) => call.method)).toEqual(["eth_chainId", "eth_call"]);
  });

  it("opens a mismatching endpoint's circuit and uses the next RPC", async () => {
    const spoofing = await stub({ mode: "wrong-chain", wrongChainId: 1 });
    const honest = await stub({ balances: { [OWNER]: "250000" } });
    const pool = new EvmRpcPool([spoofing.url, honest.url]);

    const reading = await pool.readBalance({
      chainId: 8453,
      token: TOKEN,
      owner: OWNER,
      nowEpochMs: NOW,
    });

    expect(reading.balanceAtomic).toBe(250_000n);
    expect(reading.endpoint).toBe(`127.0.0.1:${honest.port}`);
    // The spoofing endpoint was never asked for a balance.
    expect(spoofing.calls.map((call) => call.method)).toEqual(["eth_chainId"]);

    // Its circuit is open for 30 s, so the next read skips it entirely.
    spoofing.reset();
    await pool.readBalance({
      chainId: 8453,
      token: TOKEN,
      owner: OWNER,
      nowEpochMs: NOW + 1_000,
    });
    expect(spoofing.calls).toHaveLength(0);

    // Once the circuit closes it is retried — and re-verified, so a still-spoofing endpoint
    // cannot slip through on the far side of the window.
    await pool.readBalance({
      chainId: 8453,
      token: TOKEN,
      owner: OWNER,
      nowEpochMs: NOW + CIRCUIT_OPEN_MS + 1,
    });
    expect(spoofing.calls.map((call) => call.method)).toEqual(["eth_chainId"]);
  });

  it("fails with the mismatch category when every endpoint reports the wrong chain", async () => {
    const rpc = await stub({ mode: "wrong-chain", wrongChainId: 137 });
    const pool = new EvmRpcPool([rpc.url]);

    await expect(
      pool.readBalance({ chainId: 8453, token: TOKEN, owner: OWNER, nowEpochMs: NOW }),
    ).rejects.toMatchObject({ failure: "chain-id-mismatch" });
  });

  it("honours the per-provider deadline and falls through to a healthy endpoint", async () => {
    const slow = await stub({ mode: "hang" });
    const fast = await stub({ balances: { [OWNER]: "1" } });
    const pool = new EvmRpcPool([slow.url, fast.url], { timeoutMs: 120 });

    const started = performance.now();
    const reading = await pool.readBalance({
      chainId: 8453,
      token: TOKEN,
      owner: OWNER,
      nowEpochMs: NOW,
    });

    expect(reading.balanceAtomic).toBe(1n);
    // The hung provider cost roughly one deadline, not an open-ended wait.
    expect(performance.now() - started).toBeLessThan(2_000);
  });

  it("classifies transport, protocol, and JSON-RPC failures without quoting the provider", async () => {
    for (const [mode, failure] of [
      ["http-error", "transport"],
      ["garbage", "protocol"],
      ["rpc-error", "protocol"],
    ] as const) {
      const rpc = await stub({ mode });
      const pool = new EvmRpcPool([rpc.url]);
      const error = await pool
        .readBalance({ chainId: 8453, token: TOKEN, owner: OWNER, nowEpochMs: NOW })
        .catch((caught: unknown) => caught);

      expect(error).toBeInstanceOf(EvmRpcError);
      expect((error as EvmRpcError).failure).toBe(failure);
      expect((error as EvmRpcError).message).not.toContain("stub-configured-error");
    }
  });

  it("uses an open endpoint only when every endpoint is open", async () => {
    const first = await stub({ mode: "http-error" });
    const second = await stub({ mode: "http-error" });
    const health = new HealthIndex();
    const pool = new EvmRpcPool([first.url, second.url], {
      health,
      networkId: "eip155:8453",
    });

    // A single transport failure does not open a circuit — SPEC §6.5's thresholds are five
    // consecutive failures or half of at least ten samples. It takes five rounds.
    for (let round = 0; round < 5; round += 1) {
      await expect(
        pool.readBalance({ chainId: 8453, token: TOKEN, owner: OWNER, nowEpochMs: NOW }),
      ).rejects.toBeInstanceOf(EvmRpcError);
    }
    for (const endpoint of pool.endpointLabels) {
      expect(health.state(HealthIndex.endpointId("eip155:8453", endpoint), NOW)).toBe(
        "open",
      );
    }

    first.setMode("ok");
    first.setBalance(OWNER, "42");
    // Now both circuits really are open, and SPEC §6.5 permits a last-resort attempt rather
    // than failing outright while the window runs.
    const reading = await pool.readBalance({
      chainId: 8453,
      token: TOKEN,
      owner: OWNER,
      nowEpochMs: NOW + 10,
    });
    expect(reading.balanceAtomic).toBe(42n);
  });

  it("reports the endpoint it read from into the shared health index", async () => {
    const rpc = await stub({ balances: { [OWNER]: "9" } });
    const health = new HealthIndex();
    const pool = new EvmRpcPool([rpc.url], { health, networkId: "eip155:8453" });

    const reading = await pool.readBalance({
      chainId: 8453,
      token: TOKEN,
      owner: OWNER,
      nowEpochMs: NOW,
    });

    // The route planner scores the candidate from this key, so the pool must report the one
    // endpoint that actually answered rather than the network as a whole.
    expect(reading.endpointId).toBe(
      HealthIndex.endpointId("eip155:8453", `127.0.0.1:${rpc.port}`),
    );
    expect(health.inspect(reading.endpointId, NOW).sampleCount).toBe(1);
    expect(health.score(reading.endpointId, NOW)).toBeGreaterThan(0.8);
  });

  it("consults at most two providers per network and can be reset", async () => {
    const rpc = await stub({ balances: { [OWNER]: "7" } });
    const health = new HealthIndex();
    const pool = new EvmRpcPool([rpc.url, "http://127.0.0.1:1/", "http://127.0.0.1:2/"], {
      health,
      networkId: "eip155:8453",
    });
    expect(pool.endpointLabels).toHaveLength(2);

    await pool.readBalance({ chainId: 8453, token: TOKEN, owner: OWNER, nowEpochMs: NOW });
    expect(health.size).toBe(1);

    // Resetting one pool forgets only its own endpoints; a shared index keeps the rest.
    health.recordFailure(
      HealthIndex.endpointId("solana:mainnet", "other.example.com"),
      NOW,
    );
    pool.resetHealth();
    expect(health.size).toBe(1);

    await expect(
      pool.readBalance({ chainId: 8453, token: TOKEN, owner: OWNER, nowEpochMs: NOW }),
    ).resolves.toMatchObject({ balanceAtomic: 7n });
  });

  it("rejects malformed addresses and an empty endpoint list before any request", async () => {
    const rpc = await stub();
    const pool = new EvmRpcPool([rpc.url]);
    await expect(
      pool.readBalance({ chainId: 8453, token: "0xnope", owner: OWNER, nowEpochMs: NOW }),
    ).rejects.toMatchObject({ failure: "protocol" });
    expect(rpc.calls).toHaveLength(0);

    await expect(
      new EvmRpcPool([]).readBalance({
        chainId: 8453,
        token: TOKEN,
        owner: OWNER,
        nowEpochMs: NOW,
      }),
    ).rejects.toMatchObject({ failure: "transport" });
  });

  it("keeps provider credentials out of endpoint labels", () => {
    const pool = new EvmRpcPool(["https://rpc.example.com/v2/SECRET-API-KEY"]);
    expect(pool.endpointLabels).toEqual(["rpc.example.com"]);
  });
});
