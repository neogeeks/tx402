/**
 * RPC failover and decision-time budget (T-008, T-020, SPEC §6.5, §12.3).
 *
 * The fault is injected at the transport, not at a mock: the manifest's first Base RPC host is
 * routed to a stub that accepts the connection and never answers — the observable behaviour of
 * total packet loss — while the second is healthy. Everything above that is the shipped code.
 *
 * The performance assertion follows SPEC §12.3's definition exactly: the 402 decision window
 * starts when the complete challenge has been received and ends before the signer is invoked,
 * and it is measured warmed. Warming is not a convenience here, it is the property under test —
 * the steady state of an endpoint under sustained loss is that its circuit is open and it is no
 * longer contacted at all.
 */

import { randomBytes } from "node:crypto";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { HEALTH_OPEN_MS } from "../src/core/health.js";
import {
  createTx402Client,
  type Tx402Clock,
  type Tx402ClientConfig,
} from "../src/core/client.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import type { EvmSigner } from "../src/core/signers.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";

const BASE_ID = "eip155:8453";
const BASE = BUNDLED_MANIFEST.networks[BASE_ID] as EvmManifestNetwork;
const USDC = BASE.assets[0] as EvmManifestAsset;
const PRIMARY_HOST = new URL(BASE.rpcUrls[0] as string).host;
const SECONDARY_HOST = new URL(BASE.rpcUrls[1] as string).host;
const PAY_TO = "0x1234567890AbcdEF1234567890aBcdef12345678";
const T = 1_785_715_200_000;

const REQUIREMENT = {
  scheme: "exact",
  network: BASE_ID,
  asset: USDC.address,
  amount: "50000",
  payTo: PAY_TO,
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let merchant: Merchant;
let primary: EvmRpcStub;
let secondary: EvmRpcStub;
let signer: EvmSigner & { signCount: number; decisions: number[] };
let payer: `0x${string}`;
/** When the complete 402 challenge was handed back to tx402 (SPEC §12.3). */
let challengeReceivedAt = 0;
/**
 * How many times each RPC host was actually contacted.
 *
 * Counted at the transport rather than read from the stub's call log: a stub in `hang` mode
 * never finishes parsing a request, so it records nothing — and "was the dark endpoint
 * contacted at all?" is exactly the question these tests ask.
 */
let hits: { primary: number; secondary: number };

function timingSigner(): EvmSigner & { signCount: number; decisions: number[] } {
  const inner = privateKeyToEvmSigner(`0x${randomBytes(32).toString("hex")}`);
  const wrapper: EvmSigner & { signCount: number; decisions: number[] } = {
    kind: "evm",
    signCount: 0,
    decisions: [],
    getAddress: () => inner.getAddress(),
    signTypedData: (request) => {
      wrapper.signCount += 1;
      // The far edge of the decision window: parse, policy, balance queries, sort, reserve.
      wrapper.decisions.push(performance.now() - challengeReceivedAt);
      return inner.signTypedData(request);
    },
  };
  return wrapper;
}

beforeEach(async () => {
  hits = { primary: 0, secondary: 0 };
  signer = timingSigner();
  payer = await signer.getAddress();
  // Total packet loss: the socket is accepted and no bytes ever come back.
  primary = await createEvmRpcStub({
    chainId: BASE.chainId,
    token: USDC.address,
    mode: "hang",
  });
  secondary = await createEvmRpcStub({
    chainId: BASE.chainId,
    token: USDC.address,
    balances: { [payer]: "5000000" },
  });
  merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
    body: JSON.stringify({ ok: true }),
  });

  const realFetch = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: Request | string | URL, init?: RequestInit) => {
    const host = new URL(input instanceof Request ? input.url : input).host;
    const target =
      host === PRIMARY_HOST
        ? primary.url
        : host === SECONDARY_HOST
          ? secondary.url
          : undefined;
    if (target === undefined) {
      const response = await realFetch(input, init);
      if (response.status === 402) challengeReceivedAt = performance.now();
      return response;
    }
    hits[host === PRIMARY_HOST ? "primary" : "secondary"] += 1;
    // The RPC pool calls `fetch(url, init)` with its own per-provider deadline signal in
    // `init`. Forward `init` by identity rather than rebuilding a Request: a rebuilt Request
    // only *follows* the original's signal through a WeakRef, and against a stub that never
    // answers, a broken follow chain is a hang with no deadline at all (see S5, `withDeadline`).
    return realFetch(target, init);
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await merchant.close();
  await primary.close();
  await secondary.close();
});

function client(overrides: Tx402ClientConfig = {}) {
  return createTx402Client({
    signers: { evm: signer },
    allowInsecureLocalhost: true,
    policy: {
      maxPerRequest: "0.50 USDC",
      maxPerHour: "50.00 USDC",
      allowedNetworks: [BASE_ID],
    },
    ...overrides,
  });
}

/** A clock whose epoch reading the test drives; monotonic stays real for durations. */
function steppableClock(): Tx402Clock & { advance(ms: number): void } {
  let epoch = T;
  return {
    now: () => epoch,
    monotonic: () => performance.now(),
    advance: (ms: number) => {
      epoch += ms;
    },
  };
}

function percentile(samples: readonly number[], fraction: number): number {
  const sorted = [...samples].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.ceil(fraction * sorted.length) - 1);
  return sorted[Math.max(0, index)] as number;
}

describe("M5 RPC failover", () => {
  it("T-008 uses the healthy secondary when the primary never answers", async () => {
    const response = await client().fetch(`${merchant.url}/resource`);

    expect(response.status).toBe(200);
    expect(signer.signCount).toBe(1);
    // The primary was tried once and abandoned at its deadline; the balance, and the chain
    // identity it was trusted on, both came from the secondary.
    expect(hits.primary).toBe(1);
    expect(secondary.calls.map((call) => call.method)).toEqual(["eth_chainId", "eth_call"]);
  });

  it("T-020 keeps every request on the backup while the primary stays dark", async () => {
    const tx402 = client();
    for (let index = 0; index < 8; index += 1) {
      const response = await tx402.fetch(`${merchant.url}/resource`);
      expect(response.status).toBe(200);
    }

    expect(signer.signCount).toBe(8);
    // Every one of the eight paid calls was funded through the configured backup.
    expect(secondary.calls.filter((call) => call.method === "eth_call")).toHaveLength(8);
    // And the primary stopped being contacted once five consecutive failures opened it —
    // the point of the circuit is that sustained loss costs its deadline five times, not
    // once per request forever (SPEC §6.5).
    expect(hits.primary).toBe(5);
  });

  it("T-008 keeps warmed decision overhead under the 150 ms p95 gate", async () => {
    const tx402 = client();
    // Warm-up: five failures open the primary's circuit, which is the steady state SPEC
    // §12.3's methodology measures. The cold path is asserted by the first test above.
    for (let index = 0; index < 5; index += 1)
      await tx402.fetch(`${merchant.url}/resource`);
    expect(hits.primary).toBe(5);

    signer.decisions.length = 0;
    for (let index = 0; index < 20; index += 1)
      await tx402.fetch(`${merchant.url}/resource`);

    expect(signer.decisions).toHaveLength(20);
    const p95 = percentile(signer.decisions, 0.95);
    expect(p95).toBeLessThan(150);
  }, 30_000);

  it("probes the primary again once the open window elapses, then re-opens it", async () => {
    const clock = steppableClock();
    const tx402 = client({ clock });
    for (let index = 0; index < 5; index += 1)
      await tx402.fetch(`${merchant.url}/resource`);
    expect(hits.primary).toBe(5);

    // Still inside the 30 s window: skipped entirely.
    clock.advance(HEALTH_OPEN_MS - 1);
    await tx402.fetch(`${merchant.url}/resource`);
    expect(hits.primary).toBe(5);

    // On the far side, exactly one half-open probe is spent — and its failure re-opens the
    // circuit rather than costing a probe on every subsequent request.
    clock.advance(1);
    await tx402.fetch(`${merchant.url}/resource`);
    expect(hits.primary).toBe(6);
    await tx402.fetch(`${merchant.url}/resource`);
    expect(hits.primary).toBe(6);
  }, 30_000);

  it("resetHealth clears the circuit so the primary is tried again", async () => {
    const tx402 = client();
    for (let index = 0; index < 5; index += 1)
      await tx402.fetch(`${merchant.url}/resource`);
    expect(hits.primary).toBe(5);

    tx402.resetHealth();
    await tx402.fetch(`${merchant.url}/resource`);
    // One index, one reset: no adapter had to be loaded or awaited for this to take effect.
    expect(hits.primary).toBe(6);
  }, 30_000);

  it("recovers immediately when the primary starts answering again", async () => {
    const clock = steppableClock();
    const tx402 = client({ clock });
    for (let index = 0; index < 5; index += 1)
      await tx402.fetch(`${merchant.url}/resource`);

    primary.setMode("ok");
    primary.setBalance(payer, "5000000");
    clock.advance(HEALTH_OPEN_MS);

    const before = secondary.calls.length;
    await tx402.fetch(`${merchant.url}/resource`);
    // The half-open probe succeeded, so the circuit closed and the primary served the read.
    expect(primary.calls.map((call) => call.method)).toEqual(["eth_chainId", "eth_call"]);
    expect(secondary.calls).toHaveLength(before);

    // Closed for good: the next request needs no probe accounting at all.
    await tx402.fetch(`${merchant.url}/resource`);
    expect(secondary.calls).toHaveLength(before);
  }, 30_000);
});
