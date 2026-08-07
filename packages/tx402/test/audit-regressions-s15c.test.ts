/**
 * Regressions for the S15c audit re-run's findings O57 and O58.
 *
 * Written from the governing text — SPEC §5.3, §6.7, §10, and ADR-016/018 — and run against
 * the S15c commit `38155c3` first, to confirm they failed there. The S15 audit's central
 * complaint was that the green suite asserted what the implementation did rather than what
 * the contract required, so a regression derived from the implementation is worth nothing.
 *
 * The O58 half is deliberately a *table*, and the identical table appears in
 * `packages/tx402-python/tests/test_audit_regressions_s15c.py`. The finding was that two
 * helpers documented as interchangeable returned different strings for the same URL; the
 * only test that could have caught it is one both languages answer.
 */

import { randomBytes } from "node:crypto";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client, type Tx402Logger } from "../src/core/client.js";
import { MemorySpendStore } from "../src/core/ledger.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import { normalizePolicyHost } from "../src/core/policy.js";
import type { EvmSigner } from "../src/core/signers.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";

const BASE = BUNDLED_MANIFEST.networks["eip155:8453"] as EvmManifestNetwork;
const USDC = BASE.assets[0] as EvmManifestAsset;
const RPC_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));

const REQUIREMENT = {
  scheme: "exact",
  network: "eip155:8453",
  asset: USDC.address,
  amount: "50000",
  payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let rpc: EvmRpcStub;
let signer: EvmSigner;
const servers: Merchant[] = [];

/** Every event, in emission order, with the level it was emitted at. */
class RecordingLogger implements Tx402Logger {
  readonly events: { level: string; event: Record<string, unknown> }[] = [];

  debug(event: Readonly<Record<string, unknown>>): void {
    this.events.push({ level: "debug", event: { ...event } });
  }
  info(event: Readonly<Record<string, unknown>>): void {
    this.events.push({ level: "info", event: { ...event } });
  }
  warn(event: Readonly<Record<string, unknown>>): void {
    this.events.push({ level: "warn", event: { ...event } });
  }
  error(event: Readonly<Record<string, unknown>>): void {
    this.events.push({ level: "error", event: { ...event } });
  }

  named(name: string): { level: string; event: Record<string, unknown> }[] {
    return this.events.filter((entry) => entry.event["event"] === name);
  }

  names(): string[] {
    return this.events.map((entry) => String(entry.event["event"]));
  }
}

async function merchantFor(scenario: string): Promise<Merchant> {
  const server = await createTestMerchant({
    scenario,
    requirements: [REQUIREMENT],
    body: JSON.stringify({ ok: true }),
  });
  servers.push(server);
  return server;
}

beforeEach(async () => {
  signer = privateKeyToEvmSigner(`0x${randomBytes(32).toString("hex")}`);
  const payer = await signer.getAddress();
  rpc = await createEvmRpcStub({
    chainId: 8453,
    token: USDC.address,
    balances: { [payer]: "5000000" },
  });

  const realFetch = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: Request | string | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (!RPC_HOSTS.has(url.host)) return realFetch(request);
    return realFetch(rpc.url, {
      method: request.method,
      headers: request.headers,
      body: await request.text(),
    });
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(servers.splice(0).map((server) => server.close()));
  await rpc.close();
});

function client(logger: Tx402Logger, overrides: Record<string, unknown> = {}) {
  return createTx402Client({
    signers: { evm: signer },
    allowInsecureLocalhost: true,
    logger,
    spendStore: new MemorySpendStore(),
    policy: {
      maxPerRequest: "0.50 USDC",
      maxPerHour: "10.00 USDC",
      allowedNetworks: ["eip155:8453"],
    },
    ...overrides,
  });
}

/* ------------------------------------------------------------------------------------- */
/* O57 — a completion event is a statement about the disposition, not about a header       */
/* ------------------------------------------------------------------------------------- */

describe("O57 payment.completed follows the disposition", () => {
  it("emits no completion when a headerless 403 refuses the paid request", async () => {
    // SPEC §10 gives `payment.completed` the field `paid`, and SPEC §6.7 decides what that
    // value is. A merchant that refuses without claiming a settlement has proven no payment
    // occurred: the reservation is released and the error carries `paid: false`. Reporting
    // `payment.completed` with `paid: true` for the same request id — which is what the
    // absent-header branch did from the read site — tells a reconciliation system the
    // opposite of what the SDK itself concluded a microsecond later.
    const logger = new RecordingLogger();
    const server = await merchantFor("refused-after-signature");

    await expect(client(logger).fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_RESOURCE_DELIVERY",
      context: { paid: false },
    });

    expect(logger.named("payment.completed")).toEqual([]);
    expect(logger.names()).toContain("request.failed");
    expect(logger.named("request.failed")[0]?.event["paid"]).toBe(false);
  });

  it("emits no completion for a headerless 402 re-challenge, once per attempt or at all", async () => {
    // The re-challenge loop makes this the loudest version of the finding: every signed
    // attempt read a headerless response and announced a completed payment before deciding
    // to release the reservation and sign again. Two attempts, two false completions, and a
    // final error that says nothing was paid.
    const logger = new RecordingLogger();
    const server = await merchantFor("always-402");

    await expect(
      client(logger, { policy: { maxPaidAttempts: 2 } }).fetch(`${server.url}/resource`),
    ).rejects.toMatchObject({ code: "TX402_RESOURCE_DELIVERY", context: { paid: false } });

    expect(logger.named("payment.completed")).toEqual([]);
    // The attempts really did happen — this is not passing because nothing was signed.
    expect(logger.named("request.retried")).toHaveLength(2);
  });

  it("still reports the permitted absent header on a delivered 2xx, and warns", async () => {
    // The other half, so the fix cannot be "stop emitting the event". SPEC §6.7 forgives a
    // missing PAYMENT-RESPONSE because the pinned protocol marks it optional, and *this* is
    // the disposition where an absent header accompanies a real payment. One event, at
    // `warn`, carrying both the reason and the fields SPEC §10 requires.
    const logger = new RecordingLogger();
    const server = await merchantFor("missing-payment-response");

    await expect(client(logger).fetch(`${server.url}/resource`)).resolves.toHaveProperty(
      "status",
      200,
    );

    const completed = logger.named("payment.completed");
    expect(completed).toHaveLength(1);
    expect(completed[0]?.level).toBe("warn");
    expect(completed[0]?.event).toMatchObject({
      paid: true,
      reason: "payment-response-absent",
    });
    expect(completed[0]?.event["totalSdkOverheadMs"]).toBeTypeOf("number");
  });

  it("reports an unparseable header as unknown, after the table has called it ambiguous", async () => {
    // ADR-016: a present header that does not decode is evidence in neither direction, so
    // the money is retained and the outcome is unknown. The completion event says exactly
    // that, and it is emitted from the ambiguous branch rather than from the reader, so it
    // cannot outlive a future change to what a malformed header means.
    const logger = new RecordingLogger();
    const server = await merchantFor("corrupt-payment-response");

    await expect(client(logger).fetch(`${server.url}/resource`)).rejects.toMatchObject({
      code: "TX402_PAYMENT_AMBIGUOUS",
      context: { paid: "unknown" },
    });

    const completed = logger.named("payment.completed");
    expect(completed).toHaveLength(1);
    expect(completed[0]?.event).toMatchObject({
      paid: "unknown",
      reason: "payment-response-unparseable",
    });
    // Ordering is the whole finding: the completion must not precede the decision, and the
    // failure must be the last word on the request.
    expect(logger.names().indexOf("payment.completed")).toBeLessThan(
      logger.names().indexOf("request.failed"),
    );
  });

  it("never claims paid: true for a request whose error says paid: false", async () => {
    // The invariant behind all four cases, asserted directly across the scenarios that end
    // unpaid. A stream that contradicts the SDK's own conclusion is worse than a silent
    // one, because it is the stream an operator reconciles against.
    for (const scenario of [
      "refused-after-signature",
      "always-402",
      "unsuccessful-settlement",
    ]) {
      const logger = new RecordingLogger();
      const server = await merchantFor(scenario);

      await expect(client(logger).fetch(`${server.url}/resource`)).rejects.toMatchObject({
        context: { paid: false },
      });

      const claimedPaid = logger.events.filter((entry) => entry.event["paid"] === true);
      expect(claimedPaid, `${scenario} claimed a completed payment`).toEqual([]);
    }
  });
});

/* ------------------------------------------------------------------------------------- */
/* O58 — one canonical policy host, in both languages (ADR-018 amendment)                  */
/* ------------------------------------------------------------------------------------- */

/**
 * The parity table. Every row is asserted identically in the Python suite; changing either
 * helper alone fails a test rather than being found by an audit.
 */
const CANONICAL_HOSTS: [string, string][] = [
  ["https://bücher.example/x", "xn--bcher-kva.example"],
  ["https://xn--bcher-kva.example/x", "xn--bcher-kva.example"],
  ["https://BÜCHER.example/x", "xn--bcher-kva.example"],
  ["https://faß.de/", "xn--fa-hia.de"],
  ["https://日本.example:8443/a?b=c", "xn--wgv71a.example"],
  ["https://EXAMPLE.com:443/a", "example.com"],
  ["https://a.test./x", "a.test"],
  ["https://a.test../x", "a.test."],
  ["https://[2001:DB8::1]:9/x", "[2001:db8::1]"],
  ["https://127.0.0.1:8787/x", "127.0.0.1"],
  ["https://./x", ""],
];

describe("O58 canonical policy host", () => {
  it.each(CANONICAL_HOSTS)("normalizes %s to %s", (url, expected) => {
    expect(normalizePolicyHost(url)).toBe(expected);
  });

  it("gives a Unicode and a punycoded URL the same ledger key", () => {
    // ADR-018 makes this function "the public way to derive the exact key a client reserves
    // under". If the two spellings of one host produce two keys, the caller's own hourly cap
    // is silently doubled by how they happened to type the URL.
    expect(normalizePolicyHost("https://bücher.example/one")).toBe(
      normalizePolicyHost("https://xn--bcher-kva.example/two"),
    );
  });

  it("accepts a Unicode allowlist entry for a real punycoded request host", async () => {
    // A request URL is punycoded by the URL parser before it reaches the wire, so an
    // allowlist that normalizes to a U-label can never match one. Python failed closed here
    // where TypeScript allowed; this pins the allowing side so the fix cannot land as
    // "make TypeScript refuse it too".
    const logger = new RecordingLogger();
    const server = await merchantFor("pay-once");
    const host = normalizePolicyHost(server.url);

    await expect(
      client(logger, {
        policy: { allowedDomains: [host], allowedNetworks: ["eip155:8453"] },
      }).fetch(`${server.url}/resource`),
    ).resolves.toHaveProperty("status", 200);

    expect(logger.named("request.started")[0]?.event["normalizedHost"]).toBe(host);
  });
});
