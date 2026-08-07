/**
 * T-015: the logger receives seeded secrets and none of them appear (SPEC §12.2, §10).
 *
 * Mirrors `packages/tx402-python/tests/test_diagnostics.py`. Per ADR-005 the two SDKs must
 * emit the same event stream, so the same properties are asserted in both languages and the
 * event names and field sets are pinned identically.
 *
 * The test is adversarial rather than illustrative. Every input the request path touches is
 * seeded with a unique searchable marker — the signing key, the bearer token, a query-string
 * credential, the request body, the merchant's settlement id — the whole event stream from a
 * real paid call is serialised, and every marker is searched for.
 *
 * Asserting on the *absence of secrets* rather than on the presence of expected fields is
 * deliberate: a field-shape assertion passes forever while a newly added field quietly
 * carries a key, which is exactly when SEC-003 most needs to fail loudly.
 *
 * Unlike the Python mirror the signature here is genuine — a real key signs real EIP-712
 * typed data and the test merchant validates the result — so "the signature never reaches a
 * log" is proven against the bytes that actually went on the wire, in every encoding.
 */

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client, type Tx402Logger } from "../src/core/client.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import type { EvmSigner } from "../src/core/signers.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";

const BASE = BUNDLED_MANIFEST.networks["eip155:8453"] as EvmManifestNetwork;
const USDC = BASE.assets[0] as EvmManifestAsset;
const RPC_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));
const PAY_TO = "0x1234567890AbcdEF1234567890aBcdef12345678";

/**
 * A fixed test key. Fixed rather than random so the assertion names a concrete string:
 * "this exact value must not appear anywhere". It funds nothing and signs only this test.
 */
const SEED_PRIVATE_KEY =
  "0xa11ce00000000000000000000000000000000000000000000000000000000001" as const;

// Long, unique, mutually non-overlapping, so any hit is attributable to one seed.
const SEED_SETTLEMENT_ID = "SEEDSETTLEMENTccccccccccccccccccccccccccccccccccccccccc03";
const SEED_BEARER = "SEEDBEARERdddddddddddddddddddddddddddddddddddddddddddddd04";
const SEED_QUERY_CREDENTIAL = "SEEDQUERYeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee05";
const SEED_BODY = "SEEDBODYffffffffffffffffffffffffffffffffffffffffffffffff06";

const SEEDS = [
  SEED_PRIVATE_KEY,
  SEED_PRIVATE_KEY.slice(2),
  SEED_SETTLEMENT_ID,
  SEED_BEARER,
  SEED_QUERY_CREDENTIAL,
  SEED_BODY,
];

const REQUIREMENT = {
  scheme: "exact",
  network: "eip155:8453",
  asset: USDC.address,
  amount: "50000",
  payTo: PAY_TO,
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

interface RecordedEvent {
  readonly level: keyof Tx402Logger;
  readonly event: Record<string, unknown>;
}

/** Captures every event at every level, in order. */
function recordingLogger(): Tx402Logger & {
  readonly records: RecordedEvent[];
  names(): string[];
  find(name: string): Record<string, unknown>;
  serialised(): string;
} {
  const records: RecordedEvent[] = [];
  const push = (level: keyof Tx402Logger) => (event: Record<string, unknown>) => {
    records.push({ level, event: { ...event } });
  };
  return {
    records,
    debug: push("debug"),
    info: push("info"),
    warn: push("warn"),
    error: push("error"),
    names: () => records.map((record) => String(record.event["event"])),
    find(name) {
      const hit = records.find((record) => record.event["event"] === name);
      if (hit === undefined) {
        throw new Error(
          `no ${name} event in ${records.map((r) => r.event["event"]).join(", ")}`,
        );
      }
      return hit.event;
    },
    // A value that cannot be serialised must not silently skip the search, so BigInt and
    // friends are stringified rather than allowed to throw.
    serialised: () =>
      JSON.stringify(records, (_key: string, value: unknown): unknown =>
        typeof value === "bigint" ? value.toString() : value,
      ),
  };
}

let merchant: Merchant;
let rpc: EvmRpcStub;
let signer: EvmSigner;
let signatures: string[];

beforeEach(async () => {
  signatures = [];
  const inner = privateKeyToEvmSigner(SEED_PRIVATE_KEY);
  signer = {
    kind: "evm",
    getAddress: () => inner.getAddress(),
    signTypedData: async (request) => {
      const signature = await inner.signTypedData(request);
      // Retained only so the assertions can search for the exact bytes transmitted.
      signatures.push(signature);
      return signature;
    },
  };
  const payer = await signer.getAddress();

  merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
    settlementId: SEED_SETTLEMENT_ID,
    body: JSON.stringify({ ok: true }),
  });
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
  await merchant.close();
  await rpc.close();
});

function client(logger: Tx402Logger, overrides: Record<string, unknown> = {}) {
  return createTx402Client({
    signers: { evm: signer },
    allowInsecureLocalhost: true,
    logger,
    policy: {
      maxPerRequest: "0.50 USDC",
      maxPerHour: "10.00 USDC",
      allowedNetworks: ["eip155:8453"],
    },
    ...overrides,
  });
}

/** One full, successful paid call carrying every seed. */
async function paidCall(logger: Tx402Logger): Promise<Response> {
  return client(logger).fetch(`${merchant.url}/resource?api_key=${SEED_QUERY_CREDENTIAL}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${SEED_BEARER}`, "content-type": "application/json" },
    body: JSON.stringify({ prompt: SEED_BODY }),
  });
}

describe("T-015 no seeded secret reaches the logger", () => {
  it("leaks nothing from a successful paid call", async () => {
    const logger = recordingLogger();
    const response = await paidCall(logger);
    expect(response.status).toBe(200);

    // The paying path really ran, so "nothing leaked" is not merely "nothing happened".
    expect(logger.names()).toContain("sign.completed");
    expect(logger.names()).toContain("payment.completed");

    const blob = logger.serialised();
    for (const seed of SEEDS) expect(blob).not.toContain(seed);
  });

  it("leaks the real signature in no encoding", async () => {
    const logger = recordingLogger();
    await paidCall(logger);
    const blob = logger.serialised();

    expect(signatures).toHaveLength(1);
    const signature = signatures[0] as string;
    const raw = signature.slice(2);
    expect(blob).not.toContain(signature);
    expect(blob).not.toContain(raw);
    expect(blob).not.toContain(Buffer.from(raw, "hex").toString("base64"));
    expect(blob).not.toContain(Buffer.from(raw, "hex").toString("base64url"));
  });

  it("leaks nothing from a policy rejection either", async () => {
    // A different set of events is built on the failure path, so it needs its own check.
    const logger = recordingLogger();
    await expect(
      client(logger, { policy: { maxPerRequest: "0.01 USDC" } }).fetch(
        `${merchant.url}/resource?api_key=${SEED_QUERY_CREDENTIAL}`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${SEED_BEARER}` },
          body: JSON.stringify({ prompt: SEED_BODY }),
        },
      ),
    ).rejects.toThrow();

    expect(logger.names()).toContain("request.failed");
    const blob = logger.serialised();
    for (const seed of SEEDS) expect(blob).not.toContain(seed);
    // SEC-002: policy is evaluated before any signer call.
    expect(signatures).toHaveLength(0);
  });

  it("hashes the settlement id rather than dropping it", async () => {
    // Absence would also pass the leak test, so pin that the hash is genuinely present —
    // otherwise deleting the field would look like a security fix while removing the
    // operator's only way to correlate a log line with a settlement.
    const logger = recordingLogger();
    await paidCall(logger);
    const completed = logger.find("payment.completed");
    expect(String(completed["settlementIdHash"])).toMatch(/^sha256:[0-9a-f]{64}$/u);
  });
});

describe("SPEC §10 event contract", () => {
  it("carries the minimum fields for every event", async () => {
    const logger = recordingLogger();
    await paidCall(logger);
    const required: Record<string, string[]> = {
      "request.started": ["requestId", "method", "normalizedHost"],
      "payment.required": ["requestId", "requirementCount", "headerHash"],
      "policy.checked": ["requestId", "outcome", "policyCode"],
      "route.planned": ["requestId", "candidateCount", "selectedNetwork", "selectedScheme"],
      "budget.reserved": ["requestId", "reservationId", "assetId", "amountAtomic"],
      "sign.started": ["requestId", "signerKind"],
      "sign.completed": ["requestId", "signerKind", "durationMs"],
      "request.retried": ["requestId", "attempt", "selectedNetwork"],
      "payment.completed": ["requestId", "paid", "totalSdkOverheadMs"],
    };
    for (const [name, fields] of Object.entries(required)) {
      const event = logger.find(name);
      for (const field of fields) expect(event).toHaveProperty(field);
    }
  });

  it("emits the documented sequence for a successful call", async () => {
    const logger = recordingLogger();
    await paidCall(logger);
    expect(logger.names()).toEqual([
      "request.started",
      "payment.required",
      "policy.checked",
      "route.planned",
      "budget.reserved",
      "sign.started",
      "sign.completed",
      "request.retried",
      "payment.completed",
    ]);
  });

  it("reports non-negative durations", async () => {
    const logger = recordingLogger();
    await paidCall(logger);
    expect(Number(logger.find("sign.completed")["durationMs"])).toBeGreaterThanOrEqual(0);
    expect(
      Number(logger.find("payment.completed")["totalSdkOverheadMs"]),
    ).toBeGreaterThanOrEqual(0);
  });

  it("hands each sink a frozen event", async () => {
    // Two sinks sharing one event is normal in a fan-out logger, and a mutable object
    // would let the first rewrite what the second sees.
    const captured: Record<string, unknown>[] = [];
    const capture = (event: Record<string, unknown>) => {
      captured.push(event);
    };
    await paidCall({ debug: capture, info: capture, warn: capture, error: capture });
    expect(captured.length).toBeGreaterThan(0);
    expect(Object.isFrozen(captured[0])).toBe(true);
  });
});

describe("logger isolation", () => {
  it("never fails a payment because the logger threw", async () => {
    // The worst outcome for an observability feature is failing a settled payment.
    const explode = () => {
      throw new Error("disk full");
    };
    const response = await paidCall({
      debug: explode,
      info: explode,
      warn: explode,
      error: explode,
    });
    expect(response.status).toBe(200);
    // And the money still moved, so isolation did not skip the commit.
    expect(merchant.paidRequests).toHaveLength(1);
  });
});
