/** Solana exact-payment fixture-harness integration (T-003, SEC-002). */

import {
  createSignableMessage,
  generateKeyPairSigner,
  type KeyPairSigner,
} from "@solana/kit";
import { createSvmRpcStub, type SvmRpcStub } from "@tx402-dev/svm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client } from "../src/core/client.js";
import { MemorySpendStore, type SpendStore } from "../src/core/ledger.js";
import type { SvmManifestAsset, SvmManifestNetwork } from "../src/core/manifest.js";
import type { SolanaSigner } from "../src/core/signers.js";
import { isTransportFailure } from "../src/solana/adapter.js";
import { derivePaymentAtas } from "../src/solana/signer.js";

const NETWORK_ID = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const NETWORK = BUNDLED_MANIFEST.networks[NETWORK_ID] as SvmManifestNetwork;
const USDC = NETWORK.assets[0] as SvmManifestAsset;
const PAY_TO = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const BLOCKHASH = "11111111111111111111111111111111";
const RPC_HOSTS = new Set(NETWORK.rpcUrls.map((url) => new URL(url).host));

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let merchant: Merchant;
let rpc: SvmRpcStub;
let kitSigner: KeyPairSigner;
let signer: SolanaSigner & { signCount: number };
let feePayer: string;

function recordingStore(log: string[]): SpendStore {
  const inner = new MemorySpendStore();
  return {
    kind: inner.kind,
    reserve: async (input) => {
      const value = await inner.reserve(input);
      log.push("reserve");
      return value;
    },
    commit: async (input) => {
      const value = await inner.commit(input);
      log.push("commit");
      return value;
    },
    release: async (id, now) => {
      const value = await inner.release(id, now);
      log.push("release");
      return value;
    },
    getBudgetState: (query) => inner.getBudgetState(query),
  };
}

function requirement() {
  return {
    scheme: "exact",
    network: NETWORK_ID,
    asset: USDC.mint,
    amount: "50000",
    payTo: PAY_TO,
    maxTimeoutSeconds: 60,
    extra: {
      feePayer,
      recentBlockhash: BLOCKHASH,
      lastValidBlockHeight: "999999",
      memo: "tx402-svm-fixture",
    },
  };
}

async function startMerchant(): Promise<void> {
  merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [requirement()],
    body: JSON.stringify({ ok: true, resource: "solana-paid" }),
  });
}

beforeEach(async () => {
  kitSigner = await generateKeyPairSigner();
  feePayer = (await generateKeyPairSigner()).address.toString();
  signer = {
    kind: "solana",
    signCount: 0,
    getPublicKey: () => Promise.resolve(kitSigner.address.toString()),
    signTransaction: async (request) => {
      signer.signCount += 1;
      const [signatures] = await kitSigner.signMessages([
        createSignableMessage(request.messageBytes),
      ]);
      const signature = signatures?.[kitSigner.address];
      if (signature === undefined) throw new Error("fixture signer produced no signature");
      return new Uint8Array(signature);
    },
  };
  const atas = await derivePaymentAtas({
    mint: USDC.mint,
    payer: kitSigner.address.toString(),
    recipient: PAY_TO,
  });
  rpc = await createSvmRpcStub({
    genesisHash: NETWORK.genesisHash,
    mint: USDC.mint,
    decimals: USDC.decimals,
    tokenAccounts: {
      [atas.source]: {
        owner: kitSigner.address.toString(),
        mint: USDC.mint,
        amount: "5000000",
        decimals: USDC.decimals,
      },
    },
  });
  await startMerchant();

  const realFetch = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: Request | string | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (!RPC_HOSTS.has(new URL(request.url).host)) return realFetch(request);
    return realFetch(rpc.url, {
      method: request.method,
      headers: request.headers,
      body: await request.text(),
      signal: request.signal,
    });
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await merchant.close();
  await rpc.close();
});

function client(overrides: Parameters<typeof createTx402Client>[0] = {}) {
  return createTx402Client({
    signers: { solana: signer },
    allowInsecureLocalhost: true,
    policy: {
      maxPerRequest: "0.50 USDC",
      maxPerHour: "10.00 USDC",
      allowedNetworks: ["solana:devnet"],
    },
    ...overrides,
  });
}

describe("M4 Solana paid call", () => {
  it("T-003 reserves, signs one validated SVM transaction, retries, and commits", async () => {
    const order: string[] = [];
    const observed: Array<{
      messageBytes: number;
      transactionBytes: number;
      network: string;
    }> = [];
    const recordingSigner: SolanaSigner = {
      kind: "solana",
      getPublicKey: () => signer.getPublicKey(),
      signTransaction: async (request) => {
        order.push("sign");
        observed.push({
          messageBytes: request.messageBytes.byteLength,
          transactionBytes: request.transactionBytes.byteLength,
          network: request.presentation.network,
        });
        return signer.signTransaction(request);
      },
    };
    const tx402 = client({
      spendStore: recordingStore(order),
      signers: { solana: recordingSigner },
    });

    const response = await tx402.fetch(`${merchant.url}/resource`);
    await expect(response.json()).resolves.toEqual({ ok: true, resource: "solana-paid" });
    expect(order).toEqual(["reserve", "sign", "commit"]);
    expect(signer.signCount).toBe(1);
    expect(merchant.paidRequests).toHaveLength(1);
    expect(merchant.violations).toEqual([]);
    expect(observed[0]).toMatchObject({ network: NETWORK_ID });
    expect(observed[0]?.messageBytes).toBeGreaterThan(0);
    expect(observed[0]?.transactionBytes).toBeLessThanOrEqual(1232);
    expect(tx402.getBudgetState()).toMatchObject({
      committedAtomic: "50000",
      reservedAtomic: "0",
    });

    // The balance endpoint and the exact endpoint handed upstream both prove the cluster.
    expect(rpc.calls.map((call) => call.method)).toEqual([
      "getGenesisHash",
      "getAccountInfo",
      "getGenesisHash",
      "getAccountInfo",
    ]);
  });

  it("normalizes the solana:devnet alias to the canonical network", async () => {
    await expect(client().fetch(`${merchant.url}/resource`)).resolves.toHaveProperty(
      "status",
      200,
    );
    expect(signer.signCount).toBe(1);
  });

  it("rejects insufficient ATA balance without a reservation or signer call", async () => {
    const atas = await derivePaymentAtas({
      mint: USDC.mint,
      payer: kitSigner.address.toString(),
      recipient: PAY_TO,
    });
    rpc.setTokenAccount(atas.source, {
      owner: kitSigner.address.toString(),
      mint: USDC.mint,
      amount: "49999",
      decimals: USDC.decimals,
    });
    const order: string[] = [];
    await expect(
      client({ spendStore: recordingStore(order) }).fetch(`${merchant.url}/resource`),
    ).rejects.toMatchObject({
      code: "TX402_LIQUIDITY",
      details: {
        deficits: [
          {
            network: NETWORK_ID,
            available: "49999",
            required: "50000",
          },
        ],
      },
    });
    expect(order).toEqual([]);
    expect(signer.signCount).toBe(0);
  });

  it("rejects a genesis-hash mismatch before balance, reservation, or signing", async () => {
    rpc.setMode("wrong-cluster");
    const order: string[] = [];
    await expect(
      client({ spendStore: recordingStore(order) }).fetch(`${merchant.url}/resource`),
    ).rejects.toMatchObject({
      code: "TX402_TRANSPORT",
      details: { causeCategory: "genesis-hash-mismatch" },
    });
    expect(rpc.calls.every((call) => call.method === "getGenesisHash")).toBe(true);
    expect(order).toEqual([]);
    expect(signer.signCount).toBe(0);
  });

  it("rejects a missing fee payer before reservation and signing", async () => {
    await merchant.close();
    merchant = await createTestMerchant({
      scenario: "pay-once",
      requirements: [{ ...requirement(), extra: { recentBlockhash: BLOCKHASH } }],
    });
    const order: string[] = [];
    await expect(
      client({ spendStore: recordingStore(order) }).fetch(`${merchant.url}/resource`),
    ).rejects.toMatchObject({
      code: "TX402_PAYMENT_REQUIRED_INVALID",
      details: { reason: "svm-feePayer-missing" },
    });
    expect(order).toEqual([]);
    expect(signer.signCount).toBe(0);
  });

  it("releases the reservation when the external signer returns a malformed signature", async () => {
    const order: string[] = [];
    const malformed: SolanaSigner = {
      kind: "solana",
      getPublicKey: () => signer.getPublicKey(),
      signTransaction: () => {
        order.push("sign");
        return Promise.resolve(new Uint8Array(63));
      },
    };
    const tx402 = client({
      spendStore: recordingStore(order),
      signers: { solana: malformed },
    });
    await expect(tx402.fetch(`${merchant.url}/resource`)).rejects.toMatchObject({
      code: "TX402_SIGNER",
      details: { signerKind: "solana", causeCategory: "signature-malformed" },
    });
    expect(order).toEqual(["reserve", "sign", "release"]);
    expect(merchant.paidRequests).toHaveLength(0);
  });
});

describe("upstream payload-creation failures are classified by cause (O35)", () => {
  // `ExactSvmScheme` performs its own RPC inside `createPaymentPayload`, so a rate-limited
  // endpoint surfaces there rather than through tx402's pool. Reporting that as a signer
  // fault is wrong twice: wrong category, and wrong `retryable` — only TransportError is
  // retryable (ADR-011). Seen once at S12 and left unexplained as the second half of O35.

  it("recognises a rate limit, a socket failure, and an HTTP status as transport", () => {
    expect(isTransportFailure(new Error("HTTP 429 Too Many Requests"))).toBe(true);
    expect(isTransportFailure(new Error("Rate limit exceeded"))).toBe(true);
    expect(isTransportFailure(Object.assign(new Error("nope"), { status: 429 }))).toBe(
      true,
    );
    expect(isTransportFailure(Object.assign(new Error("nope"), { status: 503 }))).toBe(
      true,
    );
    // `fetch` rejects with a TypeError whose `cause` holds the real error, which is why the
    // cause chain is walked rather than only the top-level object inspected.
    expect(
      isTransportFailure(
        new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } }),
      ),
    ).toBe(true);
    expect(
      isTransportFailure(
        new Error("outer", {
          cause: new TypeError("inner", { cause: { code: "ETIMEDOUT" } }),
        }),
      ),
    ).toBe(true);
  });

  it("leaves a deterministic construction fault classified as a signer error", () => {
    // The conservative direction. A false positive here would tell a caller to retry a
    // fault that will never succeed, forever.
    expect(isTransportFailure(new Error("memo exceeds the instruction limit"))).toBe(false);
    expect(isTransportFailure(new Error("mint is Token-2022"))).toBe(false);
    expect(isTransportFailure(Object.assign(new Error("nope"), { status: 200 }))).toBe(
      false,
    );
    expect(isTransportFailure(undefined)).toBe(false);
    expect(isTransportFailure(null)).toBe(false);
  });

  it("does not follow a cause chain indefinitely", () => {
    // A self-referential cause is malformed input, not a hang.
    const looped: { cause?: unknown } = {};
    looped.cause = looped;
    expect(isTransportFailure(looped)).toBe(false);
  });
});
