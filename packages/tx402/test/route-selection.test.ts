/**
 * Multi-network route selection through the real client (T-004, T-005, SPEC §6.4).
 *
 * A merchant offers Base and Solana in one challenge, both chain adapters are configured, and
 * both chains are served by their local RPC fixture. Nothing inside tx402 is stubbed: the
 * assertions are about which route the shipped planner picks and which signer it then
 * invokes — the only observation that cannot be faked by a diagnostic string.
 */

import {
  createSignableMessage,
  generateKeyPairSigner,
  type KeyPairSigner,
} from "@solana/kit";
import { randomBytes } from "node:crypto";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createSvmRpcStub, type SvmRpcStub } from "@tx402-dev/svm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client, type Tx402ClientConfig } from "../src/core/client.js";
import type {
  EvmManifestAsset,
  EvmManifestNetwork,
  SvmManifestAsset,
  SvmManifestNetwork,
} from "../src/core/manifest.js";
import type { EvmSigner, SolanaSigner } from "../src/core/signers.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";
import { derivePaymentAtas } from "../src/solana/signer.js";

const BASE_ID = "eip155:8453";
const SOLANA_ID = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const BASE = BUNDLED_MANIFEST.networks[BASE_ID] as EvmManifestNetwork;
const SOLANA = BUNDLED_MANIFEST.networks[SOLANA_ID] as SvmManifestNetwork;
const BASE_USDC = BASE.assets[0] as EvmManifestAsset;
const SOLANA_USDC = SOLANA.assets[0] as SvmManifestAsset;
const BASE_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));
const SOLANA_HOSTS = new Set(SOLANA.rpcUrls.map((url) => new URL(url).host));

const EVM_PAY_TO = "0x1234567890AbcdEF1234567890aBcdef12345678";
const SVM_PAY_TO = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const BLOCKHASH = "11111111111111111111111111111111";
const AMOUNT = "50000";

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let merchant: Merchant;
let evmRpc: EvmRpcStub;
let svmRpc: SvmRpcStub;
let evmSigner: EvmSigner & { signCount: number };
let svmSigner: SolanaSigner & { signCount: number };
let kitSigner: KeyPairSigner;
let payer: `0x${string}`;
let feePayer: string;

function countingEvmSigner(): EvmSigner & { signCount: number } {
  const inner = privateKeyToEvmSigner(`0x${randomBytes(32).toString("hex")}`);
  const wrapper: EvmSigner & { signCount: number } = {
    kind: "evm",
    signCount: 0,
    getAddress: () => inner.getAddress(),
    signTypedData: (request) => {
      wrapper.signCount += 1;
      return inner.signTypedData(request);
    },
  };
  return wrapper;
}

function countingSolanaSigner(): SolanaSigner & { signCount: number } {
  const wrapper: SolanaSigner & { signCount: number } = {
    kind: "solana",
    signCount: 0,
    getPublicKey: () => Promise.resolve(kitSigner.address.toString()),
    signTransaction: async (request) => {
      wrapper.signCount += 1;
      const [signatures] = await kitSigner.signMessages([
        createSignableMessage(request.messageBytes),
      ]);
      const signature = signatures?.[kitSigner.address];
      if (signature === undefined) throw new Error("fixture signer produced no signature");
      return new Uint8Array(signature);
    },
  };
  return wrapper;
}

/** Base first, Solana second — so a planner that honoured arrival order would pick Base. */
function requirements() {
  return [
    {
      scheme: "exact",
      network: BASE_ID,
      asset: BASE_USDC.address,
      amount: AMOUNT,
      payTo: EVM_PAY_TO,
      maxTimeoutSeconds: 120,
      extra: { name: "USD Coin", version: "2" },
    },
    {
      scheme: "exact",
      network: SOLANA_ID,
      asset: SOLANA_USDC.mint,
      amount: AMOUNT,
      payTo: SVM_PAY_TO,
      maxTimeoutSeconds: 60,
      extra: {
        feePayer,
        recentBlockhash: BLOCKHASH,
        lastValidBlockHeight: "999999",
        memo: "tx402-route-selection",
      },
    },
  ];
}

beforeEach(async () => {
  kitSigner = await generateKeyPairSigner();
  feePayer = (await generateKeyPairSigner()).address.toString();
  evmSigner = countingEvmSigner();
  svmSigner = countingSolanaSigner();
  payer = await evmSigner.getAddress();

  evmRpc = await createEvmRpcStub({
    chainId: BASE.chainId,
    token: BASE_USDC.address,
    balances: { [payer]: "5000000" },
  });

  const atas = await derivePaymentAtas({
    mint: SOLANA_USDC.mint,
    payer: kitSigner.address.toString(),
    recipient: SVM_PAY_TO,
  });
  svmRpc = await createSvmRpcStub({
    genesisHash: SOLANA.genesisHash,
    mint: SOLANA_USDC.mint,
    decimals: SOLANA_USDC.decimals,
    tokenAccounts: {
      [atas.source]: {
        owner: kitSigner.address.toString(),
        mint: SOLANA_USDC.mint,
        amount: "5000000",
        decimals: SOLANA_USDC.decimals,
      },
    },
  });

  merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: requirements(),
    body: JSON.stringify({ ok: true }),
  });

  const realFetch = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: Request | string | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    const host = new URL(request.url).host;
    const target = BASE_HOSTS.has(host)
      ? evmRpc.url
      : SOLANA_HOSTS.has(host)
        ? svmRpc.url
        : undefined;
    if (target === undefined) return realFetch(request);
    return realFetch(target, {
      method: request.method,
      headers: request.headers,
      body: await request.text(),
    });
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await merchant.close();
  await evmRpc.close();
  await svmRpc.close();
});

function client(overrides: Tx402ClientConfig = {}) {
  return createTx402Client({
    signers: { evm: evmSigner, solana: svmSigner },
    allowInsecureLocalhost: true,
    policy: {
      maxPerRequest: "0.50 USDC",
      maxPerHour: "10.00 USDC",
      allowedNetworks: [BASE_ID, SOLANA_ID],
    },
    ...overrides,
  });
}

describe("M5 multi-network route selection", () => {
  it("T-004 selects Base when both are viable and Base is preferred", async () => {
    const events: Record<string, unknown>[] = [];
    const response = await client({
      routing: { preferNetworks: [BASE_ID] },
      logger: {
        debug: (event) => events.push(event),
        info: (event) => events.push(event),
        warn: (event) => events.push(event),
        error: (event) => events.push(event),
      },
    }).fetch(`${merchant.url}/resource`);

    expect(response.status).toBe(200);
    expect(evmSigner.signCount).toBe(1);
    // The decisive assertion: the Solana signer was never asked, so the route was not merely
    // reported as Base, it was paid on Base.
    expect(svmSigner.signCount).toBe(0);

    const planned = events.find((event) => event.event === "route.planned");
    expect(planned).toMatchObject({
      candidateCount: 2,
      selectedNetwork: BASE_ID,
      selectedScheme: "exact",
      selectedRank: 1,
    });
    // Both chains were queried, which is what makes this a selection rather than a filter.
    expect(evmRpc.calls.length).toBeGreaterThan(0);
    expect(svmRpc.calls.length).toBeGreaterThan(0);
  });

  it("T-005 falls to Solana when the preferred Base balance is insufficient", async () => {
    evmRpc.setBalance(payer, "10000");

    const response = await client({ routing: { preferNetworks: [BASE_ID] } }).fetch(
      `${merchant.url}/resource`,
    );

    expect(response.status).toBe(200);
    // Preference cannot lift a non-viable candidate above a viable one (SPEC §6.4 step 18).
    expect(evmSigner.signCount).toBe(0);
    expect(svmSigner.signCount).toBe(1);
  });

  it("selects Solana when Solana is the preferred network", async () => {
    const response = await client({ routing: { preferNetworks: [SOLANA_ID] } }).fetch(
      `${merchant.url}/resource`,
    );

    expect(response.status).toBe(200);
    // The merchant offered Base first, so this is preference deciding rather than order.
    expect(svmSigner.signCount).toBe(1);
    expect(evmSigner.signCount).toBe(0);
  });

  it("accepts a manifest alias as a preference and matches the canonical network", async () => {
    const response = await client({
      routing: { preferNetworks: ["solana:mainnet"] },
    }).fetch(`${merchant.url}/resource`);

    expect(response.status).toBe(200);
    expect(svmSigner.signCount).toBe(1);
  });

  it("plans identically across repeated identical challenges", async () => {
    const tx402 = client({ routing: { preferNetworks: [SOLANA_ID] } });
    await tx402.fetch(`${merchant.url}/resource`);
    await tx402.fetch(`${merchant.url}/resource`);

    // Two passes, same challenge, same health state: the same chain both times (step 19).
    expect(svmSigner.signCount).toBe(2);
    expect(evmSigner.signCount).toBe(0);
  });

  it("reports both networks' deficits when neither can pay", async () => {
    evmRpc.setBalance(payer, "1");
    svmRpc.setTokenAccount(
      (
        await derivePaymentAtas({
          mint: SOLANA_USDC.mint,
          payer: kitSigner.address.toString(),
          recipient: SVM_PAY_TO,
        })
      ).source,
      {
        owner: kitSigner.address.toString(),
        mint: SOLANA_USDC.mint,
        amount: "2",
        decimals: SOLANA_USDC.decimals,
      },
    );

    const error = await client()
      .fetch(`${merchant.url}/resource`)
      .catch((caught: unknown) => caught);

    expect(error).toMatchObject({ code: "TX402_LIQUIDITY" });
    expect((error as { details: { deficits: unknown[] } }).details.deficits).toEqual([
      {
        network: BASE_ID,
        assetId: `${BASE_ID}/erc20:${BASE_USDC.address}`,
        required: AMOUNT,
        available: "1",
      },
      {
        network: SOLANA_ID,
        assetId: `${SOLANA_ID}/token:${SOLANA_USDC.mint}`,
        required: AMOUNT,
        available: "2",
      },
    ]);
    // SEC-002: a liquidity rejection never reaches a signer.
    expect(evmSigner.signCount + svmSigner.signCount).toBe(0);
  });

  it("pays on the one network that has a configured signer", async () => {
    const response = await client({ signers: { solana: svmSigner } }).fetch(
      `${merchant.url}/resource`,
    );

    expect(response.status).toBe(200);
    expect(svmSigner.signCount).toBe(1);
    // Base became a `no-signer-configured` candidate rather than an error, and no Base RPC
    // call was made — an unpayable route must not cost a round trip.
    expect(evmRpc.calls).toHaveLength(0);
  });

  it("rejects a preference naming a network the manifest does not declare", () => {
    // A misspelled preference that silently matched nothing would be indistinguishable from
    // one that is simply never offered, so it fails at construction (SPEC §4.1).
    let thrown: unknown;
    try {
      client({ routing: { preferNetworks: ["eip155:999999"] } });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { configPath: "routing.preferNetworks[0]" },
    });
  });
});
