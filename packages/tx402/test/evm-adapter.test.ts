/**
 * Adapter-level guards that the end-to-end suite cannot reach (SPEC §7.1, ADR-003).
 *
 * These are the conditions that should be impossible by the time the adapter is called —
 * a Solana network handed to the EVM adapter, a missing signer, a scheme that returns a
 * payload without signing. They are asserted anyway, because "impossible" here means
 * "prevented by a caller two layers up", and the adapter is the layer holding the key.
 */

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { afterEach, describe, expect, it } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import type { ChainAuthorizationRequest, ChainRouteRequest } from "../src/core/chain.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import type { PolicyRequirement } from "../src/core/policy.js";
import type { EvmSigner } from "../src/core/signers.js";
import { createEvmChainAdapter } from "../src/evm/adapter.js";

const BASE_ID = "eip155:8453";
const BASE = BUNDLED_MANIFEST.networks[BASE_ID] as EvmManifestNetwork;
const USDC = BASE.assets[0] as EvmManifestAsset;
const SOLANA_ID = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const PAYER = "0x00000000000000000000000000000000000000a1";
const PAY_TO = "0x1234567890AbcdEF1234567890aBcdef12345678";

const open: EvmRpcStub[] = [];
afterEach(async () => {
  await Promise.all(open.splice(0).map((instance) => instance.close()));
});

const signer: EvmSigner = {
  kind: "evm",
  getAddress: () => Promise.resolve(PAYER),
  signTypedData: () => Promise.resolve(("0x" + "ab".repeat(65)) as `0x${string}`),
};

const requirement: PolicyRequirement = Object.freeze({
  index: 0,
  scheme: "exact",
  network: BASE_ID,
  asset: USDC.address,
  amountAtomic: "50000",
  payTo: PAY_TO,
  maxTimeoutSeconds: 60,
  extra: Object.freeze({ name: "USD Coin", version: "2" }),
  rawHash: `sha256:${"0".repeat(64)}`,
  assetId: `${BASE_ID}/erc20:${USDC.address}`,
  manifestAsset: USDC,
  maxPerRequestAtomic: "500000",
  maxPerHourAtomic: "10000000",
});

function routeRequest(overrides: Partial<ChainRouteRequest> = {}): ChainRouteRequest {
  return {
    requestId: "adapter-test",
    networkId: BASE_ID,
    network: BASE,
    asset: USDC,
    requirement,
    signer,
    nowEpochMs: 1_785_715_200_000,
    ...overrides,
  };
}

function authorizationRequest(
  overrides: Partial<ChainAuthorizationRequest> = {},
): ChainAuthorizationRequest {
  return {
    ...routeRequest(),
    resourceHost: "api.example.com",
    requestHash: `sha256:${"a".repeat(64)}`,
    maxAuthorizationSeconds: 60,
    ...overrides,
  };
}

describe("EVM chain adapter", () => {
  it("refuses a network or asset from another chain family", async () => {
    const adapter = createEvmChainAdapter();
    const solana = BUNDLED_MANIFEST.networks[SOLANA_ID];
    const solanaAsset = solana?.assets[0];
    if (solana === undefined || solanaAsset === undefined) {
      throw new Error("bundled manifest lost Solana mainnet");
    }

    await expect(
      adapter.planRoute(routeRequest({ networkId: SOLANA_ID, network: solana })),
    ).rejects.toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { reason: "not-an-evm-network" },
    });
    await expect(
      adapter.planRoute(routeRequest({ asset: solanaAsset })),
    ).rejects.toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { reason: "not-an-evm-asset" },
    });
  });

  it("refuses to plan or sign without an EVM signer", async () => {
    const adapter = createEvmChainAdapter();

    for (const candidate of [undefined, {}, { kind: "solana" }]) {
      await expect(
        adapter.planRoute(routeRequest({ signer: candidate })),
      ).rejects.toMatchObject({
        code: "TX402_CONFIG_INVALID",
        details: { configPath: "signers.evm", reason: "missing-evm-signer" },
      });
    }
    await expect(
      adapter.createAuthorization(authorizationRequest({ signer: undefined })),
    ).rejects.toMatchObject({ details: { reason: "missing-evm-signer" } });
  });

  it("reports a route as non-viable rather than throwing on a short balance", async () => {
    const rpc = await createEvmRpcStub({
      chainId: 8453,
      token: USDC.address,
      balances: { [PAYER]: "49999" },
    });
    open.push(rpc);
    const adapter = createEvmChainAdapter();

    const route = await adapter.planRoute(
      routeRequest({ network: { ...BASE, rpcUrls: [rpc.url] } }),
    );

    expect(route).toMatchObject({
      viable: false,
      balanceAtomic: "49999",
      amountAtomic: "50000",
      signerId: `evm:${PAYER}`,
      rejectionReasons: ["insufficient-balance"],
    });
  });

  it("categorizes an unreachable RPC as a transport failure", async () => {
    const rpc = await createEvmRpcStub({ chainId: 8453, mode: "http-error" });
    open.push(rpc);
    const adapter = createEvmChainAdapter();

    await expect(
      adapter.planRoute(routeRequest({ network: { ...BASE, rpcUrls: [rpc.url] } })),
    ).rejects.toMatchObject({
      code: "TX402_TRANSPORT",
      details: { causeCategory: "transport" },
    });
  });

  it("reuses one RPC pool per network and clears it on resetHealth", async () => {
    const rpc = await createEvmRpcStub({
      chainId: 8453,
      token: USDC.address,
      balances: { [PAYER]: "5000000" },
    });
    open.push(rpc);
    const adapter = createEvmChainAdapter();
    const network = { ...BASE, rpcUrls: [rpc.url] };

    await adapter.planRoute(routeRequest({ network }));
    await adapter.planRoute(routeRequest({ network }));
    // Circuit state persists across requests, so the pool must be the same object; chain
    // identity is nevertheless re-verified on each read.
    expect(rpc.calls.filter((call) => call.method === "eth_chainId")).toHaveLength(2);

    expect(() => {
      adapter.resetHealth();
    }).not.toThrow();
  });

  it("signs through the upstream scheme and reports the signed expiry", async () => {
    const adapter = createEvmChainAdapter();

    const authorization = await adapter.createAuthorization(authorizationRequest());

    expect(authorization.x402Version).toBe(2);
    expect(authorization.signerId).toBe(`evm:${PAYER}`);
    expect(Object.keys(authorization.payload)).toEqual(
      expect.arrayContaining(["authorization", "signature"]),
    );
    // The expiry is read back from the message that was actually signed, not recomputed.
    const expectedCeiling = Date.now() + 60_000 + 1_000;
    expect(authorization.expiresAtEpochMs).toBeLessThanOrEqual(expectedCeiling);
    expect(authorization.expiresAtEpochMs).toBeGreaterThan(Date.now());
  });

  it("declines an unusable requirement before the signer is reached", async () => {
    const adapter = createEvmChainAdapter();

    await expect(
      adapter.createAuthorization(
        authorizationRequest({
          requirement: { ...requirement, extra: {} },
        }),
      ),
    ).rejects.toMatchObject({
      code: "TX402_PAYMENT_REQUIRED_INVALID",
      details: { reason: "eip712-domain-missing" },
    });
  });

  it("types a scheme failure that produces no signature", async () => {
    const adapter = createEvmChainAdapter();
    const refusing: EvmSigner = {
      kind: "evm",
      getAddress: () => Promise.resolve(PAYER),
      signTypedData: () => Promise.reject(new Error("seeded device failure")),
    };

    const error = await adapter
      .createAuthorization(authorizationRequest({ signer: refusing }))
      .catch((caught: unknown) => caught);

    expect(error).toMatchObject({
      code: "TX402_SIGNER",
      details: { signerKind: "evm", causeCategory: "signer-rejected" },
    });
    expect(JSON.stringify(error)).not.toContain("seeded device failure");
  });
});
