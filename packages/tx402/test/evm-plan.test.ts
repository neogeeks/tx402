/**
 * The pure half of the Base adapter (SPEC §7.1, §6.6).
 *
 * Everything asserted here happens before an address is resolved, a balance is read, or a
 * signer is touched, which is what makes an unusable merchant offer free to reject.
 */

import { describe, expect, it } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import {
  encodeBalanceOfCallData,
  planExactEvmAuthorization,
  type ExactEvmRequirementInput,
} from "../src/evm/plan.js";

const NETWORK = BUNDLED_MANIFEST.networks["eip155:8453"] as EvmManifestNetwork;
const ASSET = NETWORK.assets[0] as EvmManifestAsset;
const PAYER = "0x1111111111111111111111111111111111111111";
const PAY_TO = "0x2222222222222222222222222222222222222222";
const NOW = 1_785_000_000_000;
const CONTEXT = { requestId: "plan-test", phase: "route" } as const;

function requirement(
  overrides: Partial<ExactEvmRequirementInput> = {},
): ExactEvmRequirementInput {
  return {
    index: 0,
    scheme: "exact",
    network: "eip155:8453",
    asset: ASSET.address,
    amountAtomic: "50000",
    payTo: PAY_TO,
    maxTimeoutSeconds: 60,
    extra: { name: "USD Coin", version: "2" },
    ...overrides,
  };
}

function plan(overrides: Partial<ExactEvmRequirementInput> = {}, payer = PAYER) {
  return planExactEvmAuthorization({
    requirement: requirement(overrides),
    networkId: "eip155:8453",
    network: NETWORK,
    asset: ASSET,
    payer,
    nowEpochMs: NOW,
    maxAuthorizationSeconds: 60,
    context: CONTEXT,
  });
}

describe("exact EVM authorization plan", () => {
  it("binds the manifest token, chain, and payout address", () => {
    const result = plan();

    expect(result).toMatchObject({
      chainId: 8453,
      verifyingContract: ASSET.address,
      domainName: "USD Coin",
      domainVersion: "2",
      payer: PAYER,
      recipient: PAY_TO,
      valueAtomic: "50000",
      validAfterSeconds: 0,
    });
    // The verifying contract comes from the signed manifest, so a merchant that spells the
    // token address differently cannot move the signature to another contract.
    expect(result.verifyingContract).toBe(ASSET.address);
  });

  it("clamps the authorization lifetime to 60 seconds without exceeding the merchant bound", () => {
    // SPEC §6.6: min(60, merchant max). Both directions matter — the cap must bite on a
    // generous merchant, and must not extend a stricter one.
    expect(plan({ maxTimeoutSeconds: 600 }).lifetimeSeconds).toBe(60);
    expect(plan({ maxTimeoutSeconds: 30 }).lifetimeSeconds).toBe(30);
    expect(plan({ maxTimeoutSeconds: 60 }).lifetimeSeconds).toBe(60);

    const generous = plan({ maxTimeoutSeconds: 600 });
    expect(generous.notAfterEpochSeconds - generous.notBeforeEpochSeconds).toBe(60);
    expect(generous.notBeforeEpochSeconds).toBe(Math.floor(NOW / 1000));
  });

  it("encodes balanceOf call data as selector plus a left-padded owner", () => {
    expect(plan().balanceOfCallData).toBe(
      `0x70a08231${"0".repeat(24)}${PAYER.slice(2).toLowerCase()}`,
    );
    expect(encodeBalanceOfCallData("0xABCDEF0123456789abcdef0123456789ABCDEF01")).toBe(
      `0x70a08231${"0".repeat(24)}abcdef0123456789abcdef0123456789abcdef01`,
    );
    expect(() => encodeBalanceOfCallData("0xshort")).toThrow(TypeError);
  });

  it("declines schemes and transfer methods v0.1 does not implement", () => {
    expect(() => plan({ scheme: "upto" })).toThrowError(/exact payment scheme/u);
    expect(() =>
      plan({ extra: { name: "USD Coin", version: "2", assetTransferMethod: "permit2" } }),
    ).toThrowError(/not supported in v0.1/u);
    // The eip3009 method is the supported one and must be accepted when stated explicitly.
    expect(
      plan({ extra: { name: "USD Coin", version: "2", assetTransferMethod: "eip3009" } })
        .lifetimeSeconds,
    ).toBe(60);
  });

  it("requires the EIP-712 token domain the upstream scheme signs over", () => {
    for (const extra of [
      {},
      { name: "USD Coin" },
      { version: "2" },
      { name: "", version: "2" },
      { name: "USD Coin", version: 2 },
    ]) {
      expect(() => plan({ extra })).toThrowError(/eip712-domain-missing/u);
    }
    // A version the token does not use would produce a signature the token rejects
    // on-chain. Declining costs nothing; signing would burn a nonce and a reservation.
    expect(() => plan({ extra: { name: "USD Coin", version: "1" } })).toThrowError(
      /eip712-domain-mismatch/u,
    );
  });

  it("rejects addresses, amounts, and identifiers that do not match the manifest", () => {
    expect(() =>
      plan({ asset: "0x0000000000000000000000000000000000000009" }),
    ).toThrowError(/asset-not-manifest-asset/u);
    expect(() => plan({ payTo: "not-an-address" })).toThrowError(/pay-to-invalid/u);
    expect(() => plan({}, "0xnope")).toThrowError(/payer-invalid/u);
    expect(() => plan({ amountAtomic: "0" })).toThrowError(/amount-not-atomic-integer/u);
    expect(() => plan({ maxTimeoutSeconds: 0 })).toThrowError(/max-timeout-invalid/u);
    expect(() =>
      planExactEvmAuthorization({
        requirement: requirement(),
        networkId: "eip155:8453",
        network: { ...NETWORK, chainId: 1 },
        asset: ASSET,
        payer: PAYER,
        nowEpochMs: NOW,
        maxAuthorizationSeconds: 60,
        context: CONTEXT,
      }),
    ).toThrowError(/network-chain-id-mismatch/u);
    expect(() => plan({ network: "eip155:84532" })).toThrowError(/network-not-canonical/u);
  });

  it("reports a typed error code for every rejection", () => {
    try {
      plan({ extra: {} });
      expect.unreachable("plan should have rejected");
    } catch (error) {
      expect(error).toMatchObject({
        code: "TX402_PAYMENT_REQUIRED_INVALID",
        context: { requestId: "plan-test", phase: "route" },
        details: { reason: "eip712-domain-missing" },
      });
    }
    try {
      plan({ scheme: "upto" });
      expect.unreachable("plan should have rejected");
    } catch (error) {
      expect(error).toMatchObject({
        code: "TX402_SCHEME_UNSUPPORTED",
        details: { offeredSchemes: ["upto"], offeredNetworks: ["eip155:8453"] },
      });
    }
  });
});
