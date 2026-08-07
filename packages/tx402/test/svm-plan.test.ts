import { describe, expect, it } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import type { SvmManifestAsset, SvmManifestNetwork } from "../src/core/manifest.js";
import { planExactSvmAuthorization } from "../src/solana/plan.js";

const NETWORK_ID = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const network = BUNDLED_MANIFEST.networks[NETWORK_ID] as SvmManifestNetwork;
const asset = network.assets[0] as SvmManifestAsset;
const PAYER = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const RECIPIENT = "11111111111111111111111111111111";
const context = { requestId: "svm-plan", phase: "route" as const };

function requirement(overrides: Record<string, unknown> = {}) {
  return {
    index: 0,
    scheme: "exact",
    network: NETWORK_ID,
    asset: asset.mint,
    amountAtomic: "50000",
    payTo: RECIPIENT,
    maxTimeoutSeconds: 60,
    extra: { feePayer: RECIPIENT },
    ...overrides,
  };
}

function plan(
  overrides: {
    requirement?: Record<string, unknown>;
    payer?: string;
    asset?: SvmManifestAsset;
    maxAuthorizationSeconds?: number;
  } = {},
) {
  return planExactSvmAuthorization({
    requirement: requirement(overrides.requirement),
    networkId: NETWORK_ID,
    network,
    asset: overrides.asset ?? asset,
    payer: overrides.payer ?? PAYER,
    maxAuthorizationSeconds: overrides.maxAuthorizationSeconds ?? 60,
    context,
  });
}

describe("SVM authorization planning", () => {
  it("clamps lifetime and accepts numeric lastValidBlockHeight", async () => {
    await expect(
      plan({
        maxAuthorizationSeconds: 20,
        requirement: {
          maxTimeoutSeconds: 30,
          extra: { feePayer: RECIPIENT, lastValidBlockHeight: 123 },
        },
      }),
    ).resolves.toMatchObject({ lifetimeSeconds: 20, lastValidBlockHeight: "123" });
  });

  it("defaults a malformed optional block height and ignores non-string memo metadata", async () => {
    const value = await plan({
      requirement: {
        extra: { feePayer: RECIPIENT, lastValidBlockHeight: -1, memo: 42 },
      },
    });
    expect(value.lastValidBlockHeight).toBe("0");
    expect(value).not.toHaveProperty("memo");
  });

  it("rejects Token-2022 before deriving accounts", async () => {
    await expect(
      plan({ asset: { ...asset, tokenProgram: "token-2022" } as never }),
    ).rejects.toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { reason: "token-2022-excluded" },
    });
  });

  it.each([
    [{ scheme: "upto" }, "svm-route-mismatch"],
    [{ network: "solana:wrong" }, "svm-route-mismatch"],
    [{ asset: PAYER }, "svm-route-mismatch"],
    [{ payTo: "not-base58" }, "svm-pay-to-invalid"],
    [{ extra: {} }, "svm-feePayer-missing"],
    [{ extra: { feePayer: "not-base58" } }, "svm-feePayer-invalid"],
  ])("rejects an invalid requirement %#", async (change, reason) => {
    await expect(plan({ requirement: change })).rejects.toMatchObject({
      details: { reason },
    });
  });

  it("rejects a malformed signer public key", async () => {
    await expect(plan({ payer: "not-base58" })).rejects.toMatchObject({
      details: { reason: "svm-payer-invalid" },
    });
  });
});
