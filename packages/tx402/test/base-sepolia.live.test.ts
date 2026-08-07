/**
 * Base Sepolia live coverage (SPEC §12.1 "Public testnet", PLAN.md open item O2).
 *
 * Skipped unless `TX402_BASE_SEPOLIA_PRIVATE_KEY` is set, so it never runs in ordinary CI and
 * never needs a funded wallet to be present for the suite to be green. Point it at a
 * dedicated, low-balance wallet — SPEC §13 asks for exactly that, and nothing else should
 * ever be reachable from a test process.
 *
 * ```sh
 * TX402_BASE_SEPOLIA_PRIVATE_KEY=0x… pnpm --filter tx402 exec vitest run test/base-sepolia.live.test.ts
 * ```
 *
 * **What is real here and what is not.** Chain identity, the USDC balance read, and the
 * EIP-712 signature are real: they go to the manifest's published Base Sepolia RPC endpoints
 * and through the caller's actual key. Settlement is not, and cannot be — ADR-002 makes the
 * merchant, not the buyer, responsible for calling `/verify` and `/settle`, so the buyer SDK
 * has no settlement path to exercise. The local test merchant plays the merchant's half and
 * validates the authorization it receives. Set `TX402_LIVE_MERCHANT_URL` to run the same
 * client against a real x402 merchant instead, which is what closes the loop end to end.
 */

import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client } from "../src/core/client.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import { formatMoneyDecimal } from "../src/core/money.js";
import { EvmRpcPool } from "../src/evm/rpc.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";

const PRIVATE_KEY = process.env.TX402_BASE_SEPOLIA_PRIVATE_KEY;
const LIVE_MERCHANT_URL = process.env.TX402_LIVE_MERCHANT_URL;

const NETWORK_ID = "eip155:84532";
const SEPOLIA = BUNDLED_MANIFEST.networks[NETWORK_ID] as EvmManifestNetwork;
const USDC = SEPOLIA.assets[0] as EvmManifestAsset;

/** 0.01 USDC. Small enough that a lightly funded wallet can run this repeatedly. */
const PRICE_ATOMIC = "10000";

describe.skipIf(PRIVATE_KEY === undefined)("Base Sepolia (live, opt-in)", () => {
  // Built in `beforeAll`, not at collection time: a skipped describe body still runs, and
  // constructing a signer from an absent key would fail the whole file rather than skip it.
  let signer: ReturnType<typeof privateKeyToEvmSigner>;
  let merchant: Awaited<ReturnType<typeof createTestMerchant>> | undefined;
  let payer: `0x${string}`;

  beforeAll(async () => {
    signer = privateKeyToEvmSigner(PRIVATE_KEY as `0x${string}`);
    payer = await signer.getAddress();
    merchant = await createTestMerchant({
      scenario: "pay-once",
      requirements: [
        {
          scheme: "exact",
          network: NETWORK_ID,
          asset: USDC.address,
          amount: PRICE_ATOMIC,
          payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
          maxTimeoutSeconds: 120,
          // Circle's Base Sepolia USDC uses the domain name "USDC"; mainnet uses
          // "USD Coin". A real merchant supplies whichever its token actually declares.
          extra: { name: "USDC", version: "2" },
        },
      ],
    });
  });

  afterAll(async () => {
    await merchant?.close();
  });

  it("verifies the published RPC endpoints really serve chain 84532", async () => {
    const pool = new EvmRpcPool(SEPOLIA.rpcUrls, { timeoutMs: 5_000 });

    const reading = await pool.readBalance({
      chainId: SEPOLIA.chainId,
      token: USDC.address,
      owner: payer,
      nowEpochMs: Date.now(),
    });

    expect(reading.chainId).toBe(84532);
    // Reported so a funding failure reads as a balance, not as an opaque assertion.
    expect(
      `${formatMoneyDecimal(reading.balanceAtomic, USDC.decimals)} ${USDC.symbol}`,
    ).toMatch(/USDC$/u);
    expect(reading.balanceAtomic).toBeGreaterThanOrEqual(BigInt(PRICE_ATOMIC));
  }, 30_000);

  it("completes a paid call with a real signature over live chain state", async () => {
    const client = createTx402Client({
      signers: { evm: signer },
      allowInsecureLocalhost: true,
      policy: {
        maxPerRequest: "0.10 USDC",
        maxPerHour: "1.00 USDC",
        // SPEC §5.4: a test network is usable only through an explicit opt-in.
        allowedNetworks: [NETWORK_ID],
      },
    });

    const response = await client.fetch(
      LIVE_MERCHANT_URL ?? `${merchant?.url ?? ""}/resource`,
    );

    expect(response.status).toBe(200);
    expect(client.getBudgetState().committedAtomic).toBe(PRICE_ATOMIC);
    if (LIVE_MERCHANT_URL === undefined) {
      expect(merchant?.paidRequests).toHaveLength(1);
      expect(merchant?.violations).toEqual([]);
    }
  }, 60_000);
});
