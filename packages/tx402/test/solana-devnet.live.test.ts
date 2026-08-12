/**
 * Opt-in Solana Devnet smoke. It queries the real cluster and signs a real SPL-USDC
 * transaction, while the deterministic local merchant accepts the authorization without
 * broadcasting it. Set TX402_SOLANA_DEVNET_KEYPAIR to a JSON array of 64 keypair bytes.
 */

import {
  createKeyPairSignerFromBytes,
  createSignableMessage,
  generateKeyPairSigner,
} from "@solana/kit";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client } from "../src/core/client.js";
import type { SvmManifestAsset, SvmManifestNetwork } from "../src/core/manifest.js";
import type { SolanaSigner } from "../src/core/signers.js";

const KEYPAIR = process.env.TX402_SOLANA_DEVNET_KEYPAIR;
const live = KEYPAIR === undefined ? describe.skip : describe;
const NETWORK_ID = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/**
 * The RPC override the runbook (`operations/solana-devnet.mdx`) documents for this suite: public
 * Devnet is heavily rate-limited, so an operator points this at a private endpoint. Wired exactly
 * as `volume.live.test.ts` does — before this, the suite built its client with no `routing`
 * key, so `TX402_SOLANA_DEVNET_RPC_URL` was silently inert on the very path it documents.
 */
function rpcOverrideFor(networkId: string, variable: string) {
  const url = process.env[variable];
  return url === undefined ? {} : { routing: { rpcOverrides: { [networkId]: [url] } } };
}
const NETWORK = BUNDLED_MANIFEST.networks[NETWORK_ID] as SvmManifestNetwork;
const USDC = NETWORK.assets[0] as SvmManifestAsset;
const PAY_TO = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

live("Solana Devnet live smoke", () => {
  let merchant: Awaited<ReturnType<typeof createTestMerchant>>;
  let signer: SolanaSigner;

  beforeAll(async () => {
    const bytes = new Uint8Array(JSON.parse(KEYPAIR ?? "[]") as number[]);
    const keypair = await createKeyPairSignerFromBytes(bytes);
    const feePayer = (await generateKeyPairSigner()).address.toString();
    signer = {
      kind: "solana",
      getPublicKey: () => Promise.resolve(keypair.address.toString()),
      signTransaction: async (request) => {
        const [signatures] = await keypair.signMessages([
          createSignableMessage(request.messageBytes),
        ]);
        const signature = signatures?.[keypair.address];
        if (signature === undefined) throw new Error("Devnet signer produced no signature");
        return new Uint8Array(signature);
      },
    };
    merchant = await createTestMerchant({
      scenario: "pay-once",
      requirements: [
        {
          scheme: "exact",
          network: NETWORK_ID,
          asset: USDC.mint,
          amount: "1",
          payTo: PAY_TO,
          maxTimeoutSeconds: 60,
          extra: { feePayer },
        },
      ],
    });
  });

  afterAll(async () => merchant.close());

  it("builds and signs a paid call using real Devnet identity, mint, blockhash, and ATA state", async () => {
    const client = createTx402Client({
      signers: { solana: signer },
      allowInsecureLocalhost: true,
      policy: {
        maxPerRequest: "0.01 USDC",
        maxPerHour: "0.01 USDC",
        allowedNetworks: ["solana:devnet"],
      },
      ...rpcOverrideFor(NETWORK_ID, "TX402_SOLANA_DEVNET_RPC_URL"),
    });
    await expect(client.fetch(`${merchant.url}/resource`)).resolves.toHaveProperty(
      "status",
      200,
    );
    expect(merchant.paidRequests).toHaveLength(1);
  });
});
