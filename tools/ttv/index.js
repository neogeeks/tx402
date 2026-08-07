#!/usr/bin/env node
/**
 * Time-to-value measurement (SPEC §16).
 *
 *   . tools/live-env.sh && node tools/ttv/index.js [base-sepolia|solana-devnet]
 *
 * The release-defining check is that a fresh user completes **a real paid call in under
 * five minutes without reading source code**. This script measures the part of that a
 * machine can measure: the wall-clock time from "an installed package and a funded wallet"
 * to "a settled on-chain payment and a delivered resource", following the documented
 * quickstart path.
 *
 * **The settlement is real.** The merchant runs locally, and that does not make the money
 * fake — settlement does, and this settles. The merchant is wired to the public x402
 * facilitator at https://x402.org/facilitator, which verifies the authorization and
 * broadcasts the transfer. Real testnet USDC moves, and the transaction the facilitator
 * returns is printed and recorded.
 *
 * ADR-002 keeps `/verify` and `/settle` on the merchant, so the buyer SDK still never
 * learns a facilitator exists. That separation is exactly what makes a local merchant a
 * legitimate fixture here: the buyer's code path is the shipped one, byte for byte, and
 * the only thing the fixture supplies is the counterparty.
 *
 * Why not the public demo merchant: `x402.org/protected` returns 502.
 *
 * **This spends money on every run.** It is not free and it is not idempotent.
 */

import { createTestMerchant } from "@tx402-dev/test-merchant";

import { BUNDLED_MANIFEST } from "../../packages/tx402/dist/core/bundled-manifest.js";
import { createTx402Client } from "../../packages/tx402/dist/index.js";
import {
  keypairToSolanaSigner,
  privateKeyToEvmSigner,
} from "../../packages/tx402/dist/signers/index.js";

const FACILITATOR = process.env["TX402_FACILITATOR_URL"] ?? "https://x402.org/facilitator";

/**
 * Everything that differs between chains, and nothing that does not.
 *
 * The measured path below is identical for every network — same client, same policy shape,
 * same dry run, same paid call. That is deliberate: a TTV number is only comparable across
 * chains if the thing being timed is the same thing. Hard-coding Base, as this tool did
 * through S13, made the Solana number unobtainable rather than merely unmeasured (O40).
 */
const NETWORKS = {
  "base-sepolia": {
    caip2: "eip155:84532",
    keyEnv: "TX402_BASE_SEPOLIA_PRIVATE_KEY",
    keyHint: "a 0x-prefixed 32-byte hex private key",
    rpcOverrideEnv: "TX402_BASE_SEPOLIA_RPC_URL",
    /** The asset's on-chain identifier, as the manifest records it. */
    assetRef: (asset) => asset.address,
    signer: (value) => privateKeyToEvmSigner(value),
    /**
     * A throwaway address nothing in this project holds a key for. Each run sends it
     * 0.001 USDC, which is the price of proving value genuinely left the payer's wallet.
     */
    defaultPayTo: "0x1CB8D0000000000000000000000000000000402A",
    /** EIP-712 domain metadata the merchant must publish for an EIP-3009 authorization. */
    extra: (asset) => ({ name: "USDC", version: asset.eip712Version }),
    explorer: (tx) => `https://sepolia.basescan.org/tx/${tx}`,
  },
  "solana-devnet": {
    caip2: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    keyEnv: "TX402_SOLANA_DEVNET_KEYPAIR",
    keyHint: "a JSON array of 64 keypair bytes",
    rpcOverrideEnv: "TX402_SOLANA_DEVNET_RPC_URL",
    assetRef: (asset) => asset.mint,
    signer: (value) => keypairToSolanaSigner(value),
    /**
     * **This recipient is not arbitrary.** An SPL transfer requires the destination's
     * associated token account to already exist; a fresh Devnet address has none, and the
     * transfer fails `/settle` with `transaction_simulation_failed`. That looked exactly
     * like a tx402 defect at S13 when it was a missing account. This address holds USDC on
     * Devnet and therefore has the ATA.
     */
    defaultPayTo: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    /**
     * Solana's fee payer is the facilitator's, not the buyer's — which is what keeps the
     * buyer's SOL untouched. Read from `/supported` rather than hard-coded, so a
     * facilitator that rotates its fee payer does not silently break this.
     */
    extra: (_asset, supported) => ({ feePayer: supported.extra?.feePayer }),
    explorer: (tx) => `https://explorer.solana.com/tx/${tx}?cluster=devnet`,
  },
};

const requested = process.argv[2] ?? "base-sepolia";
const config = NETWORKS[requested];
if (config === undefined) {
  console.error(
    `Unknown network "${requested}". Choose one of: ${Object.keys(NETWORKS).join(", ")}`,
  );
  process.exit(2);
}

const KEY = process.env[config.keyEnv];
if (KEY === undefined) {
  console.error(
    `${config.keyEnv} is not set — it should be ${config.keyHint}.\n` +
      "Run `. tools/live-env.sh` first — it normalises the .env names and prints which\n" +
      "resolved. Without it the live suites silently skip and look exactly like an\n" +
      "unfunded wallet (PLAN.md open item O33).",
  );
  process.exit(2);
}

/** Override with `TX402_TTV_PAY_TO` to send it somewhere you own. */
const PAY_TO = process.env["TX402_TTV_PAY_TO"] ?? config.defaultPayTo;

const network = BUNDLED_MANIFEST.networks[config.caip2];
const usdc = network.assets[0];

/** ADR-015: a keyed endpoint when one is configured, the signed manifest otherwise. */
const rpcOverride = process.env[config.rpcOverrideEnv];
const routing =
  rpcOverride === undefined ? {} : { rpcOverrides: { [config.caip2]: [rpcOverride] } };

/** One pass of the quickstart, timed by phase. */
async function main() {
  const marks = [];
  const started = performance.now();
  const mark = (label) =>
    marks.push({ label, atMs: Math.round(performance.now() - started) });

  console.log(`  network       ${requested} (${config.caip2})`);
  if (rpcOverride !== undefined) {
    // Never the URL itself: an RPC endpoint carries its API key in the path (ADR-015).
    console.log(`  rpc           override from ${config.rpcOverrideEnv}`);
  }

  // Confirm the facilitator supports what we are about to ask of it, before spending
  // anyone's time. A merchant offering terms its facilitator cannot settle is a
  // configuration error, and finding it here rather than after a signature is cheaper.
  const supported = await (await fetch(`${FACILITATOR}/supported`)).json();
  const kind = supported.kinds.find(
    (entry) =>
      entry.x402Version === 2 && entry.scheme === "exact" && entry.network === config.caip2,
  );
  if (kind === undefined) {
    throw new Error(`facilitator does not support exact/${config.caip2} at x402Version 2`);
  }
  mark("facilitator capability confirmed");

  const signer = await config.signer(KEY);
  const payer = await (signer.kind === "evm" ? signer.getAddress() : signer.getPublicKey());
  mark("signer ready");
  console.log(`  payer         ${payer}`);
  console.log(`  merchant      ${PAY_TO}`);

  const merchant = await createTestMerchant({
    scenario: "pay-once",
    facilitatorUrl: FACILITATOR,
    body: JSON.stringify({ ok: true, resource: "ttv" }),
    requirements: [
      {
        scheme: "exact",
        network: config.caip2,
        asset: config.assetRef(usdc),
        // 0.001 USDC. Small enough to run this repeatedly, large enough to be a real
        // token transfer rather than a zero-value no-op.
        amount: "1000",
        // A recipient the payer does not control, so the on-chain transfer is a genuine
        // buyer→merchant movement rather than a self-transfer. Paying yourself would still
        // consume the authorization and still prove settlement, but it would leave "did
        // value actually leave the wallet" untested, which is the one question a payment
        // SDK cannot afford to leave open.
        payTo: PAY_TO,
        maxTimeoutSeconds: 120,
        extra: config.extra(usdc, kind),
      },
    ],
  });
  mark("merchant listening");

  const tx402 = createTx402Client({
    signers: signer.kind === "evm" ? { evm: signer } : { solana: signer },
    policy: {
      maxPerRequest: "0.10 USDC",
      maxPerHour: "1.00 USDC",
      allowedNetworks: [config.caip2],
    },
    routing,
    allowInsecureLocalhost: true,
  });
  mark("client constructed");

  try {
    // --- the dry run a first-time user does first --------------------------------------
    const plan = await tx402.plan(`${merchant.url}/resource`);
    mark("dry run complete (no signature, no reservation)");
    console.log(
      `  plan: ${plan.selected?.amountAtomic} atomic on ${plan.selected?.network}, ` +
        `rank ${plan.selected?.rank} of ${plan.candidates?.length}`,
    );

    // --- the real, settled call ---------------------------------------------------------
    const paidAt = performance.now();
    const response = await tx402.fetch(`${merchant.url}/resource`);
    const paidMs = Math.round(performance.now() - paidAt);
    mark("paid call complete");

    const settlement = merchant.requests.find((entry) => entry.settlement)?.settlement;
    const body = await response.text();

    console.log(`\n  status        ${response.status}`);
    console.log(`  body          ${body}`);
    console.log(`  settled       ${settlement?.success}`);
    console.log(`  transaction   ${settlement?.transaction}`);
    console.log(`  explorer      ${config.explorer(settlement?.transaction ?? "")}`);
    console.log(`  paid call     ${paidMs} ms`);

    if (settlement?.success !== true) {
      throw new Error(
        `settlement did not succeed: ${settlement?.errorReason ?? "unknown"}. ` +
          "The payment was not real, so this measurement does not count.",
      );
    }

    console.log("\n  Phase timings");
    let previous = 0;
    for (const { label, atMs } of marks) {
      console.log(`    ${String(atMs).padStart(6)} ms  (+${atMs - previous})  ${label}`);
      previous = atMs;
    }

    const totalMs = marks.at(-1).atMs;
    const budgetMs = 5 * 60 * 1000;
    console.log(
      `\n  TOTAL ${totalMs} ms (${(totalMs / 1000).toFixed(2)} s) ` +
        `against a ${budgetMs / 1000} s budget — ${totalMs < budgetMs ? "PASS" : "FAIL"}`,
    );
    if (totalMs >= budgetMs) process.exitCode = 1;
  } finally {
    await merchant.close();
  }
}

await main();
