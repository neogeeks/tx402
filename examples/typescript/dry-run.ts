/**
 * Inspect a merchant's terms without paying, and without a key.
 *
 *   export TX402_MERCHANT_URL=https://...
 *   pnpm --filter tx402-example-typescript dry-run
 *
 * `client.inspect()` performs the request, decodes and strictly validates the merchant's
 * `PAYMENT-REQUIRED` challenge, and stops. It configures no signer, contacts no chain, and
 * cannot spend anything — so it is safe to run in a loop, in CI, or from an agent that
 * should be able to find out what something costs without being able to buy it.
 *
 * **`inspect()` and `plan()` are different questions, and only one of them is keyless.**
 * `inspect()` answers "what is this merchant asking for?" — a property of the challenge
 * alone. `plan()` answers "what would I actually pay, and by which route?", which means
 * ranking the offered routes, which means reading your address and balance on each one. A
 * route it cannot price is a route it cannot rank, so `plan()` — and the CLI's `--dry-run`,
 * which is the same call — require a configured signer. Neither ever produces a signature.
 */

import { createTx402Client, isTx402Error } from "tx402";

const MERCHANT_URL = process.env["TX402_MERCHANT_URL"];
if (MERCHANT_URL === undefined) {
  console.error("Set TX402_MERCHANT_URL first.");
  process.exit(2);
}

// The SDK requires HTTPS for every merchant; this opt-in is scoped to localhost by the SDK
// itself and is derived from the URL, so copying this file carries no relaxation with it.
const merchantHost = new URL(MERCHANT_URL).hostname.replace(/^\[|\]$/gu, "");
const isLocalhost = ["localhost", "127.0.0.1", "::1"].includes(merchantHost);

// No signers configured at all, and none needed: `inspect()` never reaches a chain.
const tx402 = createTx402Client({
  ...(isLocalhost ? { allowInsecureLocalhost: true } : {}),
  policy: {
    maxPerRequest: "1.00 USDC",
    // Testnets are never allowed by default, because a silent fall back from production to
    // a testnet is worse than a refusal. Naming them is the opt-in.
    allowedNetworks: ["eip155:84532", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"],
  },
});

try {
  const inspection = await tx402.inspect(MERCHANT_URL);

  if (inspection.paymentRequired === undefined) {
    console.log(
      `No payment required — the resource answered ${inspection.response.status}.`,
    );
    process.exit(0);
  }

  console.log(`request      ${inspection.requestId}`);
  console.log(`requirements ${inspection.paymentRequired.requirements.length}`);
  console.log(`header hash  ${inspection.paymentRequired.headerHash}\n`);

  console.log("What the merchant accepts:");
  for (const requirement of inspection.paymentRequired.requirements) {
    console.log(
      `  [${requirement.index}] ${requirement.amountAtomic} atomic  ` +
        `${requirement.scheme} on ${requirement.network}`,
    );
  }

  console.log("\nNothing was signed, no budget was reserved, and no chain was contacted.");
  console.log("To see how tx402 would rank these routes, configure a signer and use");
  console.log("`client.plan()` — or `tx402 call <url> --dry-run` from the CLI.");
} catch (error) {
  if (!isTx402Error(error)) throw error;
  // Inspection can still fail: an unreachable merchant, or a challenge that does not decode.
  // Both are worth seeing before you try to pay.
  console.error(`${error.code}: ${error.message}`);
  process.exitCode = 1;
}
