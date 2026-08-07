/**
 * tx402 quickstart — a real paid call on Base Sepolia.
 *
 *   export TX402_DEV_PRIVATE_KEY=0x...            # a dedicated, low-balance test wallet
 *   export TX402_MERCHANT_URL=https://...         # a merchant that answers 402
 *   pnpm --filter tx402-example-typescript quickstart
 *
 * This is the shortest complete thing that pays for something. It is written to be read
 * top to bottom rather than to be clever.
 */

import { createTx402Client, isTx402Error } from "tx402";
import { privateKeyToEvmSigner } from "tx402/signers";

const MERCHANT_URL = process.env["TX402_MERCHANT_URL"];
const PRIVATE_KEY = process.env["TX402_DEV_PRIVATE_KEY"];

if (MERCHANT_URL === undefined || PRIVATE_KEY === undefined) {
  console.error("Set TX402_MERCHANT_URL and TX402_DEV_PRIVATE_KEY first.");
  process.exit(2);
}

// A key in an environment variable is a key any child process can read. Fine for a
// throwaway testnet wallet, wrong for anything else — use a KMS or hardware signer, which
// implement the same two-method interface. See docs/security/keys.
const evm = privateKeyToEvmSigner(PRIVATE_KEY as `0x${string}`);

// The SDK requires HTTPS for every merchant, and the only way out is this explicit opt-in —
// which the SDK itself scopes to `localhost`, `127.0.0.1` and `::1`, so it cannot downgrade a
// real merchant even if it is left on. It is derived from the URL rather than hardcoded so
// that copying this file does not carry an unnecessary relaxation into your own code.
const merchantHost = new URL(MERCHANT_URL).hostname.replace(/^\[|\]$/gu, "");
const isLocalhost = ["localhost", "127.0.0.1", "::1"].includes(merchantHost);

const tx402 = createTx402Client({
  signers: { evm },

  // Needed only for the quickstart's local test merchant, which speaks plain HTTP.
  ...(isLocalhost ? { allowInsecureLocalhost: true } : {}),

  // These are the guardrails, and they run before the signer is reachable. `maxPerHour` is
  // the one that bounds a compromise: if something induces this process to pay repeatedly,
  // the ceiling is this number rather than the wallet balance.
  policy: {
    maxPerRequest: "0.10 USDC",
    maxPerHour: "1.00 USDC",
    allowedNetworks: ["eip155:84532"], // Base Sepolia only
    allowedDomains: [new URL(MERCHANT_URL).hostname],
  },

  // tx402 never writes to the console itself. Every event here is redaction-safe by
  // construction — identifiers, hashes, atomic amounts, and categories, never a signature.
  logger: {
    debug: () => undefined,
    info: (event) => console.error("[tx402]", JSON.stringify(event)),
    warn: (event) => console.error("[tx402]", JSON.stringify(event)),
    error: (event) => console.error("[tx402]", JSON.stringify(event)),
  },
});

try {
  const response = await tx402.fetch(MERCHANT_URL);
  console.log(`${response.status} ${response.statusText}`);
  console.log(await response.text());
} catch (error) {
  if (!isTx402Error(error)) throw error;

  console.error(`\n${error.code}: ${error.message}`);
  console.error("details:", JSON.stringify(error.details, null, 2));

  if (error.code === "TX402_PAYMENT_AMBIGUOUS") {
    // The one case that needs a human. The signature reached the merchant and tx402 could
    // not determine the outcome, so the money may or may not have moved. The budget
    // reservation is deliberately retained rather than released, which is why retrying
    // here can pay twice.
    console.error("\nThe payment may have settled. Reconcile before retrying.");
  }

  process.exitCode = 1;
}
