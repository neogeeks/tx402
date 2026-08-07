#!/usr/bin/env node
/**
 * Runs the test merchant as a standalone process.
 *
 * The TypeScript suite imports `createTestMerchant` directly. Python cannot, so it spawns
 * this and reads one JSON line from stdout:
 *
 *     {"url":"http://127.0.0.1:54321","port":54321,"scenario":"pay-once"}
 *
 * The line is emitted only once the server is actually listening, which is what lets a test
 * harness wait on a readable event rather than polling a port.
 *
 *   node tools/test-merchant/cli.js --scenario pay-once [--port 0] [--requirements base,solana]
 */

import { createTestMerchant } from "./index.js";
import { DEFAULT_REQUIREMENTS, SCENARIOS } from "./scenarios.js";

/** @param {string[]} argv */
function parseFlags(argv) {
  /** @type {Record<string, string>} */
  const flags = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) continue;
    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[token.slice(2)] = next;
      index += 1;
    } else {
      flags[token.slice(2)] = "true";
    }
  }
  return flags;
}

const USAGE = `tx402-test-merchant — deterministic x402 merchant (SPEC §13)

Usage:
  tx402-test-merchant [--scenario <name>] [--port <n>] [--requirements <list>]

Options:
  --scenario <name>       default: pay-once
  --port <n>              default: 0 (ephemeral)
  --requirements <list>   comma-separated: ${Object.keys(DEFAULT_REQUIREMENTS).join(", ")}
  --facilitator <url>     settle for real through this x402 facilitator, e.g.
                          https://x402.org/facilitator — without it PAYMENT-RESPONSE is
                          deterministic and no money moves

Scenarios:
${Object.entries(SCENARIOS)
  .map(([name, scenario]) => `  ${name.padEnd(26)} ${scenario.description.split(".")[0]}.`)
  .join("\n")}

Prints one JSON line to stdout once listening, then runs until terminated.`;

const flags = parseFlags(process.argv.slice(2));

if (flags.help || flags.h) {
  console.log(USAGE);
  process.exit(0);
}

const requirementKeys = (flags.requirements ?? "base").split(",").map((key) => key.trim());
for (const key of requirementKeys) {
  if (!(key in DEFAULT_REQUIREMENTS)) {
    console.error(
      `Unknown requirement set ${JSON.stringify(key)}. ` +
        `Known: ${Object.keys(DEFAULT_REQUIREMENTS).join(", ")}`,
    );
    process.exit(2);
  }
}

/**
 * Replaces the static Solana fee payer with the one this facilitator actually publishes.
 *
 * The static default in `scenarios.js` keeps the deterministic merchant plannable, but a
 * facilitator that rotates its fee payer would otherwise make the documented quickstart
 * fail at `/settle` with a transaction the facilitator will not sign — and the buyer would
 * see a signing-time error for a merchant-side configuration fact. Reading `/supported` is
 * what `tools/ttv` has always done; the quickstart merchant now does it too (PLAN.md O64).
 *
 * A facilitator that cannot be reached, or that publishes no fee payer, leaves the static
 * default in place: this is a test fixture, and failing to start would be a worse answer
 * than starting with the value that was correct at the time of writing.
 *
 * @param {Record<string, unknown>[]} requirements
 * @param {string} facilitatorUrl
 */
async function withPublishedFeePayer(requirements, facilitatorUrl) {
  let supported;
  try {
    const response = await fetch(`${facilitatorUrl}/supported`);
    supported = await response.json();
  } catch (error) {
    console.error(
      `warning: could not read ${facilitatorUrl}/supported ` +
        `(${error instanceof Error ? error.message : String(error)}); ` +
        "keeping the built-in Solana fee payer.",
    );
    return requirements;
  }
  return requirements.map((requirement) => {
    if (!String(requirement["network"]).startsWith("solana:")) return requirement;
    const kind = (supported?.kinds ?? []).find(
      (entry) =>
        entry.x402Version === 2 &&
        entry.scheme === "exact" &&
        entry.network === requirement["network"],
    );
    const feePayer = kind?.extra?.feePayer;
    if (typeof feePayer !== "string" || feePayer.length === 0) return requirement;
    return { ...requirement, extra: { ...requirement["extra"], feePayer } };
  });
}

let requirements = requirementKeys.map((key) => DEFAULT_REQUIREMENTS[key]);
if (flags.facilitator !== undefined) {
  requirements = await withPublishedFeePayer(requirements, flags.facilitator);
}

const merchant = await createTestMerchant({
  scenario: flags.scenario ?? "pay-once",
  port: Number(flags.port ?? 0),
  requirements,
  // Exposed so the documented quickstart can reach a *settled* payment without a public
  // demo merchant. `tools/ttv` has used this since S12; leaving it off the CLI meant the
  // quickstart could not offer a merchant URL that actually moves money (PLAN.md O50).
  ...(flags.facilitator === undefined ? {} : { facilitatorUrl: flags.facilitator }),
});

// One line, flushed immediately: the harness blocks on this to learn the ephemeral port.
console.log(
  JSON.stringify({
    url: merchant.url,
    port: merchant.port,
    scenario: merchant.scenario,
    settles: flags.facilitator !== undefined,
  }),
);

const shutdown = () => {
  void merchant.close().then(() => process.exit(0));
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
