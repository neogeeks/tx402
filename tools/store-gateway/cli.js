#!/usr/bin/env node
/**
 * Runs a reference Node capability gateway fronting a deterministically-seeded
 * `MemorySpendStore`, as a standalone process — the store analog of `tools/test-merchant/cli.js`.
 *
 * The TypeScript CLI-verb golden generator/pin serve this in process; Python cannot, so it spawns
 * this and reads one JSON line from stdout:
 *
 *     {"url":"http://127.0.0.1:54321","dataToken":"…","adminToken":"…","seed":"governed"}
 *
 * The line is emitted only once the gateway is actually listening, so a harness waits on a
 * readable event rather than polling a port. Both languages share `seeds.js`, so the store state
 * behind the gateway is byte-identical whichever side dialled it — that is what pins the verbs'
 * `--json` across the two CLIs.
 *
 *   node tools/store-gateway/cli.js --seed governed [--port 0]
 */

import { MemorySpendStore } from "../../packages/tx402/dist/index.js";
import { bearerTokenScope, serveGateway } from "../../packages/tx402/dist/gateway/index.js";

import { applySeed, SEED_NAMES } from "./seeds.js";

/** Fixed tokens; the store is a throwaway test fixture, so these are not secrets. */
const DATA_TOKEN = "data-token";
const ADMIN_TOKEN = "admin-token";

/** @param {readonly string[]} argv */
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

const flags = parseFlags(process.argv.slice(2));
if (flags.help || flags.h) {
  console.log(
    `tx402-store-gateway — seeded MemorySpendStore behind a reference gateway (SPEC §12.5)\n\n` +
      `Usage:\n  node tools/store-gateway/cli.js --seed <name> [--port <n>]\n\n` +
      `Seeds: ${SEED_NAMES.join(", ")}`,
  );
  process.exit(0);
}

const seed = flags.seed ?? "governed";
if (!SEED_NAMES.includes(seed)) {
  console.error(`Unknown seed ${JSON.stringify(seed)}. Known: ${SEED_NAMES.join(", ")}`);
  process.exit(2);
}

// A fixed seed time keeps the seeded records deterministic; the CLI queries with its own clock,
// but the seeded spend is always fresh relative to it (well inside the rolling window).
const now = Date.now();
const store = new MemorySpendStore();
await applySeed(store, seed, now);

const gateway = await serveGateway(
  {
    dataStore: store,
    adminStore: store,
    resolveScope: bearerTokenScope({ dataToken: DATA_TOKEN, adminToken: ADMIN_TOKEN }),
  },
  { port: Number(flags.port ?? 0) },
);

// One line, flushed immediately: the harness blocks on this to learn the ephemeral port.
console.log(
  JSON.stringify({
    url: gateway.url,
    dataToken: DATA_TOKEN,
    adminToken: ADMIN_TOKEN,
    seed,
  }),
);

const shutdown = () => {
  void gateway.close().then(() => process.exit(0));
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
