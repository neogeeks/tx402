// Serve the reference Worker capability gateway (fronting a Durable Object) over local HTTP for the
// Python behind-gateway suite. It bundles the test worker with esbuild and runs it in a
// LOCAL Workers runtime via miniflare (workerd) — no Cloudflare account, no network, the same
// runtime the vitest DO suite uses. The Python test (`tests/test_gateway_durable.py`) spawns this,
// reads the `{ url }` handshake line, and drives `check_durable_spend_store` over BOTH topologies
// through the Python `HttpGatewaySpendStore`.
//
// Placed under packages/tx402 so esbuild + miniflare (transitive deps of the pool) resolve.

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import { Miniflare } from "miniflare";

const here = dirname(fileURLToPath(import.meta.url));

// Bundle the test worker (its DO + gateway core) into one ESM module. `cloudflare:workers` and the
// node builtins are provided by the runtime (nodejs_compat), so they stay external.
const bundled = await build({
  entryPoints: [join(here, "test-worker.ts")],
  bundle: true,
  format: "esm",
  platform: "neutral",
  target: "es2022",
  external: ["cloudflare:workers", "node:*"],
  write: false,
  legalComments: "none",
});
const script = bundled.outputFiles[0].text;

const mf = new Miniflare({
  modules: [{ type: "ESModule", path: "worker.mjs", contents: script }],
  compatibilityDate: "2024-11-01",
  compatibilityFlags: ["nodejs_compat"],
  durableObjects: {
    SPEND_DO: { className: "Tx402SpendStoreDO", useSQLite: true },
  },
  bindings: {
    TX402_DO_ADMIN_SECRET:
      process.env.TX402_DO_ADMIN_SECRET ?? "test-admin-secret-tx402-do",
    TX402_DO_TEST_MODE: "1",
    TX402_GATEWAY_DATA_TOKEN: process.env.TX402_GATEWAY_DATA_TOKEN ?? "data-token-abc",
    TX402_GATEWAY_ADMIN_TOKEN: process.env.TX402_GATEWAY_ADMIN_TOKEN ?? "admin-token-xyz",
  },
});

const url = await mf.ready;
process.stdout.write(`${JSON.stringify({ url: url.origin })}\n`);

const shutdown = () => {
  mf.dispose().finally(() => process.exit(0));
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
