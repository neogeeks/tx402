import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

/**
 * Runs `test/durable-object.test.ts` in a LOCAL Cloudflare Workers runtime (workerd via
 * `@cloudflare/vitest-pool-workers` — O8, no Cloudflare account, SPEC §12.3/§12.4). Separate from
 * the default `vitest.config.ts` (which runs the node suites and EXCLUDES this file), because the
 * DO harness needs the real Workers runtime with SQLite-backed Durable Objects — not node.
 *
 * Two bindings to one `Tx402SpendStoreDO` class model the two topologies: `SPEND_DO` addressed
 * per-scope (`idFromName(scope)`) is id-per-scope (`atomicGlobalFreeze:false`); `COORDINATOR_DO`
 * addressed by one fixed name is single-coordinator (`atomicGlobalFreeze:true`). `useSQLite` gives
 * each the SQLite storage the atom writes; `nodejs_compat` lets the shared contract harness import
 * `node:crypto` (via `core/ledger.ts`). `TX402_DO_ADMIN_SECRET` is the admin-token trust root the
 * DO verifies inside itself; `TX402_DO_TEST_MODE` enables the injectable backend clock + the reset/
 * evict hooks the harness drives (all inert in production, where the env sets neither).
 */
export default defineWorkersConfig({
  test: {
    include: ["test/durable-object.test.ts"],
    poolOptions: {
      workers: {
        main: "./test/durable-object/worker.ts",
        singleWorker: true,
        isolatedStorage: false,
        miniflare: {
          compatibilityDate: "2024-11-01",
          compatibilityFlags: ["nodejs_compat"],
          durableObjects: {
            SPEND_DO: { className: "Tx402SpendStoreDO", useSQLite: true },
            COORDINATOR_DO: { className: "Tx402SpendStoreDO", useSQLite: true },
          },
          bindings: {
            TX402_DO_ADMIN_SECRET: "test-admin-secret-tx402-do",
            TX402_DO_TEST_MODE: "1",
          },
        },
      },
    },
  },
});
