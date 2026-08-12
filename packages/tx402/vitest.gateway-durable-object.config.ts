import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

/**
 * Runs `test/gateway-durable-object.test.ts` — the capability gateway over a Durable Object — in a
 * LOCAL Cloudflare Workers runtime. It is a SEPARATE config from
 * `vitest.durable-object.config.ts` on purpose: `@cloudflare/vitest-pool-workers` reloads the shared
 * worker between test files in a single run, which invalidates the DO instances the earlier DO
 * adapter suite created ("…invalidating this Durable Object. Please retry…"). Giving this suite its
 * own run (its own worker process) removes that cross-file invalidation entirely.
 *
 * The bindings mirror the DO config: one `Tx402SpendStoreDO` class reached per-scope (`SPEND_DO`,
 * `id-per-scope` → `atomicGlobalFreeze:false`) and via a fixed coordinator id (`single-coordinator`
 * → `atomicGlobalFreeze:true`); `useSQLite`; `nodejs_compat` for `node:crypto`; the admin-token trust
 * root + the test-mode flag that enables the reset/clock hooks the harness drives out-of-band.
 */
export default defineWorkersConfig({
  test: {
    include: ["test/gateway-durable-object.test.ts"],
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
