import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts", "src/**/*.test.ts"],
    // The Durable Object suites need the Workers runtime, not node — they run via
    // vitest.durable-object.config.ts (@cloudflare/vitest-pool-workers). Excluded here so the
    // default node run does not try to load `cloudflare:test` / `cloudflare:workers` (the DO
    // adapter suite and the capability gateway over the DO both use it).
    exclude: [
      ...configDefaults.exclude,
      "test/durable-object.test.ts",
      "test/gateway-durable-object.test.ts",
    ],
    coverage: {
      provider: "v8",
      // Chain adapters and the private-key convenience signer are production code carrying
      // security-critical assertions (SEC-001, SPEC §6.6, §7.1/§7.2), so they are held to the same
      // SPEC §12.1 threshold as `core`. The CLI joins them at M7.
      include: [
        "src/core/**/*.ts",
        "src/evm/**/*.ts",
        "src/solana/**/*.ts",
        "src/signers/**/*.ts",
      ],
      reporter: ["text", "lcov"],
      // SPEC §12.1: >=90% line and branch coverage in core modules. Enforced from M0
      // rather than deferred — the gate is far cheaper to hold from
      // the first core module onward than to reach retroactively across eight milestones.
      thresholds: {
        lines: 90,
        branches: 90,
        functions: 90,
        statements: 90,
      },
    },
  },
});
