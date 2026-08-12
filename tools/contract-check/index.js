#!/usr/bin/env node
/**
 * SpendStore contract-suite runner — the stable root script for the 0.2.0 contract twins.
 *
 *   node tools/contract-check/index.js
 *
 * **Why this exists as a script (PLAN-0.2.0.md §14, O9).** The single-plane SpendStore contract
 * must be *invocable* in both languages, not merely defined. This runs:
 *
 *   - Python: `python -m tx402.spend_store_contract` — the real `__main__` entry point that
 *     replaces the old zero-check no-op (O9), against `MemorySpendStore` v2.
 *   - TypeScript: the `checkSpendStore` twin via vitest, against `MemorySpendStore` v2.
 *
 * so the same command runs the contract in both languages locally and in CI and cannot drift
 * from a prose-only job name. Both suites also run inside `pnpm test` / `pytest`; this is the
 * standalone entry the plan requires.
 *
 * The durable harness (`checkDurableSpendStore` / `check_durable_spend_store`) needs a live
 * backend and both credential planes, so it runs from the durable suites (S7/S8, see
 * `tools/durable-check`), not here.
 */

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const steps = [
  {
    label: "python  -m tx402.spend_store_contract",
    cmd: "uv",
    args: [
      "run",
      "--project",
      "packages/tx402-python",
      "python",
      "-W",
      "ignore::RuntimeWarning",
      "-m",
      "tx402.spend_store_contract",
    ],
  },
  {
    label: "typescript  checkSpendStore (vitest)",
    cmd: "pnpm",
    args: [
      "-C",
      "packages/tx402",
      "exec",
      "vitest",
      "run",
      "test/spend-store-contract.test.ts",
      "--coverage=false",
    ],
  },
];

let failed = false;
for (const step of steps) {
  const result = spawnSync(step.cmd, step.args, { cwd: repoRoot, stdio: "inherit" });
  if (result.status === 0) {
    console.log(`OK    ${step.label}`);
  } else {
    console.error(`FAIL  ${step.label}`);
    failed = true;
  }
}

if (failed) {
  console.error("\nFAIL  spend-store contract suites");
  process.exit(1);
}
console.log("\nOK    spend-store contract suites green in both languages");
