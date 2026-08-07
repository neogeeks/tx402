#!/usr/bin/env node
/**
 * Size gate for the tx402 core import path.
 *
 * Implements the two-part budget from ADR-008:
 *
 *   1. OWN CODE (blocking)  — what tx402 itself emits on the `.` export, with @x402/core,
 *                             zod, and all chain adapters treated as external.
 *   2. TOTAL CORE PATH      — the same entry point with @x402/core and zod bundled in.
 *                             Reported until frozen at M1 (PLAN.md open item O4).
 *
 * Chain adapters are measured separately and excluded from both figures, matching the
 * SPEC §12.3 carve-out for "optional chain adapters".
 *
 * Exits non-zero if any enforced limit is exceeded.
 */

import { build } from "esbuild";
import { gzipSync } from "node:zlib";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../..");
const pkgSrc = path.join(repoRoot, "packages/tx402/src");

const limits = JSON.parse(readFileSync(path.join(here, "limits.json"), "utf8"));

/**
 * Node built-ins. Never bundled by anyone — a consumer's bundler resolves them from the
 * runtime — so they count against neither figure. tx402 reaches for `node:crypto` on the
 * core path for Ed25519 manifest verification, which SPEC §5.4 requires at construction and
 * SPEC §3.2 forbids implementing by hand.
 */
const NODE_BUILTINS = ["node:*"];

/** Dependencies that are never tx402's own code. */
const PROTOCOL_DEPS = ["@x402/core", "zod"];
/**
 * Optional chain adapters — excluded from the core-path figures by ADR-008 and by
 * SPEC §12.3's "excluding optional chain adapters".
 *
 * The two relative paths are the lazy `import()` targets in `src/core/chain.ts`. A real
 * bundler code-splits them, so a caller who never pays on a chain never downloads its
 * adapter; without these entries esbuild would inline both into the core measurement and
 * report adapter bytes as core bytes.
 */
const CHAIN_DEPS = [
  "@x402/evm",
  "@x402/evm/*",
  "@x402/svm",
  "@x402/svm/*",
  "viem",
  "viem/*",
  "@solana/kit",
  "@solana-program/*",
  "../evm/adapter.js",
  "../solana/adapter.js",
];

/**
 * Bundles an entry point and returns its minified gzipped size in bytes.
 *
 * @param {string} entry Absolute path to the entry module.
 * @param {string[]} external Package specifiers to leave unbundled.
 * @returns {Promise<{ raw: number, gzip: number }>}
 */
async function measure(entry, external) {
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    minify: true,
    format: "esm",
    platform: "neutral",
    target: "es2022",
    external,
    write: false,
    legalComments: "none",
  });

  const output = result.outputFiles[0].contents;
  return { raw: output.byteLength, gzip: gzipSync(output, { level: 9 }).byteLength };
}

const kib = (bytes) => `${(bytes / 1024).toFixed(2)} KiB`;

/**
 * @param {string} label
 * @param {{ raw: number, gzip: number }} size
 * @param {{ limit: number | null, enforced: boolean }} [budget]
 * @returns {boolean} true when the measurement is within budget (or unbudgeted)
 */
function report(label, size, budget) {
  const base = `${label.padEnd(34)} ${kib(size.gzip).padStart(10)} gz  (${kib(size.raw)} raw)`;

  if (!budget || budget.limit === null) {
    console.log(`  ${base}   —`);
    return true;
  }

  const ok = size.gzip <= budget.limit;
  const verdict = budget.enforced
    ? `${ok ? "PASS" : "FAIL"} (limit ${kib(budget.limit)})`
    : `${ok ? "ok" : "over"} (reported only, limit ${kib(budget.limit)})`;

  console.log(`  ${base}   ${verdict}`);
  return ok || !budget.enforced;
}

async function main() {
  console.log("\ntx402 size gate — ADR-008\n");

  const ownCode = await measure(path.join(pkgSrc, "index.ts"), [
    ...NODE_BUILTINS,
    ...PROTOCOL_DEPS,
    ...CHAIN_DEPS,
  ]);
  const totalCorePath = await measure(path.join(pkgSrc, "index.ts"), [
    ...NODE_BUILTINS,
    ...CHAIN_DEPS,
  ]);

  console.log("Core import path (`tx402`)");
  let passing = report("own code (blocking)", ownCode, limits.ownCodeGzipBytes);
  passing =
    report("+ @x402/core + zod", totalCorePath, limits.totalCorePathGzipBytes) && passing;

  console.log("\nOptional chain adapters (excluded from the gate)");
  for (const [label, entry] of [
    ["tx402/evm", "evm/index.ts"],
    ["tx402/solana", "solana/index.ts"],
  ]) {
    report(
      label,
      await measure(path.join(pkgSrc, entry), [
        ...NODE_BUILTINS,
        ...PROTOCOL_DEPS,
        ...CHAIN_DEPS,
      ]),
    );
  }

  if (limits.totalCorePathGzipBytes.limit === null) {
    console.log(
      "\nNote: the total core-path ceiling is not yet frozen (PLAN.md open item O4).\n" +
        "      Freeze it at M1 by amending ADR-008 and setting it in tools/size-gate/limits.json.",
    );
  }

  console.log(passing ? "\nSize gate passed.\n" : "\nSize gate FAILED.\n");
  process.exitCode = passing ? 0 : 1;
}

await main();
