#!/usr/bin/env node
/**
 * Cross-language CLI `--json` parity (PLAN.md open item **O107**).
 *
 *   tx402-cli-parity build   regenerate core-spec/cli-json/expected.json from the TS CLI
 *   tx402-cli-parity check   fail if the committed golden disagrees with a fresh TS run
 *
 * `docs/.../guides/cli.mdx` opens by promising that both packages emit "the same `--json`
 * document". S34 drove both CLIs across all 17 test-merchant scenarios and found that the
 * Python CLI dropped the route fields from `error.context` on every post-routing failure
 * (O107). Nothing in the gate set diffed the two documents, so the divergence shipped.
 *
 * This tool records the canonical document — the TypeScript CLI's output, run in process
 * against the real deterministic test merchant and a stubbed RPC — as a language-neutral
 * fixture. `packages/tx402/test/cli-json-parity.test.ts` re-derives it live and asserts it
 * matches, so a TypeScript change fails on the spot; `packages/tx402-python/tests/
 * test_cli_json_parity.py` pins the Python CLI to the same fixture, so a Python change
 * fails too. The golden is the seam the two independent pins meet at.
 *
 * The normalization below erases only what is not the SDK's to promise: request/reservation
 * identifiers, wall-clock durations, the latency-derived health score (SPEC §6.4 makes it a
 * function of a fresh probe), the merchant's own body and ephemeral redirect origins. Every
 * field the SDK actually produces — exit code, route identity, settlement, and the whole of
 * `error` — is compared verbatim.
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createTestMerchant, SCENARIOS } from "../test-merchant/index.js";
import { createEvmRpcStub } from "../evm-rpc-stub/index.js";
import { run } from "../../packages/tx402/dist/cli/run.js";
import { privateKeyToEvmSigner } from "../../packages/tx402/dist/signers/index.js";
import { BUNDLED_MANIFEST } from "../../packages/tx402/dist/core/bundled-manifest.js";

import { normalize } from "./normalize.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../..");
const goldenPath = path.join(repoRoot, "core-spec/cli-json/expected.json");

/** A fixed development key; the merchant is deterministic and never settles for real. */
const DEV_KEY = "0xa11ce00000000000000000000000000000000000000000000000000000000001";

const BASE = BUNDLED_MANIFEST.networks["eip155:8453"];
const USDC = BASE.assets[0];
const RPC_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));
const REQUIREMENT = {
  scheme: "exact",
  network: "eip155:8453",
  asset: USDC.address,
  amount: "50000",
  payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

/** Runs the TS CLI in process for one scenario and returns its normalized `--json`. */
async function runScenario(scenario) {
  const merchant = await createTestMerchant({
    scenario,
    requirements: [REQUIREMENT],
    body: JSON.stringify({ ok: true }),
  });
  const signer = privateKeyToEvmSigner(DEV_KEY);
  const payer = await signer.getAddress();
  const rpc = await createEvmRpcStub({
    chainId: 8453,
    token: USDC.address,
    balances: { [payer]: "5000000" },
  });
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    if (!RPC_HOSTS.has(new URL(request.url).host)) return realFetch(request);
    return realFetch(rpc.url, {
      method: request.method,
      headers: request.headers,
      body: await request.text(),
    });
  };
  const out = [];
  const io = {
    argv: [
      "call",
      `${merchant.url}/resource`,
      "--max-spend",
      "0.10 USDC",
      "--timeout",
      "1500",
      "--json",
    ],
    env: { TX402_DEV_PRIVATE_KEY: DEV_KEY },
    stdout: (text) => out.push(text),
    stderr: () => {},
    readFile: () => {
      throw new Error("no filesystem in this harness");
    },
  };
  let exitCode;
  try {
    exitCode = await run(io);
  } finally {
    globalThis.fetch = realFetch;
    await merchant.close();
    await rpc.close();
  }
  return { exitCode, json: normalize(JSON.parse(out.join(""))) };
}

/** @returns {Promise<Record<string, {exitCode: number, json: unknown}>>} */
export async function generateParity() {
  /** @type {Record<string, {exitCode: number, json: unknown}>} */
  const results = {};
  for (const scenario of Object.keys(SCENARIOS)) {
    results[scenario] = await runScenario(scenario);
  }
  return results;
}

function serialize(results) {
  return `${JSON.stringify(results, null, 2)}\n`;
}

async function build() {
  const results = await generateParity();
  mkdirSync(path.dirname(goldenPath), { recursive: true });
  writeFileSync(goldenPath, serialize(results));
  console.log(
    `Wrote ${path.relative(repoRoot, goldenPath)}  (${Object.keys(results).length} scenarios)`,
  );
  return 0;
}

async function check() {
  const fresh = serialize(await generateParity());
  let committed;
  try {
    committed = readFileSync(goldenPath, "utf8");
  } catch {
    console.error(
      "FAIL  core-spec/cli-json/expected.json is missing. Run: tx402-cli-parity build",
    );
    return 1;
  }
  if (
    createHash("sha256").update(fresh).digest("hex") !==
    createHash("sha256").update(committed).digest("hex")
  ) {
    console.error(
      "FAIL  the TypeScript CLI --json no longer matches the committed parity golden.",
    );
    console.error(
      "      A deliberate change means: rerun `tx402-cli-parity build` and update the",
    );
    console.error("      Python pin, so both languages move together. See PLAN.md O107.");
    return 1;
  }
  console.log(
    `OK    TypeScript CLI --json matches the parity golden (${Object.keys(JSON.parse(committed)).length} scenarios)`,
  );
  return 0;
}

const USAGE = `tx402-cli-parity — cross-language CLI --json parity (O107)

Usage:
  tx402-cli-parity build   regenerate core-spec/cli-json/expected.json
  tx402-cli-parity check   fail if the golden disagrees with a fresh TypeScript run`;

// Only dispatch when executed directly, so the test can import `generateParity` without
// running the CLI (which would print usage on import).
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const command = process.argv[2];
  if (command === "build") process.exitCode = await build();
  else if (command === "check") process.exitCode = await check();
  else if (command === undefined || command === "-h" || command === "--help")
    console.log(USAGE);
  else {
    console.error(`Unknown command: ${command}\n\n${USAGE}`);
    process.exitCode = 2;
  }
}
