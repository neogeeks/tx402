/**
 * Cross-language CLI `--json` parity — the TypeScript pin (PLAN.md open item **O107**).
 *
 * `docs/.../guides/cli.mdx` opens by promising both packages emit "the same `--json`
 * document". S34 drove both CLIs across all 17 test-merchant scenarios and found the Python
 * CLI dropped `network`/`scheme`/`amountAtomic`/`assetId` from `error.context` on every
 * post-routing failure (O107). Nothing diffed the two documents, so it shipped.
 *
 * `core-spec/cli-json/expected.json` is the canonical document, generated from the
 * TypeScript CLI by `tools/cli-parity`. This test re-derives it from the TypeScript
 * **source** — the same in-process CLI path `cli.test.ts` drives, against the real
 * deterministic merchant and a stubbed RPC — and asserts it still matches. Its Python twin
 * (`packages/tx402-python/tests/test_cli_json_parity.py`) pins the other language to the
 * same file. A change in either CLI now fails a test.
 *
 * When a change to the shared document is intentional, rebuild the golden with
 * `node tools/cli-parity/index.js build` (after `pnpm build`) and update the Python pin, so
 * both languages move together.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createEvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant, SCENARIOS } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { run, type CliIo } from "../src/cli/run.js";
import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";
// Shared with the generator and the Python pin so the three cannot drift.
import { normalize } from "../../../tools/cli-parity/normalize.js";

const BASE = BUNDLED_MANIFEST.networks["eip155:8453"] as EvmManifestNetwork;
const USDC = BASE.assets[0] as EvmManifestAsset;
const RPC_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));
const DEV_KEY = "0xa11ce00000000000000000000000000000000000000000000000000000000001";

const REQUIREMENT = {
  scheme: "exact",
  network: "eip155:8453",
  asset: USDC.address,
  amount: "50000",
  payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

const golden = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../../core-spec/cli-json/expected.json", import.meta.url)),
    "utf8",
  ),
) as Record<string, { exitCode: number; json: unknown }>;

let rpc: Awaited<ReturnType<typeof createEvmRpcStub>>;

beforeEach(async () => {
  const payer = await privateKeyToEvmSigner(DEV_KEY).getAddress();
  rpc = await createEvmRpcStub({
    chainId: 8453,
    token: USDC.address,
    balances: { [payer]: "5000000" },
  });
  const realFetch = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: Request | string | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (!RPC_HOSTS.has(new URL(request.url).host)) return realFetch(request);
    return realFetch(rpc.url, {
      method: request.method,
      headers: request.headers,
      body: await request.text(),
    });
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await rpc.close();
});

async function runScenario(scenario: string) {
  const merchant = await createTestMerchant({
    scenario,
    requirements: [REQUIREMENT],
    body: JSON.stringify({ ok: true }),
  });
  const out: string[] = [];
  const io: CliIo = {
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
  try {
    const exitCode = await run(io);
    return { exitCode, json: normalize(JSON.parse(out.join(""))) };
  } finally {
    await merchant.close();
  }
}

describe("CLI --json is identical across the two languages (O107)", () => {
  // The golden is the shared contract; deriving the scenario list from it means a scenario
  // added on one side without the other is a failure, not a silently skipped row.
  for (const scenario of Object.keys(SCENARIOS)) {
    it(`matches the golden for ${scenario}`, async () => {
      expect(
        golden[scenario],
        `scenario ${scenario} missing from the golden`,
      ).toBeDefined();
      const actual = await runScenario(scenario);
      expect(actual.exitCode).toBe(golden[scenario]!.exitCode);
      expect(actual.json).toEqual(golden[scenario]!.json);
    });
  }

  it("covers exactly the scenarios the merchant offers", () => {
    expect(Object.keys(golden).sort()).toEqual(Object.keys(SCENARIOS).sort());
  });
});
