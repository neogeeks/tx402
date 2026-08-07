/**
 * Regressions for the S18 fresh-eyes UX pass (§11.3), open items O72–O76.
 *
 * Each one was run against `7376245` first and observed to fail there. A regression that
 * passes before the fix is not evidence.
 *
 * Two of the five are documentation-only and are asserted as such:
 *
 *  - **O72/O73** (the step-6 snippet could not run under either documented install row) is a
 *    property of `quickstart.mdx`, not of the library. The library behaved exactly as
 *    designed — `keypairToSolanaSigner` lazily imports `@solana/kit` and throws when handed
 *    an unset variable, both deliberately. What was wrong is that the page told a reader to
 *    call it while installing neither. The assertions below therefore read the page and
 *    check the invariant that was violated: no chain-specific snippet may reference the
 *    other chain's signer or key. That is the thing that broke, so that is the thing pinned.
 *  - **O76** (the quickstart troubleshooting table omitted exit 9) is likewise a fixture
 *    assertion against the page.
 *
 * O74 and O75 are behavioural and are driven through the real CLI path.
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { EXIT_CODES } from "../src/cli/exit-codes.js";
import { run, type CliIo } from "../src/cli/run.js";
import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client } from "../src/core/client.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DOCS = join(REPO, "docs", "src", "content", "docs");

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

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let merchant: Merchant;
let rpc: EvmRpcStub;

function io(argv: string[], overrides: Partial<CliIo> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const harness: CliIo & { out: string[]; err: string[] } = {
    out,
    err,
    argv,
    env: {},
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    readFile: () => {
      throw new Error("no filesystem in this test");
    },
    ...overrides,
  };
  return harness;
}

/**
 * Drives the CLI exactly as a shell does: the key arrives through the documented
 * environment variable and the CLI builds its own signers from it.
 *
 * Injecting a client instead would bypass `resolveSigners`, and the payer address the
 * settlement report carries comes from precisely those signers — so an injected client
 * would assert the reporting path against a configuration no real run ever has.
 */
const DEV_ENV = { TX402_DEV_PRIVATE_KEY: DEV_KEY } as const;

async function startMerchant(scenario: string): Promise<void> {
  merchant = await createTestMerchant({
    scenario,
    requirements: [REQUIREMENT],
    body: JSON.stringify({ ok: true }),
  });
}

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
  // The documentation-fixture blocks below never start one.
  await merchant?.close();
  merchant = undefined as unknown as Merchant;
  await rpc.close();
});

describe("O72/O73 — each documented install row runs that page's code", () => {
  const quickstart = () => readFileSync(join(DOCS, "start", "quickstart.mdx"), "utf8");

  /** The fenced blocks whose info string names a language and a chain. */
  function chainBlocks(source: string): { title: string; body: string }[] {
    const blocks: { title: string; body: string }[] = [];
    const pattern = /```(?:ts|python) title="([^"]*—[^"]*)"\n([\s\S]*?)```/gu;
    for (const match of source.matchAll(pattern)) {
      blocks.push({ title: match[1] as string, body: match[2] as string });
    }
    return blocks;
  }

  it("gives every step-6 snippet a chain in its title", () => {
    // The original single snippet was titled `quickstart.ts` and configured both chains at
    // once, which is what made it unrunnable under either install row.
    const blocks = chainBlocks(quickstart());
    expect(blocks.length).toBe(4);
    expect(blocks.filter((block) => /Base Sepolia/u.test(block.title))).toHaveLength(2);
    expect(blocks.filter((block) => /Solana Devnet/u.test(block.title))).toHaveLength(2);
  });

  it("never references the other chain's signer or key inside a chain-specific snippet", () => {
    // This is the finding, stated exactly: a Base-row reader has no `@solana/kit` and no
    // `TX402_DEV_SOLANA_KEYPAIR`, so a Base snippet that names either cannot run, and the
    // mirror holds for Solana.
    const blocks = chainBlocks(quickstart());
    // Without this the loop below passes vacuously against the pre-fix page, which had no
    // chain-titled blocks at all — the exact state this test exists to reject.
    expect(blocks.length).toBeGreaterThan(0);
    for (const block of blocks) {
      const solana =
        /keypairToSolanaSigner|keypair_to_solana_signer|SOLANA_KEYPAIR|solana_signer|solana:/u;
      const evm =
        /privateKeyToEvmSigner|private_key_to_evm_signer|TX402_DEV_PRIVATE_KEY|evm_signer|eip155:/u;
      if (/Base Sepolia/u.test(block.title)) {
        expect(block.body).not.toMatch(solana);
        expect(block.body).toMatch(evm);
      } else {
        expect(block.body).not.toMatch(evm);
        expect(block.body).toMatch(solana);
      }
    }
  });

  it("tells the TypeScript reader to make the project a module, and how to run it", () => {
    // Without `"type": "module"` the snippet dies on `Top-level await is currently not
    // supported with the "cjs" output format` before reaching any tx402 code, and the page
    // previously named no scaffold and no runner at all.
    const source = quickstart();
    expect(source).toContain("npm pkg set type=module");
    expect(source).toMatch(/npx tsx quickstart\.ts/u);
    expect(source).toMatch(/python quickstart\.py/u);
  });
});

describe("O74 — settlement facts reach the operator", () => {
  it("reports the settlement identifier and payer on a delivered payment", async () => {
    await startMerchant("pay-once");
    const harness = io(["call", merchant.url, "--max-spend", "0.10 USDC", "--json"], {
      env: DEV_ENV,
    });
    expect(await run(harness)).toBe(EXIT_CODES.success);

    const document = JSON.parse(harness.out.join("")) as {
      settlement: { status: string; transaction: string | null; payer: string | null };
    };
    expect(document.settlement.status).toBe("committed");
    // The merchant reports a settlement identifier, so it must survive to the document —
    // unhashed, because a `sha256:…` cannot be looked up on a block explorer (ADR-019).
    expect(document.settlement.transaction).toBeTruthy();
    expect(document.settlement.transaction).not.toMatch(/^sha256:/u);
    expect(document.settlement.payer).toBe(
      await privateKeyToEvmSigner(DEV_KEY).getAddress(),
    );
  });

  it("reports settlement on exit 9, where money moved and nothing was delivered", async () => {
    await startMerchant("settled-but-refused");
    const harness = io(["call", merchant.url, "--max-spend", "0.10 USDC", "--json"], {
      env: DEV_ENV,
    });
    expect(await run(harness)).toBe(EXIT_CODES.resourceFailure);

    const document = JSON.parse(harness.out.join("")) as {
      settlement: { status: string; transaction: string | null };
    };
    expect(document.settlement.status).toBe("committed");
    expect(document.settlement.transaction).toBeTruthy();
  });

  it("prints the settlement facts on stderr too, so reconciling needs no second run", async () => {
    // The whole point of exit 9's advice is "do not retry". Requiring `--json` to obtain the
    // identifier would mean re-running the payment to find out what the payment was.
    await startMerchant("settled-but-refused");
    const harness = io(["call", merchant.url, "--max-spend", "0.10 USDC"], {
      env: DEV_ENV,
    });
    expect(await run(harness)).toBe(EXIT_CODES.resourceFailure);

    const stderr = harness.err.join("");
    expect(stderr).toContain("payer");
    expect(stderr).toContain("settlement");
    expect(stderr).toContain(await privateKeyToEvmSigner(DEV_KEY).getAddress());
  });

  it("reports null rather than inventing a settlement when nothing was signed", async () => {
    // A merchant that never charges must not produce a settlement object, or the field
    // becomes meaningless the first time someone trusts it.
    await startMerchant("unpaid-200");
    const harness = io(["call", merchant.url, "--max-spend", "0.10 USDC", "--json"], {
      env: DEV_ENV,
    });
    expect(await run(harness)).toBe(EXIT_CODES.success);
    const document = JSON.parse(harness.out.join("")) as { settlement: unknown };
    expect(document.settlement).toBeNull();
  });

  it("keeps the event stream's settlement identifier hashed", async () => {
    // The other half of ADR-019: exposing the raw value on the buyer's own stdout must not
    // relax the SPEC §10 rule for events, which are what reach a log aggregator.
    await startMerchant("pay-once");
    const events: Record<string, unknown>[] = [];
    const client = createTx402Client({
      signers: { evm: privateKeyToEvmSigner(DEV_KEY) },
      policy: { maxPerRequest: "0.10 USDC", allowedNetworks: ["eip155:8453"] },
      logger: {
        debug: (event) => events.push({ ...event }),
        info: (event) => events.push({ ...event }),
        warn: (event) => events.push({ ...event }),
        error: (event) => events.push({ ...event }),
      },
      allowInsecureLocalhost: true,
    });
    await client.fetch(merchant.url);

    const completed = events.find((event) => event["event"] === "payment.completed");
    expect(completed).toBeDefined();
    expect(completed?.["settlementIdHash"]).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(completed?.["settlementId"]).toBeUndefined();
  });
});

describe("O75 — a printed remedy the operator can actually follow", () => {
  it("prints offeredNetworks on stderr without --json", async () => {
    // The most likely first error. `--network` is mandatory on a testnet, the message says
    // to copy a value out of `offeredNetworks`, and that key previously existed only under
    // `--json` — so the default run printed advice referring to something it never showed.
    await startMerchant("pay-once");
    // This merchant offers eip155:8453, which the default policy already allows, so the
    // refusal is driven by naming a network it does not offer — the same
    // TX402_SCHEME_UNSUPPORTED a testnet user hits by omitting `--network` entirely.
    const refused = io(
      ["call", merchant.url, "--max-spend", "0.10 USDC", "--network", "eip155:84532"],
      { env: DEV_ENV },
    );
    expect(await run(refused)).toBe(EXIT_CODES.protocol);

    const stderr = refused.err.join("");
    expect(stderr).toContain("TX402_SCHEME_UNSUPPORTED");
    expect(stderr).toContain("offeredNetworks");
    expect(stderr).toContain("eip155:8453");
  });

  it("keeps stdout clean while doing it", async () => {
    // The SPEC §11 split is not negotiable: the remedy is a diagnostic and belongs on
    // stderr, or `tx402 call … > out.json` stops producing a usable file.
    await startMerchant("pay-once");
    const harness = io(
      ["call", merchant.url, "--max-spend", "0.10 USDC", "--network", "eip155:84532"],
      { env: DEV_ENV },
    );
    expect(await run(harness)).toBe(EXIT_CODES.protocol);
    expect(harness.out.join("")).toBe("");
  });
});

describe("O76 — the quickstart troubleshooting table covers exit 9", () => {
  it("documents exit 9 on the page a stuck user is actually on", () => {
    // The error reference documented 9 correctly all along. The quickstart did not, and the
    // quickstart is where someone whose payment vanished is standing.
    const source = readFileSync(join(DOCS, "start", "quickstart.mdx"), "utf8");
    const table = source.slice(source.indexOf("## If it did not work"));
    for (const code of ["3", "4", "5", "7", "8", "9"]) {
      expect(table).toMatch(new RegExp(`\\|\\s*\`${code}\`\\s*\\|`, "u"));
    }
  });
});
