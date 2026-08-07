/**
 * Regressions for the S16 fresh-eyes UX pass (§11.3), open items O64 and O67–O71.
 *
 * Derived from the findings and from the governing text — SPEC §4.3, §10, §11, §16 — and run
 * against `00c1685` first to confirm each one failed there. A regression that passes before
 * the fix is not evidence, and S15's central complaint was a suite that asserted what the
 * implementation did rather than what the contract required.
 *
 * Two findings are deliberately **not** here. O63 is a USER item about an empty public
 * repository and nothing in this tree can assert it. O65 and O66 were adjudicated to the
 * documentation rather than the code — SPEC §4.3 specifies the production-only network
 * default and SPEC §11 requires `--dry-run` to plan routes — so the CLI regressions below
 * pin the behaviour the docs were corrected to describe, rather than changing it.
 *
 * The O64 block is the important one, and it is a *fixture* test on purpose. `tools/ttv`
 * measures SPEC §16 and reports PASS while building its own requirement object, so it never
 * touches `DEFAULT_REQUIREMENTS` — the object the quickstart tells a reader to run. That gap
 * is why a broken quickstart merchant survived every green gate.
 */

import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant, DEFAULT_REQUIREMENTS } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client } from "../src/core/client.js";
import { MemorySpendStore } from "../src/core/ledger.js";
import type {
  EvmManifestAsset,
  EvmManifestNetwork,
  SvmManifestAsset,
  SvmManifestNetwork,
} from "../src/core/manifest.js";
import { planExactEvmAuthorization } from "../src/evm/plan.js";
import type { EvmSigner } from "../src/core/signers.js";
import { planExactSvmAuthorization } from "../src/solana/plan.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

const BASE_SEPOLIA = BUNDLED_MANIFEST.networks["eip155:84532"] as EvmManifestNetwork;
const BASE_SEPOLIA_USDC = BASE_SEPOLIA.assets[0] as EvmManifestAsset;
const RPC_HOSTS = new Set(BASE_SEPOLIA.rpcUrls.map((url) => new URL(url).host));

const context = { requestId: "s16-regression", phase: "policy" } as const;

/** The four requirement sets the merchant's `--requirements` flag actually offers. */
const EVM_SETS = ["base", "baseSepolia"] as const;
const SVM_SETS = ["solana", "solanaDevnet"] as const;

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

const servers: Merchant[] = [];
let rpc: EvmRpcStub;
let signer: EvmSigner;

beforeEach(async () => {
  signer = privateKeyToEvmSigner(`0x${randomBytes(32).toString("hex")}`);
  const payer = await signer.getAddress();
  rpc = await createEvmRpcStub({
    chainId: 84532,
    token: BASE_SEPOLIA_USDC.address,
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
  await Promise.all(servers.splice(0).map((server) => server.close()));
  await rpc.close();
});

describe("O64 — every documented requirement set is payable as published", () => {
  // The planners are called directly because they are exactly what threw during S16:
  // `eip712-domain-missing` at evm/plan.ts:174 and `svm-feePayer-missing` at
  // solana/plan.ts:65. No RPC is involved, so a failure here is unambiguous.
  it.each(EVM_SETS)("%s carries an EIP-712 domain the signer can use", (key) => {
    const requirement = DEFAULT_REQUIREMENTS[key];
    const network = BUNDLED_MANIFEST.networks[requirement.network] as EvmManifestNetwork;
    const asset = network.assets[0] as EvmManifestAsset;

    expect(() =>
      planExactEvmAuthorization({
        requirement: {
          scheme: requirement.scheme,
          network: requirement.network,
          asset: requirement.asset,
          payTo: requirement.payTo,
          amountAtomic: requirement.amount,
          maxTimeoutSeconds: requirement.maxTimeoutSeconds,
          extra: requirement.extra,
        },
        networkId: requirement.network,
        network,
        asset,
        payer: "0x1CB8D0000000000000000000000000000000402A",
        maxAuthorizationSeconds: 120,
        nowEpochMs: Date.now(),
        context,
      }),
    ).not.toThrow();
  });

  it.each(SVM_SETS)("%s names the fee payer the transfer needs", async (key) => {
    const requirement = DEFAULT_REQUIREMENTS[key];
    const network = BUNDLED_MANIFEST.networks[requirement.network] as SvmManifestNetwork;
    const asset = network.assets[0] as SvmManifestAsset;

    await expect(
      planExactSvmAuthorization({
        requirement: {
          index: 0,
          scheme: requirement.scheme,
          network: requirement.network,
          asset: requirement.asset,
          payTo: requirement.payTo,
          amountAtomic: requirement.amount,
          maxTimeoutSeconds: requirement.maxTimeoutSeconds,
          extra: requirement.extra,
        },
        networkId: requirement.network,
        network,
        asset,
        payer: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        maxAuthorizationSeconds: 120,
        context,
      }),
    ).resolves.toBeDefined();
  });

  // The journey S16 actually ran: the documented merchant command, then the documented
  // client call. This is the one that proves the *fixture* is payable, not just the object.
  it("plans a route against the merchant the quickstart tells you to start", async () => {
    const merchant = await createTestMerchant({
      scenario: "pay-once",
      requirements: [DEFAULT_REQUIREMENTS.baseSepolia],
    });
    servers.push(merchant);

    const client = createTx402Client({
      signers: { evm: signer },
      spendStore: new MemorySpendStore(),
      policy: { maxPerRequest: "0.10 USDC", allowedNetworks: ["eip155:84532"] },
      allowInsecureLocalhost: true,
    });

    const plan = await client.plan(`${merchant.url}/resource`);
    expect(plan.selected?.network).toBe("eip155:84532");
    expect(plan.selected?.amountAtomic).toBe("50000");
    expect(plan.selected?.viable).toBe(true);
  });
});

describe("O68–O71 — the runnable examples are runnable", () => {
  const examples = join(REPO, "examples");
  const tsPackage = JSON.parse(
    readFileSync(join(examples, "typescript", "package.json"), "utf8"),
  ) as { scripts: Record<string, string>; engines?: { node?: string } };

  // O70: a script naming a file that does not exist is a documented command that cannot run.
  it("declares no script pointing at a missing file", () => {
    const missing = Object.entries(tsPackage.scripts)
      .flatMap(([name, command]) => {
        const source = command.match(/[\w./-]+\.ts\b/u)?.[0];
        return source === undefined ? [] : [{ name, source }];
      })
      .filter(({ source }) => !existsSync(join(examples, "typescript", source)));
    expect(missing).toEqual([]);
  });

  // O69: the examples must run on the floor the quickstart and the package both state.
  // `--experimental-strip-types` is Node 22.6+, and the published SDK declares >=20.19.0.
  it("does not require a newer Node than the published package declares", () => {
    const sdkFloor = (
      JSON.parse(readFileSync(join(REPO, "packages", "tx402", "package.json"), "utf8")) as {
        engines: { node: string };
      }
    ).engines.node;
    expect(sdkFloor).toBe(">=20.19.0");

    const strippers = Object.entries(tsPackage.scripts).filter(([, command]) =>
      command.includes("--experimental-strip-types"),
    );
    // Either the examples stopped needing the flag, or they state the floor it implies —
    // what must not survive is the silent mismatch S16 hit.
    if (strippers.length > 0) {
      expect(tsPackage.engines?.node).toBeDefined();
    }
  });

  // O68: the docs' inline snippet opts into localhost; the runnable files did not, so the
  // quickstart's own merchant was rejected by the examples it points at.
  it.each([
    ["typescript", "quickstart.ts"],
    ["typescript", "dry-run.ts"],
    ["python", "quickstart.py"],
    ["python", "dry_run.py"],
  ])("%s/%s opts into localhost the way the docs snippet does", (language, file) => {
    const source = readFileSync(join(examples, language, file), "utf8");
    expect(source).toMatch(/allow_?[Ii]nsecure_?[Ll]ocalhost/u);
  });

  // O71: `TX402_MERCHANT_URL` appeared in no README, no docs page, and no help text —
  // only in the error message you get for not having set it.
  it("documents TX402_MERCHANT_URL in an examples README", () => {
    const readme = join(examples, "README.md");
    expect(existsSync(readme)).toBe(true);
    expect(readFileSync(readme, "utf8")).toContain("TX402_MERCHANT_URL");
  });
});

describe("O71(a) — a misconfigured logger is refused, not silently ignored", () => {
  // SPEC §10 specifies the logger as an object carrying debug/info/warn/error. A function
  // satisfies neither, and `emit`'s try/catch — which is correct, and stays, so that a
  // logger fault can never fail a payment — turned that into zero events and no error.
  it.each([
    ["a function", () => undefined],
    ["a partial object", { info: () => undefined }],
    ["a non-callable member", { debug: 1, info: 2, warn: 3, error: 4 }],
  ])("rejects %s at construction", (_label, logger) => {
    expect(() =>
      createTx402Client({ logger: logger as never, spendStore: new MemorySpendStore() }),
    ).toThrowError(/logger/iu);
  });

  it("still accepts a complete logger", () => {
    const noop = () => undefined;
    expect(() =>
      createTx402Client({
        logger: { debug: noop, info: noop, warn: noop, error: noop },
        spendStore: new MemorySpendStore(),
      }),
    ).not.toThrow();
  });
});

describe("O71(b) — the generated API page reaches the client's own methods", () => {
  // `inspect`, `plan`, `getBudgetState` and `queryBudgetState` are what made S16's
  // reconciliation task solvable, and none of them appeared anywhere on the docs site.
  it.each([
    "fetch",
    "inspect",
    "plan",
    "getBudgetState",
    "queryBudgetState",
    "resetHealth",
  ])("lists %s", (method) => {
    const page = readFileSync(
      join(REPO, "docs", "src", "content", "docs", "reference", "api-typescript.mdx"),
      "utf8",
    );
    expect(page).toContain(`\`${method}(`);
  });
});
