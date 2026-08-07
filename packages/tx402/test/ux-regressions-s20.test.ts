/**
 * Regressions for the S20 fresh-eyes UX pass (§11.3), open items O77–O81.
 *
 * Each one was run against `ee587df` first and observed to fail there. A regression that
 * passes before the fix is not evidence.
 *
 * O77 and O79 are one defect in one function. `resolveSigners` loaded a chain's signer
 * inside a `try` whose `catch` reported *every* failure as a malformed environment
 * variable — so an absent `@solana/kit` was announced as a bad Solana keypair, and it was
 * announced fatally, killing requests that had named an EVM network and needed no Solana
 * anything. The bare-install case escaped the `try` entirely and surfaced as a raw
 * `ERR_MODULE_NOT_FOUND` quoting an absolute path.
 *
 * The missing-package branch is exercised by mocking the signers module to reject the way
 * Node actually rejects, rather than by uninstalling a package in a fixture: the branch
 * under test is "how is this error classified", and a mock states that directly.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { EXIT_CODES } from "../src/cli/exit-codes.js";
import { run, type CliIo } from "../src/cli/run.js";
import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { CHAIN_INSTALL_COMMANDS } from "../src/core/client.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import type * as signersModule from "../src/signers/index.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";
import { EXAMPLES, read, readerSurfaces, relative, sitePages } from "./reader-surfaces.js";

type SignersModule = typeof signersModule;

const BASE = BUNDLED_MANIFEST.networks["eip155:8453"] as EvmManifestNetwork;
const USDC = BASE.assets[0] as EvmManifestAsset;
const RPC_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));
const DEV_KEY = "0xa11ce00000000000000000000000000000000000000000000000000000000001";
const SOLANA_KEYPAIR = JSON.stringify(
  Array.from({ length: 64 }, (_, index) => index % 256),
);

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

/** The error Node raises for an absent optional peer, code and all. */
function moduleNotFound(specifier: string): Error {
  const error = new Error(`Cannot find package '${specifier}'`);
  (error as { code?: string }).code = "ERR_MODULE_NOT_FOUND";
  return error;
}

beforeEach(async () => {
  merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
    body: JSON.stringify({ ok: true }),
  });
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
  vi.doUnmock("../src/signers/index.js");
  vi.resetModules();
  await merchant.close();
  await rpc.close();
});

describe("O77 — a missing chain package is not a malformed key", () => {
  it("does not fail a request for a chain it never needed", async () => {
    // The exact shape of the finding: Base row installed, both keys exported per the
    // quickstart's "Setting both is fine", and an EVM-only request. Solana's absence must
    // not be able to stop this.
    vi.doMock("../src/signers/index.js", async () => {
      const actual = await vi.importActual<SignersModule>("../src/signers/index.js");
      return {
        ...actual,
        keypairToSolanaSigner: () => Promise.reject(moduleNotFound("@solana/kit")),
      };
    });
    const { run: runMocked } = await import("../src/cli/run.js");

    const harness = io(
      [
        "call",
        merchant.url,
        "--max-spend",
        "0.10 USDC",
        "--network",
        "eip155:8453",
        "--dry-run",
      ],
      {
        env: {
          TX402_DEV_PRIVATE_KEY: DEV_KEY,
          TX402_DEV_SOLANA_KEYPAIR: SOLANA_KEYPAIR,
        },
      },
    );

    expect(await runMocked(harness)).toBe(EXIT_CODES.success);
    const stderr = harness.err.join("");
    // Reported, not silent — and reported as what it is.
    expect(stderr).toContain("optional chain packages are not installed");
    expect(stderr).toContain(CHAIN_INSTALL_COMMANDS["solana"] as string);
    // And emphatically NOT as a bad key, which is what sent the reporter off to regenerate
    // a keypair that was already valid.
    expect(stderr).not.toContain("is not a JSON array of 64 Solana keypair bytes");
    expect(stderr).toContain("would pay");
  });

  it("still reports a genuinely malformed key as a malformed key", async () => {
    // The other half. Collapsing the two failures in the safe direction would be just as
    // wrong as collapsing them in the unsafe one.
    const harness = io(
      ["call", merchant.url, "--max-spend", "0.10 USDC", "--network", "eip155:8453"],
      { env: { TX402_DEV_PRIVATE_KEY: "0xnothex" } },
    );
    expect(await run(harness)).toBe(EXIT_CODES.usage);
    expect(harness.err.join("")).toContain(
      "TX402_DEV_PRIVATE_KEY is not a 0x-prefixed 32-byte hex private key",
    );
  });
});

describe("O79 — a bare install fails as a typed error, not a raw crash", () => {
  it("names the package to install and leaks no filesystem path", async () => {
    // `tx402/signers` imports `viem/accounts` at module scope, so on a bare install the
    // failure is a module resolution error reaching the signer-loading `catch`. Raised
    // from the factory here so the error keeps its `code`, which is what the branch reads.
    vi.doMock("../src/signers/index.js", async () => {
      const actual = await vi.importActual<SignersModule>("../src/signers/index.js");
      return {
        ...actual,
        privateKeyToEvmSigner: () => {
          throw moduleNotFound("viem");
        },
      };
    });
    const { run: runMocked } = await import("../src/cli/run.js");

    const harness = io(
      [
        "call",
        merchant.url,
        "--max-spend",
        "0.10 USDC",
        "--network",
        "eip155:8453",
        "--dry-run",
      ],
      { env: { TX402_DEV_PRIVATE_KEY: DEV_KEY } },
    );

    // Exit 5, the documented "no offered network has a configured signer" — not an
    // unhandled rejection.
    expect(await runMocked(harness)).toBe(EXIT_CODES.protocol);
    const stderr = harness.err.join("");
    expect(stderr).toContain(CHAIN_INSTALL_COMMANDS["eip155"] as string);
    expect(stderr).not.toContain("ERR_MODULE_NOT_FOUND");
    // The original leaked an absolute path and an internal `dist/` path into the operator's
    // terminal, which is both noise and a small information disclosure.
    expect(stderr).not.toMatch(/\/node_modules\/|\/dist\//u);
  });
});

describe("O78 — the dry-run examples are keyless because they ask the keyless question", () => {
  const sources = [
    join(EXAMPLES, "typescript", "dry-run.ts"),
    join(EXAMPLES, "python", "dry_run.py"),
  ];

  it("calls inspect(), never plan()", () => {
    // `plan()` ranks routes, which reads a balance, which needs a signer. Promising a
    // keyless run and then calling it is what made both examples fail on every run.
    // Matched on the client call specifically: both files still *discuss* `plan()` in
    // prose, which is the point of the third assertion below.
    for (const file of sources) {
      const source = readFileSync(file, "utf8");
      expect(source).toMatch(/tx402\.inspect\(/u);
      expect(source).not.toMatch(/tx402\.plan\(/u);
    }
  });

  it("keeps the README's keyless claim true", () => {
    const readme = readFileSync(join(EXAMPLES, "README.md"), "utf8");
    expect(readme).toContain("The dry-run examples need no key at all");
  });

  it("explains why the CLI's dry run does need one", () => {
    // The obvious next question, and leaving it unanswered is how the contradiction got
    // written in the first place.
    for (const file of sources) {
      expect(readFileSync(file, "utf8")).toMatch(/plan\(\)/u);
    }
  });
});

describe("O80/O81 — the published site resolves, and cites nothing a reader cannot reach", () => {
  /**
   * Link resolution is a property of the *site*, so it is checked over site pages. The
   * citation rule below is not — it is a property of anything a reader reads — and it is
   * checked over every reader-facing surface instead. Scoping that one to `docs/` is what
   * let the very commit that removed thirteen citations from `docs/` add two more to
   * `examples/`: this file bound `EXAMPLES` and never swept it. See `reader-surfaces.ts`.
   */
  const pages = sitePages;

  it("has no site-relative link to a file the site does not publish", () => {
    // `../../adr/…md` and `../../core-spec/…json` render as site URLs and 404: neither
    // directory is part of the built site.
    for (const file of pages()) {
      const source = readFileSync(file, "utf8");
      expect(source).not.toMatch(/\]\(\.\.\/\.\.\/adr\//u);
      expect(source).not.toMatch(/\]\(\.\.\/\.\.\/core-spec\//u);
      // A `.md` suffix on an internal link misses Starlight's directory routes.
      expect(source).not.toMatch(/\]\(\.\.[^)]*\.md\)/u);
    }
  });

  it("cites no internal planning artifact, on any surface a reader reads", () => {
    // PLAN.md is not published, so an open-item number or a session identifier resolves to
    // nothing for a stranger — and "an earlier revision of this page was wrong" tells a new
    // reader nothing while undercutting the page they are reading.
    //
    // Widened twice over the original: to every reader-facing surface rather than the site
    // alone, and to the bare `S21` / `(O78)` forms as well as the prose ones. The narrow
    // version matched `session S12` and `open item O3` and so could not see the citations
    // that were added to the examples while it was passing. The bare-identifier sweep lives
    // in the S23 suite alongside the finding that motivated it; these four stay because a
    // prose citation is worth naming distinctly when it fails.
    for (const file of readerSurfaces()) {
      const source = read(file);
      expect(source, relative(file)).not.toMatch(/PLAN\.md/u);
      expect(source, relative(file)).not.toMatch(/open item \*{0,2}O\d/u);
      expect(source, relative(file)).not.toMatch(/the S\d+ audit/u);
      expect(source, relative(file)).not.toMatch(/session S\d+/u);
    }
  });
});
