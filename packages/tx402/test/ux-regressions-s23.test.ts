/**
 * Regressions for the third fresh-eyes UX pass (§11.3), open items O82–O85.
 *
 * Each assertion below was run against `03f368f` first and observed to fail there. A
 * regression that passes before the fix is not evidence, and two of the four items being
 * fixed here were *introduced* by earlier remediation sessions that trusted their own scope.
 *
 * Three of the four are prose defects against code that is already correct. That is not a
 * reason to guard them loosely: a false sentence in the quickstart's troubleshooting table
 * is read by someone whose payment has already failed, and it told them the opposite of the
 * right action. Where a prose claim describes a behaviour, the behaviour is pinned too — so
 * a future session cannot make the sentence true by changing the code underneath it.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { EXIT_CODES } from "../src/cli/exit-codes.js";
import { run, type CliIo } from "../src/cli/run.js";
import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";
import { DOCS, EXAMPLES, REPO, read, readerSurfaces, relative } from "./reader-surfaces.js";

const QUICKSTART = join(DOCS, "start", "quickstart.mdx");
const LANDING = join(DOCS, "index.mdx");
const CLI_GUIDE = join(DOCS, "guides", "cli.mdx");
const POLICY_GUIDE = join(DOCS, "guides", "policy.mdx");
const CONFIGURATION = join(DOCS, "reference", "configuration.mdx");
const KEYS = join(DOCS, "security", "keys.mdx");
const ROOT_README = join(REPO, "README.md");
const DOCS_GEN = join(REPO, "tools", "docs-gen", "index.js");

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

describe("O82 — no page promises a core-only install can dry-run", () => {
  /**
   * It never can, and the reason is structural rather than unlucky: `--dry-run` plans
   * routes, planning ranks candidates by balance, and reading a balance needs a chain
   * adapter. A core install has none. Reproduced live at both `03f368f` and this commit —
   * core-only tarball, key exported, `--dry-run` → exit 5, `TX402_SCHEME_UNSUPPORTED`, in
   * TypeScript and in Python alike.
   *
   * This is the half of its own finding that the previous remediation left standing: it
   * fixed the raw crash the same claim produced and closed the item with the claim intact.
   */
  it("does not claim the bare install is enough for a dry run", () => {
    for (const file of readerSurfaces()) {
      const source = read(file);
      // The exact shape of the false claim, and the shape any restatement of it would take:
      // a bare-install sentence that resolves to `--dry-run` being available.
      expect(
        source,
        `${relative(file)} claims a core-only install suffices for --dry-run`,
      ).not.toMatch(/on its own[\s\S]{0,160}enough for[\s\S]{0,40}--dry-run/u);
    }
  });

  it("states both prerequisites where the quickstart introduces the install", () => {
    // Step 1 has to agree with step 4 of the same page. Step 4 already said a dry run needs
    // a configured key; step 1 said the opposite about the packages, in both tabs' reach.
    // Asserted over step 1 specifically, because that is where a reader decides what to
    // install and the contradiction was only visible by reading three sections apart.
    const source = read(QUICKSTART);
    const step1 = source.slice(source.indexOf("## 1. Install"), source.indexOf("## 2."));
    expect(step1).toMatch(/--dry-run/u);
    expect(step1).toMatch(/chain adapter/u);
    // Both tabs: only the TypeScript one carried the false claim, but a Python reader
    // installing the bare package hits the identical exit 5.
    expect(step1).toMatch(/tx402\[evm\]/u);
  });

  it("gives the landing page's zero-code command an install that can run it", () => {
    // The landing page never made the claim in words. It made it in structure: an install
    // block of `npm install tx402` / `pip install tx402` and nothing else, then `--dry-run`
    // presented as "without writing any code at all".
    const source = read(LANDING);
    const install = source.slice(source.indexOf("## Install"), source.indexOf("## Three"));
    expect(install).toMatch(/@x402\/evm/u);
    expect(install).toMatch(/tx402\[evm\]/u);
  });

  it("points the keyless question at the call that is actually keyless", () => {
    // `--dry-run` is the wrong recommendation for "let the agent find out what something
    // costs without being able to pay": it needs a key and a chain adapter. `inspect()`
    // needs neither and answers exactly that question.
    expect(read(KEYS)).toMatch(/inspect\(\)/u);
  });
});

describe("O83 — exit 9 is not described as proof that money moved", () => {
  /**
   * Exit 9 covers both halves of a range. `unsuccessful-settlement` and `always-402` both
   * exit 9 with `settlement: null` and an on-chain delta of zero; `settled-but-refused`
   * exits 9 with a committed settlement and a real transaction hash. The docs described only
   * the second and told everyone reading the first not to retry and to quote a hash that
   * does not exist — when retrying is the correct action and no money had moved.
   *
   * Verified live against the public facilitator on Base Sepolia rather than from tool
   * output: balance held at 17,798,000 atomic across both zero-delta scenarios, and moved
   * by exactly 50,000 on the one that settled.
   */
  it("does not state unconditionally that exit 9 means the money moved", () => {
    for (const file of readerSurfaces()) {
      const source = read(file);
      expect(
        source,
        `${relative(file)} says exit 9 always means a completed payment`,
      ).not.toMatch(/The money _did_ move/u);
      expect(source).not.toMatch(/Payment was fine; the resource was not delivered/u);
    }
  });

  it("does not tell a reader that a null settlement means nothing was signed", () => {
    // Wrong for its own reason: under `unsuccessful-settlement` a signature *was* produced
    // and transmitted. It is the settlement the merchant refused, not the signing.
    const source = read(CLI_GUIDE);
    expect(source).not.toMatch(/"settlement": null`? — nothing was ever signed/u);
  });

  it("names the field that actually carries the distinction", () => {
    // `context.paid` is what separates the two halves, and neither page mentioned it.
    for (const file of [QUICKSTART, CLI_GUIDE]) {
      expect(read(file), `${relative(file)} never mentions context.paid`).toMatch(
        /context\.paid|`paid`/u,
      );
    }
  });

  it("fixes the generated exit-code table at its source", () => {
    // `reference/errors` is generated. Editing the emitted page would be reverted by the
    // next `docs:check`, so the claim has to be corrected in the generator.
    expect(readFileSync(DOCS_GEN, "utf8")).not.toMatch(/Payment was fine/u);
  });
});

describe("O83 — and the code the prose now describes stays that way", () => {
  /**
   * This block passed at `03f368f` and is expected to: the machine-readable output was
   * already correct and O83 is a prose defect. It is here so that the prose cannot be made
   * true in the wrong direction — by changing the exit mapping or the JSON to match the
   * sentence, instead of changing the sentence to match the code.
   */
  let merchant: Awaited<ReturnType<typeof createTestMerchant>>;
  let rpc: EvmRpcStub;

  beforeEach(async () => {
    merchant = await createTestMerchant({
      scenario: "unsuccessful-settlement",
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
    await merchant.close();
    await rpc.close();
  });

  it("reports a refused settlement as exit 9, unpaid, with no settlement object", async () => {
    const out: string[] = [];
    const harness: CliIo = {
      argv: [
        "call",
        merchant.url,
        "--max-spend",
        "0.10 USDC",
        "--network",
        "eip155:8453",
        "--json",
      ],
      env: { TX402_DEV_PRIVATE_KEY: DEV_KEY },
      stdout: (text) => out.push(text),
      stderr: () => undefined,
      readFile: () => {
        throw new Error("no filesystem in this test");
      },
    };

    expect(await run(harness)).toBe(EXIT_CODES.resourceFailure);
    const document = JSON.parse(out.join("")) as {
      settlement: unknown;
      error: { context: { paid: unknown }; details: { reason: unknown } };
    };
    // All three are what the prose now says, and all three are what a stuck reader acts on.
    expect(document.settlement).toBeNull();
    expect(document.error.context.paid).toBe(false);
    expect(document.error.details.reason).toBe("settlement-unsuccessful");
  });
});

describe("O84 — the reference pages do not describe TypeScript as if it were both languages", () => {
  /**
   * The README indexes Configuration as "every option in both languages" while two
   * documented things could not be done in Python from what was written: `timeouts`, which
   * Python had no spelling for at all, and the `getBudgetState()`/`queryBudgetState()` split,
   * whose Python block carried the name of one call and the signature of the other.
   *
   * The two halves are not the same defect and are not fixed the same way — see ADR-021.
   * `timeouts.initialRequestMs` is a **SPEC §4.3** configuration field, language-neutral and
   * normative, so the gap was closed in code. The budget-state split is required of
   * TypeScript by SPEC §4.1 and of Python by nothing, so it is documented per language
   * rather than mirrored into an API no specification asks for.
   */
  it("spells every documented timeout in both languages", () => {
    const source = read(CONFIGURATION);
    // The TypeScript spellings were the only ones present. Python's are flat and differently
    // named, which is exactly why omitting them left a reader guessing at a nested object
    // that does not exist.
    expect(source).toMatch(/initialRequestMs/u);
    expect(source).toMatch(/initial_request_timeout_ms/u);
    expect(source).toMatch(/paymentRetryMs/u);
    expect(source).toMatch(/payment_retry_timeout_ms/u);
  });

  it("does not present the two-call budget split as cross-language", () => {
    const source = read(POLICY_GUIDE);
    expect(source).not.toMatch(/Two calls, and the difference matters\./u);
    // Python's single call is the store query. Showing it under the snapshot's description
    // is what produced `TypeError: missing 2 required keyword-only arguments`.
    expect(source).toMatch(/policy_scope=/u);
    expect(source).toMatch(/TypeScript/u);
  });

  it("does not index the configuration reference as complete for both languages", () => {
    expect(read(ROOT_README)).not.toMatch(/Every option in both languages/u);
  });

  it("labels the API reference link as the TypeScript surface", () => {
    // `/reference/api-python/` is a 404, so a generic "read the API reference" sends a
    // Python reader to a page about a language they are not using, with nowhere else to go.
    const source = read(CONFIGURATION);
    expect(source).toMatch(/\[[^\]]*TypeScript[^\]]*\]\(\.\.\/api-typescript\/\)/u);
  });
});

describe("O85 — shipped text cites no internal session or open-item bookkeeping", () => {
  /**
   * The narrow version of this guard already existed and did not fire, for two reasons that
   * are each worth more than the finding: it walked `docs/` only, and it matched
   * `session S12` and `open item O3` rather than the bare `S21` and `(O78)` that the
   * examples actually carried. Both are widened here — see `reader-surfaces.ts` for why the
   * surface list is a module rather than a constant in one test file.
   */
  const files = [
    join(EXAMPLES, "typescript", "dry-run.ts"),
    join(EXAMPLES, "python", "dry_run.py"),
  ];

  it("carries no session identifier or open-item number on any reader-facing surface", () => {
    for (const file of readerSurfaces()) {
      const source = read(file);
      expect(source, `${relative(file)} cites a session identifier`).not.toMatch(
        /(?<![0-9A-Za-z_])S\d{1,3}(?![0-9A-Za-z_])/u,
      );
      expect(source, `${relative(file)} cites an open-item number`).not.toMatch(
        /(?<![0-9A-Za-z_])O\d{1,3}(?![0-9A-Za-z_])/u,
      );
    }
  });

  it("keeps the explanation that makes the examples correct", () => {
    // Only the bug-advertisement paragraph goes. The `inspect()`-vs-`plan()` explanation
    // above it is the reason these files are right, and is the thing a reader came for.
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      expect(source).toMatch(/different questions, and only one of them is keyless/u);
      expect(source).toMatch(/inspect\(\)/u);
    }
  });
});
