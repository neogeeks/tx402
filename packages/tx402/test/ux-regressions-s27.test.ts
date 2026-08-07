/**
 * Regressions for the fifth fresh-eyes UX pass (§11.3), open items O92–O95.
 *
 * Each assertion below was run against `290d69c` first and observed to fail there.
 *
 * O95 is the one worth reading twice. It is the **fourth** appearance of a single shape: a
 * guard scoped to the instances a finding happened to name rather than to the class it
 * belongs to. O72's root cause survived in a second location as O77. O79 was closed with
 * half of it unfixed and came back as O82. O81 removed thirteen unresolvable citations from
 * `docs/` and the same commit added two to `examples/`, invisible to a sweep that walked
 * `docs/` only — which became O85. And the guard written for O85 matched `PLAN.md`, session
 * identifiers and open-item numbers, but never `SPEC §4.3` or `ADR-010` — so ninety-seven
 * citations to documents the site does not publish sat untouched on fifteen pages while
 * three cold passes ran over them.
 *
 * The lesson is not "add the missing pattern". It is that a citation guard should ask what a
 * reader can reach, rather than enumerate the artifacts a maintainer happens to name — so
 * the assertion below is written against the published route set, not a keyword list.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { EXIT_CODES } from "../src/cli/exit-codes.js";
import { run, type CliIo } from "../src/cli/run.js";
import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { privateKeyToEvmSigner } from "../src/signers/index.js";
import {
  DOCS,
  REPO,
  read,
  readerSurfaces,
  relative,
  sitePages,
} from "./reader-surfaces.js";

const RELEASING = join(DOCS, "operations", "releasing.mdx");
const CLI_GUIDE = join(DOCS, "guides", "cli.mdx");
const RELEASE_WORKFLOW = join(REPO, ".github", "workflows", "release.yml");

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

/** The job names in `release.yml`, read off the workflow rather than restated. */
function releaseJobs(): string[] {
  const source = readFileSync(RELEASE_WORKFLOW, "utf8");
  const jobsBlock = source.slice(source.indexOf("\njobs:"));
  return [...jobsBlock.matchAll(/^ {2}([a-z][\w-]*):$/gmu)].map((m) => m[1] as string);
}

describe("O92 — the releasing runbook describes the pipeline that exists", () => {
  /**
   * The page said "four jobs, in order: verify → npm + PyPI → smoke". There are five, and the
   * undocumented one is a **hard gate**: `docs-published` sits between `verify` and both
   * publish jobs, each of which declares `needs: [verify, docs-published]`.
   *
   * This is the page a maintainer reads when a tag does not publish, and the job most likely
   * to block a first release was the one job it never mentioned — while the Docs workflow
   * fails closed today for want of deploy credentials.
   */
  it("names every job in the release workflow", () => {
    const page = read(RELEASING);
    const missing = releaseJobs().filter((job) => !page.includes(job));
    expect(missing, `releasing page never mentions: ${missing.join(", ")}`).toEqual([]);
  });

  it("does not understate the job count", () => {
    const page = read(RELEASING);
    const counts = ["one", "two", "three", "four", "five", "six", "seven"];
    const expected = counts[releaseJobs().length - 1] as string;
    const claimed = /has (\w+) jobs/u.exec(page)?.[1];
    expect(claimed, "the page states a job count").toBeDefined();
    expect(claimed).toBe(expected);
  });

  it("records that the documentation gate can block a publish", () => {
    // The consequence, not just the name: both publish jobs depend on it.
    const page = read(RELEASING);
    expect(page).toMatch(/docs-published/u);
    expect(page).toMatch(/block/iu);
  });
});

describe("O93 — exit 8 gives one piece of advice, and gives it for both of its codes", () => {
  /**
   * Two renderers collided on the same sentence. An advisory keyed off
   * `TX402_PAYMENT_AMBIGUOUS` printed "the payment may have settled — do not retry…", and the
   * settlement block header printed "the payment may have settled" immediately after it. So
   * an ambiguous payment said it twice.
   *
   * The mirror-image half is the one that matters: `TX402_REDIRECT_BLOCKED` is the *other*
   * exit-8 code, reached only after a signature was transmitted, and the error reference
   * groups the two as identically dangerous — but it never printed the "do not retry" half at
   * all, because the advisory was keyed on a code rather than on the disposition.
   *
   * Both now derive from `context.paid`, which is the field that actually carries "money may
   * have moved", so the two codes cannot drift apart again.
   */
  let merchant: Awaited<ReturnType<typeof createTestMerchant>>;
  let rpc: EvmRpcStub;

  const stderrFor = async (
    scenario: "hang-after-signature" | "cross-origin-redirect" | "settled-but-refused",
    extraArgv: string[] = [],
  ): Promise<{ code: number; err: string }> => {
    merchant = await createTestMerchant({
      scenario,
      requirements: [REQUIREMENT],
      body: JSON.stringify({ ok: true }),
    });
    const err: string[] = [];
    const harness: CliIo = {
      argv: [
        "call",
        merchant.url,
        "--max-spend",
        "0.10 USDC",
        "--network",
        "eip155:8453",
        ...extraArgv,
      ],
      env: { TX402_DEV_PRIVATE_KEY: DEV_KEY },
      stdout: () => undefined,
      stderr: (text) => err.push(text),
      readFile: () => {
        throw new Error("no filesystem in this test");
      },
    };
    const code = await run(harness);
    return { code, err: err.join("") };
  };

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
    await merchant?.close();
    await rpc.close();
  });

  it("says 'may have settled' exactly once on an ambiguous payment", async () => {
    const { code, err } = await stderrFor("hang-after-signature", ["--timeout", "1500"]);
    expect(code).toBe(EXIT_CODES.ambiguousPayment);
    expect(err.split("the payment may have settled").length - 1).toBe(1);
  });

  it("tells a blocked cross-origin redirect not to retry, as it tells an ambiguous one", async () => {
    const { code, err } = await stderrFor("cross-origin-redirect");
    expect(code).toBe(EXIT_CODES.ambiguousPayment);
    // The whole point of exit 8 having its own code is that a human stops. Printing the
    // reconciliation values without the instruction was half the message.
    expect(err).toMatch(/do not retry without checking the merchant/u);
    expect(err.split("the payment may have settled").length - 1).toBe(1);
  });

  it("still distinguishes a settled payment from an ambiguous one", async () => {
    // The do-not-regress half: exit 9 with money actually moved must not be collapsed into
    // the ambiguous wording, because the correct action differs.
    const { code, err } = await stderrFor("settled-but-refused");
    expect(code).toBe(EXIT_CODES.resourceFailure);
    expect(err).toMatch(/the payment settled — the resource is what failed/u);
    expect(err).not.toMatch(/may have settled/u);
  });
});

describe("O94 — the CLI guide does not overstate what a null identifier proves", () => {
  /**
   * The page said a `null` transaction on a committed payment means "tx402 has no
   * identifier", **never** "there was no payment". The project's own
   * `missing-payment-response` fixture falsifies the absolute: run against a real facilitator
   * it reports `status: "committed"` with no on-chain settlement at all.
   *
   * The behaviour is correct and deliberate — a 200 to a signature-bearing request is the
   * merchant asserting acceptance, and tx402 never calls a facilitator. The error direction
   * is conservative: the buyer's ledger over-counts spend and can never under-count it, so
   * there is no path to buyer loss. The word "never" is what is wrong, on the page someone
   * reads while reconciling money.
   */
  it("does not claim a null identifier can never mean no payment", () => {
    for (const file of readerSurfaces()) {
      // Newline-tolerant: the sentence wraps mid-phrase in the source, and a regex that
      // matched only the unwrapped form passed against the very text it was written for.
      expect(read(file), relative(file)).not.toMatch(/never\s+"there\s+was no payment"/u);
    }
  });

  it("says what tx402 actually knows, and names the warning that fires", () => {
    const page = read(CLI_GUIDE);
    expect(page).toMatch(/payment-response-absent/u);
    expect(page).toMatch(/cannot distinguish/iu);
  });
});

describe("O95 — the site cites nothing a reader of the site cannot reach", () => {
  /**
   * Ninety-seven citations to `SPEC §…`, `ADR-…` and `SEC-…` across fifteen pages, against
   * two that were links. The site publishes no `spec` or `adr` route, and those documents are
   * to be removed from the repository before it is made public — so **linking them would have
   * been the wrong repair**, manufacturing ninety-seven dead links instead of leaving ninety-
   * seven dead references. The two existing links are removed here for the same reason.
   *
   * Where a citation carried reasoning, the reasoning is now on the page. Where it was
   * provenance decoration in a section subtitle, it is gone. A reader loses nothing they could
   * have acted on, and the pages no longer point outside themselves for the substance of what
   * they assert.
   *
   * Asserted against the **published route set** rather than a keyword list, because a
   * keyword list is exactly what let this survive: the previous guard enumerated `PLAN.md`,
   * session identifiers and open-item numbers, and this class was none of them.
   */
  const CITATION = /(?<![\w`/-])(?:SPEC\s*§\s*[\d.]+|ADR-\d{3}|SEC-\d{3})/gu;

  it("carries no citation to an unpublished internal document", () => {
    const offenders: string[] = [];
    for (const file of readerSurfaces()) {
      const hits = [...read(file).matchAll(CITATION)].map((m) => m[0]);
      if (hits.length > 0) {
        offenders.push(
          `${relative(file)} (${hits.length}): ${hits.slice(0, 3).join(", ")}`,
        );
      }
    }
    expect(offenders, `unresolvable citations remain:\n${offenders.join("\n")}`).toEqual(
      [],
    );
  });

  it("links no file that is scheduled to leave the repository", () => {
    // `SPEC.md`, `PRD.md`, `adr/` and `core-spec/` are internal design records and are to be
    // removed before the repository is published. A link to any of them is a future 404.
    for (const file of sitePages()) {
      const source = read(file);
      expect(source, relative(file)).not.toMatch(
        /https:\/\/github\.com\/[^)]*\/(?:blob|tree)\/main\/(?:adr|core-spec|SPEC\.md|PRD\.md)/u,
      );
    }
  });

  it("still explains the behaviour the citations used to stand in for", () => {
    // The failure mode of this fix would be deleting the reasoning along with the pointer.
    // These are the load-bearing claims the citations were attached to.
    const config = read(join(DOCS, "reference", "configuration.mdx"));
    expect(config).toMatch(/never silently shortens/u);
    expect(config).toMatch(/production/u);
    const policy = read(join(DOCS, "guides", "policy.mdx"));
    expect(policy).toMatch(/evaluation order|order is fixed/iu);
  });
});
