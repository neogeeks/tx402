/**
 * Regressions for the sixth fresh-eyes UX pass (§11.3), open items O96–O99.
 *
 * Each assertion below was run against `08df8f7` first and observed to fail there.
 *
 * **Two of the four were introduced by the previous remediation session**, which is now the
 * fifth consecutive time that has happened. O98 is the plainer failure and the more useful
 * one to learn from: a bulk edit removed a link and replaced its *text* with prose, leaving
 * the sentence around it — "see … for why" — pointing at nothing. The local edit was right
 * and the sentence was never re-read. O97's documented contract was written from reading two
 * `emit` call sites and inferring they were alternatives, without running them; they both
 * fire, so the rule described has never been implemented in either language.
 *
 * The guard that follows from that: where a page states a contract about runtime behaviour,
 * assert the behaviour, not the sentence.
 */

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { EXIT_CODES, exitCodeFor } from "../src/cli/exit-codes.js";
import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client } from "../src/core/client.js";
import { isTx402Error, type Tx402Error } from "../src/core/errors.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";
import { DOCS, read, readerSurfaces, relative, sitePages } from "./reader-surfaces.js";
import { join } from "node:path";

const LIFECYCLE = join(DOCS, "guides", "lifecycle.mdx");
const SECURITY = join(DOCS, "security", "index.mdx");
const PUBLISHING = join(DOCS, "operations", "publishing.mdx");

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

type Scenario =
  "rechallenge-malformed" | "corrupt-payment-response" | "malformed-challenge";

interface Observed {
  readonly error: Tx402Error;
  readonly failedAt: readonly string[];
}

describe("O96/O97 — what the client does after a signature has been transmitted", () => {
  let merchant: Awaited<ReturnType<typeof createTestMerchant>>;
  let rpc: EvmRpcStub;

  const observe = async (scenario: Scenario): Promise<Observed> => {
    merchant = await createTestMerchant({
      scenario,
      requirements: [REQUIREMENT],
      body: JSON.stringify({ ok: true }),
    });
    const failedAt: string[] = [];
    const record =
      (level: string) =>
      (event: Record<string, unknown>): void => {
        if (event["event"] === "request.failed") failedAt.push(level);
      };
    const client = createTx402Client({
      signers: { evm: privateKeyToEvmSigner(DEV_KEY) },
      policy: { maxPerRequest: "0.10 USDC", allowedNetworks: ["eip155:8453"] },
      allowInsecureLocalhost: true,
      logger: {
        debug: () => undefined,
        info: () => undefined,
        warn: record("warn"),
        error: record("error"),
      },
    });
    try {
      await client.fetch(merchant.url);
    } catch (error) {
      if (!isTx402Error(error)) throw error;
      return { error, failedAt };
    }
    throw new Error(`${scenario} unexpectedly succeeded`);
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

  /**
   * O96 — an undecodable 402 re-challenge is a **post-transmission** outcome, and was
   * classified as if nothing had been signed.
   *
   * The merchant takes the signature, then answers with a 402 whose `PAYMENT-REQUIRED` does
   * not decode. Before this, that produced `TX402_PAYMENT_REQUIRED_INVALID` with **no**
   * `context.paid` at all and exit `5` — a band the CLI guide documents as "no signature was
   * ever produced", and whose advice is "nothing local helps". The sibling case, an
   * undecodable `PAYMENT-RESPONSE` after the same signature, correctly produced exit `8`.
   *
   * The release stays: an HTTP `402` is intelligible whatever the header says, and it is the
   * merchant declining the payment — settlement evidence still outranks the status line, so a
   * merchant that settles *and* says so is still caught as paid. What changes is the
   * classification, to the band that already means "a signature was transmitted, nothing was
   * delivered, and no money moved": exit `9` with `paid: false`. See ADR-022.
   */
  it("classifies an undecodable re-challenge as a delivery failure, not a bad challenge", async () => {
    const { error } = await observe("rechallenge-malformed");
    expect(error.code).toBe("TX402_RESOURCE_DELIVERY");
    expect(error.context.paid).toBe(false);
    expect(error.details["reason"]).toBe("rechallenge-undecodable");
    // The band is the point of ADR-022, so assert the exit code the CLI will actually
    // return rather than only the class it came from.
    expect(exitCodeFor(error)).toBe(EXIT_CODES.resourceFailure);
    expect(exitCodeFor(error)).not.toBe(EXIT_CODES.protocol);
  });

  it("keeps the decode diagnostic that made the old error useful", async () => {
    // The reason a reader was sent to exit 5 was real: the merchant's header is malformed and
    // they need to know how. Re-banding the outcome must not cost them that.
    const { error } = await observe("rechallenge-malformed");
    expect(error.details["schemaPath"]).toBeDefined();
    expect(error.message).toMatch(/re-?challenge/iu);
  });

  it("still reports a malformed *first* challenge as exit 5, with no payment context", async () => {
    // The do-not-regress half, and the reason this fix is scoped rather than global: before
    // any signature exists, an undecodable challenge is exactly what exit 5 is for.
    const { error } = await observe("malformed-challenge");
    expect(error.code).toBe("TX402_PAYMENT_REQUIRED_INVALID");
    expect(error.context.paid).toBeUndefined();
  });

  it("leaves the ambiguous sibling exactly where it was", async () => {
    const { error } = await observe("corrupt-payment-response");
    expect(error.code).toBe("TX402_PAYMENT_AMBIGUOUS");
    expect(error.context.paid).toBe("unknown");
  });

  /**
   * O97 — `request.failed` was emitted **twice** on every ambiguous path, once at `warn` and
   * once at `error`, with the same `requestId` and an identical payload. An operator counting
   * the event double-counts; an operator alerting on `error` pages for outcomes the
   * documentation calls `warn`.
   *
   * The documented rule — "`warn` when the outcome is ambiguous and the money is still
   * reserved, `error` otherwise" — was written from reading the two `emit` sites and assuming
   * they were alternatives. They are not, and were not in either language: Python emitted once
   * at `error` and never `warn`, so neither implementation matched the page and the two did
   * not match each other.
   */
  it("emits request.failed exactly once, whatever the disposition", async () => {
    for (const scenario of [
      "corrupt-payment-response",
      "rechallenge-malformed",
      "malformed-challenge",
    ] as const) {
      const { failedAt } = await observe(scenario);
      expect(
        failedAt.length,
        `${scenario} emitted request.failed ${failedAt.length}×`,
      ).toBe(1);
      await merchant.close();
    }
  });

  it("emits it at warn when money is still in play, and error otherwise", async () => {
    // The rule the page states, now asserted against the behaviour rather than trusted.
    expect((await observe("corrupt-payment-response")).failedAt).toEqual(["warn"]);
    await merchant.close();
    expect((await observe("malformed-challenge")).failedAt).toEqual(["error"]);
  });
});

describe("O98 — no page sends a reader to something that is not there", () => {
  /**
   * Introduced by the previous session, in the commit that removed ninety-seven unreachable
   * references. A link was replaced by its own description and the scaffolding around it was
   * left standing: "Same-origin redirects are not followed either in v0.1 — see **a
   * deliberate v0.1 narrowing** for why, and what it would take to change." The reader is
   * directed, in as many words, at content that does not exist.
   */
  it("has no cross-reference phrasing with nothing to reference", () => {
    /**
     * Written as a scan rather than one regex, after two attempts that could not fail.
     * The offending sentence wraps across three lines *and* contains `v0.1`, so a pattern
     * excluding newlines missed it and a pattern excluding `.` missed it too. Collapsing
     * whitespace first and then asking a single question — "does the span between `see` and
     * `for why` contain a link?" — has neither failure mode.
     */
    const offenders: string[] = [];
    for (const file of sitePages()) {
      const flat = read(file).replace(/\s+/gu, " ");
      for (const match of flat.matchAll(/\bsee\b(.{0,80}?)\bfor (?:why|how|more)\b/giu)) {
        const span = match[1] as string;
        // A real cross-reference carries a markdown link or an inline anchor.
        if (!span.includes("](") && !span.includes("<a ")) {
          offenders.push(`${relative(file)}: "see${span}for …"`);
        }
      }
    }
    expect(offenders, offenders.join("\n")).toEqual([]);
  });

  it("explains the same-origin redirect narrowing where it raises it", () => {
    // The repair is to answer the question on the page, not to delete the promise of an
    // answer — the reader wanted the reason, and it is a short one.
    // Not a ban on the phrase — it is honest prose in its own right, and the sibling
    // assertion above is what catches it being used as a link substitute. What matters here
    // is that the page answers the question it raises instead of deferring it.
    //
    // Searched over the whole page with whitespace collapsed, rather than a slice anchored on
    // one sentence. The first version anchored on "Same-origin redirects are not followed",
    // which S31 legitimately reworded — `indexOf` returned -1, `slice(-1)` yielded a newline,
    // and the assertion failed for a reason that had nothing to do with what it guards. An
    // anchor that can silently miss is the same hazard as a pattern that cannot match.
    const flat = read(SECURITY).replace(/\s+/gu, " ");
    expect(flat, "the page must still discuss same-origin redirects").toMatch(
      /same-origin/iu,
    );
    expect(flat).toMatch(/idempot/iu);
    expect(flat).toMatch(/second charge|charge twice|pay twice/iu);
  });
});

describe("O97 — the lifecycle page's level table matches the code", () => {
  it("states one level per event, and the two conditional ones are real", () => {
    const source = read(LIFECYCLE);
    // The table must not claim `request.failed` is `warn` *or* `error` as alternatives
    // unless the code actually chooses between them — which is now asserted above.
    expect(source).toMatch(/request\.failed/u);
    expect(source).not.toMatch(/emitted twice/u);
  });
});

describe("O99 — the publishing runbook's verification command works as printed", () => {
  /**
   * PyPI moved the licence into `info.license_expression`; `info.license` is now `null`, so
   * the documented command prints `tx402 0.0.0 None` rather than the recorded
   * `tx402 0.0.0 Apache-2.0`. Small, and on a page whose whole job is telling an operator
   * what a correct result looks like.
   */
  it("reads the licence from the field PyPI actually populates", () => {
    const source = read(PUBLISHING);
    expect(source).toMatch(/license_expression/u);
  });

  it("does not record an expected output the command cannot produce", () => {
    const source = read(PUBLISHING);
    // The recorded observation has to match what the printed command returns today.
    expect(source).not.toMatch(/print\(d\['name'\], d\['version'\], d\['license'\]\)/u);
  });
});

describe("O96–O99 — none of this reintroduced an unreachable reference", () => {
  const CITATION = /(?<![\w`/-])(?:SPEC\s*§\s*[\d.]+|ADR-\d{3}|SEC-\d{3})/gu;

  it("keeps every reader-facing surface free of internal citations", () => {
    // The previous session cleared ninety-seven of these and introduced O98 doing it. This
    // batch touches four of the same pages.
    for (const file of readerSurfaces()) {
      expect(
        [...read(file).matchAll(CITATION)].map((m) => m[0]),
        relative(file),
      ).toEqual([]);
    }
  });
});
