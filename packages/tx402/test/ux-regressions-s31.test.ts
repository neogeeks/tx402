/**
 * Regressions for the seventh fresh-eyes UX pass (§11.3), open items O100–O103.
 *
 * Each assertion below was run against `dc373ef` first and observed to fail there.
 *
 * **Three of the four items were sentences this project's own remediation sessions wrote, and
 * all three were written the same way: by reading source and describing what it looked like it
 * would do, rather than by running it.** O100 and O102 were written at S29 — in the very commit
 * whose ADR-022 diagnosed that exact habit as the cause of the defect it was fixing. O103 was
 * written at S25.
 *
 * So the guards here do not check wording. Every one of them derives the fact from the running
 * client and compares the page against it, which is the only form that could have caught any of
 * the three: each was a brand-new sentence, and a pattern list only catches a class already
 * seen. See ADR-023 for the rule this batch is really about.
 */

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client } from "../src/core/client.js";
import { isTx402Error, type Tx402Error } from "../src/core/errors.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";
import { DOCS, read, relative, sitePages } from "./reader-surfaces.js";
import { join } from "node:path";

const SECURITY = join(DOCS, "security", "index.mdx");
const LIFECYCLE = join(DOCS, "guides", "lifecycle.mdx");
const QUICKSTART = join(DOCS, "start", "quickstart.mdx");

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

interface Run {
  /** The thrown error, or `undefined` when the call resolved. */
  readonly error?: Tx402Error;
  /** One entry per request the merchant saw: whether it carried a signature. */
  readonly merchantSaw: readonly ("signed" | "unsigned")[];
  /** `level:event` for every event emitted, in order. */
  readonly events: readonly string[];
  /** `reason` values seen on a `warn`-level `payment.completed`. */
  readonly warnReasons: readonly string[];
}

describe("O100–O103 — pages describing runtime behaviour, checked against the runtime", () => {
  let merchant: Awaited<ReturnType<typeof createTestMerchant>>;
  let rpc: EvmRpcStub;

  const exercise = async (scenario: string): Promise<Run> => {
    merchant = await createTestMerchant({
      scenario,
      requirements: [REQUIREMENT],
      body: JSON.stringify({ ok: true }),
    });
    const merchantSaw: ("signed" | "unsigned")[] = [];
    const events: string[] = [];
    const warnReasons: string[] = [];
    const merchantPort = new URL(merchant.url).port;

    const realFetch = globalThis.fetch;
    vi.stubGlobal("fetch", async (input: Request | string | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (RPC_HOSTS.has(new URL(request.url).host)) {
        return realFetch(rpc.url, {
          method: request.method,
          headers: request.headers,
          body: await request.text(),
        });
      }
      if (new URL(request.url).port === merchantPort) {
        merchantSaw.push(request.headers.get("PAYMENT-SIGNATURE") ? "signed" : "unsigned");
      }
      return realFetch(request);
    });

    const record =
      (level: string) =>
      (event: Record<string, unknown>): void => {
        const name = String(event["event"]);
        events.push(`${level}:${name}`);
        const reason = event["reason"];
        if (
          level === "warn" &&
          name === "payment.completed" &&
          typeof reason === "string"
        ) {
          warnReasons.push(reason);
        }
      };

    const client = createTx402Client({
      signers: { evm: privateKeyToEvmSigner(DEV_KEY) },
      policy: { maxPerRequest: "0.10 USDC", allowedNetworks: ["eip155:8453"] },
      allowInsecureLocalhost: true,
      logger: {
        debug: record("debug"),
        info: record("info"),
        warn: record("warn"),
        error: record("error"),
      },
    });

    try {
      await client.fetch(merchant.url);
      return { merchantSaw, events, warnReasons };
    } catch (error) {
      if (!isTx402Error(error)) throw error;
      return { error, merchantSaw, events, warnReasons };
    }
  };

  const countOf = (events: readonly string[], name: string): number =>
    events.filter((entry) => entry.endsWith(`:${name}`)).length;

  beforeEach(async () => {
    const payer = await privateKeyToEvmSigner(DEV_KEY).getAddress();
    rpc = await createEvmRpcStub({
      chainId: 8453,
      token: USDC.address,
      balances: { [payer]: "5000000" },
    });
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    await merchant?.close();
    await rpc.close();
  });

  /**
   * O100 — the security page said a cross-origin paid retry "fails **before** the signature is
   * transmitted", and that on a redirect "you get the response, see the `Location`, and decide".
   *
   * Observed, both scenarios: the merchant receives a **signed** request and answers `307`, and
   * the call **throws**. Nothing is returned to the caller, and the same-origin error carries
   * only `causeCategory` and `reservationExpiresAtEpochMs` — no `Location`, no origins.
   *
   * The second sentence is S29's. The first predates it and contradicted both the error
   * reference and the lifecycle table, which had it right all along.
   */
  it("transmits the signature before a redirect is refused, on both redirect kinds", async () => {
    for (const scenario of ["cross-origin-redirect", "same-origin-redirect"]) {
      const run = await exercise(scenario);
      expect(run.merchantSaw, `${scenario} merchant requests`).toEqual([
        "unsigned",
        "signed",
      ]);
      expect(run.error, `${scenario} must not resolve`).toBeDefined();
      expect(run.error?.context.paid).toBe("unknown");
      await merchant.close();
    }
  });

  it("does not tell a reader they get the response back from a redirect", () => {
    const source = read(SECURITY);
    expect(source).not.toMatch(/you get the response, see the `Location`, and decide/u);
    expect(source).not.toMatch(/fails \*\*before\*\* the signature is\s+transmitted/u);
  });

  it("says the signature is already out, and that both kinds are exit 8", () => {
    const source = read(SECURITY);
    const section = source.slice(
      source.indexOf("redirect"),
      source.indexOf("redirect") + 1400,
    );
    expect(section).toMatch(/already/iu);
    expect(section).toMatch(/exit `?8`?/u);
    expect(section).toMatch(/reconcile/iu);
  });

  /**
   * O102 — "Each event is emitted exactly once per request" was false for seven of the ten
   * names the moment it was written. Observed across sixteen scenarios: three names are emitted
   * once per **request**, and seven once per **attempt** — so a re-challenged call emits each of
   * those seven twice. The same page's own "every attempt re-plans from scratch" section says so.
   *
   * This is the sentence that matters operationally, because the page then singles out
   * `budget.reserved` as the event worth alerting on, and it is one of the seven.
   */
  it("emits exactly three of the ten event names once per request", async () => {
    const run = await exercise("rechallenge-once");
    for (const name of ["request.started", "payment.completed"]) {
      expect(countOf(run.events, name), `${name} on a re-challenged call`).toBe(1);
    }
    for (const name of [
      "payment.required",
      "policy.checked",
      "route.planned",
      "budget.reserved",
      "sign.started",
      "sign.completed",
      "request.retried",
    ]) {
      expect(countOf(run.events, name), `${name} on a re-challenged call`).toBe(2);
    }
  });

  it("does not claim every event is emitted once per request", () => {
    for (const file of sitePages()) {
      expect(read(file), relative(file)).not.toMatch(/emitted exactly once per request/u);
    }
  });

  it("names the per-attempt events, and budget.reserved among them", () => {
    // Whitespace-collapsed before searching. Two guards in the previous two sessions were
    // caught unable to fail because the phrase they looked for wrapped across a line, and
    // this page is prose that prettier rewraps freely.
    const flat = read(LIFECYCLE).replace(/\s+/gu, " ");
    expect(flat).toMatch(/once per \*\*attempt\*\*/iu);
    const perAttempt = flat.slice(flat.indexOf("Once per **attempt**"));
    // The seven the survey observed, in the row that claims to list them.
    for (const name of [
      "payment.required",
      "policy.checked",
      "route.planned",
      "budget.reserved",
      "sign.started",
      "sign.completed",
      "request.retried",
    ]) {
      expect(perAttempt.slice(0, 400), `per-attempt row omits ${name}`).toMatch(
        new RegExp(name.replace(".", "\\."), "u"),
      );
    }
  });

  /**
   * O103 — `payment.completed` at `warn` was documented as meaning the merchant "supplied no
   * settlement evidence and it committed anyway". Observed reasons at `warn`, across sixteen
   * scenarios, are three — and the third is a merchant that *did* supply a successful
   * `PAYMENT-RESPONSE`, which is the opposite of the documented condition.
   */
  it("warns on payment.completed for a merchant that did supply settlement evidence", async () => {
    const run = await exercise("settled-but-refused");
    expect(run.warnReasons).toContain("settlement-succeeded-resource-unusable");
    expect(run.error?.context.paid).toBe(true);
  });

  it("does not describe the warn as meaning evidence was absent", () => {
    const source = read(LIFECYCLE);
    expect(source).not.toMatch(
      /`warn` when the merchant supplied no settlement evidence and it committed anyway/u,
    );
    // All three observed reasons, so the page cannot describe a subset again.
    for (const reason of [
      "payment-response-absent",
      "payment-response-unparseable",
      "settlement-succeeded-resource-unusable",
    ]) {
      expect(source, `lifecycle omits ${reason}`).toMatch(new RegExp(reason, "u"));
    }
  });
});

describe("O101 — the exit-5 remedy names the packages that actually fix it", () => {
  /**
   * The quickstart's exit-5 table told a stuck Solana user to install "the Solana trio". The
   * install row two hundred lines above lists **four** packages, `viem` among them, and `viem`
   * is genuinely required: `tx402/signers` imports `viem/accounts` at module scope, so the
   * import fails outright without it whichever chain you are paying on.
   *
   * Asymmetric as written, too — the Base remedy in the same cell names `viem` explicitly.
   */
  it("does not prescribe a count that excludes a required package", () => {
    expect(read(QUICKSTART)).not.toMatch(/the Solana trio/u);
  });

  it("names viem in the Solana remedy, as the install row does", () => {
    const source = read(QUICKSTART);
    const row = source.slice(source.indexOf("No offered network has a configured signer"));
    const cell = row.slice(0, row.indexOf("\n"));
    // The Solana half specifically. `viem` already appeared in this cell for Base, so a bare
    // substring check passed at `dc373ef` — against the very cell it was written for.
    const solanaHalf = cell.slice(cell.indexOf("for Base") + "for Base".length);
    expect(solanaHalf, `Solana remedy: ${solanaHalf}`).toMatch(/viem/u);
    // The install row is the authority, and it lists four packages including viem.
    const install = source.slice(source.indexOf("# Solana instead"));
    expect(install.slice(0, 200)).toMatch(/viem/u);
  });
});
