/**
 * Regressions for the eighth fresh-eyes UX pass (§11.3), open items O104–O105.
 *
 * Each assertion below was run against `977b4fc` first and observed to fail there — except
 * the two marked as breadth guards, which pass there by design and are explained below.
 *
 * **O104 is a new sub-shape and worth naming precisely.** The previous batch's rule (ADR-023)
 * says behavioural prose must be written from execution. That addresses a sentence being wrong
 * *when written*. O104 is a sentence that enumerated a closed set, was already missing a member
 * on the day it was written, and then had a *fifth* member added underneath it by a later
 * change — with nothing to notice either. Execution-at-writing-time does not catch the second
 * half: the page was not edited when the set grew.
 *
 * The guard shape that does catch it is to **derive the set from the running client and assert
 * the page accounts for every member**, so that adding a member fails a test rather than
 * quietly invalidating a sentence. That is what the first block does.
 *
 * The second and third blocks apply the same shape to two *other* closed sets that no finding
 * has named yet — the install commands and the `tx402/signers` exports. Scoping a guard to the
 * set a finding happened to point at, rather than to the class, is this project's single most
 * repeated mistake (O72→O77, O79→O82, O81→O85, O85's guard→O95, ADR-023's principle→O104).
 */

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { CHAIN_INSTALL_COMMANDS, createTx402Client } from "../src/core/client.js";
import { isTx402Error } from "../src/core/errors.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import * as signers from "../src/signers/index.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";
import { DOCS, read } from "./reader-surfaces.js";
import { join } from "node:path";

const QUICKSTART = join(DOCS, "start", "quickstart.mdx");
const API_PAGE = join(DOCS, "reference", "api-typescript.mdx");

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

/** Every scenario that can reach a delivery failure, plus the ones that must not. */
const SCENARIOS = [
  "always-402",
  "refused-after-signature",
  "rechallenge-malformed",
  "unsuccessful-settlement",
  "settled-but-refused",
  "settled-but-rechallenged",
] as const;

describe("O104 — the quickstart accounts for every exit-9 reason the client can produce", () => {
  let merchant: Awaited<ReturnType<typeof createTestMerchant>>;
  let rpc: EvmRpcStub;

  /** `reason` → `paid`, observed by running each scenario rather than read off the source. */
  const observedReasons = async (): Promise<Map<string, unknown>> => {
    const found = new Map<string, unknown>();
    for (const scenario of SCENARIOS) {
      merchant = await createTestMerchant({
        scenario,
        requirements: [REQUIREMENT],
        body: JSON.stringify({ ok: true }),
      });
      const client = createTx402Client({
        signers: { evm: privateKeyToEvmSigner(DEV_KEY) },
        policy: { maxPerRequest: "0.10 USDC", allowedNetworks: ["eip155:8453"] },
        allowInsecureLocalhost: true,
      });
      try {
        await client.fetch(merchant.url);
      } catch (error) {
        if (isTx402Error(error) && error.code === "TX402_RESOURCE_DELIVERY") {
          found.set(String(error.details["reason"]), error.context.paid);
        }
      }
      await merchant.close();
    }
    return found;
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
    await rpc.close();
  });

  it("finds more than one unpaid reason, so the sweep is doing something", async () => {
    // A survey that silently found nothing would make every assertion below vacuous.
    const reasons = await observedReasons();
    const unpaid = [...reasons].filter(([, paid]) => paid === false);
    expect(unpaid.length).toBeGreaterThanOrEqual(4);
    expect([...reasons].some(([, paid]) => paid === true)).toBe(true);
  });

  it("names every unpaid reason on the page that tells a reader how to act", async () => {
    const reasons = await observedReasons();
    const page = read(QUICKSTART);
    const missing = [...reasons]
      .filter(([, paid]) => paid === false)
      .map(([reason]) => reason)
      .filter((reason) => !page.includes(reason));
    expect(
      missing,
      `quickstart omits unpaid exit-9 reasons: ${missing.join(", ")}`,
    ).toEqual([]);
  });

  it("does not present the unpaid reasons as a closed set of two", () => {
    // The exact failure: an enumeration that reads as exhaustive and is not. It was missing a
    // member the day it was written, and gained another when `rechallenge-undecodable` was
    // added later — with nothing anywhere to notice either event.
    const page = read(QUICKSTART);
    expect(page).not.toMatch(
      /`settlement-unsuccessful` and\s+`max-paid-attempts-exhausted` are the unpaid ones/u,
    );
  });

  it("still distinguishes the one paid reason from the unpaid ones", async () => {
    const reasons = await observedReasons();
    const paid = [...reasons]
      .filter(([, value]) => value === true)
      .map(([reason]) => reason);
    expect(paid).toEqual(["settlement-succeeded-resource-unusable"]);
    expect(read(QUICKSTART)).toMatch(/settlement-succeeded-resource-unusable/u);
  });
});

describe("O105 — the API page describes every export of the module it lists", () => {
  /**
   * The `tx402/signers` row said the module "wraps a raw private key as an `EvmSigner`". It
   * exports two helpers, and the omitted one — `keypairToSolanaSigner` — is what the
   * quickstart's own Solana snippet imports. The page states its purpose as answering "what is
   * available and from where", which is what makes an incomplete row a defect rather than a
   * summary.
   */
  it("mentions every function tx402/signers exports", () => {
    const exported = Object.keys(signers).filter(
      (name) => typeof (signers as Record<string, unknown>)[name] === "function",
    );
    expect(exported.length).toBeGreaterThanOrEqual(2);
    const page = read(API_PAGE);
    const missing = exported.filter((name) => !page.includes(name));
    expect(missing, `API page omits: ${missing.join(", ")}`).toEqual([]);
  });

  it("does not describe the module as EVM-only", () => {
    const page = read(API_PAGE);
    expect(page).not.toMatch(
      /Development only — wraps a raw private key as an `EvmSigner`\./u,
    );
  });
});

describe("O104/O105 breadth — other closed sets the docs restate", () => {
  /**
   * **These two pass at `977b4fc` and are not evidence.** They exist because the recurring
   * mistake in this repository is guarding the set a finding pointed at and leaving its
   * siblings unguarded — four documented times. The install commands are the sharpest case:
   * that single set is behind O72, O77, O82 and O101, and nothing has ever pinned the pages
   * to it.
   */
  it("quotes the install command for every chain family, verbatim from the constant", () => {
    const page = read(QUICKSTART);
    const families = Object.keys(CHAIN_INSTALL_COMMANDS);
    expect(families.length).toBeGreaterThanOrEqual(2);
    for (const family of families) {
      const command = CHAIN_INSTALL_COMMANDS[family] as string;
      expect(
        page,
        `quickstart does not quote the ${family} install command verbatim`,
      ).toContain(command);
    }
  });

  it("names every package of every install command in the exit-5 remedy", () => {
    // The remedy row is where a reader lands *after* the install went wrong, so it is the one
    // place a missing package matters most — and it is the row O101 was wrong on.
    const page = read(QUICKSTART);
    const row = page.slice(page.indexOf("No offered network has a configured signer"));
    const cell = row.slice(0, row.indexOf("\n"));
    expect(cell.length).toBeGreaterThan(80);
    const packages = new Set(
      Object.values(CHAIN_INSTALL_COMMANDS)
        .flatMap((command) => command.split(/\s+/u))
        .filter((token) => token !== "npm" && token !== "install" && token !== "tx402"),
    );
    const missing = [...packages].filter((name) => !cell.includes(name));
    expect(missing, `exit-5 remedy omits: ${missing.join(", ")}`).toEqual([]);
  });
});
