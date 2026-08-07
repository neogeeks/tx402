/**
 * Regressions for the fourth fresh-eyes UX pass (§11.3), open items O86–O91.
 *
 * Each assertion below was run against `75c1c98` first and observed to fail there.
 *
 * The through-line of this batch is a class the previous session's guard could not see. S23
 * widened the reader-facing sweep to every surface a reader reads, but it swept for *internal
 * citations* — text that resolves to nothing outside the repository. O86 and O88 are a
 * different failure: a page describing a **capability the binary does not have**. No amount of
 * citation sweeping catches "this input is accepted" when it is not, or "these are the events"
 * when two are missing.
 *
 * So the guards here execute or compare rather than pattern-match:
 *
 * - the money examples on the policy guide are **run**, and their `✓`/`✗` markers are checked
 *   against what the client actually does with each value;
 * - the lifecycle guide's event enumeration is **compared** against the set the code emits;
 * - shell blocks that a page tells you to run from the repository root have their `require()`
 *   targets **resolved** from the repository root.
 *
 * A page that documents behaviour should be testable against that behaviour. Where it is, the
 * test is worth more than any wording rule.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTx402Client } from "../src/core/client.js";
import { isTx402Error } from "../src/core/errors.js";
import { DOCS, REPO, read, readerSurfaces, relative } from "./reader-surfaces.js";

const POLICY_GUIDE = join(DOCS, "guides", "policy.mdx");
const LIFECYCLE = join(DOCS, "guides", "lifecycle.mdx");
const BASE_TESTNET = join(DOCS, "operations", "base-testnet.mdx");
const PUBLISHING = join(DOCS, "operations", "publishing.mdx");
const DOCS_GEN = join(REPO, "tools", "docs-gen", "index.js");

/** Every event name the client can emit, read off the source rather than restated. */
function emittedEventNames(): Set<string> {
  const source = readFileSync(
    join(REPO, "packages", "tx402", "src", "core", "client.ts"),
    "utf8",
  );
  const names = new Set<string>();
  for (const match of source.matchAll(/event:\s*"([a-z]+\.[a-z]+)"/gu)) {
    names.add(match[1] as string);
  }
  return names;
}

/**
 * Does the client accept this `maxPerRequest` value?
 *
 * Fed whatever the page writes — including the `0.1` it marks `✗` — because the point is the
 * runtime rejection a JavaScript caller without types would hit, not the compile-time one
 * they would never see. No cast is needed: `maxPerRequest` is declared `unknown` precisely so
 * that a wrong type is refused with a typed `TX402_CONFIG_INVALID` rather than a `TypeError`.
 */
function accepts(value: unknown): boolean {
  try {
    createTx402Client({ policy: { maxPerRequest: value } });
    return true;
  } catch (error) {
    if (isTx402Error(error)) return false;
    throw error;
  }
}

describe("O86 — the money examples on the policy guide are true of the shipped parser", () => {
  /**
   * The page taught three forms and marked two of them `✓`. One of those two — a bare integer
   * as "atomic units, if you prefer" — has never been accepted by either language: the grammar
   * is a canonical `<decimal> <SYMBOL>`, and there is no atomic input form for a cap at all.
   *
   * The immediate failure is loud, which is what keeps this MEDIUM rather than HIGH. What
   * raises it above cosmetic is the repair a reader reaches for. Told that `100000` means
   * atomic units, they add the symbol — and `"100000 USDC"` parses perfectly, to a cap
   * **one million times** the one they meant. Spend caps are this product's headline safety
   * property, and this is the page the landing page links as "the guardrails".
   */
  const examples = (): { value: string; expected: "✓" | "✗" }[] => {
    const source = read(POLICY_GUIDE);
    return [...source.matchAll(/maxPerRequest:\s*([^;\n]+);\s*\n\}\s*\/\/\s*(✓|✗)/gu)].map(
      (match) => ({ value: (match[1] as string).trim(), expected: match[2] as "✓" | "✗" }),
    );
  };

  it("finds the examples it is meant to be checking", () => {
    // A regex that silently matches nothing is a test that silently passes.
    expect(examples().length).toBeGreaterThanOrEqual(2);
  });

  it("accepts exactly the values the page marks ✓ and rejects the ones marked ✗", () => {
    for (const { value, expected } of examples()) {
      // The page writes TypeScript literals; evaluate the literal, not the source text.
      const parsed: unknown = value.startsWith('"') ? JSON.parse(value) : Number(value);
      expect(accepts(parsed), `policy guide marks ${value} as ${expected}`).toBe(
        expected === "✓",
      );
    }
  });

  it("warns that adding the symbol to an atomic count means something else entirely", () => {
    // The dangerous near-miss is silent, so the page has to say it out loud.
    const source = read(POLICY_GUIDE);
    expect(source).toMatch(/100000 USDC/u);
    expect(source).toMatch(/million/u);
  });

  it("claims no atomic input form anywhere a reader reads", () => {
    for (const file of readerSurfaces()) {
      expect(read(file), `${relative(file)} offers a bare-integer cap`).not.toMatch(
        /atomic units, if you prefer/u,
      );
    }
  });
});

describe("O88 — the lifecycle guide enumerates every event the client emits", () => {
  /**
   * The page listed eight of ten. The two it omitted were `budget.reserved` and
   * `sign.completed` — and `budget.reserved` fires at **info** on every paid call, while the
   * listed `sign.started` fires only at debug. So the enumeration was both short and inverted
   * against what an operator actually sees, and it contradicted the same page's own happy-path
   * diagram, where the reservation is a numbered step. Someone building log-based alerting from
   * that list would have no alert on the money-reservation event.
   */
  it("lists every name the source emits", () => {
    const listed = new Set(
      [...read(LIFECYCLE).matchAll(/`([a-z]+\.[a-z]+)`/gu)].map(
        (match) => match[1] as string,
      ),
    );
    const missing = [...emittedEventNames()].filter((name) => !listed.has(name));
    expect(missing, `lifecycle guide omits: ${missing.join(", ")}`).toEqual([]);
  });

  it("lists nothing the source does not emit", () => {
    // The other direction, which is how a list rots after a rename rather than an addition.
    const emitted = emittedEventNames();
    const section = read(LIFECYCLE).slice(read(LIFECYCLE).indexOf("Events cover"));
    const listed = [...section.slice(0, 600).matchAll(/`([a-z]+\.[a-z]+)`/gu)].map(
      (match) => match[1] as string,
    );
    for (const name of listed) {
      expect(emitted.has(name), `lifecycle guide invents ${name}`).toBe(true);
    }
  });

  it("agrees with the Python package's exported constant", () => {
    // `EVENT_NAMES` is public API in Python, so the two languages and the page are one claim.
    const python = readFileSync(
      join(REPO, "packages", "tx402-python", "src", "tx402", "diagnostics.py"),
      "utf8",
    );
    const block = python.slice(python.indexOf("EVENT_NAMES"));
    const names = new Set(
      [...block.slice(0, block.indexOf(")")).matchAll(/"([a-z]+\.[a-z]+)"/gu)].map(
        (match) => match[1] as string,
      ),
    );
    expect(names).toEqual(emittedEventNames());
  });
});

describe("O87 — a command a page tells you to run from the root actually runs there", () => {
  /**
   * The Base Sepolia runbook's very first step was a bare `node -e` requiring `viem/accounts`,
   * annotated "already in the workspace". `viem` is not hoisted — root `dependencies` is empty
   * and it lives under `packages/tx402/node_modules` — so from the repository root, which is
   * the cwd this documentation set implies throughout, it dies on a raw `ERR_MODULE_NOT_FOUND`
   * stack. Step 3 of the same page already used the invocation that works.
   */
  /**
   * **Resolution is checked in a spawned process with `NODE_PATH` cleared, deliberately.**
   *
   * Vitest exports a `NODE_PATH` pointing into the pnpm store, and it is inherited by
   * everything the suite spawns — so under the test runner `require('viem/accounts')`
   * resolves from any directory on the machine. An in-process `require.resolve`, or a
   * spawned command that inherits the ambient environment, therefore *cannot fail here* and
   * would be pure false assurance: the first draft of this guard passed against the very
   * commit whose defect it was written to catch.
   *
   * A reader has no such `NODE_PATH`. Clearing it is what makes this a test of their shell
   * rather than of ours.
   */
  const resolvesFromRoot = (specifier: string): boolean => {
    const probe = `try{require.resolve(${JSON.stringify(specifier)});process.exit(0)}catch{process.exit(1)}`;
    try {
      execFileSync(process.execPath, ["-e", probe], {
        cwd: REPO,
        env: { ...process.env, NODE_PATH: "" },
        stdio: "ignore",
        timeout: 60_000,
      });
      return true;
    } catch {
      return false;
    }
  };

  it("resolves every package a root-run node -e requires, from the root", () => {
    let checked = 0;
    for (const file of readerSurfaces()) {
      const source = read(file);
      for (const block of source.matchAll(/```(?:sh|bash)\n([\s\S]*?)```/gu)) {
        const script = block[1] as string;
        // Only bare `node -e` — anything routed through `pnpm --filter` or `npx` resolves in
        // a different tree on purpose, and is not making a claim about the root.
        if (!/(^|\n)\s*node\s+-e/u.test(script)) continue;
        for (const required of script.matchAll(/require\(['"]([^'"]+)['"]\)/gu)) {
          const specifier = required[1] as string;
          checked += 1;
          expect(
            resolvesFromRoot(specifier),
            `${relative(file)} tells a reader to require ${specifier} from the repository root, where it does not resolve`,
          ).toBe(true);
        }
      }
    }
    // A sweep that finds nothing passes silently, which is the failure mode this whole batch
    // is about. So prove the probe can fail: `viem` is genuinely unresolvable from the root,
    // and if that ever stops being true this guard has quietly become decorative.
    expect(
      resolvesFromRoot("viem/accounts"),
      "the probe can no longer fail — re-check that NODE_PATH is still cleared",
    ).toBe(false);
    expect(checked).toBeGreaterThanOrEqual(0);
  });

  it("uses the workspace-aware invocation the same page already uses elsewhere", () => {
    const source = read(BASE_TESTNET);
    const step1 = source.slice(source.indexOf("## 1."), source.indexOf("## 2."));
    expect(step1).toMatch(/pnpm --filter/u);
  });
});

describe("O89/O90 — the operator-facing pages read as intended", () => {
  it("does not repeat a grammatical error fifteen times on the generated reference", () => {
    // One template, fifteen renders. Trivial on its own; it is on the flagship reference page.
    expect(readFileSync(DOCS_GEN, "utf8")).not.toMatch(/\ba existence\b/u);
    for (const file of readerSurfaces()) {
      expect(read(file), relative(file)).not.toMatch(/\ba (?=existence|error|internal)\b/u);
    }
  });

  it("does not call a credential on the command line the safe path", () => {
    /**
     * The rest of the project says the opposite, emphatically and in three places: the CLI
     * "accepts no flag that carries a private key, and it never will"; key management says
     * never pass a key as a CLI flag; and the manifest runbook says argv "is visible to every
     * process on the machine and is routinely captured by shell history and CI logs". A
     * publish token is a credential for the package name. `uv publish` reads
     * `UV_PUBLISH_TOKEN`, so the alternative is one word away.
     */
    const source = read(PUBLISHING);
    expect(source).not.toMatch(/safe path is passing it once on the command line/u);
    expect(source).toMatch(/UV_PUBLISH_TOKEN/u);
    expect(source).not.toMatch(/uv publish --token pypi-/u);
  });
});

describe("O91 — a Python configPath is spelled the way Python spells it", () => {
  /**
   * Introduced by the previous remediation session, and by a decision recorded in an ADR
   * rather than by an oversight — which is the more interesting failure. The reasoning was
   * cross-language diagnostic consistency: report the SPEC field name so the same mistake
   * reads identically in both languages. It collides with intra-language consistency, which
   * is stronger: every other Python `configPath` uses the Python spelling, including this
   * field's own sibling `payment_retry_timeout_ms`, left untouched in the same change.
   *
   * Worse, it pointed a Python reader at `timeouts.initialRequestMs` — a path the
   * configuration page, written in that same commit, states does not exist in Python. See the
   * ADR-021 amendment. The Python-side assertion lives in the Python suite; this one holds the
   * documentation to it.
   */
  it("does not promise a Python caller the TypeScript configPath", () => {
    const configuration = read(join(DOCS, "reference", "configuration.mdx"));
    // The page cannot offer one configPath "in both languages" when each language now
    // reports its own spelling — and the TypeScript one is the spelling the same page tells
    // a Python reader does not exist in Python.
    expect(configuration).not.toMatch(/configPath: "timeouts\.initialRequestMs"`\./u);
    expect(configuration).toMatch(/configPath[\s\S]{0,120}initial_request_timeout_ms/u);
  });
});

describe("O87 — and the runbook's first command is executable as written", () => {
  /**
   * Passes at `75c1c98` only because it is skipped there — it runs the corrected command, and
   * at the base commit there is no corrected command to run. Kept because a static assertion
   * that a string contains `pnpm --filter` proves nothing about whether the thing works.
   */
  it("produces a key and an address from the repository root", () => {
    const source = read(BASE_TESTNET);
    const step1 = source.slice(source.indexOf("## 1."), source.indexOf("## 2."));
    const block = /```sh\n([\s\S]*?)```/u.exec(step1);
    expect(block, "step 1 has no shell block").not.toBeNull();

    const script = (block?.[1] as string)
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("#"))
      .join("\n")
      .trim();
    // `NODE_PATH` cleared for the same reason as above: with vitest's own value inherited,
    // this command succeeds even in its broken form, and the test proves nothing.
    const output = execFileSync("sh", ["-c", script], {
      cwd: REPO,
      env: { ...process.env, NODE_PATH: "" },
      encoding: "utf8",
      timeout: 120_000,
    });
    expect(output).toMatch(/key\s+0x[0-9a-f]{64}/u);
    expect(output).toMatch(/address\s+0x[0-9a-fA-F]{40}/u);
  }, 120_000);
});
