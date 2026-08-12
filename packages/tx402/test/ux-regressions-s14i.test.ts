/**
 * S14i remediation guards for the two S14h P2 findings that are TypeScript-package-level:
 *
 *  - **U13** — the shipped operator code examples must type-check against the CONCRETE store they
 *    construct. The concrete `RedisSpendStore` admin methods gained the optional trailing
 *    `_nowEpochMs?: number` (matching `SpendStoreAdmin` + `MemorySpendStore`), so an example that
 *    passes `Date.now()` compiles. This file constructs a `RedisSpendStore` and RUNS every admin
 *    call WITH the trailing timestamp: the file lives under `test/**`, which
 *    `pnpm typecheck` compiles under the exact profile the docs assume (strict, nodenext,
 *    esModuleInterop, `@types/node`), so dropping the optional param fails the gate — the
 *    falsifiability guard. Doc-parity string checks pin the examples to what the code accepts.
 *
 *  - **U14** — TypeScript now exports a runtime `EVENT_NAMES` + `Tx402EventName` union (PRD §26:
 *    the set is exported in BOTH languages). Asserts the export equals the names the client
 *    actually emits AND Python's `EVENT_NAMES`, so the three cannot drift.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { EVENT_NAMES, type Tx402EventName } from "../src/core/client.js";
import type { BudgetLimits } from "../src/core/ledger.js";
import { RedisSpendStore, type RedisConnection } from "../src/redis/store.js";
import { DOCS, REPO, read } from "./reader-surfaces.js";

// ── U13 — the concrete RedisSpendStore admin methods accept the docs' trailing timestamp ────────

/**
 * A no-op connection that resolves every command. The admin verbs the operator docs use touch
 * `set`/`del`/`hset`/`evalsha`, none of whose return values they parse, so canned replies suffice —
 * this exercises the CALL ARITY (the U13 defect) at both compile time and runtime without a server.
 */
const NOOP_CONN: RedisConnection = {
  evalsha: () => Promise.resolve(""),
  eval: () => Promise.resolve(""),
  get: () => Promise.resolve(null),
  set: () => Promise.resolve("OK"),
  del: () => Promise.resolve(1),
  hset: () => Promise.resolve(1),
  hgetall: () => Promise.resolve({}),
  keys: () => Promise.resolve([]),
  configGet: () => Promise.resolve({}),
};

describe("U13 — operator examples type-check against the concrete RedisSpendStore", () => {
  it("every admin method accepts the trailing nowEpochMs the docs pass (Date.now())", async () => {
    const admin = new RedisSpendStore({ client: NOOP_CONN, admin: true });
    const scope = "api.merchant.example";
    const network = "eip155:8453";
    const assetId = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
    const limits: BudgetLimits = {
      maxPerHourAtomic: "5000000",
      maxTotalAtomic: "100000000",
    };

    // Each call passes the trailing timestamp exactly as shared-store.mdx / kill-switch.mdx /
    // recipient-rotation.mdx do. If the concrete method dropped the optional param, this file
    // would fail `pnpm typecheck` ("Expected N arguments, but got N+1") — the falsifiability guard.
    await expect(
      (async () => {
        await admin.freeze(scope, Date.now());
        await admin.unfreeze(scope, Date.now());
        await admin.setBudgetLimits(scope, assetId, limits, Date.now());
        await admin.setRecipientPins(scope, network, ["0xabc"], Date.now());
        await admin.setTofuEnabled(scope, true, Date.now());
        await admin.setRecipientAssertionRequired(scope, true, Date.now());
        await admin.resetCumulative(scope, assetId, Date.now());
      })(),
    ).resolves.toBeUndefined();
  });

  it("the three operator runbooks pass the trailing timestamp the concrete store now accepts", () => {
    const sharedStore = read(join(DOCS, "operations", "shared-store.mdx"));
    const killSwitch = read(join(DOCS, "operations", "kill-switch.mdx"));
    const rotation = read(join(DOCS, "operations", "recipient-rotation.mdx"));

    // The docs construct a concrete store and call admin methods with a trailing Date.now().
    expect(sharedStore).toContain("new RedisSpendStore(");
    expect(sharedStore).toMatch(/admin\.setBudgetLimits\([\s\S]*Date\.now\(\)/u);
    expect(killSwitch).toMatch(/\.freeze\("[^"]+", Date\.now\(\)\)/u);
    expect(rotation).toMatch(/admin\.setRecipientPins\([\s\S]*Date\.now\(\)/u);
  });
});

// ── U14 — TS exports EVENT_NAMES + a Tx402EventName union, in sync with what the client emits ────

/** The event names the client actually emits, parsed from the source (as ux-regressions-s25 does). */
function emittedEventNames(): Set<string> {
  const source = readFileSync(
    join(REPO, "packages", "tx402", "src", "core", "client.ts"),
    "utf8",
  );
  const names = new Set<string>();
  for (const match of source.matchAll(/event:\s*"([a-z]+\.[a-z]+)"/gu))
    names.add(match[1] as string);
  return names;
}

/** Python's exported `EVENT_NAMES`, so the two languages stay one claim (PRD §26). */
function pythonEventNames(): Set<string> {
  const python = readFileSync(
    join(REPO, "packages", "tx402-python", "src", "tx402", "diagnostics.py"),
    "utf8",
  );
  const block = python.slice(python.indexOf("EVENT_NAMES"));
  return new Set(
    [...block.slice(0, block.indexOf(")")).matchAll(/"([a-z]+\.[a-z]+)"/gu)].map(
      (match) => match[1] as string,
    ),
  );
}

describe("U14 — TypeScript exports EVENT_NAMES and it matches what it emits + Python", () => {
  it("exports a runtime EVENT_NAMES tuple of the fourteen request-path names", () => {
    expect(EVENT_NAMES).toHaveLength(14);
    // Exercise the type union so a regression in the `as const` narrowing is caught too.
    const first: Tx402EventName = EVENT_NAMES[0];
    expect(first).toBe("request.started");
  });

  it("EVENT_NAMES equals the set the client actually emits", () => {
    expect(new Set(EVENT_NAMES)).toEqual(emittedEventNames());
  });

  it("EVENT_NAMES equals Python's exported EVENT_NAMES", () => {
    expect(new Set(EVENT_NAMES)).toEqual(pythonEventNames());
  });
});
