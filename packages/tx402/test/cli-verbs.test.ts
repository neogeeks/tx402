/**
 * The operator verbs: `freeze`, `unfreeze`, `budget`, `pins`, `rotate-recipient`.
 *
 * Driven in process through the injected `CliIo`, against a reference gateway
 * fronting a real `MemorySpendStore` — so every assertion is about the actual store effect and
 * the actual exit code (ADR-023: tests run the behaviour). The store credential comes from the
 * environment, never a flag; the admin/data split is exercised end to end. The
 * cross-language `--json` shapes are pinned separately by the CLI-json golden.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { parseArgs } from "../src/cli/args.js";
import { EXIT_CODES, UsageError } from "../src/cli/exit-codes.js";
import { run, type CliIo } from "../src/cli/run.js";
import { MemorySpendStore } from "../src/core/ledger.js";
import {
  bearerTokenScope,
  serveGateway,
  type RunningGateway,
} from "../src/gateway/index.js";

const SCOPE = "api.merchant.example";
const NETWORK = "eip155:8453";
const ASSET_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const ASSET_ID = `${NETWORK}/erc20:${ASSET_ADDRESS}`;
const PIN_A = "0x1111111111111111111111111111111111111111";
const PIN_B = "0x2222222222222222222222222222222222222222";

const throwFs = () => {
  throw new Error("no filesystem in this harness");
};

/** The verb `--json` shape, typed at the boundary so field access is not `any`. */
interface VerbJson {
  ok?: boolean;
  scope?: string;
  committedAtomic?: string;
  cumulativeConsumedAtomic?: string;
  limitSource?: string;
  perHourLimitAtomic?: string | null;
  cumulativeLimitAtomic?: string | null;
  availablePerHourAtomic?: string | null;
  availableCumulativeAtomic?: string | null;
  asset?: string;
  recipients?: string[];
  error?: { code: string; message: string; details: Record<string, string> };
}
const parseJson = (text: string): VerbJson => JSON.parse(text) as VerbJson;

let store: MemorySpendStore;
let gateway: RunningGateway;

/** Runs the CLI in process and returns `{ code, out, err }`. Env carries the store config. */
async function cli(argv: string[], env: Record<string, string>) {
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIo = {
    argv,
    env,
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    readFile: throwFs,
  };
  const code = await run(io);
  return { code, out: out.join(""), err: err.join("") };
}

/** The env pointing at the running gateway. `admin` adds the admin bearer token. */
function env(plane: "data" | "admin"): Record<string, string> {
  const base = { TX402_SPEND_STORE: gateway.url, TX402_SPEND_STORE_TOKEN: "data-token" };
  return plane === "admin" ? { ...base, TX402_SPEND_STORE_ADMIN: "admin-token" } : base;
}

/** Reserve+commit `amount` so the scope carries committed (and cumulative) spend. */
async function seedCommitted(amount: string): Promise<void> {
  const now = Date.now();
  const { reservation } = await store.reserve({
    requestId: `t-commit-${amount}`,
    policyScope: SCOPE,
    requestFingerprint: `t-commit-fp-${amount}`,
    assetId: ASSET_ID,
    amountAtomic: amount,
    maxPerHourAtomic: "1000000000",
    nowEpochMs: now,
  });
  await store.commit({
    reservationId: reservation.reservationId,
    policyScope: SCOPE,
    assetId: ASSET_ID,
    committedAtEpochMs: now,
  });
}

beforeEach(async () => {
  store = new MemorySpendStore();
  gateway = await serveGateway({
    dataStore: store,
    adminStore: store,
    resolveScope: bearerTokenScope({ dataToken: "data-token", adminToken: "admin-token" }),
  });
});

afterEach(async () => {
  await gateway.close();
});

describe("verb argument parsing (SPEC §10)", () => {
  it("parses each verb into its typed command", () => {
    expect(parseArgs(["freeze", SCOPE], throwFs)).toMatchObject({
      kind: "freeze",
      options: { target: SCOPE, json: false },
    });
    expect(parseArgs(["unfreeze", "*"], throwFs)).toMatchObject({ kind: "unfreeze" });
    expect(
      parseArgs(["budget", SCOPE, "--network", NETWORK, "--max-per-hour", "5"], throwFs),
    ).toMatchObject({ kind: "budget", options: { network: NETWORK, maxPerHour: "5" } });
    expect(parseArgs(["pins", SCOPE, "--network", NETWORK], throwFs)).toMatchObject({
      kind: "pins",
    });
    expect(
      parseArgs(
        ["rotate-recipient", SCOPE, "--network", NETWORK, "--to", PIN_A, PIN_B],
        throwFs,
      ),
    ).toMatchObject({ kind: "rotate-recipient", options: { to: [PIN_A, PIN_B] } });
  });

  it("rejects malformed verb invocations with a usage error", () => {
    expect(() => parseArgs(["freeze"], throwFs)).toThrow(UsageError);
    expect(() => parseArgs(["budget", SCOPE], throwFs)).toThrow(/--network/u);
    expect(() => parseArgs(["pins", SCOPE], throwFs)).toThrow(/--network/u);
    expect(() =>
      parseArgs(["rotate-recipient", SCOPE, "--network", NETWORK], throwFs),
    ).toThrow(/--to/u);
    expect(() =>
      parseArgs(["rotate-recipient", SCOPE, "--network", NETWORK, "--to"], throwFs),
    ).toThrow(/--to/u);
    expect(() => parseArgs(["freeze", SCOPE, "--network", NETWORK], throwFs)).toThrow(
      /not valid for freeze/u,
    );
    // A `call`-only value flag on a verb is refused.
    expect(() =>
      parseArgs(["budget", SCOPE, "--network", NETWORK, "--max-spend", "1"], throwFs),
    ).toThrow(UsageError);
    expect(() => parseArgs(["frobnicate"], throwFs)).toThrow(/Unknown command/u);
  });
});

describe("freeze / unfreeze (admin, SPEC §10)", () => {
  it("freezes and unfreezes a scope in the store", async () => {
    const froze = await cli(["freeze", SCOPE], env("admin"));
    expect(froze.code).toBe(EXIT_CODES.success);
    expect(await store.isFrozen(SCOPE)).toBe(true);

    const thawed = await cli(["unfreeze", SCOPE], env("admin"));
    expect(thawed.code).toBe(EXIT_CODES.success);
    expect(await store.isFrozen(SCOPE)).toBe(false);
  });

  it("normalizes a URL or bare host, and passes '*' through", async () => {
    await cli(["freeze", "https://API.Merchant.Example/x"], env("admin"));
    expect(await store.isFrozen(SCOPE)).toBe(true);
    await cli(["freeze", "*"], env("admin"));
    expect(await store.isFrozen("*")).toBe(true);
  });

  it("refuses an admin verb run with only a data credential (exit 2)", async () => {
    const result = await cli(["freeze", SCOPE, "--json"], env("data"));
    expect(result.code).toBe(EXIT_CODES.usage);
    const json = parseJson(result.out);
    expect(json.ok).toBe(false);
    expect(json.error?.code).toBe("TX402_CONFIG_INVALID");
    expect(json.error?.details.reason).toBe("admin-credential-required");
    // The refusal is BEFORE the store is touched — nothing was frozen.
    expect(await store.isFrozen(SCOPE)).toBe(false);
  });
});

describe("budget (data, SPEC §10 P1-8b)", () => {
  beforeEach(async () => {
    await seedCommitted("300000");
  });

  it("reports administered caps and derived availability", async () => {
    await store.setBudgetLimits(
      SCOPE,
      ASSET_ID,
      { maxPerHourAtomic: "1000000", maxTotalAtomic: "5000000" },
      Date.now(),
    );
    const result = await cli(
      ["budget", SCOPE, "--network", NETWORK, "--asset", ASSET_ADDRESS, "--json"],
      env("data"),
    );
    const json = parseJson(result.out);
    expect(json.committedAtomic).toBe("300000");
    expect(json.limitSource).toBe("administered");
    expect(json.perHourLimitAtomic).toBe("1000000");
    expect(json.availablePerHourAtomic).toBe("700000");
    expect(json.availableCumulativeAtomic).toBe("4700000");
  });

  it("derives availability from the value-flags when no limit is administered", async () => {
    const result = await cli(
      [
        "budget",
        SCOPE,
        "--network",
        NETWORK,
        "--asset",
        ASSET_ADDRESS,
        "--max-per-hour",
        "2000000",
        "--json",
      ],
      env("data"),
    );
    const json = parseJson(result.out);
    expect(json.limitSource).toBe("value-flags");
    expect(json.perHourLimitAtomic).toBe("2000000");
    expect(json.availablePerHourAtomic).toBe("1700000");
    // No --max-total was given, so the cumulative dimension stays null.
    expect(json.cumulativeLimitAtomic).toBeNull();
    expect(json.availableCumulativeAtomic).toBeNull();
  });

  it("reports null availability with limitSource 'unknown' when nothing caps it", async () => {
    const result = await cli(
      ["budget", SCOPE, "--network", NETWORK, "--asset", ASSET_ADDRESS, "--json"],
      env("data"),
    );
    const json = parseJson(result.out);
    expect(json.limitSource).toBe("unknown");
    expect(json.availablePerHourAtomic).toBeNull();
    expect(json.availableCumulativeAtomic).toBeNull();
    expect(json.cumulativeConsumedAtomic).toBe("300000");
  });

  it("defaults the asset to the network's canonical manifest asset", async () => {
    const result = await cli(
      ["budget", SCOPE, "--network", NETWORK, "--json"],
      env("data"),
    );
    const json = parseJson(result.out);
    expect(json.asset).toBe(ASSET_ID);
  });
});

describe("pins (data) and rotate-recipient (admin, SPEC §6/§10)", () => {
  it("reads the pinned recipients", async () => {
    await store.setRecipientPins(SCOPE, NETWORK, [PIN_A, PIN_B], Date.now());
    const result = await cli(["pins", SCOPE, "--network", NETWORK, "--json"], env("data"));
    expect(parseJson(result.out).recipients).toEqual([PIN_A, PIN_B]);
  });

  it("reports the recipient-policy state on the HUMAN surface too, not only --json (O21/O41c)", async () => {
    await store.setRecipientPins(SCOPE, NETWORK, [PIN_A], Date.now());
    await store.setTofuEnabled(SCOPE, true, Date.now());
    await store.setRecipientAssertionRequired(SCOPE, true, Date.now());
    const result = await cli(["pins", SCOPE, "--network", NETWORK], env("data"));
    expect(result.code).toBe(EXIT_CODES.success);
    // The human table mirrors the --json `tofuEnabled`/`recipientAssertionRequired` fields, so the
    // two surfaces cannot drift (only the JSON was pinned before).
    expect(result.out).toMatch(/tofu enabled\s+true/u);
    expect(result.out).toMatch(/assertion required\s+true/u);
  });

  it("rotates recipients, canonicalizing the new set (SPEC §6.4)", async () => {
    const result = await cli(
      [
        "rotate-recipient",
        SCOPE,
        "--network",
        NETWORK,
        "--to",
        "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa",
        PIN_B,
        "--json",
      ],
      env("admin"),
    );
    expect(result.code).toBe(EXIT_CODES.success);
    // eip155 recipients are lowercased; the store now holds the canonical set.
    expect(await store.getRecipientPins(SCOPE, NETWORK)).toEqual([
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      PIN_B,
    ]);
    expect(parseJson(result.out).recipients).toEqual([
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      PIN_B,
    ]);
  });

  it("warns freeze-before-rotate on an unfrozen gateway scope (§6.7), and not when frozen", async () => {
    const unfrozen = await cli(
      ["rotate-recipient", SCOPE, "--network", NETWORK, "--to", PIN_A],
      env("admin"),
    );
    expect(unfrozen.err).toMatch(/not frozen/u);
    expect(unfrozen.err).toMatch(/freeze the scope before rotating/u);
    // The reader-facing warning must not cite an internal SPEC section (O33).
    expect(unfrozen.err).not.toMatch(/§|SPEC/u);

    await store.freeze(SCOPE, Date.now());
    const frozen = await cli(
      ["rotate-recipient", SCOPE, "--network", NETWORK, "--to", PIN_B],
      env("admin"),
    );
    expect(frozen.err).toBe("");
  });

  it("refuses rotate-recipient with only a data credential (exit 2)", async () => {
    const result = await cli(
      ["rotate-recipient", SCOPE, "--network", NETWORK, "--to", PIN_A, "--json"],
      env("data"),
    );
    expect(result.code).toBe(EXIT_CODES.usage);
    expect(parseJson(result.out).error?.details.reason).toBe("admin-credential-required");
  });
});

describe("store-config resolution (SPEC §9.1)", () => {
  it("refuses a do:// DSN (a DO is not a CLI store — P1-8a)", async () => {
    const result = await cli(["pins", SCOPE, "--network", NETWORK, "--json"], {
      TX402_SPEND_STORE: "do://SPEND_STORE",
      TX402_SPEND_STORE_TOKEN: "data-token",
    });
    expect(result.code).toBe(EXIT_CODES.usage);
    expect(parseJson(result.out).error?.details.reason).toBe(
      "durable-object-not-a-cli-dsn",
    );
  });

  it("refuses an unset store", async () => {
    const result = await cli(["pins", SCOPE, "--network", NETWORK, "--json"], {});
    expect(parseJson(result.out).error?.details.reason).toBe("spend-store-unset");
  });

  it("maps a store outage to exit 7 (transport), not a crash", async () => {
    await gateway.close(); // the backend is now unreachable
    const result = await cli(["pins", SCOPE, "--network", NETWORK], env("data"));
    expect(result.code).toBe(EXIT_CODES.transport);
    // Re-open so afterEach's close() is a no-op-safe double close.
    gateway = await serveGateway({
      dataStore: store,
      adminStore: store,
      resolveScope: bearerTokenScope({
        dataToken: "data-token",
        adminToken: "admin-token",
      }),
    });
  });
});
