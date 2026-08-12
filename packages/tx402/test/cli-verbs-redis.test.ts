/**
 * The operator verbs (SPEC §10) against a LIVE store — both a raw `redis://` DSN AND a gateway
 * URL fronting the same Redis (SPEC §9.1's two topologies), with real data/admin credentials.
 *
 * Skipped unless `TX402_TEST_REDIS_URL` is set (mirrors `redis-store.test.ts` / `tools/durable
 * -check`), so the unit matrix stays infra-free; the `durable-store` CI job runs it. This is the
 * end-to-end proof that the CLI resolves the store from the environment (never a flag), plumbs
 * the data vs admin credential to the right plane, and that each verb actually mutates/reads the
 * durable backend — not just an in-process `MemorySpendStore` (ADR-023: tests run the behaviour).
 */

import { Redis } from "ioredis";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";

import { run, type CliIo } from "../src/cli/run.js";
import {
  bearerTokenScope,
  serveGateway,
  type RunningGateway,
} from "../src/gateway/index.js";
import { RedisSpendStore } from "../src/redis/store.js";

const URL = process.env.TX402_TEST_REDIS_URL;

const NETWORK = "eip155:8453";
const ASSET_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const ASSET_ID = `${NETWORK}/erc20:${ASSET_ADDRESS}`;
const PIN_A = "0x1111111111111111111111111111111111111111";
const PIN_B = "0x2222222222222222222222222222222222222222";
const NEW_PIN = "0x3333333333333333333333333333333333333333";

const throwFs = () => {
  throw new Error("no filesystem in this harness");
};

interface VerbJson {
  scope?: string;
  committedAtomic?: string;
  limitSource?: string;
  availablePerHourAtomic?: string | null;
  recipients?: string[];
  frozen?: boolean;
  error?: { code: string; details: Record<string, string> };
}

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
  return {
    code,
    out: out.join(""),
    err: err.join(""),
    json: () => JSON.parse(out.join("")) as VerbJson,
  };
}

describe.skipIf(!URL)("operator verbs against a live store (SPEC §10, §9.1)", () => {
  // A fresh namespace per test isolates the state so the assertions are deterministic even
  // against a persistent DB.
  let ns: string;
  let scope: string;
  let admin: RedisSpendStore;
  let clients: Redis[];
  let gateway: RunningGateway | undefined;
  let counter = 0;

  const newClient = (): Redis => {
    const client = new Redis(URL!);
    clients.push(client);
    return client;
  };

  beforeEach(async () => {
    counter += 1;
    ns = `tx402-cli-${Date.now()}-${counter}`;
    scope = `merchant-${counter}.example`;
    clients = [];
    admin = new RedisSpendStore({
      client: newClient(),
      namespace: ns,
      admin: true,
    });
    await admin.reset();
  });

  afterEach(async () => {
    if (gateway !== undefined) {
      await gateway.close();
      gateway = undefined;
    }
    await Promise.all(clients.map((client) => client.quit().catch(() => undefined)));
  });

  afterAll(async () => {
    // A best-effort sweep of this suite's namespaces so a persistent DB does not accumulate them.
    const sweep = new Redis(URL!);
    const keys = await sweep.keys("tx402-cli-*");
    if (keys.length > 0) await sweep.del(...keys);
    await sweep.quit();
  });

  /** Seed committed spend + administered caps + an allowlist directly on the durable store. */
  async function seed(): Promise<void> {
    const now = Date.now();
    await admin.setBudgetLimits(scope, ASSET_ID, {
      maxPerHourAtomic: "1000000",
      maxTotalAtomic: "5000000",
    });
    const { reservation } = await admin.reserve({
      requestId: "seed",
      policyScope: scope,
      requestFingerprint: "seed-fp",
      assetId: ASSET_ID,
      amountAtomic: "300000",
      maxPerHourAtomic: "1000000",
      maxTotalAtomic: "5000000",
      nowEpochMs: now,
    });
    await admin.commit({
      reservationId: reservation.reservationId,
      policyScope: scope,
      assetId: ASSET_ID,
      committedAtEpochMs: now,
    });
    await admin.setRecipientPins(scope, NETWORK, [PIN_A, PIN_B]);
  }

  describe("raw redis:// DSN", () => {
    const dataEnv = () => ({
      TX402_SPEND_STORE: URL!,
      TX402_SPEND_STORE_TOKEN: URL!,
      TX402_SPEND_STORE_NAMESPACE: ns,
    });
    const adminEnv = () => ({ ...dataEnv(), TX402_SPEND_STORE_ADMIN: URL! });

    it("runs all five verbs and mutates/reads the live backend", async () => {
      await seed();

      // freeze / unfreeze (admin)
      expect((await cli(["freeze", scope], adminEnv())).code).toBe(0);
      expect(await admin.isFrozen(scope)).toBe(true);
      expect((await cli(["unfreeze", scope], adminEnv())).code).toBe(0);
      expect(await admin.isFrozen(scope)).toBe(false);

      // budget (data) — administered caps + committed spend
      const budget = await cli(
        ["budget", scope, "--network", NETWORK, "--asset", ASSET_ADDRESS, "--json"],
        dataEnv(),
      );
      expect(budget.json().committedAtomic).toBe("300000");
      expect(budget.json().limitSource).toBe("administered");
      expect(budget.json().availablePerHourAtomic).toBe("700000");

      // pins (data)
      const pins = await cli(["pins", scope, "--network", NETWORK, "--json"], dataEnv());
      expect(pins.json().recipients).toEqual([PIN_A, PIN_B]);

      // rotate-recipient (admin) — a raw Redis backend is unified, so NO freeze warning (§6.7)
      const rotate = await cli(
        ["rotate-recipient", scope, "--network", NETWORK, "--to", NEW_PIN, "--json"],
        adminEnv(),
      );
      expect(rotate.code).toBe(0);
      expect(rotate.err).toBe("");
      expect(rotate.json().recipients).toEqual([NEW_PIN]);
      expect(await admin.getRecipientPins(scope, NETWORK)).toEqual([NEW_PIN]);
    });

    it("refuses an admin verb with only the data credential (exit 2)", async () => {
      const result = await cli(["freeze", scope, "--json"], dataEnv());
      expect(result.code).toBe(2);
      expect(result.json().error?.details.reason).toBe("admin-credential-required");
      expect(await admin.isFrozen(scope)).toBe(false);
    });
  });

  describe("gateway URL fronting the same Redis", () => {
    async function startGateway(): Promise<{ url: string }> {
      const dataStore = new RedisSpendStore({
        client: newClient(),
        namespace: ns,
        admin: false,
      });
      const adminStore = new RedisSpendStore({
        client: newClient(),
        namespace: ns,
        admin: true,
      });
      gateway = await serveGateway({
        dataStore,
        adminStore,
        resolveScope: bearerTokenScope({ dataToken: "data-tok", adminToken: "admin-tok" }),
      });
      return { url: gateway.url };
    }

    it("runs the verbs through the gateway with data/admin bearer tokens", async () => {
      await seed();
      const { url } = await startGateway();
      const dataEnv = { TX402_SPEND_STORE: url, TX402_SPEND_STORE_TOKEN: "data-tok" };
      const adminEnv = { ...dataEnv, TX402_SPEND_STORE_ADMIN: "admin-tok" };

      expect((await cli(["freeze", scope], adminEnv)).code).toBe(0);
      expect(await admin.isFrozen(scope)).toBe(true);

      const budget = await cli(
        ["budget", scope, "--network", NETWORK, "--asset", ASSET_ADDRESS, "--json"],
        dataEnv,
      );
      expect(budget.json().limitSource).toBe("administered");
      expect(budget.json().frozen).toBe(true);

      const pins = await cli(["pins", scope, "--network", NETWORK, "--json"], dataEnv);
      expect(pins.json().recipients).toEqual([PIN_A, PIN_B]);

      // An admin verb with a data token is refused server-side (403 → admin-credential-required).
      const denied = await cli(["unfreeze", scope, "--json"], dataEnv);
      expect(denied.code).toBe(2);
      expect(denied.json().error?.details.reason).toBe("admin-credential-required");
    });
  });
});
