/**
 * `RedisSpendStore` against a LIVE Redis (SPEC §12.2/§12.4, ADR-023 — tests that RUN the
 * behaviour). Skipped unless `TX402_TEST_REDIS_URL` is set (mirrors `tools/durable-check`), so a
 * no-Redis checkout still passes; the `durable-store` CI job and the local instance set it.
 *
 * Arms (each gated on the infrastructure it needs):
 *
 *  - **standalone** (`TX402_TEST_REDIS_URL`): both TS clients (ioredis + node-redis) run the whole
 *    contract — the single-plane `checkSpendStore` and the durable `checkDurableSpendStore` with
 *    the S7b governance checks (freeze incl. the capability-parameterized global arm, pins, and
 *    administered limits). `atomicGlobalFreeze` is `true` here, so the capable global-freeze arm
 *    runs. Plus the persistence-disabled warning and the raw Redis ACL data/admin split.
 *  - **cluster** (`TX402_TEST_REDIS_CLUSTER` = comma-separated `host:port` seeds): both clients run
 *    the whole harness against a real 3-master Cluster with `atomicGlobalFreeze:false`, so the
 *    single-slot `{ns:scope}` atom is proven on Cluster and the *incapable* global-freeze arm runs
 *    (`freeze("*")` → `global-freeze-unsupported`).
 *  - **restart** (`TX402_TEST_REDIS_RESTART=1`): a dedicated AOF instance the test starts, drives
 *    the whole harness against, and restarts mid-run to prove `_check_restart` (SPEC §12.4).
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Redis } from "ioredis";
import { createClient } from "redis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  checkDurableSpendStore,
  checkSpendStore,
  type DurableSpendStoreHarness,
} from "../src/core/spend-store-contract.js";
import { RedisSpendStore, type RedisClient } from "../src/redis/store.js";

const URL = process.env.TX402_TEST_REDIS_URL;
const CLUSTER_SEEDS = (process.env.TX402_TEST_REDIS_CLUSTER ?? "")
  .split(",")
  .map((seed) => seed.trim())
  .filter(Boolean);
const RESTART_ENABLED = process.env.TX402_TEST_REDIS_RESTART === "1";

const POOL_SIZE = 24; // ≥ the 20 independent connections the parallel atomicity check needs.
const SHARED_NS = "tx402-durable";

function quit(client: unknown): Promise<unknown> {
  const candidate = client as { quit?: () => Promise<unknown>; disconnect?: () => unknown };
  if (typeof candidate.quit === "function") return Promise.resolve(candidate.quit());
  if (typeof candidate.disconnect === "function") {
    return Promise.resolve(candidate.disconnect());
  }
  return Promise.resolve();
}

// ── standalone: both single-connection clients ───────────────────────────────────────────────

interface Arm {
  readonly name: string;
  readonly open: () => Promise<RedisClient>;
}

const STANDALONE_ARMS: readonly Arm[] = [
  {
    name: "ioredis",
    open: () => Promise.resolve(new Redis(URL!) as unknown as RedisClient),
  },
  {
    name: "node-redis",
    open: async () => {
      const client = createClient({ url: URL! });
      await client.connect();
      return client;
    },
  },
];

describe.skipIf(!URL)("RedisSpendStore (live Redis, SPEC §12.2)", () => {
  for (const arm of STANDALONE_ARMS) {
    describe(arm.name, () => {
      const pool: RedisClient[] = [];

      beforeAll(async () => {
        for (let index = 0; index < POOL_SIZE; index += 1) pool.push(await arm.open());
        await new RedisSpendStore({ client: pool[0]!, namespace: SHARED_NS }).reset();
        // Pre-clean the single-plane contract namespaces so a re-run against a persistent DB is
        // clean (each checkSpendStore factory call reuses `contract-<arm>-<n>`, and the pinned test
        // clock keeps its records from expiring). CI's DB is already fresh, so this is a no-op there.
        for (let index = 0; index < 16; index += 1) {
          await new RedisSpendStore({
            client: pool[0]!,
            namespace: `contract-${arm.name}-${index}`,
          }).reset();
        }
      });

      afterAll(async () => {
        await Promise.all(pool.map((client) => quit(client).catch(() => undefined)));
        pool.length = 0;
      });

      it("passes the single-plane contract twin (checkSpendStore)", async () => {
        let counter = 0;
        await checkSpendStore(
          () =>
            new RedisSpendStore({
              client: pool[0]!,
              namespace: `contract-${arm.name}-${counter++}`,
              testClock: true,
            }),
        );
      });

      it("passes the durable harness incl. governance (checkDurableSpendStore)", async () => {
        let round = 0;
        const data = (): RedisSpendStore =>
          new RedisSpendStore({
            client: pool[round++ % pool.length]!,
            namespace: SHARED_NS,
            testClock: true,
          });
        const control = (admin: boolean): RedisSpendStore =>
          new RedisSpendStore({
            client: pool[0]!,
            namespace: SHARED_NS,
            admin,
            testClock: true,
          });
        const harness: DurableSpendStoreHarness = {
          connectData: data,
          connectAdmin: () => control(true),
          connectAdminWithDataCredential: () => control(false),
          reset: () => control(false).reset(),
          setBackendClock: (nowEpochMs) => control(false).setBackendClock(nowEpochMs),
        };
        await checkDurableSpendStore(harness);
      });

      it("reports the persistence-disabled warning only when AOF is off (§12.2)", async () => {
        // Exercise the adapter's own configGet across whichever client this arm uses.
        const store = new RedisSpendStore({ client: pool[0]!, namespace: "tx402-persist" });
        // The CI/local instance runs with AOF on, so no warning is due.
        expect(await store.warnIfPersistenceDisabled()).toBeNull();
        // Toggle AOF off at runtime via a client-agnostic side connection, then restore.
        const toggle = new Redis(URL!);
        try {
          await toggle.call("CONFIG", "SET", "appendonly", "no");
          const warning = await store.warnIfPersistenceDisabled();
          expect(warning).toContain("persistence is disabled");
          expect(warning).toContain("appendonly");
          await toggle.call("CONFIG", "SET", "appendonly", "yes");
          expect(await store.warnIfPersistenceDisabled()).toBeNull();
        } finally {
          await toggle.call("CONFIG", "SET", "appendonly", "yes").catch(() => undefined);
          await quit(toggle).catch(() => undefined);
        }
      });
    });
  }

  // ── raw Redis ACL data/admin-state separation (SPEC §9.1/§12.2) ────────────────────────────
  //
  // The EVAL-path boundary (S7a uses EVAL/EVALSHA, not FUNCTION — O14): a data user needs +eval to
  // run reserve/commit, so the SPEC's `+fcall|<name>` per-function ACL does not apply. Admin-STATE
  // integrity is instead a KEY-PATTERN ACL — the data user gets RW on the data keys and READ-ONLY
  // on the admin-state keys — and it holds even under +eval because each `redis.call` inside a
  // script is ACL-checked (a crafted EVAL that writes a frozen key is denied). The one honest gap:
  // `{ns:scope}:pins:<network>` is written by BOTH admin `setRecipientPins` AND the in-reserve TOFU
  // claim, so it must be data-writable — the durable boundary is the gateway (§9.1, S9). Patterns
  // use the CONCRETE scope, not a `{ns:*}` wildcard-inside-braces (which mis-matches on some Redis
  // builds); ACL DRYRUN verifies the split.
  describe("raw Redis ACL data/admin separation (§9.1/§12.2)", () => {
    const NS = "tx402-acl";
    const SCOPE = "merchant.example";
    const TAG = `{${NS}:${SCOPE}}`;
    const ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
    const FINGERPRINT = `sha256:${"0".repeat(64)}`;
    const NOW = 1_800_000_000_000;
    let root: Redis;

    const dataPatterns = [
      `%RW~${TAG}`,
      `%RW~${TAG}:res:*`,
      `%RW~${TAG}:cmt:*`,
      `%RW~${TAG}:*:total`,
      `%RW~${TAG}:*:exposed`,
      `%RW~${TAG}:pins:*`,
      `%R~${TAG}:frozen`,
      `%R~${TAG}:*:limits`,
      `%R~${TAG}:tofu-enabled`,
      `%R~${TAG}:recipient-required`,
      `%R~{${NS}}:global-frozen`,
    ];

    beforeAll(async () => {
      root = new Redis(URL!);
      for (const user of ["tx402data", "tx402admin"]) {
        await root.call("ACL", "DELUSER", user).catch(() => undefined);
      }
      // The reserve atom reads backend TIME inside the script, so the data user needs +time; the
      // admin-STATE keys are read-only to it; -@dangerous drops KEYS/FLUSH/DEBUG/INFO.
      await root.call(
        "ACL",
        "SETUSER",
        "tx402data",
        "on",
        ">datapass",
        "+@read",
        "+@write",
        "-@dangerous",
        "+eval",
        "+evalsha",
        "+time",
        "+select", // so the data user can reach a non-zero test DB (URL may carry /15)
        ...dataPatterns,
      );
      await root.call(
        "ACL",
        "SETUSER",
        "tx402admin",
        "on",
        ">adminpass",
        "+@all",
        "~*",
        "&*",
      );
      for (const key of await root.keys(`{${NS}*`)) await root.del(key);
    });

    afterAll(async () => {
      for (const user of ["tx402data", "tx402admin"]) {
        await root.call("ACL", "DELUSER", user).catch(() => undefined);
      }
      for (const key of await root.keys(`{${NS}*`)) await root.del(key);
      await quit(root).catch(() => undefined);
    });

    it("ACL DRYRUN denies admin-state writes, allows reads + the pins gap", async () => {
      const dryrun = async (...command: string[]): Promise<string> =>
        String(await root.call("ACL", "DRYRUN", "tx402data", ...command));
      // Denied: a data user cannot write frozen / limits / tofu-enabled / recipient-required.
      for (const command of [
        ["SET", `${TAG}:frozen`, "1"],
        ["HSET", `${TAG}:${ASSET}:limits`, "maxPerHourAtomic", "1"],
        ["SET", `${TAG}:tofu-enabled`, "1"],
        ["SET", `${TAG}:recipient-required`, "1"],
      ]) {
        expect(await dryrun(...command)).not.toBe("OK");
      }
      // Allowed: reads of the admin-state keys, and writes to the data keys.
      expect(await dryrun("GET", `${TAG}:frozen`)).toBe("OK");
      expect(await dryrun("HSET", `${TAG}:res:${ASSET}:id`, "state", "reserved")).toBe(
        "OK",
      );
      // The honest gap: the pins key IS data-writable (the in-reserve TOFU claim needs it).
      expect(await dryrun("HSET", `${TAG}:pins:eip155:8453`, "recipients", "0x0")).toBe(
        "OK",
      );
    });

    it("the data credential runs reserve/commit but a crafted EVAL cannot write admin state", async () => {
      // Same DB as `root` (the URL's), so the reserve's keys land where cleanup runs.
      const dataClient = new Redis(URL!, {
        username: "tx402data",
        password: "datapass",
        enableReadyCheck: false,
        maxRetriesPerRequest: 2,
      });
      const adminClient = new Redis(URL!, {
        username: "tx402admin",
        password: "adminpass",
        enableReadyCheck: false,
        maxRetriesPerRequest: 2,
      });
      try {
        const data = new RedisSpendStore({
          client: dataClient,
          namespace: NS,
          admin: false,
        });
        const admin = new RedisSpendStore({
          client: adminClient,
          namespace: NS,
          admin: true,
        });
        // The full EVAL data path works under the restricted credential.
        const reserved = await data.reserve({
          reservationId: "acl-1",
          requestId: "acl-1",
          policyScope: SCOPE,
          requestFingerprint: FINGERPRINT,
          assetId: ASSET,
          amountAtomic: "7",
          maxPerHourAtomic: "100",
          nowEpochMs: NOW,
        });
        expect(reserved.reservation.state).toBe("reserved");
        const entry = await data.commit({
          reservationId: "acl-1",
          policyScope: SCOPE,
          assetId: ASSET,
          committedAtEpochMs: NOW,
        });
        expect(entry.amountAtomic).toBe("7");

        // The load-bearing point: +eval does NOT let the data user write admin state — the inner
        // redis.call is ACL-checked, so a hand-crafted script targeting a frozen key is denied.
        // Assert the SECURITY PROPERTY (rejected + the key stays absent), not the error wording,
        // which varies across Redis versions and clients.
        let craftedRejected = false;
        try {
          await dataClient.eval(
            "return redis.call('SET', KEYS[1], '1')",
            1,
            `${TAG}:frozen`,
          );
        } catch {
          craftedRejected = true;
        }
        expect(craftedRejected).toBe(true);
        expect(await root.exists(`${TAG}:frozen`)).toBe(0);
        // The app-level split still holds: the data-plane store refuses admin ops before Redis.
        await expect(data.freeze(SCOPE)).rejects.toMatchObject({
          details: { reason: "admin-credential-required" },
        });
        // The admin credential performs admin ops.
        await admin.freeze(SCOPE);
        expect(await data.isFrozen(SCOPE)).toBe(true);
        await admin.unfreeze(SCOPE);
      } finally {
        await Promise.all(
          [quit(dataClient), quit(adminClient)].map((p) => p.catch(() => undefined)),
        );
      }
    });
  });
});

// ── cluster: atomicGlobalFreeze:false, on a real 3-master Cluster ─────────────────────────────
//
// The Cluster arm runs the WHOLE durable harness over ioredis, proving the `{ns:scope}` atom is
// single-slot on a real Cluster (every key an atom touches shares the scope's hash tag) and the
// INCAPABLE global-freeze arm — `freeze("*")` → `global-freeze-unsupported`, because the
// `{ns}:global-frozen` key hashes to a foreign slot and the reserve atom must not read it (§5.2/
// §12.2). It is ioredis-only: node-redis v4's Cluster client does not reliably follow a MOVED for
// an `EVAL`, so node-redis is exercised in full on the standalone arm above rather than flakily
// here; ioredis carries the Cluster proof.

const CLUSTER_NS = "tx402-cluster";

describe.skipIf(CLUSTER_SEEDS.length === 0)(
  "RedisSpendStore (Redis Cluster, atomicGlobalFreeze:false, SPEC §5.2/§12.2)",
  () => {
    let cluster: InstanceType<typeof Redis.Cluster>;

    beforeAll(async () => {
      const nodes = CLUSTER_SEEDS.map((seed) => {
        const [host, port] = seed.split(":");
        return { host: host!, port: Number(port) };
      });
      cluster = new Redis.Cluster(nodes);
      await new Promise<void>((resolve, reject) => {
        cluster.once("ready", resolve);
        cluster.once("error", reject);
      });
    });
    afterAll(async () => {
      await quit(cluster).catch(() => undefined);
    });

    it("runs the whole durable harness single-slot with the incapable global-freeze arm (ioredis)", async () => {
      const store = (admin: boolean): RedisSpendStore =>
        new RedisSpendStore({
          client: cluster,
          namespace: CLUSTER_NS,
          admin,
          atomicGlobalFreeze: false, // the {ns}:global-frozen key hashes to a foreign slot.
          testClock: true,
        });
      const harness: DurableSpendStoreHarness = {
        connectData: () => store(false),
        connectAdmin: () => store(true),
        connectAdminWithDataCredential: () => store(false),
        // The store's KEYS-based reset is single-node; on Cluster flush every master instead.
        reset: async () => {
          await Promise.all(cluster.nodes("master").map((node) => node.flushall()));
        },
        setBackendClock: (nowEpochMs) => store(false).setBackendClock(nowEpochMs),
      };
      await checkDurableSpendStore(harness);
    });
  },
);

// ── restart: a dedicated AOF instance the test owns and restarts (SPEC §12.4) ─────────────────

const RESTART_PORT = 6399;

function rawPing(port: number, timeoutMs = 500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    let buffer = "";
    const done = (ok: boolean): void => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => socket.write("PING\r\n"));
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (buffer.includes("\r\n")) done(buffer.startsWith("+PONG"));
    });
    socket.on("timeout", () => done(false));
    socket.on("error", () => done(false));
  });
}

async function waitFor(predicate: () => Promise<boolean>, tries = 60): Promise<boolean> {
  for (let attempt = 0; attempt < tries; attempt += 1) {
    if (await predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return false;
}

function redisServerAvailable(): boolean {
  return spawnSync("redis-server", ["--version"], { stdio: "ignore" }).status === 0;
}

class DedicatedRedis {
  readonly #dir: string;
  constructor(readonly port: number) {
    this.#dir = mkdtempSync(join(tmpdir(), "tx402-restart-"));
  }
  #launch(): void {
    // AOF on + RDB off so a survivor is proven durable via the append-only file, not a snapshot.
    spawnSync("redis-server", [
      "--port",
      String(this.port),
      "--dir",
      this.#dir,
      "--appendonly",
      "yes",
      "--save",
      "",
      "--daemonize",
      "yes",
      "--pidfile",
      join(this.#dir, "redis.pid"),
    ]);
  }
  async start(): Promise<boolean> {
    this.#launch();
    return waitFor(() => rawPing(this.port));
  }
  async restart(): Promise<void> {
    spawnSync("redis-cli", ["-p", String(this.port), "shutdown", "nosave"], {
      stdio: "ignore",
    });
    await waitFor(async () => !(await rawPing(this.port)));
    this.#launch();
    await waitFor(() => rawPing(this.port));
  }
  async stop(): Promise<void> {
    spawnSync("redis-cli", ["-p", String(this.port), "shutdown", "nosave"], {
      stdio: "ignore",
    });
    await waitFor(async () => !(await rawPing(this.port)));
    rmSync(this.#dir, { recursive: true, force: true });
  }
}

describe.skipIf(!RESTART_ENABLED || !redisServerAvailable())(
  "RedisSpendStore (AOF restart durability, SPEC §12.4)",
  () => {
    const server = new DedicatedRedis(RESTART_PORT);
    const RESTART_NS = "tx402-restart";
    const pool: Redis[] = [];

    beforeAll(async () => {
      const up = await server.start();
      if (!up) throw new Error("dedicated Redis did not come up for the restart arm");
      for (let index = 0; index < POOL_SIZE; index += 1) {
        pool.push(new Redis({ port: RESTART_PORT, maxRetriesPerRequest: null }));
      }
      await new RedisSpendStore({ client: pool[0]!, namespace: RESTART_NS }).reset();
    }, 30_000);

    afterAll(async () => {
      await Promise.all(pool.map((client) => quit(client).catch(() => undefined)));
      pool.length = 0;
      await server.stop();
    }, 30_000);

    it("survives a server restart with AOF (checkDurableSpendStore incl. _check_restart)", async () => {
      let round = 0;
      const control = (admin: boolean): RedisSpendStore =>
        new RedisSpendStore({
          client: pool[0]!,
          namespace: RESTART_NS,
          admin,
          testClock: true,
        });
      const harness: DurableSpendStoreHarness = {
        connectData: () =>
          new RedisSpendStore({
            client: pool[round++ % pool.length]!,
            namespace: RESTART_NS,
            testClock: true,
          }),
        connectAdmin: () => control(true),
        connectAdminWithDataCredential: () => control(false),
        reset: () => control(false).reset(),
        setBackendClock: (nowEpochMs) => control(false).setBackendClock(nowEpochMs),
        restart: () => server.restart(),
      };
      await checkDurableSpendStore(harness);
    }, 60_000);
  },
);

// ── O26: setBudgetLimits atomicity — a failed replacement must not lose the prior cap ──────────
describe.skipIf(!URL)(
  "O26 — setBudgetLimits is one atom (a failed write preserves the cap)",
  () => {
    const SCOPE = "o26.example";
    const ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
    const NS = "tx402-o26";

    it("a setBudgetLimits whose write fails leaves the prior administered cap intact", async () => {
      const client = new Redis(URL!);
      try {
        const admin = new RedisSpendStore({ client, admin: true, namespace: NS });
        await admin.setBudgetLimits(SCOPE, ASSET, { maxPerHourAtomic: "100" });
        expect((await admin.getBudgetLimits(SCOPE, ASSET)).maxPerHourAtomic).toBe("100");

        // A transport that fails the limits WRITE. The atom runs as ONE `evalsha` (or `eval` on a
        // NOSCRIPT); the pre-fix code ran `del` THEN `hset`. Failing `evalsha`/`eval`/`hset` makes the
        // write fail either way — but only the atom leaves the prior cap intact; `del`-then-`hset`
        // deleted the cap before `hset` threw, so it was permanently lost (O26).
        const boom = (): never => {
          throw new Error("injected: limits write failed");
        };
        const failing = new Proxy(client, {
          get(target, prop, receiver): unknown {
            if (prop === "evalsha" || prop === "eval" || prop === "hset") return boom;
            const value: unknown = Reflect.get(target, prop, receiver);
            return typeof value === "function"
              ? (value as (...args: unknown[]) => unknown).bind(target)
              : value;
          },
        });
        const failingAdmin = new RedisSpendStore({
          client: failing,
          admin: true,
          namespace: NS,
        });
        await expect(
          failingAdmin.setBudgetLimits(SCOPE, ASSET, { maxPerHourAtomic: "50" }),
        ).rejects.toThrow();

        // The prior cap survived — the replacement is one atom, so a failure rolled back / never ran.
        expect((await admin.getBudgetLimits(SCOPE, ASSET)).maxPerHourAtomic).toBe("100");
      } finally {
        await quit(client);
      }
    });
  },
);
