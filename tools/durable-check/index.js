#!/usr/bin/env node
/**
 * Durable-store conformance runner — the stable root script for the 0.2.0 durable suites.
 *
 *   node tools/durable-check/index.js [redis|do|all]     (default: all)
 *
 * **Why this exists as a script and not a CI job name.** `PLAN-0.2.0.md` §14 requires the new
 * durable/gateway suites to hang off a *stable root script* (`tools/durable-check`,
 * `tools/gateway-golden`) rather than a prose-only CI job, so the same command runs locally and
 * in CI and cannot drift from what the workflow claims to run. This is the S1 **skeleton**: it
 * wires the command, the package.json script, and the CI jobs so they are green from the first
 * commit; the real `checkDurableSpendStore` arms land with their features —
 *
 *   - `redis`  → `SPEC-0.2.0.md` §12.2, session **S7** (`tx402/redis`, `tx402.stores.redis`)
 *   - `do`     → `SPEC-0.2.0.md` §12.3, session **S8** (`tx402/durable-object`, local Workers runtime)
 *   - behind the gateway → §12.5, session **S9** (see `tools/gateway-golden`)
 *
 * The `redis` arm is REAL as of S7a and grew the S7b governance arms. When `TX402_TEST_REDIS_URL`
 * is set (the CI `durable-store` job launches an AOF Redis 7 for it; a local run points it at the
 * O2 instance), it first proves the service answers a raw `PING`, then runs the actual durable
 * conformance suites — `checkDurableSpendStore`/`check_durable_spend_store` across BOTH TypeScript
 * client arms (ioredis + node-redis) and BOTH Python arms (sync + async), now including the
 * governance checks (freeze with the capability-parameterized global arm, pins, administered
 * limits), the persistence-disabled warning, and the raw Redis ACL data/admin split. Two more
 * arms turn on via env, so the same command covers them locally and in CI (§14):
 *
 *   - `TX402_TEST_REDIS_CLUSTER` (comma-separated `host:port` seeds) → the whole harness on a real
 *     3-master Cluster with `atomicGlobalFreeze:false` (the incapable global-freeze arm).
 *   - `TX402_TEST_REDIS_RESTART=1` → the AOF restart-durability arm (`_check_restart`), which spawns
 *     a dedicated instance it restarts; it needs `redis-server` on PATH.
 *
 * With no URL set (the ordinary local run) the redis arm is a no-op and exits 0.
 *
 * The Python arm is best-effort locally: if `uv` is not on PATH it is skipped with a note, so a
 * TypeScript-only checkout still passes; the CI `durable-store` job installs uv, so both arms run.
 *
 * The `do` arm is REAL as of S8: the Durable Object adapter and its harness run in a LOCAL Workers
 * runtime (workerd via `@cloudflare/vitest-pool-workers` ~0.12 — O8), needing no Cloudflare account
 * and no network (O2). `pnpm durable:check do` runs the whole `checkDurableSpendStore` on BOTH
 * topologies — id-per-scope (`atomicGlobalFreeze:false`, the incapable global-freeze arm) and
 * single-coordinator (`atomicGlobalFreeze:true`, the capable arm) — plus the single-plane
 * `checkSpendStore` twin, admin-token denial, fail-closed overload, and a local throughput baseline
 * (a real deployed-coordinator throughput acceptance is S14/S15, SPEC §12.3).
 */

import { spawnSync } from "node:child_process";
import net from "node:net";
import tls from "node:tls";

/**
 * Mask any `user:password@` credential in a DSN before it is printed to a CI log (O28). A DSN with
 * no userinfo is returned unchanged. Every rendering of `TX402_TEST_REDIS_URL` /
 * `TX402_TEST_REDIS_CLUSTER` goes through this — a password Redis / Upstash `rediss://` URL must
 * never appear in the build output.
 */
function redactDsn(url) {
  return String(url).replace(/(^|\/\/)([^/@\s]+)@/u, (_match, prefix) => `${prefix}***@`);
}

/**
 * O8 (PLAN-0.2.0 §13). The repo is on Vitest `^2.1` (2.1.9 installed). The newest
 * `@cloudflare/vitest-pool-workers` line still compatible with Vitest 2.1.x is `0.12.x`
 * (peer `vitest 2.0.x - 3.2.x`, highest patch 0.12.21); `0.13.0` jumps the peer to
 * `vitest ^4.1.0`. Decision: **pin `@cloudflare/vitest-pool-workers@~0.12` and do NOT bump Vitest
 * for 0.2.0.** S8 landed the pin + the exact lockfile patch + the DO vitest project, plus a root
 * `pnpm.overrides` on `@types/node` (wrangler pulls v24 transitively, which would otherwise split
 * Vitest into two peer-variants the pool rejects as "multiple vitest versions").
 */
const DO_POOL_PIN = "@cloudflare/vitest-pool-workers@~0.12 (Vitest ^2.1; no bump — O8)";

/**
 * A credential- and TLS-aware Redis `PING` — no client dependency, just `node:net`/`node:tls`
 * speaking RESP (O28). A `rediss://` URL connects over TLS (verifying the certificate BEFORE any
 * secret is sent, so the password is never exposed to a MITM), and a URL carrying `user:password@`
 * sends `AUTH` before `PING`. This is what lets a password-protected Redis and the documented
 * Upstash `rediss://` endpoint pass preflight — the raw plaintext socket could not. Resolves
 * `{ ok: true }` on `+PONG`, otherwise `{ ok: false, why }` where `why` never contains the URL.
 */
function redisPing(url, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      resolve({ ok: false, why: `not a URL: ${redactDsn(url)}` });
      return;
    }
    const secure = parsed.protocol === "rediss:";
    const port = Number(parsed.port || 6379);
    const host = parsed.hostname || "127.0.0.1";
    const username = parsed.username ? decodeURIComponent(parsed.username) : "";
    const password = parsed.password ? decodeURIComponent(parsed.password) : "";

    const onReady = () => {
      // AUTH first when credentials are present (RESP1 inline is enough for a preflight); then PING.
      if (password) {
        socket.write(
          username ? `AUTH ${username} ${password}\r\n` : `AUTH ${password}\r\n`,
        );
      }
      socket.write("PING\r\n");
    };
    const socket = secure
      ? tls.connect({ host, port, servername: host }, onReady)
      : net.createConnection({ host, port }, onReady);

    let buffer = "";
    let awaitingAuth = Boolean(password);
    const done = (result) => {
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let newline = buffer.indexOf("\r\n");
      while (newline !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 2);
        if (awaitingAuth) {
          awaitingAuth = false;
          if (!line.startsWith("+OK")) {
            done({ ok: false, why: `AUTH rejected: ${JSON.stringify(line)}` });
            return;
          }
        } else {
          done(
            line.startsWith("+PONG")
              ? { ok: true }
              : { ok: false, why: `unexpected reply ${JSON.stringify(line)}` },
          );
          return;
        }
        newline = buffer.indexOf("\r\n");
      }
    });
    socket.on("timeout", () => done({ ok: false, why: `timed out after ${timeoutMs}ms` }));
    socket.on("error", (error) => done({ ok: false, why: error.message }));
  });
}

/** Run a subprocess inheriting stdio + env (so `TX402_TEST_REDIS_URL` reaches the suite). */
function runSuite(label, command, args, options = {}) {
  console.log(`\n▶ ${label}: ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.error) {
    console.error(`FAIL  ${label}: ${result.error.message}`);
    return false;
  }
  return result.status === 0;
}

async function checkRedis() {
  const url = process.env.TX402_TEST_REDIS_URL;
  if (!url) {
    console.log(
      "SKIP  redis durable suite — TX402_TEST_REDIS_URL not set. Point it at a Redis 7.0+ " +
        "instance (O2) to run checkDurableSpendStore across all four adapter arms.",
    );
    return true;
  }
  const result = await redisPing(url);
  if (!result.ok) {
    console.error(`FAIL  Redis at ${redactDsn(url)} did not answer PING: ${result.why}`);
    return false;
  }
  console.log(
    `OK    Redis reachable at ${redactDsn(url)} (PING → PONG). Running the durable suite (§12.2).`,
  );

  // Optional Cluster arm: prove the first seed answers PING so a misconfigured seed fails loudly
  // rather than silently skipping the Cluster coverage.
  const clusterSeeds = (process.env.TX402_TEST_REDIS_CLUSTER ?? "")
    .split(",")
    .map((seed) => seed.trim())
    .filter(Boolean);
  if (clusterSeeds.length > 0) {
    const seed = clusterSeeds[0];
    const clusterResult = await redisPing(`redis://${seed}`);
    if (!clusterResult.ok) {
      console.error(
        `FAIL  Redis Cluster seed ${redactDsn(seed)} did not answer PING: ${clusterResult.why}`,
      );
      return false;
    }
    console.log(
      `OK    Redis Cluster seed ${redactDsn(seed)} reachable — the Cluster arm will run.`,
    );
  } else {
    console.log("NOTE  TX402_TEST_REDIS_CLUSTER unset — the Cluster arm is skipped.");
  }
  if (process.env.TX402_TEST_REDIS_RESTART === "1") {
    console.log(
      "NOTE  TX402_TEST_REDIS_RESTART=1 — the AOF restart arm will spawn its own instance.",
    );
  }

  // TypeScript arms (ioredis + node-redis), run from source by vitest — no build needed.
  const ts = runSuite("TypeScript (ioredis + node-redis)", "pnpm", [
    "-C",
    "packages/tx402",
    "exec",
    "vitest",
    "run",
    "test/redis-store.test.ts",
  ]);
  if (!ts) return false;

  // Python arms (sync + async). Best-effort locally: skip cleanly if `uv` is not installed.
  const uvPresent = spawnSync("uv", ["--version"], { stdio: "ignore" }).error === undefined;
  if (!uvPresent) {
    console.log(
      "SKIP  Python redis arm — `uv` not on PATH. Install uv (or run the CI durable-store job) " +
        "to exercise RedisSpendStore + AsyncRedisSpendStore.",
    );
    return true;
  }
  // `--no-cov`: this focused subset must not be held to the 90% coverage gate (the full suite is).
  return runSuite(
    "Python (sync + async)",
    "uv",
    ["run", "pytest", "tests/test_redis_store.py", "--no-cov", "-q"],
    { cwd: "packages/tx402-python" },
  );
}

function checkDurableObject() {
  // Runs in a LOCAL Workers runtime (workerd) — no Cloudflare account, no network (O2). Vite
  // transforms the source, so no `pnpm build` is needed. The DO vitest project runs the whole
  // durable harness on both topologies + the DO-specific properties (SPEC §12.3/§12.4). The
  // capability gateway over the DO (§12.5) runs as a SEPARATE config so the pool's between-file
  // worker reload cannot invalidate DO instances across the two suites.
  console.log(`\n▶ Durable Object suite (local Workers runtime; pool ${DO_POOL_PIN})`);
  const adapter = runSuite("Durable Object (Workers runtime)", "pnpm", [
    "-C",
    "packages/tx402",
    "exec",
    "vitest",
    "run",
    "--config",
    "vitest.durable-object.config.ts",
  ]);
  if (!adapter) return false;
  console.log(
    "\n▶ Capability gateway over the Durable Object (local Workers runtime, §12.5)",
  );
  return runSuite("Gateway over Durable Object (Workers runtime)", "pnpm", [
    "-C",
    "packages/tx402",
    "exec",
    "vitest",
    "run",
    "--config",
    "vitest.gateway-durable-object.config.ts",
  ]);
}

/**
 * Falsifiable self-test for the O28 hardening — runs offline, no Redis needed. Proves (1) every DSN
 * rendering is credential-free, and (2) `redisPing` actually sends `AUTH` before `PING` when the URL
 * carries credentials (against a mock RESP server that refuses an unauthenticated `PING`), so the
 * new AUTH path is exercised rather than merely written.
 */
async function selftest() {
  const assert = (cond, why) => {
    if (!cond) {
      console.error(`FAIL  durable-check selftest: ${why}`);
      process.exit(1);
    }
  };
  const SECRET = "s3cr3tPASSWORD";

  // (1) DSN redaction — whole-output secret scan.
  const redacted = redactDsn(`rediss://default:${SECRET}@fly-abc.upstash.io:6379`);
  assert(!redacted.includes(SECRET), "redactDsn leaked the password");
  assert(redacted.includes("upstash.io"), "redactDsn dropped the host");
  const bad = await redisPing(`garbage://user:${SECRET}@x`);
  assert(
    !bad.ok && !JSON.stringify(bad).includes(SECRET),
    "redisPing leaked the password in its result on a malformed URL",
  );

  // (2) AUTH-before-PING against a mock server that refuses an unauthenticated PING.
  const server = net.createServer((sock) => {
    let authed = false;
    sock.on("data", (chunk) => {
      for (const line of chunk.toString("utf8").split("\r\n").filter(Boolean)) {
        if (line.startsWith("AUTH ")) {
          authed = line === "AUTH testuser testpass";
          sock.write("+OK\r\n");
        } else if (line === "PING") {
          sock.write(authed ? "+PONG\r\n" : "-NOAUTH Authentication required.\r\n");
        }
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    const withAuth = await redisPing(`redis://testuser:testpass@127.0.0.1:${port}`);
    assert(
      withAuth.ok,
      `a credentialed PING must send AUTH and get PONG: ${JSON.stringify(withAuth)}`,
    );
    const withoutAuth = await redisPing(`redis://127.0.0.1:${port}`);
    assert(
      !withoutAuth.ok,
      "an un-credentialed PING to an AUTH-required server must fail — proving AUTH is what mattered",
    );
  } finally {
    server.close();
  }

  console.log(
    "OK    durable-check selftest green (DSN redaction + AUTH/TLS-aware PING, O28)",
  );
  return true;
}

const mode = (process.argv[2] ?? "all").toLowerCase();
const arms = { redis: checkRedis, do: checkDurableObject, selftest };

let ok = true;
if (mode === "all") {
  for (const run of [checkRedis, checkDurableObject]) ok = (await run()) && ok;
} else if (arms[mode]) {
  ok = await arms[mode]();
} else {
  console.error(`unknown mode "${mode}" (expected: redis | do | all)`);
  process.exit(2);
}

if (!ok) process.exit(1);
console.log("\nOK    durable-check green");
