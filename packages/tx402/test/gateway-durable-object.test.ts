/**
 * The capability gateway over the Durable Object backend, in a LOCAL Workers runtime (workerd via
 * `@cloudflare/vitest-pool-workers` — SPEC §12.5/§12.3, ADR-023). The reference Worker gateway
 * (`tx402/gateway/worker`) fronts `Tx402SpendStoreDO`; `httpGatewaySpendStore` clients drive the
 * whole `checkDurableSpendStore` through it — proving a DO-behind-the-gateway store is byte-identical
 * to a direct one. Runs via `vitest.durable-object.config.ts` (the node config excludes it).
 *
 * BOTH topologies run behind the gateway, and the `capabilities` method reports each backend's real
 * `atomicGlobalFreeze`, so the harness auto-selects the arm:
 *  - **id-per-scope** (`TX402_GATEWAY_TOPOLOGY` absent) → `atomicGlobalFreeze:false` → the INCAPABLE
 *    global-freeze arm (`freeze("*")` → `global-freeze-unsupported`) runs behind the gateway.
 *  - **single-coordinator** (`single-coordinator`) → `atomicGlobalFreeze:true` → the CAPABLE arm.
 *
 * `reset`/`setBackendClock` are test-only and act on the DO stubs directly (out-of-band) — they are
 * deliberately NOT part of the §12.5 wire method set the gateway serves.
 */

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { ConfigurationError } from "../src/core/errors.js";
import {
  checkDurableSpendStore,
  type DurableSpendStoreHarness,
} from "../src/core/spend-store-contract.js";
import type { Tx402SpendStoreDOStub } from "../src/durable-object/index.js";
import {
  HttpGatewaySpendStore,
  httpGatewaySpendStore,
  type GatewayFetch,
} from "../src/gateway/index.js";
import gatewayWorker, { type Tx402GatewayWorkerEnv } from "../src/gateway/worker.js";

declare module "cloudflare:test" {
  interface ProvidedEnv {
    SPEND_DO: DurableObjectNamespace;
    COORDINATOR_DO: DurableObjectNamespace;
    TX402_DO_ADMIN_SECRET: string;
    TX402_DO_TEST_MODE: string;
  }
}

const DATA_TOKEN = "data-token-abc";
const ADMIN_TOKEN = "admin-token-xyz";
const TIMEOUT = 60_000;
// Must match the worker gateway's coordinator id + the contract harness's scopes.
const COORDINATOR_NAME = "tx402-coordinator";
const CONTRACT_SCOPES = ["merchant.example", "other.example"];

function spendStub(scope: string): Tx402SpendStoreDOStub {
  return env.SPEND_DO.get(
    env.SPEND_DO.idFromName(scope),
  ) as unknown as Tx402SpendStoreDOStub;
}

/** An injected transport that runs each request through the reference Worker gateway with `env`. */
function workerFetch(workerEnv: Tx402GatewayWorkerEnv): GatewayFetch {
  return async (input, init) => {
    const request = new Request(input, {
      method: init.method,
      headers: init.headers,
      body: init.body,
    });
    const response = await gatewayWorker.fetch(request, workerEnv);
    const text = await response.text();
    return { status: response.status, json: () => Promise.resolve(JSON.parse(text)) };
  };
}

function workerEnv(topology: "id-per-scope" | "single-coordinator"): Tx402GatewayWorkerEnv {
  return {
    SPEND_DO: env.SPEND_DO,
    TX402_DO_ADMIN_SECRET: env.TX402_DO_ADMIN_SECRET,
    TX402_DO_TEST_MODE: env.TX402_DO_TEST_MODE,
    TX402_GATEWAY_DATA_TOKEN: DATA_TOKEN,
    TX402_GATEWAY_ADMIN_TOKEN: ADMIN_TOKEN,
    TX402_GATEWAY_TOPOLOGY: topology,
  };
}

/** Build the behind-gateway harness for a topology; reset/clock reach the DO stubs out-of-band. */
async function gatewayHarness(
  topology: "id-per-scope" | "single-coordinator",
): Promise<DurableSpendStoreHarness> {
  const fetch = workerFetch(workerEnv(topology));
  // Learn the backend's real capability once, through the gateway (SPEC §12.5).
  const probe = await httpGatewaySpendStore({
    baseUrl: "http://gw",
    token: DATA_TOKEN,
    fetch,
  });
  const capabilities = probe.capabilities;
  const client = (token: string): HttpGatewaySpendStore =>
    new HttpGatewaySpendStore({ baseUrl: "http://gw", token, capabilities, fetch });
  // The DO stubs the harness resets/clocks: every scope's own DO on id-per-scope, else the coordinator.
  const stubs = (): Tx402SpendStoreDOStub[] =>
    topology === "single-coordinator"
      ? [
          env.SPEND_DO.get(
            env.SPEND_DO.idFromName(COORDINATOR_NAME),
          ) as unknown as Tx402SpendStoreDOStub,
        ]
      : CONTRACT_SCOPES.map(spendStub);
  return {
    connectData: () => client(DATA_TOKEN),
    connectAdmin: () => client(ADMIN_TOKEN),
    connectAdminWithDataCredential: () => client(DATA_TOKEN),
    reset: async () => {
      for (const stub of stubs()) await stub.reset();
    },
    setBackendClock: async (nowEpochMs) => {
      for (const stub of stubs()) await stub.setBackendClock(nowEpochMs);
    },
  };
}

describe("capability gateway over a Durable Object (local Workers runtime, SPEC §12.5)", () => {
  it(
    "reports the id-per-scope capability as incapable through the gateway",
    async () => {
      const probe = await httpGatewaySpendStore({
        baseUrl: "http://gw",
        token: DATA_TOKEN,
        fetch: workerFetch(workerEnv("id-per-scope")),
      });
      expect(probe.capabilities.atomicGlobalFreeze).toBe(false);
    },
    TIMEOUT,
  );

  it(
    "passes the whole durable harness behind the gateway on id-per-scope (incapable global-freeze arm)",
    async () => {
      await checkDurableSpendStore(await gatewayHarness("id-per-scope"));
    },
    TIMEOUT,
  );

  it(
    "passes the whole durable harness behind the gateway on single-coordinator (capable global-freeze arm)",
    async () => {
      await checkDurableSpendStore(await gatewayHarness("single-coordinator"));
    },
    TIMEOUT,
  );

  it(
    "refuses an admin method presented with a data token at the gateway (admin-credential-required)",
    async () => {
      const harness = await gatewayHarness("id-per-scope");
      await harness.reset();
      const dataAsAdmin = harness.connectAdminWithDataCredential();
      let error: unknown;
      try {
        await dataAsAdmin.freeze("merchant.example", 1_800_000_000_000);
      } catch (caught) {
        error = caught;
      }
      expect(error).toBeInstanceOf(ConfigurationError);
      expect((error as ConfigurationError).details).toMatchObject({
        reason: "admin-credential-required",
      });
    },
    TIMEOUT,
  );
});
