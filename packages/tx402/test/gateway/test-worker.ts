/**
 * The TEST Worker for the Python behind-gateway DO suite (SPEC §12.5). It hosts the REFERENCE
 * gateway core (`handleGatewayRequest`) — the same one `tx402/gateway/worker` uses — under a
 * topology-prefixed path so ONE served instance exercises BOTH topologies, and adds `/test/*`
 * endpoints for the harness's test-only `reset`/`setBackendClock` (the DO stubs are unreachable
 * from a Python parent, and these ops are deliberately NOT part of the §12.5 wire method set). Never
 * deployed — the counterpart of `test/durable-object/worker.ts`, served locally by `serve-do.mjs`.
 *
 *   POST /{topology}/v1/{method}         → the reference gateway (topology = id-per-scope | single-coordinator)
 *   POST /{topology}/test/reset          → reset every DO the topology's harness touches
 *   POST /{topology}/test/clock?ms=<n>   → pin the backend test clock on those DOs
 */

import {
  DurableObjectSpendStore,
  durableObjectSpendStore,
  Tx402SpendStoreDO,
} from "../../src/durable-object/index.js";
import type { Tx402SpendStoreDOStub } from "../../src/durable-object/index.js";
import {
  bearerTokenScope,
  handleGatewayRequest,
  type GatewayBackend,
} from "../../src/gateway/gateway.js";

export { Tx402SpendStoreDO };

interface Env {
  SPEND_DO: DurableObjectNamespace;
  TX402_DO_ADMIN_SECRET: string;
  TX402_DO_TEST_MODE: string;
  TX402_GATEWAY_DATA_TOKEN: string;
  TX402_GATEWAY_ADMIN_TOKEN: string;
}

type Topology = "id-per-scope" | "single-coordinator";

const COORDINATOR = "tx402-coordinator";
// The scopes the contract harness (spend-store-contract.ts) touches.
const CONTRACT_SCOPES = ["merchant.example", "other.example"];

function stub(env: Env, name: string): Tx402SpendStoreDOStub {
  return env.SPEND_DO.get(
    env.SPEND_DO.idFromName(name),
  ) as unknown as Tx402SpendStoreDOStub;
}

function backend(env: Env, topology: Topology): GatewayBackend {
  const coordinator = topology === "single-coordinator";
  const atomicGlobalFreeze = coordinator;
  const locate = (scope: string): Tx402SpendStoreDOStub =>
    stub(env, coordinator ? COORDINATOR : scope);
  return {
    dataStore: durableObjectSpendStore({ locate, atomicGlobalFreeze }),
    adminStore: new DurableObjectSpendStore({
      locate,
      atomicGlobalFreeze,
      adminToken: env.TX402_DO_ADMIN_SECRET,
    }),
    resolveScope: bearerTokenScope({
      dataToken: env.TX402_GATEWAY_DATA_TOKEN,
      adminToken: env.TX402_GATEWAY_ADMIN_TOKEN,
    }),
  };
}

function harnessStubs(env: Env, topology: Topology): Tx402SpendStoreDOStub[] {
  return topology === "single-coordinator"
    ? [stub(env, COORDINATOR)]
    : CONTRACT_SCOPES.map((scope) => stub(env, scope));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const segments = url.pathname.split("/").filter((segment) => segment.length > 0);
    const topology: Topology =
      segments[0] === "single-coordinator" ? "single-coordinator" : "id-per-scope";
    if (segments[1] === "test") {
      const op = segments[2];
      if (op === "reset") {
        for (const target of harnessStubs(env, topology)) await target.reset();
        return new Response(null, { status: 204 });
      }
      if (op === "clock") {
        const ms = Number(url.searchParams.get("ms"));
        for (const target of harnessStubs(env, topology)) await target.setBackendClock(ms);
        return new Response(null, { status: 204 });
      }
      return new Response("unknown test op", { status: 400 });
    }
    return handleGatewayRequest(request, backend(env, topology));
  },
};
