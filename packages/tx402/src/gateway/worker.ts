/**
 * `tx402/gateway/worker` — the reference Cloudflare Worker capability gateway. It is
 * the natural gateway for the Durable Object backend: it fronts {@link Tx402SpendStoreDO} behind the
 * `/v1/{method}` routes, holding the DO admin token (the Worker-env secret `TX402_DO_ADMIN_SECRET`)
 * server-side and exposing only capabilities to callers over a bearer token — the durable data/admin
 * boundary and the way a non-Worker caller (the CLI, Python) reaches a DO.
 *
 * A separate entry from `tx402/gateway` because it imports the Workers runtime (via
 * `tx402/durable-object`); the request handling is the SAME isomorphic {@link handleGatewayRequest}
 * core, so the Worker and Node gateways are byte-identical and the golden pins them both.
 *
 * **Deploy:** bind {@link Tx402SpendStoreDO} (mark it `new_sqlite_classes`), set the secrets
 * `TX402_DO_ADMIN_SECRET` (the admin trust root), `TX402_GATEWAY_DATA_TOKEN`, and
 * `TX402_GATEWAY_ADMIN_TOKEN`, and choose the topology with `TX402_GATEWAY_TOPOLOGY`
 * (`id-per-scope`, the default, → `atomicGlobalFreeze:false`; `single-coordinator` →
 * `atomicGlobalFreeze:true`).
 *
 * @example
 * ```jsonc
 * // wrangler.jsonc
 * { "durable_objects": { "bindings": [{ "name": "SPEND_DO", "class_name": "Tx402SpendStoreDO" }] },
 *   "migrations": [{ "tag": "v1", "new_sqlite_classes": ["Tx402SpendStoreDO"] }] }
 * ```
 * ```ts
 * // worker.ts
 * export { Tx402SpendStoreDO, default } from "tx402/gateway/worker";
 * ```
 */

import type { Tx402DurableObjectEnv } from "../durable-object/index.js";
import {
  DurableObjectSpendStore,
  durableObjectSpendStore,
} from "../durable-object/index.js";
import type { Tx402SpendStoreDOStub } from "../durable-object/index.js";
import { bearerTokenScope, handleGatewayRequest, type GatewayBackend } from "./gateway.js";

export { Tx402SpendStoreDO } from "../durable-object/index.js";

/** The Worker environment the reference gateway reads. */
export interface Tx402GatewayWorkerEnv extends Tx402DurableObjectEnv {
  /** The Durable Object namespace bound to {@link Tx402SpendStoreDO}. */
  readonly SPEND_DO: DurableObjectNamespace;
  /** The data-plane bearer token (opaque; never a DO credential). */
  readonly TX402_GATEWAY_DATA_TOKEN: string;
  /** The admin-plane bearer token (opaque; never a DO credential). */
  readonly TX402_GATEWAY_ADMIN_TOKEN: string;
  /**
   * `single-coordinator` routes every scope to one DO so a `"*"` freeze is atomic
   * (`atomicGlobalFreeze:true`); `id-per-scope` (default) routes each scope to its own DO
   * (`atomicGlobalFreeze:false`, `freeze("*")` → `global-freeze-unsupported`). SPEC §12.3/§5.2.
   */
  readonly TX402_GATEWAY_TOPOLOGY?: string;
}

const COORDINATOR_NAME = "tx402-coordinator";

/**
 * Build the {@link GatewayBackend} for a DO deployment from the Worker env.
 * The admin store carries the DO admin token; the data store carries none, so the DO refuses an
 * admin mutation presented without it — the boundary is the token verified inside the DO, backed by
 * the gateway's own bearer-scope check.
 */
export function durableObjectGatewayBackend(env: Tx402GatewayWorkerEnv): GatewayBackend {
  const coordinator = env.TX402_GATEWAY_TOPOLOGY === "single-coordinator";
  const atomicGlobalFreeze = coordinator;
  const stub = (scope: string): Tx402SpendStoreDOStub =>
    env.SPEND_DO.get(
      env.SPEND_DO.idFromName(coordinator ? COORDINATOR_NAME : scope),
    ) as unknown as Tx402SpendStoreDOStub;
  return {
    dataStore: durableObjectSpendStore({ locate: stub, atomicGlobalFreeze }),
    adminStore: new DurableObjectSpendStore({
      locate: stub,
      atomicGlobalFreeze,
      adminToken: env.TX402_DO_ADMIN_SECRET ?? "",
    }),
    resolveScope: bearerTokenScope({
      dataToken: env.TX402_GATEWAY_DATA_TOKEN,
      adminToken: env.TX402_GATEWAY_ADMIN_TOKEN,
    }),
  };
}

export default {
  fetch(request: Request, env: Tx402GatewayWorkerEnv): Promise<Response> {
    return handleGatewayRequest(request, durableObjectGatewayBackend(env));
  },
};
