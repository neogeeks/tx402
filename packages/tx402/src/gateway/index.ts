/**
 * `tx402/gateway` — the capability gateway (SPEC §12.5): the {@link HttpGatewaySpendStore} client
 * and the reference Node gateway, plus the shared wire protocol and JSON Schema.
 *
 * A subpath export OFF the size-gated core path (ADR-008): `src/index.ts` never imports it, so it
 * adds zero bytes to the `tx402` core measurement, exactly like `tx402/redis` and
 * `tx402/durable-object`. The client holds only a bearer token — never a raw Redis/DO credential —
 * and speaks one wire protocol to any conformant gateway, so it interoperates with the reference
 * gateways here and with a third party's, and is byte-identical to a direct store (it passes the
 * same `checkSpendStore`/`checkDurableSpendStore` suites).
 *
 * The reference **Worker** gateway (which fronts a Durable Object) is `tx402/gateway/worker` — a
 * separate entry because it imports the Workers runtime; this entry stays node-safe.
 *
 * @example
 * ```ts
 * import { httpGatewaySpendStore } from "tx402/gateway";
 *
 * const store = await httpGatewaySpendStore({
 *   baseUrl: process.env.TX402_SPEND_STORE!,       // https://gateway.example
 *   token: process.env.TX402_SPEND_STORE_TOKEN!,   // a data bearer token
 * });
 * const client = createTx402Client({ spendStore: store, ... });
 * ```
 */

// The client.
export {
  HttpGatewaySpendStore,
  httpGatewaySpendStore,
  type GatewayFetch,
  type HttpGatewaySpendStoreOptions,
} from "./client.js";

// The reference Node gateway + its backend-agnostic core.
export { handleGatewayRequest, bearerTokenScope, type GatewayBackend } from "./gateway.js";
export { createGatewayServer, serveGateway, type RunningGateway } from "./node.js";

// The wire protocol + schema (so an operator can build/validate a conformant gateway).
export {
  GATEWAY_PROTOCOL_VERSION,
  GATEWAY_VERSION_HEADER,
  GATEWAY_PATH_PREFIX,
  GATEWAY_DATA_METHODS,
  GATEWAY_ADMIN_METHODS,
  gatewayPlane,
  gatewayMethodPath,
  isGatewayMethod,
  deserializeTx402Error,
  gatewayConditionError,
  type GatewayMethod,
  type GatewayScope,
  type WireError,
  type WireReservationRef,
} from "./wire.js";
export { GATEWAY_WIRE_SCHEMA, GATEWAY_ALL_METHODS } from "./schema.js";
