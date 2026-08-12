/**
 * `tx402/durable-object` — the reference durable {@link import("../core/ledger.js").SpendStore}
 * over a SQLite-backed Cloudflare Durable Object.
 *
 * A subpath export OFF the size-gated core path: `index.ts` never imports it, so it
 * adds zero bytes to the `tx402` core measurement, exactly like `tx402/redis`. Deploy the
 * {@link Tx402SpendStoreDO} class in a Worker (bind it, mark it `new_sqlite_classes`, set the
 * admin secret), then reach it from Worker code with {@link durableObjectSpendStore} (data plane)
 * or {@link DurableObjectSpendStore} with an admin token (operator plane). Non-Worker callers
 * reach it through the capability gateway.
 *
 * @example
 * ```ts
 * // worker.ts
 * export { Tx402SpendStoreDO } from "tx402/durable-object";
 * export default {
 *   async fetch(request, env) {
 *     const store = durableObjectSpendStore({
 *       locate: (scope) => env.SPEND_DO.get(env.SPEND_DO.idFromName(scope)),
 *     });
 *     // …use `store` as a SpendStore
 *   },
 * };
 * ```
 */

export { Tx402SpendStoreDO } from "./spend-store-do.js";
export type { Tx402DurableObjectEnv } from "./spend-store-do.js";
export { DurableObjectSpendStore, durableObjectSpendStore } from "./store.js";
export type { DurableObjectLocator, DurableObjectSpendStoreOptions } from "./store.js";
export type { Tx402SpendStoreDOStub } from "./protocol.js";
