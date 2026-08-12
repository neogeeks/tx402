/**
 * The test Worker entry for the Durable Object conformance suite. It exports the
 * `Tx402SpendStoreDO` class so the two DO bindings (`SPEND_DO` id-per-scope, `COORDINATOR_DO`
 * single-coordinator) resolve to it, and a trivial default handler so miniflare has an entrypoint.
 * Both bindings are `useSQLite` in the vitest config; the DO reads its admin secret and test-mode
 * flag from the shared Worker env. Never deployed — it exists only for the local Workers runtime.
 */

export { Tx402SpendStoreDO } from "../../src/durable-object/index.js";

export default {
  fetch(): Response {
    return new Response("tx402 Durable Object test worker");
  },
};
