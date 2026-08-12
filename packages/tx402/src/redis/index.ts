/**
 * `tx402/redis` — the reference durable {@link SpendStore} over Redis 7.0+.
 *
 * A subpath export off the size-gated core path: `src/index.ts` never imports it, so
 * the adapter and its optional `ioredis`/`redis` peers add nothing to the core bundle budget. A
 * caller opts in explicitly:
 *
 * @example
 * ```ts
 * import { Redis } from "ioredis"; // named export: portable everywhere; the default `import Redis` fails TS2351 under nodenext in ESM
 * import { RedisSpendStore } from "tx402/redis";
 *
 * const store = new RedisSpendStore({ client: new Redis(process.env.TX402_SPEND_STORE!) });
 * const client = createTx402Client({ spendStore: store, ... });
 * ```
 *
 * or with `node-redis`:
 *
 * @example
 * ```ts
 * import { createClient } from "redis";
 * import { RedisSpendStore } from "tx402/redis";
 *
 * const redis = createClient({ url: process.env.TX402_SPEND_STORE });
 * await redis.connect();
 * const store = new RedisSpendStore({ client: redis });
 * ```
 */

export {
  RedisSpendStore,
  fromIoredis,
  fromNodeRedis,
  type RedisClient,
  type RedisConnection,
  type RedisSpendStoreOptions,
} from "./store.js";
