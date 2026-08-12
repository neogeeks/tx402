// A reference Node capability gateway fronting Redis, for the Python behind-gateway suite
// (SPEC §12.5). The Python test (`tests/test_gateway_durable.py`) spawns this, reads the JSON
// `{ url }` line it prints on stdout, and drives `check_durable_spend_store` through the Python
// `HttpGatewaySpendStore` against it — proving a Redis-behind-the-gateway store is byte-identical
// to a direct one from the Python client. `reset`/`setBackendClock` are done by the Python test
// against Redis directly (out-of-band); they are not part of the §12.5 wire set.
//
//   TX402_TEST_REDIS_URL=... TX402_GATEWAY_NS=... TX402_GATEWAY_DATA_TOKEN=... \
//   TX402_GATEWAY_ADMIN_TOKEN=...  node test/gateway/serve-redis.mjs
//
// Placed under packages/tx402 so `ioredis` and the built adapters resolve; imports the built dist.

import { Redis } from "ioredis";

import { createGatewayServer, bearerTokenScope } from "../../dist/gateway/index.js";
import { RedisSpendStore } from "../../dist/redis/store.js";

const url = process.env.TX402_TEST_REDIS_URL;
const namespace = process.env.TX402_GATEWAY_NS ?? "tx402-gw-py-redis";
const dataToken = process.env.TX402_GATEWAY_DATA_TOKEN ?? "data-token-abc";
const adminToken = process.env.TX402_GATEWAY_ADMIN_TOKEN ?? "admin-token-xyz";

if (!url) {
  console.error("TX402_TEST_REDIS_URL is required");
  process.exit(2);
}

const client = new Redis(url);
const backend = {
  dataStore: new RedisSpendStore({ client, namespace, admin: false, testClock: true }),
  adminStore: new RedisSpendStore({ client, namespace, admin: true, testClock: true }),
  resolveScope: bearerTokenScope({ dataToken, adminToken }),
};

const server = createGatewayServer(backend);
server.listen(0, "127.0.0.1", () => {
  const { port } = server.address();
  // The one machine-readable handshake line the Python parent waits for.
  process.stdout.write(`${JSON.stringify({ url: `http://127.0.0.1:${port}` })}\n`);
});

const shutdown = () => {
  server.close(() => {
    client.quit().finally(() => process.exit(0));
  });
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
