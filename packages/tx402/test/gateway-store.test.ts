/**
 * The capability gateway (SPEC §12.5, ADR-023 — tests that RUN the behaviour).
 *
 *  - **wire contract** (always): the whole method set + the error map exercised in-process against
 *    a `MemorySpendStore`-backed reference gateway (`handleGatewayRequest`) through an injected
 *    transport — every method round-trips, a domain refusal (frozen / over-cap) returns at HTTP 200
 *    as the exact typed error, and the `401`/`403`/`426` gateway conditions map to their existing
 *    taxonomy codes. No Redis, no Workers runtime.
 *  - **behind the Node gateway, live Redis** (`TX402_TEST_REDIS_URL`): the whole
 *    `checkDurableSpendStore` runs over a REAL HTTP reference gateway (`serveGateway`) fronting a
 *    `RedisSpendStore`, driven by `httpGatewaySpendStore` clients — proving a gateway-backed store
 *    is byte-identical to a direct one. `atomicGlobalFreeze` is `true` (single-instance Redis), so
 *    the capable global-freeze arm runs behind the gateway; the incapable arm runs behind the DO
 *    gateway (`gateway-durable-object.test.ts`). `reset`/`setBackendClock` are test-only and act on
 *    the backend directly (out-of-band) — they are deliberately NOT in the §12.5 wire method set.
 */

import { Redis } from "ioredis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  BudgetExceededError,
  ConfigurationError,
  SpendScopeFrozenError,
} from "../src/core/errors.js";
import { MemorySpendStore } from "../src/core/ledger.js";
import {
  checkDurableSpendStore,
  type DurableSpendStoreHarness,
} from "../src/core/spend-store-contract.js";
import {
  HttpGatewaySpendStore,
  httpGatewaySpendStore,
  bearerTokenScope,
  handleGatewayRequest,
  serveGateway,
  type GatewayBackend,
  type GatewayFetch,
} from "../src/gateway/index.js";
import { GATEWAY_VERSION_HEADER } from "../src/gateway/wire.js";
import { RedisSpendStore, type RedisClient } from "../src/redis/store.js";

const ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const FP = `sha256:${"0".repeat(64)}`;
const NOW = 1_800_000_000_000;
const SCOPE = "merchant.example";
const DATA_TOKEN = "data-token-abc";
const ADMIN_TOKEN = "admin-token-xyz";
const CAPS = Object.freeze({ atomicGlobalFreeze: true });

/** An in-process transport: run the client's request straight through the gateway core, no socket. */
function inProcessFetch(backend: GatewayBackend): GatewayFetch {
  return async (input, init) => {
    const request = new Request(input, {
      method: init.method,
      headers: init.headers,
      body: init.body,
    });
    const response = await handleGatewayRequest(request, backend);
    const text = await response.text();
    return { status: response.status, json: () => Promise.resolve(JSON.parse(text)) };
  };
}

describe("gateway wire contract (in-process, MemorySpendStore)", () => {
  const store = new MemorySpendStore();
  const backend: GatewayBackend = {
    dataStore: store,
    adminStore: store,
    resolveScope: bearerTokenScope({ dataToken: DATA_TOKEN, adminToken: ADMIN_TOKEN }),
  };
  const fetch = inProcessFetch(backend);
  const data = new HttpGatewaySpendStore({
    baseUrl: "http://gw",
    token: DATA_TOKEN,
    capabilities: CAPS,
    fetch,
  });
  const admin = new HttpGatewaySpendStore({
    baseUrl: "http://gw",
    token: ADMIN_TOKEN,
    capabilities: CAPS,
    fetch,
  });

  it("fetches capabilities once at construction (data-plane method)", async () => {
    const built = await httpGatewaySpendStore({
      baseUrl: "http://gw",
      token: DATA_TOKEN,
      fetch,
    });
    expect(built.capabilities.atomicGlobalFreeze).toBe(true);
  });

  it("round-trips the reservation lifecycle: reserve → expose → listExposed → commit", async () => {
    const result = await data.reserve({
      reservationId: "wire-1",
      requestId: "wire-1",
      policyScope: SCOPE,
      requestFingerprint: FP,
      assetId: ASSET,
      amountAtomic: "400",
      maxPerHourAtomic: "1000000",
      nowEpochMs: NOW,
    });
    expect(result.reservation.state).toBe("reserved");
    expect(result.reservation.amountAtomic).toBe("400");
    expect(result.recipientPinEstablished).toBe(false);

    const exposed = await data.expose(
      { reservationId: "wire-1", policyScope: SCOPE, assetId: ASSET },
      NOW + 5,
    );
    expect(exposed.state).toBe("exposed");
    const listed = await data.listExposed({
      policyScope: SCOPE,
      assetId: ASSET,
      nowEpochMs: NOW + 5,
    });
    expect(listed.map((r) => r.reservationId)).toEqual(["wire-1"]);

    const entry = await data.commit({
      reservationId: "wire-1",
      policyScope: SCOPE,
      assetId: ASSET,
      committedAtEpochMs: NOW + 10,
      settlementId: "0xsettle",
    });
    expect(entry.amountAtomic).toBe("400");
    expect(entry.settlementId).toBe("0xsettle");

    const state = await data.getBudgetState({
      policyScope: SCOPE,
      assetId: ASSET,
      nowEpochMs: NOW + 10,
    });
    expect(state.committedAtomic).toBe("400");
    expect(state.storeKind).toBe("memory");
  });

  it("returns a domain refusal (over-cap) at HTTP 200 as the exact typed error", async () => {
    await data.reserve({
      reservationId: "cap-1",
      requestId: "cap-1",
      policyScope: "cap.example",
      requestFingerprint: FP,
      assetId: ASSET,
      amountAtomic: "800",
      maxPerHourAtomic: "1000",
      nowEpochMs: NOW,
    });
    await expect(
      data.reserve({
        reservationId: "cap-2",
        requestId: "cap-2",
        policyScope: "cap.example",
        requestFingerprint: FP,
        assetId: ASSET,
        amountAtomic: "300",
        maxPerHourAtomic: "1000",
        nowEpochMs: NOW,
      }),
    ).rejects.toBeInstanceOf(BudgetExceededError);
  });

  it("round-trips the admin plane: freeze → SpendScopeFrozenError, limits, pins, resolve", async () => {
    await admin.freeze("frozen.example", NOW);
    expect(await data.isFrozen("frozen.example")).toBe(true);
    let frozen: unknown;
    try {
      await data.reserve({
        reservationId: "fz-1",
        requestId: "fz-1",
        policyScope: "frozen.example",
        requestFingerprint: FP,
        assetId: ASSET,
        amountAtomic: "1",
        maxPerHourAtomic: "1000",
        nowEpochMs: NOW,
      });
    } catch (error) {
      frozen = error;
    }
    expect(frozen).toBeInstanceOf(SpendScopeFrozenError);
    expect((frozen as SpendScopeFrozenError).details.frozenScope).toBe("frozen.example");
    await admin.unfreeze("frozen.example", NOW);

    await admin.setBudgetLimits("lim.example", ASSET, { maxPerHourAtomic: "500" }, NOW);
    expect((await admin.getBudgetLimits("lim.example", ASSET)).maxPerHourAtomic).toBe(
      "500",
    );

    await admin.setRecipientPins("pin.example", "eip155:8453", ["0xabc"], NOW);
    expect(await data.getRecipientPins("pin.example", "eip155:8453")).toEqual(["0xabc"]);
    await admin.setTofuEnabled("pin.example", true, NOW);
    expect((await data.getRecipientPolicy("pin.example")).tofuEnabled).toBe(true);

    // resolveExposed on an exposed reservation.
    await data.reserve({
      reservationId: "rx-1",
      requestId: "rx-1",
      policyScope: "rx.example",
      requestFingerprint: FP,
      assetId: ASSET,
      amountAtomic: "50",
      maxPerHourAtomic: "1000",
      nowEpochMs: NOW,
    });
    await data.expose(
      { reservationId: "rx-1", policyScope: "rx.example", assetId: ASSET },
      NOW + 1,
    );
    await admin.resolveExposed(
      { reservationId: "rx-1", policyScope: "rx.example", assetId: ASSET },
      "committed",
      NOW + 2,
    );
    await admin.resetCumulative("rx.example", ASSET, NOW + 3);
  });

  it("maps 401 (unknown token) → gateway-unauthorized ConfigurationError", async () => {
    const stranger = new HttpGatewaySpendStore({
      baseUrl: "http://gw",
      token: "nope",
      capabilities: CAPS,
      fetch,
    });
    let error: unknown;
    try {
      await stranger.isFrozen(SCOPE);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(ConfigurationError);
    expect((error as ConfigurationError).details).toMatchObject({
      configPath: "gateway.auth",
      reason: "gateway-unauthorized",
    });
  });

  it("maps 403 (data token on an admin method) → admin-credential-required ConfigurationError", async () => {
    let error: unknown;
    try {
      await data.freeze(SCOPE, NOW);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(ConfigurationError);
    expect((error as ConfigurationError).details).toMatchObject({
      configPath: "gateway.auth",
      reason: "admin-credential-required",
    });
  });

  it("maps 426 (unknown protocol major) → gateway-version-unsupported ConfigurationError", async () => {
    // A transport that stamps a future version header, so the gateway rejects the major.
    const badVersionFetch: GatewayFetch = (input, init) =>
      fetch(input, {
        ...init,
        headers: { ...init.headers, [GATEWAY_VERSION_HEADER]: "2" },
      });
    const client = new HttpGatewaySpendStore({
      baseUrl: "http://gw",
      token: DATA_TOKEN,
      capabilities: CAPS,
      fetch: badVersionFetch,
    });
    let error: unknown;
    try {
      await client.isFrozen(SCOPE);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(ConfigurationError);
    expect((error as ConfigurationError).details).toMatchObject({
      configPath: "gateway.version",
      reason: "gateway-version-unsupported",
    });
  });
});

// ── behind the Node gateway, over live Redis (real HTTP) ───────────────────────────────────────

const URL = process.env.TX402_TEST_REDIS_URL;
const GATEWAY_NS = "tx402-gateway-redis";

describe.skipIf(!URL)(
  "checkDurableSpendStore behind the Node gateway (live Redis, §12.5)",
  () => {
    let client: RedisClient;
    let gateway: Awaited<ReturnType<typeof serveGateway>>;
    let control: RedisSpendStore;

    beforeAll(async () => {
      client = new Redis(URL!);
      control = new RedisSpendStore({
        client,
        namespace: GATEWAY_NS,
        admin: true,
        testClock: true,
      });
      const backend: GatewayBackend = {
        dataStore: new RedisSpendStore({
          client,
          namespace: GATEWAY_NS,
          admin: false,
          testClock: true,
        }),
        adminStore: new RedisSpendStore({
          client,
          namespace: GATEWAY_NS,
          admin: true,
          testClock: true,
        }),
        resolveScope: bearerTokenScope({ dataToken: DATA_TOKEN, adminToken: ADMIN_TOKEN }),
      };
      gateway = await serveGateway(backend);
      await control.reset();
    });

    afterAll(async () => {
      await gateway.close();
      const maybeQuit = client as unknown as { quit?: () => Promise<unknown> };
      await maybeQuit.quit?.().catch(() => undefined);
    });

    it("passes the whole durable harness through httpGatewaySpendStore clients", async () => {
      // Learn the backend's real capability once (single-instance Redis → true, the capable arm).
      const probe = await httpGatewaySpendStore({
        baseUrl: gateway.url,
        token: DATA_TOKEN,
      });
      const capabilities = probe.capabilities;
      expect(capabilities.atomicGlobalFreeze).toBe(true);

      const gatewayClient = (token: string): HttpGatewaySpendStore =>
        new HttpGatewaySpendStore({ baseUrl: gateway.url, token, capabilities });
      const harness: DurableSpendStoreHarness = {
        connectData: () => gatewayClient(DATA_TOKEN),
        connectAdmin: () => gatewayClient(ADMIN_TOKEN),
        connectAdminWithDataCredential: () => gatewayClient(DATA_TOKEN),
        // Test-only ops act on the backend directly (out-of-band) — NOT part of the §12.5 wire set.
        reset: () => control.reset(),
        setBackendClock: (nowEpochMs) => control.setBackendClock(nowEpochMs),
      };
      await checkDurableSpendStore(harness);
    });
  },
);
