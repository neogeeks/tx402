/**
 * Turns the store-config environment (SPEC §9.1) into a live {@link SpendStore} for the
 * operator verbs (SPEC §10).
 *
 * The contract is exactly SPEC §9.1's env table:
 *
 *  - `TX402_SPEND_STORE` — a `https://<gateway>/…` gateway URL (§12.5) or a
 *    `redis://…`/`rediss://…` raw-direct DSN. A bare `do://<binding>` is **not** a CLI DSN: a
 *    Durable Object is reached through a Worker binding, not dialled from the public internet
 *    (SPEC §10 P1-8a), so it is refused with a message pointing at a gateway or wrangler.
 *  - `TX402_SPEND_STORE_TOKEN` — the **data-plane** credential (a gateway bearer token; for
 *    raw Redis the data-user credential is embedded in the DSN itself).
 *  - `TX402_SPEND_STORE_ADMIN` — the **admin** credential (a gateway admin bearer token, or a
 *    raw Redis admin-user DSN). The agent process must never hold it.
 *  - `TX402_SPEND_STORE_NAMESPACE` — the deployment isolation prefix (raw Redis only). Default
 *    `tx402`.
 *
 * The data/admin split is the whole point: an admin verb resolved with only a data credential
 * is refused **here**, before the backend is touched, with the same
 * `admin-credential-required` identity the durable stores raise (SPEC §9.1). The refusal is a
 * `ConfigurationError` → CLI exit 2 (SPEC §10 reuses the existing exit numbers). A store
 * *outage* while a verb runs is a `TransportError` → exit 7 (SPEC §11).
 *
 * `tx402/redis` and `tx402/gateway` are loaded lazily so the verbs' help path — and the whole
 * of `tx402 call` — never pull a Redis client or the gateway wire code, and neither counts
 * against the ADR-008 size gate (they are off the core import graph already).
 */

import { ConfigurationError } from "../core/errors.js";
import type { RecipientPinStore, SpendStore, SpendStoreAdmin } from "../core/ledger.js";
// Type-only: erased at build time, so the redis client is still loaded lazily below.
import type { RedisClient } from "../redis/index.js";

/** The plane a verb needs: `budget`/`pins` are data, `freeze`/`unfreeze`/`rotate-recipient` are admin. */
export type StorePlane = "data" | "admin";

/** A resolved operator store: the store itself, its backend kind, and a disposer for its client. */
export interface ResolvedStore {
  readonly store: SpendStore & RecipientPinStore & SpendStoreAdmin;
  /** `"gateway"` or `"redis"` — the backend the CLI dialled. Governs the §6.7 rotate warning. */
  readonly kind: string;
  dispose(): Promise<void>;
}

const CLI_ERROR_CONTEXT = { requestId: "cli", phase: "policy" } as const;

function configError(
  message: string,
  configPath: string,
  reason: string,
): ConfigurationError {
  return new ConfigurationError(message, {
    context: CLI_ERROR_CONTEXT,
    details: { configPath, reason },
  });
}

/**
 * Mask any `user:password@` credential in a DSN before it is rendered into an error or log (O28).
 * Handles `scheme://user:pass@host` and a scheme-less `user:pass@host`; a credential-free DSN is
 * returned unchanged. Exported so the operator verbs render every DSN through the same redactor.
 */
export function redactDsn(dsn: string): string {
  // Mask the WHOLE userinfo, up to the LAST `@` before the path (the userinfo/host separator — a
  // host cannot contain `@`). `[^/\s]+` spans an unencoded `@` inside a password
  // (`redis://user:p@ss@host`), so the suffix is not left in the clear (O28/O41l). `[^/\s]` still
  // stops at the first `/`, so a `@` in the path is untouched (it is not a credential).
  return dsn.replace(/(^|\/\/)([^/\s]+)@/u, (_match, prefix: string) => `${prefix}***@`);
}

/** Loopback hosts the plaintext-http development exception permits (HTTPS is the default). */
function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

/**
 * Require an HTTPS gateway URL (O22): a plaintext `http://` gateway sends the bearer token in the
 * clear, so it is refused unless it targets a loopback host (local development). The direct gateway
 * client enforces the same rule; this surfaces it at the env-var boundary with a clear message.
 */
function assertGatewayTransport(dsn: string): void {
  let host: string;
  try {
    host = new URL(dsn).hostname;
  } catch {
    throw configError(
      `Invalid gateway URL ${JSON.stringify(redactDsn(dsn))}.`,
      "TX402_SPEND_STORE",
      "invalid-gateway-url",
    );
  }
  if (dsn.startsWith("http://") && !isLoopbackHost(host)) {
    throw configError(
      "A plaintext http:// gateway sends the bearer token in the clear. Use https://, or " +
        "http:// only to a loopback host for local development.",
      "TX402_SPEND_STORE",
      "https-required",
    );
  }
}

/** The admin-credential refusal, identical to the durable stores' admin-denied identity. */
function adminCredentialRequired(): ConfigurationError {
  return configError(
    "An admin credential is required for this operation. Set TX402_SPEND_STORE_ADMIN " +
      "(a gateway admin bearer token, or a raw Redis admin-user DSN).",
    "TX402_SPEND_STORE_ADMIN",
    "admin-credential-required",
  );
}

/**
 * Resolves the configured store for `plane`. `await` it once at the top of a verb; it fetches
 * a gateway's capabilities on construction (SPEC §12.5) and connects a Redis client, both of
 * which are async.
 */
export async function resolveSpendStore(
  env: Readonly<Record<string, string | undefined>>,
  plane: StorePlane,
): Promise<ResolvedStore> {
  const dsn = env["TX402_SPEND_STORE"];
  if (dsn === undefined || dsn === "") {
    throw configError(
      "TX402_SPEND_STORE is not set. Point it at a gateway URL (https://…) or a Redis DSN " +
        "(redis://… / rediss://…).",
      "TX402_SPEND_STORE",
      "spend-store-unset",
    );
  }

  if (dsn.startsWith("do://")) {
    // SPEC §10 P1-8a: a DO is bound in Worker code, not dialled. There is no `do://` CLI store.
    throw configError(
      "A Durable Object is reached through a Worker binding, not a DSN. Reach it through a " +
        "capability gateway (TX402_SPEND_STORE=https://gateway.example/…) or manage it with " +
        "wrangler; do:// is only meaningful inside a Worker.",
      "TX402_SPEND_STORE",
      "durable-object-not-a-cli-dsn",
    );
  }

  if (dsn.startsWith("https://") || dsn.startsWith("http://")) {
    assertGatewayTransport(dsn);
    return resolveGateway(env, dsn, plane);
  }

  if (dsn.startsWith("redis://") || dsn.startsWith("rediss://")) {
    return resolveRedis(env, dsn, plane);
  }

  throw configError(
    // Redact any embedded credential before echoing the DSN (O28).
    `Unsupported TX402_SPEND_STORE ${JSON.stringify(redactDsn(dsn))}. Use a gateway URL ` +
      "(https://…) or a Redis DSN (redis://… / rediss://…).",
    "TX402_SPEND_STORE",
    "unsupported-store-dsn",
  );
}

/** Builds a gateway-backed store; the plane's bearer token is the whole credential (§12.5). */
async function resolveGateway(
  env: Readonly<Record<string, string | undefined>>,
  baseUrl: string,
  plane: StorePlane,
): Promise<ResolvedStore> {
  const token =
    plane === "admin" ? env["TX402_SPEND_STORE_ADMIN"] : env["TX402_SPEND_STORE_TOKEN"];
  if (plane === "admin" && (token === undefined || token === "")) {
    throw adminCredentialRequired();
  }
  if (token === undefined || token === "") {
    throw configError(
      "TX402_SPEND_STORE_TOKEN is not set. A gateway store needs a data-plane bearer token.",
      "TX402_SPEND_STORE_TOKEN",
      "data-credential-required",
    );
  }

  const { httpGatewaySpendStore } = await import("../gateway/index.js");
  const store = await httpGatewaySpendStore({ baseUrl, token });
  return { store, kind: store.kind, dispose: async () => {} };
}

/** Builds a raw-direct Redis store. The admin plane needs a distinct admin-user DSN (§9.1). */
async function resolveRedis(
  env: Readonly<Record<string, string | undefined>>,
  dataDsn: string,
  plane: StorePlane,
): Promise<ResolvedStore> {
  const namespace = env["TX402_SPEND_STORE_NAMESPACE"] ?? "tx402";
  let connectionDsn = dataDsn;
  if (plane === "admin") {
    const adminDsn = env["TX402_SPEND_STORE_ADMIN"];
    if (adminDsn === undefined || adminDsn === "") throw adminCredentialRequired();
    connectionDsn = adminDsn;
  }

  const { client, dispose } = await connectRedis(connectionDsn);
  const { RedisSpendStore } = await import("../redis/index.js");
  const store = new RedisSpendStore({ client, admin: plane === "admin", namespace });
  return { store, kind: store.kind, dispose };
}

/**
 * Connects a native Redis client from a DSN, preferring `ioredis` and falling back to
 * `node-redis` — whichever optional peer is installed (SPEC §12.1). `RedisSpendStore`
 * auto-detects which one it was handed.
 */
async function connectRedis(
  dsn: string,
): Promise<{ client: RedisClient; dispose: () => Promise<void> }> {
  try {
    const ioredis = (await import("ioredis")) as unknown as {
      default: new (
        dsn: string,
        options?: Record<string, unknown>,
      ) => {
        quit(): Promise<unknown>;
        on?(event: string, listener: (...args: unknown[]) => void): unknown;
      };
    };
    // A one-shot operator verb should fail FAST on a down store — a typed, retryable
    // TransportError (exit 7) the operator can re-run — not hang through ioredis's default
    // 20-retry storm (~10 s) before rejecting (U9). A live store never engages these, and a
    // sub-second blip is still tolerated by the three quick retries.
    const client = new ioredis.default(dsn, {
      maxRetriesPerRequest: 3,
      connectTimeout: 2000,
      retryStrategy: (times: number) => (times > 3 ? null : Math.min(times * 100, 300)),
    });
    // A down server makes ioredis emit connection 'error' events; with no listener Node prints
    // "[ioredis] Unhandled error event: … ECONNREFUSED" + a stack to stderr (U9). Swallow the
    // event — the pending command still rejects, and the verb's read method classifies that
    // rejection as a typed TransportError (exit 7). The DSN is never rendered here.
    client.on?.("error", () => {});
    return {
      client: client as unknown as RedisClient,
      // Disposal must NEVER mask the verb's own result: `quit()` on a client that never reached
      // a down server rejects, and a throwing `dispose()` in a verb's `finally` would supersede
      // the store's TransportError with an untyped error (exit 2 instead of 7, U9).
      dispose: async () => {
        await client.quit().catch(() => undefined);
      },
    };
  } catch (error) {
    if (!isModuleNotFound(error)) throw error;
  }
  try {
    const nodeRedis = (await import("redis")) as unknown as {
      createClient: (options: { url: string }) => {
        connect(): Promise<unknown>;
        quit(): Promise<unknown>;
        on?(event: string, listener: (...args: unknown[]) => void): unknown;
      };
    };
    const client = nodeRedis.createClient({ url: dsn });
    // Same guard for node-redis: an unhandled 'error' event on a closed socket is fatal.
    client.on?.("error", () => {});
    await client.connect();
    return {
      client: client as unknown as RedisClient,
      dispose: async () => {
        await client.quit().catch(() => undefined);
      },
    };
  } catch (error) {
    if (!isModuleNotFound(error)) throw error;
  }
  throw configError(
    "A redis:// store needs a Redis client. Install one: `npm i ioredis` (or `npm i redis`).",
    "TX402_SPEND_STORE",
    "redis-client-not-installed",
  );
}

function isModuleNotFound(error: unknown): boolean {
  return (
    error instanceof Error && (error as { code?: unknown }).code === "ERR_MODULE_NOT_FOUND"
  );
}
