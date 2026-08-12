/**
 * `RedisSpendStore` — the reference durable {@link SpendStore} over Redis 7.0+ (SPEC §12.2,
 * ADR-025/026/027/028/029/030). Cross-language: the byte-identical Lua atoms (see `./lua.ts`)
 * back the Python `tx402.stores.redis` adapter too, so both SDKs share one backend semantics.
 *
 * Client-agnostic by construction: pass an `ioredis` client OR a `node-redis` (v4) client — the
 * two speak different method conventions (`evalsha`/`hgetall` vs `evalSha`/`hGetAll`), which a
 * thin normalizer bridges (`fromIoredis`/`fromNodeRedis`), auto-detected in the constructor. Both
 * are optional peer dependencies (§12.1); nothing here is imported by the size-gated core path.
 *
 * All spend transitions run server-side as one `EVAL` atom each (never a client read-decide-write
 * a concurrent caller could interleave, never `FUNCTION LOAD`, whose managed-Redis support is
 * spotty — O14). Windowing uses backend `TIME` inside the atom (§3.4a); the caller's `nowEpochMs`
 * never windows anything. A refusal comes back as `cjson` the adapter turns into the exact typed
 * error, so the taxonomy is identical to `MemorySpendStore` and the gateway round-trip (§12.5).
 */

import { createHash, randomBytes } from "node:crypto";

import {
  BudgetExceededError,
  ConfigurationError,
  RecipientUnpinnedError,
  SpendScopeFrozenError,
  TransportError,
  isTx402Error,
} from "../core/errors.js";
import {
  RESERVATION_TTL_MS,
  ROLLING_WINDOW_MS,
  canonicalizeAsset,
  type BudgetLimits,
  type BudgetState,
  type CommitSpendInput,
  type RecipientPinStore,
  type ReservationRef,
  type ReserveSpendInput,
  type ReserveSpendResult,
  type SpendEntry,
  type SpendQuery,
  type SpendReservation,
  type SpendReservationState,
  type SpendStore,
  type SpendStoreAdmin,
  type StoreCapabilities,
} from "../core/ledger.js";
import {
  COMMIT,
  EXPOSE,
  LIST_EXPOSED,
  RELEASE,
  RESERVE,
  RESOLVE_EXPOSED,
  SET_LIMITS,
  SNAPSHOT,
} from "./lua.js";

/**
 * The minimal Redis surface `RedisSpendStore` needs, normalized across `ioredis` and
 * `node-redis`. Users pass a native client; the constructor wraps it. Exported so a caller with
 * an exotic client (a pool, a proxy) can supply their own binding.
 */
export interface RedisConnection {
  evalsha(sha: string, keys: readonly string[], args: readonly string[]): Promise<unknown>;
  eval(script: string, keys: readonly string[], args: readonly string[]): Promise<unknown>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  del(key: string): Promise<unknown>;
  hset(key: string, fields: Record<string, string>): Promise<unknown>;
  hgetall(key: string): Promise<Record<string, string>>;
  keys(pattern: string): Promise<string[]>;
  /** `CONFIG GET <parameter>` as a `{parameter: value}` map (for the persistence check). */
  configGet(parameter: string): Promise<Record<string, string>>;
}

/** Structural shape of the `ioredis` methods used (lower-cased command names, variadic keys). */
interface IoredisLike {
  evalsha(sha: string, numkeys: number, ...rest: string[]): Promise<unknown>;
  eval(script: string, numkeys: number, ...rest: string[]): Promise<unknown>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  del(...keys: string[]): Promise<unknown>;
  hset(key: string, fields: Record<string, string>): Promise<unknown>;
  hgetall(key: string): Promise<Record<string, string>>;
  keys(pattern: string): Promise<string[]>;
}

/** Structural shape of the `node-redis` v4 methods used (camel-cased, options-object EVAL). */
interface NodeRedisLike {
  evalSha(sha: string, options: { keys: string[]; arguments: string[] }): Promise<unknown>;
  eval(script: string, options: { keys: string[]; arguments: string[] }): Promise<unknown>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  del(keys: string | string[]): Promise<unknown>;
  hSet(key: string, fields: Record<string, string>): Promise<unknown>;
  hGetAll(key: string): Promise<Record<string, string>>;
  keys(pattern: string): Promise<string[]>;
  configGet(parameter: string): Promise<Record<string, string>>;
}

// Brands a normalized connection so a raw client (ioredis and a RedisConnection both carry a
// lower-cased `evalsha`, so shape alone cannot tell them apart) is reliably distinguished from
// one already produced by the bridges below.
const BRAND = Symbol.for("tx402.redisConnection");
function brand(conn: RedisConnection): RedisConnection {
  (conn as unknown as Record<symbol, unknown>)[BRAND] = true;
  return conn;
}
function isBranded(client: RedisClient): boolean {
  return (client as unknown as Record<symbol, unknown>)[BRAND] === true;
}

/** Bridge an `ioredis` client to {@link RedisConnection}. */
export function fromIoredis(client: IoredisLike): RedisConnection {
  return brand({
    evalsha: (sha, keys, args) => client.evalsha(sha, keys.length, ...keys, ...args),
    eval: (script, keys, args) => client.eval(script, keys.length, ...keys, ...args),
    get: (key) => client.get(key),
    set: (key, value) => client.set(key, value),
    del: (key) => client.del(key),
    hset: (key, fields) => client.hset(key, fields),
    hgetall: (key) => client.hgetall(key),
    keys: (pattern) => client.keys(pattern),
    configGet: async (parameter) => {
      // ioredis returns CONFIG GET as a flat [key, value, …] array; fold it to a map. `config`
      // is accessed via a narrow local cast so IoredisLike stays minimal (its overloaded ioredis
      // signature does not fit a simple interface method).
      const withConfig = client as unknown as {
        config(subcommand: "GET", parameter: string): Promise<string[]>;
      };
      const flat = await withConfig.config("GET", parameter);
      const out: Record<string, string> = {};
      for (let index = 0; index + 1 < flat.length; index += 2) {
        const key = flat[index];
        const value = flat[index + 1];
        if (key !== undefined && value !== undefined) out[key] = value;
      }
      return out;
    },
  });
}

/** Bridge a `node-redis` (v4) client to {@link RedisConnection}. */
export function fromNodeRedis(client: NodeRedisLike): RedisConnection {
  return brand({
    evalsha: (sha, keys, args) =>
      client.evalSha(sha, { keys: [...keys], arguments: [...args] }),
    eval: (script, keys, args) =>
      client.eval(script, { keys: [...keys], arguments: [...args] }),
    get: (key) => client.get(key),
    set: (key, value) => client.set(key, value),
    del: (key) => client.del(key),
    hset: (key, fields) => client.hSet(key, fields),
    hgetall: (key) => client.hGetAll(key),
    keys: (pattern) => client.keys(pattern),
    configGet: (parameter) => client.configGet(parameter),
  });
}

/**
 * Normalize a caller's client. A connection this module already produced carries the brand and
 * passes through; `node-redis` is detected by its camel-cased `evalSha`; anything else is treated
 * as `ioredis` (lower-cased `evalsha`). Pass an `ioredis`/`node-redis` client, or a
 * `RedisConnection` built via {@link fromIoredis}/{@link fromNodeRedis}.
 */
function normalize(client: RedisClient): RedisConnection {
  if (isBranded(client)) return client as RedisConnection;
  if ("evalSha" in client) return fromNodeRedis(client);
  return fromIoredis(client as IoredisLike);
}

/** Any client `RedisSpendStore` accepts: an `ioredis`, a `node-redis` v4, or a pre-normalized one. */
export type RedisClient = IoredisLike | NodeRedisLike | RedisConnection;

export interface RedisSpendStoreOptions {
  /** An `ioredis` client, a `node-redis` v4 client, or a normalized {@link RedisConnection}. */
  readonly client: RedisClient;
  /** Deployment isolation prefix, the `ns` of the `{ns:scope}` hash tag. Default `"tx402"`. */
  readonly namespace?: string;
  /**
   * Admin plane. `false` (default) is a DATA-plane store: every admin mutation refuses with
   * `admin-credential-required`, so a compromised agent path cannot freeze a scope, widen a cap,
   * or rewrite a pin. Set `true` only for the operator store built from the admin
   * credential. (the adapter enforces the split; a raw Redis ACL user hardens it.)
   */
  readonly admin?: boolean;
  /**
   * Whether `freeze("*")` is atomic with a reservation. `true` on single-instance Redis (the
   * global flag and the scope's keys share one coordination domain); `false` on Cluster, where
   * the global key hashes to a different slot. Default `true`.
   */
  readonly atomicGlobalFreeze?: boolean;
  /**
   * TEST-ONLY. Enables the injectable backend clock: when set, `setBackendClock`
   * pins a shared time the atoms window on, and an unpinned op falls back to the caller's clock so
   * the caller-clock single-plane suite (`checkSpendStore`) runs. Production leaves this `false`,
   * so every atom windows on `redis.call('TIME')` and no clock setter has any effect.
   */
  readonly testClock?: boolean;
}

const SHA = {
  reserve: sha1(RESERVE),
  commit: sha1(COMMIT),
  release: sha1(RELEASE),
  expose: sha1(EXPOSE),
  resolveExposed: sha1(RESOLVE_EXPOSED),
  snapshot: sha1(SNAPSHOT),
  listExposed: sha1(LIST_EXPOSED),
  setLimits: sha1(SET_LIMITS),
};

function sha1(script: string): string {
  return createHash("sha1").update(script).digest("hex");
}

function uuidV7(nowEpochMs: number): string {
  const bytes = randomBytes(16);
  let timestamp = BigInt(Math.trunc(nowEpochMs));
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x70;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function isNoScript(error: unknown): boolean {
  return error instanceof Error && error.message.includes("NOSCRIPT");
}

/**
 * The reserved final-segment suffixes of the per-asset index/counter/limits keys (SPEC §12.2):
 * `…:res:<asset>:idx` / `…:cmt:<asset>:idx` (`lua.ts` `resIdx`/`cmtIdx`) and the sibling
 * `…:<asset>:total` / `…:<asset>:exposed` / `…:<asset>:limits` counters (`totalKey`/`exposedKey`/
 * `limitsKey`). A caller-supplied `reservationId` equal to any of them — or containing the `:` key
 * separator — would alias one of those keys (O48/O54). See {@link RedisSpendStore.reserve}.
 */
const RESERVED_KEY_SUFFIXES: ReadonlySet<string> = new Set([
  "idx",
  "total",
  "exposed",
  "limits",
]);

/**
 * True when `reservationId` would collide with (alias) a reserved index/counter/limits key in the
 * Redis keyspace (SPEC §12.2, O48/O54). `resKey(asset,id) = …:res:<asset>:<id>` while
 * `resIdx(asset) = …:res:<asset>:idx`, so `id === "idx"` maps a reservation HASH onto the index
 * ZSET key; likewise `resKey(A,"total") = …:res:A:total` equals `totalKey("res:A")`, so `id` equal
 * to a counter/limits suffix bricks a `res:`/`cmt:`-prefixed pseudo-asset ledger (O54). And because
 * the key builders join components with `:`, an `id` that itself contains `:` re-parses to a
 * different `(asset,id)` pair whose final segment can be a reserved suffix (`asset="A", id="B:idx"`
 * ≡ `resIdx("A:B")`) — every such collision corrupts the `(scope,asset)` ledger with `WRONGTYPE` (or,
 * for `limits`, overwrites the caps). Store-generated UUIDv7 ids and realistic CAIP-19 asset ids
 * never match. The reference `MemorySpendStore` and the DO store are immune (NUL-joined map keys / a
 * parameterized SQLite column), so this denylist is the Redis-only mitigation the SPEC-preserving
 * remediation adds; it does not change the frozen §12.2 key layout.
 */
function reservationIdAliasesKey(id: string): boolean {
  return RESERVED_KEY_SUFFIXES.has(id) || id.includes(":");
}

/**
 * Redis command names Redis itself replies to with a server error (ioredis `ReplyError`,
 * node-redis `ErrorReply`): a `WRONGTYPE`, a `NOSCRIPT`, a Lua `error()`. These are NOT store
 * outages — the server was reached and answered — so they must never be reclassified as a
 * retryable transport failure.
 */
const SERVER_REPLY_ERROR_NAMES = new Set(["ReplyError", "ErrorReply"]);

/** ioredis/node-redis connection-failure error names (the store is not reachable). */
const UNREACHABLE_ERROR_NAMES = new Set([
  "MaxRetriesPerRequestError", // ioredis: retries exhausted with the server down
  "AbortError", // ioredis: a pending command aborted because the connection dropped
  "ClientClosedError", // node-redis: the client was closed
  "SocketClosedUnexpectedlyError", // node-redis
  "ConnectionTimeoutError", // node-redis
  "ReconnectStrategyError", // node-redis: reconnection gave up
]);

/** Socket-level syscall codes that mean the server could not be reached. */
const UNREACHABLE_SYSCALL_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "EPIPE",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EHOSTUNREACH",
  "ENETUNREACH",
]);

/**
 * True when `error` is a store-*unreachable* failure (connection refused, retries exhausted,
 * socket closed, DNS failure) rather than a server reply error or a typed tx402 error (U9). A
 * `reserve` against a dead store already surfaces as a typed retryable `TransportError` (the
 * client wraps any non-typed store error, `core/client.ts`); the read methods below use this to
 * classify the SAME failure the SAME way, so a store outage on `getBudgetState`/`listExposed`/
 * `isFrozen` is a `TransportError`/exit 7, not an untyped library internal (`cli.mdx`'s
 * "exactly as a reserve would" contract).
 */
function isStoreUnreachable(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (SERVER_REPLY_ERROR_NAMES.has(error.name)) return false;
  if (UNREACHABLE_ERROR_NAMES.has(error.name)) return true;
  const code = (error as { code?: unknown }).code;
  if (typeof code === "string" && UNREACHABLE_SYSCALL_CODES.has(code)) return true;
  // ioredis also reports some disconnects as a plain Error with a telltale message.
  return (
    error.message.includes("Connection is closed") ||
    error.message.includes("Stream isn't writeable") ||
    error.message.includes("Command timed out")
  );
}

interface RawReservation {
  reservationId: string;
  policyScope: string;
  requestFingerprint: string;
  assetId: string;
  amountAtomic: string;
  createdAtEpochMs: number;
  expiresAtEpochMs: number;
  state: SpendReservationState;
}
interface RawEntry {
  reservationId: string;
  requestFingerprint: string;
  assetId: string;
  amountAtomic: string;
  committedAtEpochMs: number;
  settlementId?: string;
}
interface RawSnapshot {
  ok: true;
  committedAtomic: string;
  reservedAtomic: string;
  exposedAtomic: string;
  cumulativeCommittedAtomic: string;
  cumulativeConsumedAtomic: string;
  frozen: boolean;
  perHourLimitAtomic?: string;
  availablePerHourAtomic?: string;
  cumulativeLimitAtomic?: string;
  availableCumulativeAtomic?: string;
  entries: unknown;
  reservations: unknown;
}
type Refusal =
  | { ok: false; kind: "idreuse" }
  | { ok: false; kind: "frozen"; frozenScope: string }
  | {
      ok: false;
      kind: "recipient";
      reason: string;
      network?: string;
      presentedRecipient?: string;
      expectedRecipients?: string[];
    }
  | {
      ok: false;
      kind: "budget";
      capKind: string;
      requestedAtomic: string;
      capAtomic: string;
      committedAtomic: string;
      reservedAtomic: string;
    }
  | { ok: false; kind: "config"; configPath: string; reason: string };

function toReservation(raw: RawReservation): SpendReservation {
  return Object.freeze({
    reservationId: raw.reservationId,
    policyScope: raw.policyScope,
    requestFingerprint: raw.requestFingerprint,
    assetId: raw.assetId,
    amountAtomic: raw.amountAtomic,
    createdAtEpochMs: raw.createdAtEpochMs,
    expiresAtEpochMs: raw.expiresAtEpochMs,
    state: raw.state,
  });
}

function toEntry(raw: RawEntry): SpendEntry {
  return Object.freeze({
    reservationId: raw.reservationId,
    requestFingerprint: raw.requestFingerprint,
    assetId: raw.assetId,
    amountAtomic: raw.amountAtomic,
    committedAtEpochMs: raw.committedAtEpochMs,
    ...(raw.settlementId === undefined ? {} : { settlementId: raw.settlementId }),
  });
}

function coerceArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

/** The reference Redis {@link SpendStore} — data plane, admin plane, and recipient reads. */
export class RedisSpendStore implements SpendStore, RecipientPinStore, SpendStoreAdmin {
  readonly kind = "redis";
  readonly capabilities: StoreCapabilities;
  readonly #conn: RedisConnection;
  readonly #ns: string;
  readonly #admin: boolean;
  readonly #testClock: boolean;

  constructor(options: RedisSpendStoreOptions) {
    this.#conn = normalize(options.client);
    this.#ns = options.namespace ?? "tx402";
    this.#admin = options.admin ?? false;
    this.#testClock = options.testClock ?? false;
    this.capabilities = Object.freeze({
      atomicGlobalFreeze: options.atomicGlobalFreeze ?? true,
    });
  }

  // ── keys + clock ──────────────────────────────────────────────────────────────────────────

  #route(scope: string): string[] {
    // A representative `{ns:scope}` key so Cluster routes the atom to the scope's single slot.
    return [`{${this.#ns}:${scope}}`];
  }
  /**
   * `"1"` when the reserve/snapshot atom may consult the foreign-slot `{ns}:global-frozen` key,
   * `""` when it must not. Single-instance Redis declares `atomicGlobalFreeze` and reads it;
   * Cluster cannot (the global key hashes to a different slot from the scope's `{ns:scope}` keys,
   * and a multi-slot atom is forbidden), so it skips the read and stays single-slot (§5.2/§12.2).
   */
  #checkGlobalFrozen(): string {
    return this.capabilities.atomicGlobalFreeze ? "1" : "";
  }
  get #clockKey(): string {
    return `${this.#ns}:__test-clock__`;
  }
  #globalFrozenKey(): string {
    return `{${this.#ns}}:global-frozen`;
  }
  #scopeKey(scope: string, suffix: string): string {
    return `{${this.#ns}:${scope}}:${suffix}`;
  }

  /**
   * The `now` an atom windows on. Production (testClock off) returns `""` — the atom reads
   * `redis.call('TIME')`. Test mode returns the pinned shared clock if set (so a skewed caller
   * clock cannot double-spend, §3.4a), else the caller's clock (so `checkSpendStore` runs).
   */
  async #now(callerNow: number): Promise<string> {
    if (!this.#testClock) return "";
    const pinned = await this.#conn.get(this.#clockKey);
    return pinned ?? String(callerNow);
  }

  async #run(
    script: string,
    sha: string,
    keys: readonly string[],
    args: readonly string[],
  ): Promise<string> {
    try {
      return (await this.#conn.evalsha(sha, keys, args)) as string;
    } catch (error) {
      if (isNoScript(error)) return (await this.#conn.eval(script, keys, args)) as string;
      throw error;
    }
  }

  /**
   * Runs a store read and reclassifies a store-*unreachable* failure as a typed retryable
   * {@link TransportError} — mirroring how a `reserve` against a dead store is already classified
   * by the client (U9). A typed tx402 error (a refusal) or a server reply error passes through
   * unchanged; only an actual outage is wrapped, so the operator verbs and the SDK read methods
   * report a store outage as `TransportError`/exit 7 instead of an untyped ioredis internal.
   */
  async #read<T>(op: () => Promise<T>): Promise<T> {
    try {
      return await op();
    } catch (error) {
      if (!isTx402Error(error) && isStoreUnreachable(error)) {
        throw new TransportError("The spend store is unreachable", {
          context: { requestId: "spend-store", phase: "policy" },
          // Coarse category only (SEC-003) — never the DSN or the ioredis internal message.
          details: { causeCategory: "spend-store-unavailable", storeKind: this.kind },
        });
      }
      throw error;
    }
  }

  /**
   * Refuses a caller-supplied `reservationId` that would alias a reserved index/counter/limits key
   * (O48/O54). The Redis key builders (`lua.ts`) join untrusted components into one flat
   * `:`-separated keyspace, so `reservationId` equal to `idx`/`total`/`exposed`/`limits` — or any id
   * containing `:` — collides a reservation record with a per-asset index ZSET or counter and bricks
   * the `(scope,asset)` (or a `res:`/`cmt:`-prefixed pseudo-asset) ledger with `WRONGTYPE`. This is a
   * Redis-store-only guard (Memory + DO are immune) and does not change the frozen SPEC §12.2 key
   * layout; it fails closed with a typed `ConfigurationError` before any Redis write.
   */
  #assertReservationIdSafe(
    id: string,
    ctx: { requestId?: string; assetId?: string },
  ): void {
    if (!reservationIdAliasesKey(id)) return;
    throw new ConfigurationError(
      'reservationId may not be "idx"/"total"/"exposed"/"limits" or contain ":" — it would alias ' +
        "a reserved index/counter key in the Redis keyspace (SPEC §12.2).",
      {
        context: {
          requestId: ctx.requestId ?? "spend-store",
          phase: "policy",
          ...(ctx.assetId === undefined ? {} : { assetId: ctx.assetId }),
        },
        details: { configPath: "reservationId", reason: "reservation-id-aliases-index" },
      },
    );
  }

  #requireAdmin(): void {
    if (this.#admin) return;
    throw new ConfigurationError("An admin credential is required for this operation", {
      context: { requestId: "spend-store", phase: "policy" },
      details: { configPath: "credential", reason: "admin-credential-required" },
    });
  }

  #mapRefusal(
    res: Refusal,
    ctx: {
      requestId?: string;
      policyScope: string;
      assetId?: string;
      amountAtomic?: string;
      reservationId?: string;
    },
  ): Error {
    const requestId = ctx.requestId ?? "spend-store";
    const context = {
      requestId,
      phase: "policy" as const,
      ...(ctx.assetId === undefined ? {} : { assetId: ctx.assetId }),
      ...(ctx.amountAtomic === undefined ? {} : { amountAtomic: ctx.amountAtomic }),
      ...(ctx.reservationId === undefined ? {} : { reservationId: ctx.reservationId }),
    };
    switch (res.kind) {
      case "idreuse":
        return new Error("Reservation ID was reused with different spend data");
      case "frozen":
        return new SpendScopeFrozenError("Spending is frozen for this scope", {
          context,
          details: { scope: ctx.policyScope, frozenScope: res.frozenScope },
        });
      case "recipient": {
        const details: Record<string, unknown> = {
          merchantScope: ctx.policyScope,
          reason: res.reason,
        };
        if (res.reason === "not-allowlisted" || res.reason === "pin-mismatch") {
          details.network = res.network;
          details.presentedRecipient = res.presentedRecipient;
          details.expectedRecipients = res.expectedRecipients;
        }
        return new RecipientUnpinnedError("The recipient is not pinned for this scope", {
          context,
          details,
        });
      }
      case "budget":
        return new BudgetExceededError(
          res.capKind === "cumulative"
            ? "Cumulative spend limit would be exceeded"
            : "Hourly spend limit would be exceeded",
          {
            context,
            details: {
              requestedAtomic: res.requestedAtomic,
              capAtomic: res.capAtomic,
              committedAtomic: res.committedAtomic,
              reservedAtomic: res.reservedAtomic,
              capKind: res.capKind,
            },
          },
        );
      case "config":
        return new ConfigurationError(
          res.reason === "reservation-not-found"
            ? "The reservation ref names no record"
            : "The reservation lifecycle transition is not permitted",
          { context, details: { configPath: res.configPath, reason: res.reason } },
        );
    }
  }

  // ── data plane ──────────────────────────────────────────────────────────────────────────────

  async reserve(input: ReserveSpendInput): Promise<ReserveSpendResult> {
    const id = input.reservationId ?? uuidV7(input.nowEpochMs);
    this.#assertReservationIdSafe(id, {
      requestId: input.requestId,
      assetId: input.assetId,
    });
    const now = await this.#now(input.nowEpochMs);
    // Canonicalize the asset (SPEC §6.4, U16) before the atom keys on it, so a lowercase-administered
    // cap binds a checksummed reserve. The Lua atom is unchanged — it receives an already-canonical
    // asset and both keys on it and stores it in the reservation hash.
    const raw = await this.#run(RESERVE, SHA.reserve, this.#route(input.policyScope), [
      this.#ns,
      input.policyScope,
      canonicalizeAsset(input.assetId),
      id,
      input.requestFingerprint,
      input.amountAtomic,
      input.maxPerHourAtomic,
      input.maxTotalAtomic ?? "",
      input.recipientNetwork ?? "",
      input.recipientCanonical ?? "",
      input.recipientEnforcement ?? "",
      now,
      String(RESERVATION_TTL_MS),
      String(ROLLING_WINDOW_MS),
      this.#checkGlobalFrozen(),
    ]);
    const res = JSON.parse(raw) as
      { ok: true; reservation: RawReservation; recipientPinEstablished: boolean } | Refusal;
    if (res.ok) {
      return Object.freeze({
        reservation: toReservation(res.reservation),
        recipientPinEstablished: res.recipientPinEstablished,
      });
    }
    throw this.#mapRefusal(res, {
      requestId: input.requestId,
      policyScope: input.policyScope,
      assetId: input.assetId,
      amountAtomic: input.amountAtomic,
    });
  }

  async commit(input: CommitSpendInput): Promise<SpendEntry> {
    this.#assertReservationIdSafe(input.reservationId, { assetId: input.assetId });
    const now = await this.#now(input.committedAtEpochMs);
    const raw = await this.#run(COMMIT, SHA.commit, this.#route(input.policyScope), [
      this.#ns,
      input.policyScope,
      canonicalizeAsset(input.assetId),
      input.reservationId,
      now,
      input.settlementId ?? "",
    ]);
    const res = JSON.parse(raw) as { ok: true; entry: RawEntry } | Refusal;
    if (res.ok) return toEntry(res.entry);
    throw this.#mapRefusal(res, {
      policyScope: input.policyScope,
      assetId: input.assetId,
      reservationId: input.reservationId,
    });
  }

  async release(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation> {
    this.#assertReservationIdSafe(ref.reservationId, { assetId: ref.assetId });
    const now = await this.#now(nowEpochMs);
    const raw = await this.#run(RELEASE, SHA.release, this.#route(ref.policyScope), [
      this.#ns,
      ref.policyScope,
      canonicalizeAsset(ref.assetId),
      ref.reservationId,
      now,
    ]);
    const res = JSON.parse(raw) as { ok: true; reservation: RawReservation } | Refusal;
    if (res.ok) return toReservation(res.reservation);
    throw this.#mapRefusal(res, {
      policyScope: ref.policyScope,
      assetId: ref.assetId,
      reservationId: ref.reservationId,
    });
  }

  async expose(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation> {
    this.#assertReservationIdSafe(ref.reservationId, { assetId: ref.assetId });
    const now = await this.#now(nowEpochMs);
    const raw = await this.#run(EXPOSE, SHA.expose, this.#route(ref.policyScope), [
      this.#ns,
      ref.policyScope,
      canonicalizeAsset(ref.assetId),
      ref.reservationId,
      now,
    ]);
    const res = JSON.parse(raw) as { ok: true; reservation: RawReservation } | Refusal;
    if (res.ok) return toReservation(res.reservation);
    throw this.#mapRefusal(res, {
      policyScope: ref.policyScope,
      assetId: ref.assetId,
      reservationId: ref.reservationId,
    });
  }

  async getBudgetState(query: SpendQuery): Promise<BudgetState> {
    const raw = await this.#read(async () => {
      const now = await this.#now(query.nowEpochMs);
      return this.#run(SNAPSHOT, SHA.snapshot, this.#route(query.policyScope), [
        this.#ns,
        query.policyScope,
        canonicalizeAsset(query.assetId),
        now,
        String(ROLLING_WINDOW_MS),
        this.#checkGlobalFrozen(),
      ]);
    });
    const s = JSON.parse(raw) as RawSnapshot;
    return Object.freeze({
      storeKind: this.kind,
      policyScope: query.policyScope,
      assetId: canonicalizeAsset(query.assetId),
      committedAtomic: s.committedAtomic,
      reservedAtomic: s.reservedAtomic,
      exposedAtomic: s.exposedAtomic,
      cumulativeCommittedAtomic: s.cumulativeCommittedAtomic,
      cumulativeConsumedAtomic: s.cumulativeConsumedAtomic,
      frozen: s.frozen,
      ...(s.perHourLimitAtomic === undefined
        ? {}
        : {
            perHourLimitAtomic: s.perHourLimitAtomic,
            availablePerHourAtomic: s.availablePerHourAtomic,
          }),
      ...(s.cumulativeLimitAtomic === undefined
        ? {}
        : {
            cumulativeLimitAtomic: s.cumulativeLimitAtomic,
            availableCumulativeAtomic: s.availableCumulativeAtomic,
          }),
      entries: Object.freeze(coerceArray<RawEntry>(s.entries).map(toEntry)),
      reservations: Object.freeze(
        coerceArray<RawReservation>(s.reservations).map(toReservation),
      ),
    });
  }

  async listExposed(query: SpendQuery): Promise<readonly SpendReservation[]> {
    const raw = await this.#read(() =>
      this.#run(LIST_EXPOSED, SHA.listExposed, this.#route(query.policyScope), [
        this.#ns,
        query.policyScope,
        canonicalizeAsset(query.assetId),
      ]),
    );
    return Object.freeze(coerceArray<RawReservation>(JSON.parse(raw)).map(toReservation));
  }

  async isFrozen(scope: string): Promise<boolean> {
    return this.#read(async () => {
      // The global-freeze key is a foreign slot; a store that cannot set it (Cluster,
      // atomicGlobalFreeze:false) never reads it, so the check stays single-key-routable.
      if (
        this.capabilities.atomicGlobalFreeze &&
        (await this.#conn.get(this.#globalFrozenKey())) !== null
      )
        return true;
      return (await this.#conn.get(this.#scopeKey(scope, "frozen"))) !== null;
    });
  }

  /**
   * The warning an operator should surface when the connected Redis is NOT restart-durable, or
   * `null` when it is (SPEC §12.2 — the adapter SHOULD warn if persistence is disabled). Restart
   * durability requires AOF (`appendonly yes`, `appendfsync everysec` or stricter); without it a
   * crash or restart loses every reservation and counter. This does **not** write to the console
   * (SEC-003: library code emits no console output — diagnostics flow through the SDK logger), so a
   * caller logs the returned message. Returns `null` when AOF is on, or when `CONFIG GET` is
   * unavailable (a managed Redis may restrict it) — durability then cannot be asserted from here and
   * the shared-store runbook is authoritative.
   */
  async warnIfPersistenceDisabled(): Promise<string | null> {
    let appendonly: string | undefined;
    try {
      appendonly = (await this.#conn.configGet("appendonly")).appendonly;
    } catch {
      return null; // CONFIG restricted (e.g. a managed Redis) — cannot assert from here.
    }
    if (appendonly === "yes") return null;
    return (
      `tx402: Redis persistence is disabled (appendonly=${appendonly ?? "unknown"}). This store ` +
      "is NOT restart-durable — a crash or restart loses every reservation and counter. Enable " +
      "AOF (appendonly yes, appendfsync everysec or stricter) for a durable shared spend store " +
      "(SPEC §12.2)."
    );
  }

  // ── recipient reads (data plane, SPEC §3.1) ────────────────────────────────────────────────

  async getRecipientPins(scope: string, network: string): Promise<readonly string[]> {
    // A store outage here is a retryable TransportError, typed exactly as getBudgetState/reserve
    // already are (O53) — never an untyped ioredis internal leaking to the CLI `pins` verb (exit 7,
    // not exit 2). The S14f U9 fix wrapped the other three reads but missed this one.
    const hash = await this.#read(() =>
      this.#conn.hgetall(this.#scopeKey(scope, `pins:${network}`)),
    );
    const joined = hash.recipients;
    return Object.freeze(joined ? joined.split("\n") : []);
  }

  async getRecipientPolicy(
    scope: string,
  ): Promise<{ tofuEnabled: boolean; recipientAssertionRequired: boolean }> {
    const [tofu, required] = await this.#read(() =>
      Promise.all([
        this.#conn.get(this.#scopeKey(scope, "tofu-enabled")),
        this.#conn.get(this.#scopeKey(scope, "recipient-required")),
      ]),
    );
    return { tofuEnabled: tofu !== null, recipientAssertionRequired: required !== null };
  }

  // ── admin plane (SPEC §3.1, ADR-029). Every mutation refuses a data credential. ────────────

  // Each admin method accepts an OPTIONAL trailing `_nowEpochMs` — Redis reads its own backend
  // clock inside the atom (§3.4a), so the value is accepted-and-ignored. It is declared (like
  // MemorySpendStore's `_nowEpochMs?`) so the concrete store matches the `SpendStoreAdmin` interface
  // arity and every operator doc example that passes `Date.now()` type-checks against it (U13).

  async freeze(scope: string, _nowEpochMs?: number): Promise<void> {
    this.#requireAdmin();
    if (scope === "*") {
      if (!this.capabilities.atomicGlobalFreeze) {
        throw new ConfigurationError(
          "Atomic global freeze is not supported by this topology",
          {
            context: { requestId: "spend-store", phase: "policy" },
            details: { configPath: "freeze.global", reason: "global-freeze-unsupported" },
          },
        );
      }
      await this.#conn.set(this.#globalFrozenKey(), "1");
      return;
    }
    await this.#conn.set(this.#scopeKey(scope, "frozen"), "1");
  }

  async unfreeze(scope: string, _nowEpochMs?: number): Promise<void> {
    this.#requireAdmin();
    await this.#conn.del(
      scope === "*" ? this.#globalFrozenKey() : this.#scopeKey(scope, "frozen"),
    );
  }

  async setRecipientPins(
    scope: string,
    network: string,
    recipients: readonly string[],
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#requireAdmin();
    await this.#conn.hset(this.#scopeKey(scope, `pins:${network}`), {
      recipients: [...recipients].join("\n"),
      source: "admin-allowlist",
    });
  }

  async setBudgetLimits(
    scope: string,
    assetId: string,
    limits: BudgetLimits,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#requireAdmin();
    // ONE atom (DEL + conditional HSET), not a client-side DEL-then-HSET: a concurrent reserve sees
    // the whole old or whole new cap, never a torn value, and a failure never deletes the cap (O26).
    // Replace semantics — an absent field is removed — match MemorySpendStore/DO.
    await this.#run(SET_LIMITS, SHA.setLimits, this.#route(scope), [
      this.#ns,
      scope,
      canonicalizeAsset(assetId),
      limits.maxPerHourAtomic ?? "",
      limits.maxTotalAtomic ?? "",
    ]);
  }

  async getBudgetLimits(scope: string, assetId: string): Promise<BudgetLimits> {
    // getBudgetLimits is an admin-plane read (SPEC §3.1, part of SpendStoreAdmin): the DO gates it
    // with #verifyAdmin and the gateway 403s a data token, so the raw Redis store requires an admin
    // credential too (O55). No disclosure changes — the administered caps stay data-readable via
    // getBudgetState. A store outage is a typed retryable TransportError (O53), like the other reads.
    this.#requireAdmin();
    const hash = await this.#read(() =>
      this.#conn.hgetall(this.#scopeKey(scope, `${canonicalizeAsset(assetId)}:limits`)),
    );
    return Object.freeze({
      ...(hash.maxPerHourAtomic === undefined
        ? {}
        : { maxPerHourAtomic: hash.maxPerHourAtomic }),
      ...(hash.maxTotalAtomic === undefined ? {} : { maxTotalAtomic: hash.maxTotalAtomic }),
    });
  }

  async setRecipientAssertionRequired(
    scope: string,
    required: boolean,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#requireAdmin();
    const key = this.#scopeKey(scope, "recipient-required");
    if (required) await this.#conn.set(key, "1");
    else await this.#conn.del(key);
  }

  async setTofuEnabled(
    scope: string,
    enabled: boolean,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#requireAdmin();
    const key = this.#scopeKey(scope, "tofu-enabled");
    if (enabled) await this.#conn.set(key, "1");
    else await this.#conn.del(key);
  }

  async resolveExposed(
    ref: ReservationRef,
    outcome: "committed" | "released",
    nowEpochMs: number,
  ): Promise<void> {
    this.#requireAdmin();
    this.#assertReservationIdSafe(ref.reservationId, { assetId: ref.assetId });
    const now = await this.#now(nowEpochMs);
    const raw = await this.#run(
      RESOLVE_EXPOSED,
      SHA.resolveExposed,
      this.#route(ref.policyScope),
      [
        this.#ns,
        ref.policyScope,
        canonicalizeAsset(ref.assetId),
        ref.reservationId,
        outcome,
        now,
      ],
    );
    const res = JSON.parse(raw) as { ok: true } | Refusal;
    if (!res.ok)
      throw this.#mapRefusal(res, {
        policyScope: ref.policyScope,
        assetId: ref.assetId,
        reservationId: ref.reservationId,
      });
  }

  async resetCumulative(
    scope: string,
    assetId: string,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#requireAdmin();
    await this.#conn.del(this.#scopeKey(scope, `${canonicalizeAsset(assetId)}:total`));
  }

  // ── test-only harness helpers (SPEC §3.4a/§3.6). Never present in a production deployment. ──

  /** Pins the shared backend clock the atoms window on (enabled by `testClock`). */
  async setBackendClock(nowEpochMs: number): Promise<void> {
    await this.#conn.set(this.#clockKey, String(nowEpochMs));
  }

  /** Clears every key in this namespace (both `{ns:...}` tagged keys and the un-tagged clock). */
  async reset(): Promise<void> {
    const keys = new Set<string>();
    for (const pattern of [`{${this.#ns}*`, `${this.#ns}:*`]) {
      for (const key of await this.#conn.keys(pattern)) keys.add(key);
    }
    await Promise.all([...keys].map((key) => this.#conn.del(key)));
  }
}
