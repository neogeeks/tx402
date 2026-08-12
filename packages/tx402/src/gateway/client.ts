/**
 * `httpGatewaySpendStore` — the capability-gateway {@link SpendStore} client (SPEC §12.5). It
 * speaks the §12.5 wire protocol to any conformant gateway (the reference Worker or Node gateway,
 * or a third party's), holding only a bearer token — never a raw Redis/DO credential. Because the
 * wire contract is fixed, this client and the Python `tx402.stores.gateway` client produce
 * identical requests and map responses/errors identically (the gateway golden pins that), and a
 * gateway-backed store is byte-identical to a direct one: it passes the same `checkSpendStore`/
 * `checkDurableSpendStore` suites.
 *
 * **Capabilities are fetched ONCE, at construction.** `capabilities()` is a data-plane method;
 * {@link httpGatewaySpendStore} calls it once and freezes the result into the client's
 * `capabilities` field, so `checkDurableSpendStore` auto-selects the right freeze arm (the incapable
 * id-per-scope-DO / Redis-Cluster arm vs the capable single-coordinator-DO / single-instance-Redis
 * arm) behind the gateway exactly as it does directly.
 *
 * **The token is the whole credential.** A `data` token reaches the data methods; an `admin` token
 * also reaches `freeze`/`setRecipientPins`/`setBudgetLimits`/… . An admin method attempted with a
 * data token is refused by the gateway with `403` → a typed `admin-credential-required`
 * `ConfigurationError` — the durable data/admin boundary (SPEC §9.1), enforced server-side where the
 * raw credential lives, not by TypeScript. It does NOT close the compromised-application spending
 * path (that is 0.3.0, SPEC §1).
 */

import { ConfigurationError, TransportError, TX402_ERROR_CODES } from "../core/errors.js";
import type {
  BudgetLimits,
  BudgetState,
  CommitSpendInput,
  RecipientPinStore,
  ReservationRef,
  ReserveSpendInput,
  ReserveSpendResult,
  SpendEntry,
  SpendQuery,
  SpendReservation,
  SpendStore,
  SpendStoreAdmin,
  StoreCapabilities,
} from "../core/ledger.js";
import { GATEWAY_WIRE_DEFS, gatewayResponseSchema } from "./schema.js";
import { matchesWireSchema } from "./validate.js";
import {
  deserializeTx402Error,
  gatewayConditionError,
  gatewayMethodPath,
  refToWire,
  GATEWAY_PROTOCOL_VERSION,
  GATEWAY_VERSION_HEADER,
  type GatewayMethod,
  type WireError,
} from "./wire.js";

/** The `fetch` the client uses. Defaults to the global; injectable for tests and non-global hosts. */
export type GatewayFetch = (
  input: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    /** Redirects are refused (`"error"`), so a 3xx can never forward the bearer to another host. */
    redirect?: "error";
  },
) => Promise<{ status: number; json(): Promise<unknown> }>;

const GATEWAY_CONTEXT = { requestId: "gateway", phase: "policy" } as const;

/** Loopback hosts the plaintext-`http://` development exception permits (SPEC §12.5 is HTTPS-only). */
function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

/**
 * Require an HTTPS gateway URL (SPEC §12.5). Plaintext `http://` is permitted ONLY to a loopback
 * host, and only so local development / the test harness can front an in-process gateway; a plaintext
 * URL to any other host is refused so a bearer token is never sent in the clear (O22).
 */
function assertGatewayUrl(baseUrl: string): void {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new ConfigurationError("The gateway base URL is not a valid URL", {
      context: GATEWAY_CONTEXT,
      details: { configPath: "baseUrl", reason: "invalid-url" },
    });
  }
  if (url.protocol === "https:") return;
  if (url.protocol === "http:" && isLoopbackHost(url.hostname)) return;
  throw new ConfigurationError(
    "The gateway transport must be HTTPS; plaintext http:// is permitted only to a loopback host for local development",
    {
      context: GATEWAY_CONTEXT,
      details: { configPath: "baseUrl", reason: "https-required" },
    },
  );
}

/** A malformed gateway response the client refuses (SPEC §12.5) — non-retryable, both languages. */
function invalidGatewayResponse(): ConfigurationError {
  return new ConfigurationError("The gateway returned a malformed response", {
    context: GATEWAY_CONTEXT,
    details: { configPath: "gateway.response", reason: "gateway-invalid-response" },
  });
}

export interface HttpGatewaySpendStoreOptions {
  /** The gateway origin (optionally with a path prefix). `{baseUrl}/v1/{method}` is posted to. */
  readonly baseUrl: string;
  /** The bearer token. `data` reaches the data methods; `admin` also reaches the admin methods. */
  readonly token: string;
  /**
   * The store's declared capabilities. Normally fetched once by {@link httpGatewaySpendStore};
   * supplied directly only by a caller that already knows them (the durable harness, which learns
   * them once and hands each connection the same value).
   */
  readonly capabilities: StoreCapabilities;
  /** The `fetch` implementation. Defaults to `globalThis.fetch`. */
  readonly fetch?: GatewayFetch;
}

/** A JSON request body the client posts. The values are the primitives each method supplies. */
type Json = Record<string, unknown>;

/**
 * The wire shapes the gateway returns (SPEC §12.5), typed at the boundary so field access needs
 * no `String()` coercion. The golden validates these against the schema; the client trusts the
 * validated shape and casts once inside {@link HttpGatewaySpendStore.request}.
 */
interface WireReservationDto {
  readonly reservationId: string;
  readonly policyScope: string;
  readonly requestFingerprint: string;
  readonly assetId: string;
  readonly amountAtomic: string;
  readonly createdAtEpochMs: number;
  readonly expiresAtEpochMs: number;
  readonly state: SpendReservation["state"];
}
interface WireEntryDto {
  readonly reservationId: string;
  readonly requestFingerprint: string;
  readonly assetId: string;
  readonly amountAtomic: string;
  readonly committedAtEpochMs: number;
  readonly settlementId?: string;
}
interface WireBudgetStateDto {
  readonly storeKind: string;
  readonly policyScope?: string;
  readonly assetId?: string;
  readonly committedAtomic: string;
  readonly reservedAtomic: string;
  readonly exposedAtomic?: string;
  readonly cumulativeCommittedAtomic?: string;
  readonly cumulativeConsumedAtomic?: string;
  readonly perHourLimitAtomic?: string;
  readonly cumulativeLimitAtomic?: string;
  readonly availablePerHourAtomic?: string;
  readonly availableCumulativeAtomic?: string;
  readonly frozen?: boolean;
  readonly entries?: readonly WireEntryDto[];
  readonly reservations?: readonly WireReservationDto[];
}
interface WireBudgetLimitsDto {
  readonly maxPerHourAtomic?: string;
  readonly maxTotalAtomic?: string;
}

function toReservation(raw: WireReservationDto): SpendReservation {
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

function toEntry(raw: WireEntryDto): SpendEntry {
  return Object.freeze({
    reservationId: raw.reservationId,
    requestFingerprint: raw.requestFingerprint,
    assetId: raw.assetId,
    amountAtomic: raw.amountAtomic,
    committedAtEpochMs: raw.committedAtEpochMs,
    ...(raw.settlementId === undefined ? {} : { settlementId: raw.settlementId }),
  });
}

function toBudgetState(raw: WireBudgetStateDto): BudgetState {
  return Object.freeze({
    storeKind: raw.storeKind,
    ...(raw.policyScope === undefined ? {} : { policyScope: raw.policyScope }),
    ...(raw.assetId === undefined ? {} : { assetId: raw.assetId }),
    committedAtomic: raw.committedAtomic,
    reservedAtomic: raw.reservedAtomic,
    ...(raw.exposedAtomic === undefined ? {} : { exposedAtomic: raw.exposedAtomic }),
    ...(raw.cumulativeCommittedAtomic === undefined
      ? {}
      : { cumulativeCommittedAtomic: raw.cumulativeCommittedAtomic }),
    ...(raw.cumulativeConsumedAtomic === undefined
      ? {}
      : { cumulativeConsumedAtomic: raw.cumulativeConsumedAtomic }),
    ...(raw.perHourLimitAtomic === undefined
      ? {}
      : { perHourLimitAtomic: raw.perHourLimitAtomic }),
    ...(raw.cumulativeLimitAtomic === undefined
      ? {}
      : { cumulativeLimitAtomic: raw.cumulativeLimitAtomic }),
    ...(raw.availablePerHourAtomic === undefined
      ? {}
      : { availablePerHourAtomic: raw.availablePerHourAtomic }),
    ...(raw.availableCumulativeAtomic === undefined
      ? {}
      : { availableCumulativeAtomic: raw.availableCumulativeAtomic }),
    ...(raw.frozen === undefined ? {} : { frozen: raw.frozen }),
    entries: Object.freeze((raw.entries ?? []).map(toEntry)),
    reservations: Object.freeze((raw.reservations ?? []).map(toReservation)),
  });
}

/** The reference §12.5 gateway client — data plane, admin plane, and recipient reads on one object. */
export class HttpGatewaySpendStore
  implements SpendStore, RecipientPinStore, SpendStoreAdmin
{
  readonly kind = "gateway";
  readonly capabilities: StoreCapabilities;
  readonly #baseUrl: string;
  readonly #token: string;
  readonly #fetch: GatewayFetch;

  constructor(options: HttpGatewaySpendStoreOptions) {
    // Trim a trailing slash so `{baseUrl}/v1/{method}` never doubles it.
    const baseUrl = options.baseUrl.replace(/\/+$/u, "");
    // HTTPS by default; plaintext only to loopback — a bearer token is never sent in the clear (O22).
    // Only the real network transport can leak it, so an INJECTED `fetch` (the golden/harness, which
    // pair an `http://` placeholder with a no-socket fetch, or a caller supplying its own transport)
    // owns its own transport security and is exempt from the scheme check.
    if (options.fetch === undefined) assertGatewayUrl(baseUrl);
    this.#baseUrl = baseUrl;
    this.#token = options.token;
    this.capabilities = Object.freeze({ ...options.capabilities });
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async #request<T>(method: GatewayMethod, body: Json): Promise<T> {
    let response: { status: number; json(): Promise<unknown> };
    try {
      response = await this.#fetch(`${this.#baseUrl}${gatewayMethodPath(method)}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          [GATEWAY_VERSION_HEADER]: String(GATEWAY_PROTOCOL_VERSION),
          authorization: `Bearer ${this.#token}`,
        },
        body: JSON.stringify(body),
        // Never follow a redirect: a 3xx to another origin must not carry the bearer (O22).
        redirect: "error",
      });
    } catch (cause) {
      // A network failure or timeout is unavailability — retryable, nothing signed (SPEC §12.5).
      throw new TransportError("The capability gateway is unreachable", {
        context: { requestId: "gateway", phase: "policy" },
        details: { causeCategory: "gateway-unavailable" },
        cause,
      });
    }
    if (response.status !== 200) {
      // A gateway condition (`400/401/403/426/5xx`) maps to an existing taxonomy code (§12.5).
      // `gatewayConditionError` is defined for every non-200 status; the `??` keeps the type total.
      throw (
        gatewayConditionError(response.status) ??
        new TransportError("The capability gateway is unavailable", {
          context: { requestId: "gateway", phase: "policy" },
          details: { causeCategory: "gateway-unavailable" },
        })
      );
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch (cause) {
      throw new TransportError("The gateway returned an unreadable body", {
        context: { requestId: "gateway", phase: "policy" },
        details: { causeCategory: "gateway-unavailable" },
        cause,
      });
    }
    // Validate the whole envelope against the method's response schema (SPEC §12.5): a mistyped
    // result (a string `"false"` where a boolean is required), a missing field, or an unknown /
    // malformed error code fails validation and is refused as a protocol violation — never coerced
    // (O24). TS and Python reject identically (the same rule, driven by the same schema shapes).
    const responseSchema = gatewayResponseSchema(method);
    if (
      responseSchema === undefined ||
      !matchesWireSchema(responseSchema, payload, GATEWAY_WIRE_DEFS)
    ) {
      throw invalidGatewayResponse();
    }
    const envelope = payload as { error?: WireError; result: T };
    if (envelope.error !== undefined) {
      // Every `ConfigurationError` the frozen taxonomy defines carries `configPath`; a
      // `TX402_CONFIG_INVALID` wire error that omits it is itself a protocol violation (§12.5).
      if (
        envelope.error.code === TX402_ERROR_CODES.configInvalid &&
        typeof envelope.error.details?.configPath !== "string"
      ) {
        throw invalidGatewayResponse();
      }
      // A tx402 typed error the store raised, returned at 200 — rethrow the EXACT typed error.
      throw deserializeTx402Error(envelope.error);
    }
    return envelope.result;
  }

  // ── data plane ──────────────────────────────────────────────────────────────────────────────

  async reserve(input: ReserveSpendInput): Promise<ReserveSpendResult> {
    // Named-field body; JSON.stringify drops the undefined optional fields (§12.5).
    const result = await this.#request<{
      reservation: WireReservationDto;
      recipientPinEstablished: boolean;
    }>("reserve", { ...input });
    return Object.freeze({
      reservation: toReservation(result.reservation),
      recipientPinEstablished: result.recipientPinEstablished,
    });
  }

  async commit(input: CommitSpendInput): Promise<SpendEntry> {
    const result = await this.#request<WireEntryDto>("commit", {
      ref: refToWire({
        reservationId: input.reservationId,
        policyScope: input.policyScope,
        assetId: input.assetId,
      }),
      committedAtEpochMs: input.committedAtEpochMs,
      ...(input.settlementId === undefined ? {} : { settlementId: input.settlementId }),
    });
    return toEntry(result);
  }

  async release(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation> {
    return toReservation(
      await this.#request<WireReservationDto>("release", {
        ref: refToWire(ref),
        nowEpochMs,
      }),
    );
  }

  async expose(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation> {
    return toReservation(
      await this.#request<WireReservationDto>("expose", {
        ref: refToWire(ref),
        nowEpochMs,
      }),
    );
  }

  async getBudgetState(query: SpendQuery): Promise<BudgetState> {
    return toBudgetState(
      await this.#request<WireBudgetStateDto>("getBudgetState", {
        policyScope: query.policyScope,
        assetId: query.assetId,
        nowEpochMs: query.nowEpochMs,
      }),
    );
  }

  async listExposed(query: SpendQuery): Promise<readonly SpendReservation[]> {
    const raw = await this.#request<WireReservationDto[]>("listExposed", {
      policyScope: query.policyScope,
      assetId: query.assetId,
      nowEpochMs: query.nowEpochMs,
    });
    return Object.freeze(raw.map(toReservation));
  }

  async isFrozen(scope: string): Promise<boolean> {
    return this.#request<boolean>("isFrozen", { scope });
  }

  async getRecipientPins(scope: string, network: string): Promise<readonly string[]> {
    return Object.freeze(
      await this.#request<string[]>("getRecipientPins", { scope, network }),
    );
  }

  async getRecipientPolicy(
    scope: string,
  ): Promise<{ tofuEnabled: boolean; recipientAssertionRequired: boolean }> {
    return this.#request<{ tofuEnabled: boolean; recipientAssertionRequired: boolean }>(
      "getRecipientPolicy",
      { scope },
    );
  }

  /** Fetches the backend's declared capabilities via the data-plane `capabilities` method (§12.5). */
  async requestCapabilities(): Promise<StoreCapabilities> {
    const result = await this.#request<{ atomicGlobalFreeze: boolean }>("capabilities", {});
    return Object.freeze({ atomicGlobalFreeze: Boolean(result.atomicGlobalFreeze) });
  }

  // ── admin plane (SPEC §3.1/§12.5). A data token is refused 403 → admin-credential-required. ──

  async freeze(scope: string, nowEpochMs: number): Promise<void> {
    await this.#request<null>("freeze", { scope, nowEpochMs });
  }

  async unfreeze(scope: string, nowEpochMs: number): Promise<void> {
    await this.#request<null>("unfreeze", { scope, nowEpochMs });
  }

  async setRecipientPins(
    scope: string,
    network: string,
    recipients: readonly string[],
    nowEpochMs: number,
  ): Promise<void> {
    await this.#request<null>("setRecipientPins", {
      scope,
      network,
      recipients: [...recipients],
      nowEpochMs,
    });
  }

  async setBudgetLimits(
    scope: string,
    assetId: string,
    limits: BudgetLimits,
    nowEpochMs: number,
  ): Promise<void> {
    await this.#request<null>("setBudgetLimits", {
      scope,
      assetId,
      limits: { ...limits },
      nowEpochMs,
    });
  }

  async getBudgetLimits(scope: string, assetId: string): Promise<BudgetLimits> {
    const result = await this.#request<WireBudgetLimitsDto>("getBudgetLimits", {
      scope,
      assetId,
    });
    return Object.freeze({
      ...(result.maxPerHourAtomic === undefined
        ? {}
        : { maxPerHourAtomic: result.maxPerHourAtomic }),
      ...(result.maxTotalAtomic === undefined
        ? {}
        : { maxTotalAtomic: result.maxTotalAtomic }),
    });
  }

  async setRecipientAssertionRequired(
    scope: string,
    required: boolean,
    nowEpochMs: number,
  ): Promise<void> {
    await this.#request<null>("setRecipientAssertionRequired", {
      scope,
      required,
      nowEpochMs,
    });
  }

  async setTofuEnabled(scope: string, enabled: boolean, nowEpochMs: number): Promise<void> {
    await this.#request<null>("setTofuEnabled", { scope, enabled, nowEpochMs });
  }

  async resolveExposed(
    ref: ReservationRef,
    outcome: "committed" | "released",
    nowEpochMs: number,
  ): Promise<void> {
    await this.#request<null>("resolveExposed", {
      ref: refToWire(ref),
      outcome,
      nowEpochMs,
    });
  }

  async resetCumulative(scope: string, assetId: string, nowEpochMs: number): Promise<void> {
    await this.#request<null>("resetCumulative", { scope, assetId, nowEpochMs });
  }
}

/**
 * Construct a gateway-backed {@link SpendStore}, fetching the backend's capabilities ONCE (SPEC
 * §12.5) so `checkDurableSpendStore` selects the correct freeze arm. `await` it at startup:
 *
 * @example
 * ```ts
 * const store = await httpGatewaySpendStore({
 *   baseUrl: process.env.TX402_SPEND_STORE!, // https://gateway.example
 *   token: process.env.TX402_SPEND_STORE_TOKEN!, // a data bearer token
 * });
 * const client = createTx402Client({ spendStore: store, ... });
 * ```
 */
export async function httpGatewaySpendStore(
  options: Omit<HttpGatewaySpendStoreOptions, "capabilities"> & {
    readonly capabilities?: StoreCapabilities;
  },
): Promise<HttpGatewaySpendStore> {
  if (options.capabilities !== undefined) {
    return new HttpGatewaySpendStore({ ...options, capabilities: options.capabilities });
  }
  // Probe once with a placeholder capability, learn the real one, then build the final client.
  const probe = new HttpGatewaySpendStore({
    ...options,
    capabilities: { atomicGlobalFreeze: false },
  });
  const capabilities = await probe.requestCapabilities();
  return new HttpGatewaySpendStore({ ...options, capabilities });
}
