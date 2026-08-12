/**
 * The capability-gateway wire protocol — the ONE contract the TS and Python
 * `httpGatewaySpendStore` clients and the reference gateways (Worker + Node) all speak, so any
 * conformant client interoperates with any conformant gateway.
 *
 * Pure and isomorphic: no `fetch`, no `node:*`, no `cloudflare:*`. It carries the protocol
 * constants, the method catalogue and its data/admin plane split, the path helper, the nested
 * `ReservationRef` shape, and the two directions of error translation — serialize a store's typed
 * error to the wire (`Tx402Error.toJSON()`, done by the caller) and reconstruct the EXACT typed
 * error from a wire payload (`deserializeTx402Error`), plus the gateway-condition status map
 * (`gatewayConditionError`). Every gateway condition maps to an EXISTING taxonomy code — there is
 * no `TX402_GATEWAY_FORBIDDEN` (SPEC §12.5, resolves the round-4 taxonomy P1) — so a gateway-backed
 * store is byte-identical to a direct one and passes the same `checkSpendStore`/
 * `checkDurableSpendStore` suites.
 */

import {
  AmbiguousPaymentError,
  BudgetExceededError,
  ClockSkewError,
  ConfigurationError,
  DomainNotAllowedError,
  InsufficientLiquidityError,
  InvalidPaymentRequiredError,
  NonReplayableRequestError,
  PaidRedirectBlockedError,
  RecipientUnpinnedError,
  ReservedHeaderError,
  ResourceDeliveryError,
  SignerError,
  SpendScopeFrozenError,
  Tx402Error,
  TX402_ERROR_CODES,
  type Tx402ErrorCode,
  type Tx402ErrorContext,
  type Tx402ErrorDetails,
  TransportError,
  UnsupportedProtocolError,
  UnsupportedSchemeError,
} from "../core/errors.js";
import type { ReservationRef } from "../core/ledger.js";

/** The protocol version. The `v1` path segment; sent as the {@link GATEWAY_VERSION_HEADER}. */
export const GATEWAY_PROTOCOL_VERSION = 1;

/** The path prefix every method is posted under: `POST {baseUrl}/v1/{method}`. */
export const GATEWAY_PATH_PREFIX = `/v${GATEWAY_PROTOCOL_VERSION}`;

/** The version header a client sends and a gateway rejects an unknown major of with `426`. */
export const GATEWAY_VERSION_HEADER = "TX402-Gateway-Version";

/** A bearer token's plane (SPEC §12.5). Data methods accept either; admin methods require admin. */
export type GatewayScope = "data" | "admin";

/**
 * The complete method set (SPEC §12.5), 1:1 with the store contract. The list is exhaustive so
 * no admin verb is silently omitted; `capabilities` is data-plane so a data token can populate the
 * client's `capabilities` field at construction.
 */
export const GATEWAY_DATA_METHODS = [
  "reserve",
  "commit",
  "release",
  "expose",
  "getBudgetState",
  "listExposed",
  "isFrozen",
  "getRecipientPins",
  "getRecipientPolicy",
  "capabilities",
] as const;

export const GATEWAY_ADMIN_METHODS = [
  "freeze",
  "unfreeze",
  "setRecipientPins",
  "setBudgetLimits",
  "getBudgetLimits",
  "setRecipientAssertionRequired",
  "setTofuEnabled",
  "resolveExposed",
  "resetCumulative",
] as const;

export type GatewayDataMethod = (typeof GATEWAY_DATA_METHODS)[number];
export type GatewayAdminMethod = (typeof GATEWAY_ADMIN_METHODS)[number];
export type GatewayMethod = GatewayDataMethod | GatewayAdminMethod;

const DATA_SET: ReadonlySet<string> = new Set(GATEWAY_DATA_METHODS);
const ADMIN_SET: ReadonlySet<string> = new Set(GATEWAY_ADMIN_METHODS);

/** Whether `name` is a method the gateway serves at all. */
export function isGatewayMethod(name: string): name is GatewayMethod {
  return DATA_SET.has(name) || ADMIN_SET.has(name);
}

/** The plane a method belongs to, or `undefined` if it is not a gateway method. */
export function gatewayPlane(name: string): GatewayScope | undefined {
  if (ADMIN_SET.has(name)) return "admin";
  if (DATA_SET.has(name)) return "data";
  return undefined;
}

/** The path a method is posted to: `/v1/{method}`. */
export function gatewayMethodPath(method: GatewayMethod): string {
  return `${GATEWAY_PATH_PREFIX}/${method}`;
}

/**
 * The nested wire form of a {@link ReservationRef} (SPEC §12.5): always the full
 * `{reservationId, policyScope, assetId}` triple, never a bare id — a sharded backend routes by
 * scope+asset, so the triple IS the reservation identity (§3.1).
 */
export interface WireReservationRef {
  readonly reservationId: string;
  readonly policyScope: string;
  readonly assetId: string;
}

export function refToWire(ref: ReservationRef): WireReservationRef {
  return {
    reservationId: ref.reservationId,
    policyScope: ref.policyScope,
    assetId: ref.assetId,
  };
}

export function refFromWire(wire: WireReservationRef): ReservationRef {
  return {
    reservationId: wire.reservationId,
    policyScope: wire.policyScope,
    assetId: wire.assetId,
  };
}

/** The on-the-wire shape of a serialized tx402 error — exactly `Tx402Error.toJSON()`. */
export interface WireError {
  readonly code: Tx402ErrorCode;
  readonly message?: string;
  readonly context?: Tx402ErrorContext;
  readonly details?: Tx402ErrorDetails;
}

/** Success/void/error envelopes (SPEC §12.5). Atomic amounts are strings inside `result`. */
export interface WireResult<T> {
  readonly result: T;
}
export interface WireErrorEnvelope {
  readonly error: WireError;
}

/**
 * The code → subclass map, so a wire error reconstructs to the EXACT typed error and `instanceof`
 * survives the transport (the harness switches on `BudgetExceededError`/`SpendScopeFrozenError`/
 * `RecipientUnpinnedError`/`ConfigurationError`). Every code in the frozen taxonomy is present.
 */
const ERROR_CONSTRUCTORS: Readonly<
  Record<
    Tx402ErrorCode,
    new (
      message: string,
      options: {
        context: Tx402ErrorContext;
        details?: Tx402ErrorDetails;
      },
    ) => Tx402Error
  >
> = {
  [TX402_ERROR_CODES.configInvalid]: ConfigurationError,
  [TX402_ERROR_CODES.reservedHeader]: ReservedHeaderError,
  [TX402_ERROR_CODES.nonReplayable]: NonReplayableRequestError,
  [TX402_ERROR_CODES.protocolUnsupported]: UnsupportedProtocolError,
  [TX402_ERROR_CODES.schemeUnsupported]: UnsupportedSchemeError,
  [TX402_ERROR_CODES.paymentRequiredInvalid]: InvalidPaymentRequiredError,
  [TX402_ERROR_CODES.policyBudget]: BudgetExceededError,
  [TX402_ERROR_CODES.policyDomain]: DomainNotAllowedError,
  [TX402_ERROR_CODES.liquidity]: InsufficientLiquidityError,
  [TX402_ERROR_CODES.signer]: SignerError,
  [TX402_ERROR_CODES.clockSkew]: ClockSkewError,
  [TX402_ERROR_CODES.paymentAmbiguous]: AmbiguousPaymentError,
  [TX402_ERROR_CODES.resourceDelivery]: ResourceDeliveryError,
  [TX402_ERROR_CODES.redirectBlocked]: PaidRedirectBlockedError,
  [TX402_ERROR_CODES.transport]: TransportError,
  [TX402_ERROR_CODES.spendFrozen]: SpendScopeFrozenError,
  [TX402_ERROR_CODES.recipientUnpinned]: RecipientUnpinnedError,
};

/** A `context` that satisfies the closed envelope when the wire omitted it (never for a store error). */
function contextOr(context: Tx402ErrorContext | undefined): Tx402ErrorContext {
  return context ?? { requestId: "gateway", phase: "policy" };
}

/**
 * Reconstruct the EXACT typed error from a wire payload (SPEC §12.5). A tx402 typed error the
 * store raised is returned by the gateway at HTTP 200 as `{ error: Tx402Error.toJSON() }`; the
 * client rethrows it unchanged, so a domain refusal (frozen, over-cap, unpinned, a lifecycle
 * `ConfigurationError`) round-trips as its exact code and class. An unknown code (never emitted by
 * a conformant gateway) falls back to the base {@link Tx402Error} so `isTx402Error` still holds.
 */
export function deserializeTx402Error(wire: WireError): Tx402Error {
  const message = wire.message ?? "";
  const context = contextOr(wire.context);
  const options = { context, details: wire.details ?? {} };
  const Constructor = ERROR_CONSTRUCTORS[wire.code];
  if (Constructor !== undefined) return new Constructor(message, options);
  return new Tx402Error(wire.code, message, options);
}

/**
 * The gateway-condition status map (SPEC §12.5) — every non-200 status maps to an EXISTING
 * taxonomy code. `400/401/403/426` are `ConfigurationError` (each payload carries BOTH `configPath`
 * AND `reason`, the two keys the frozen taxonomy requires); `503`/`5xx`/timeout is a retryable
 * `TransportError (gateway-unavailable)`. `200` returns `undefined` (the body decides success vs a
 * returned typed error). A 2xx/3xx that is not 200 is treated as a protocol violation → unavailable.
 */
export function gatewayConditionError(status: number): Tx402Error | undefined {
  if (status === 200) return undefined;
  const context: Tx402ErrorContext = { requestId: "gateway", phase: "policy" };
  switch (status) {
    case 400:
      return new ConfigurationError("The gateway rejected the request as malformed", {
        context,
        details: { configPath: "gateway.request", reason: "gateway-bad-request" },
      });
    case 401:
      return new ConfigurationError("The gateway bearer token is missing or unrecognized", {
        context,
        details: { configPath: "gateway.auth", reason: "gateway-unauthorized" },
      });
    case 403:
      return new ConfigurationError("An admin credential is required for this operation", {
        context,
        details: { configPath: "gateway.auth", reason: "admin-credential-required" },
      });
    case 426:
      return new ConfigurationError("The gateway does not support this protocol version", {
        context,
        details: { configPath: "gateway.version", reason: "gateway-version-unsupported" },
      });
    default:
      // 503 / any other 5xx / an unexpected status → unavailability, retryable.
      return new TransportError("The capability gateway is unavailable", {
        context,
        details: { causeCategory: "gateway-unavailable" },
      });
  }
}

/** The wire body a gateway returns for a condition status (SPEC §12.5 error table). */
export function gatewayConditionBody(status: number): WireErrorEnvelope {
  const error = gatewayConditionError(status);
  // Only the condition statuses have a body here; a caller never asks for 200.
  const wire: WireError =
    error instanceof Tx402Error
      ? { code: error.code, details: error.details }
      : {
          code: TX402_ERROR_CODES.transport,
          details: { causeCategory: "gateway-unavailable" },
        };
  return { error: wire };
}
