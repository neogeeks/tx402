/**
 * The full JSON Schema (2020-12) for every capability-gateway request and response.
 * It ships with the reference gateway and is PINNED by the gateway golden: `tools/gateway-golden`
 * validates every committed request/response fixture against it and drift-checks the schema itself,
 * so the wire contract cannot change without the golden and the schema moving together.
 *
 * The named-field request bodies (never a positional array), the nested `ReservationRef` triple,
 * and the `{ result }` / `{ result: null }` success shapes are all expressed here as structural
 * constraints (`additionalProperties: false`), so a request that smuggles an extra field or a
 * positional shape fails validation.
 */

import { TX402_ERROR_TAXONOMY } from "../core/errors.js";
import {
  GATEWAY_ADMIN_METHODS,
  GATEWAY_DATA_METHODS,
  GATEWAY_PROTOCOL_VERSION,
} from "./wire.js";

type Schema = Record<string, unknown>;

const ref = (name: string): Schema => ({ $ref: `#/$defs/${name}` });

/**
 * A single atomic-integer INPUT amount (an amount, a cap): capped at 78 digits, matching
 * `common.schema.json#/$defs/atomicAmount` (§13). Reused for every request-side amount/limit and for
 * the single per-reservation amounts in responses.
 */
const atomicAmount: Schema = {
  type: "string",
  pattern: "^(0|[1-9][0-9]*)$",
  maxLength: 78,
};
/**
 * A lifetime ACCUMULATOR (`exposedAtomic`, `cumulativeCommittedAtomic`, `cumulativeConsumedAtomic`):
 * a non-negative integer string with NO `maxLength`, since a cumulative sum can carry past 78 digits
 * (§13, `common.schema.json#/$defs/atomicAccumulator`). Only these aggregate response fields use it;
 * every input amount/cap stays 78-capped, so an over-width input is a `400` (O23).
 */
const atomicAccumulator: Schema = { type: "string", pattern: "^(0|[1-9][0-9]*)$" };
const epochMs: Schema = { type: "integer", minimum: 0 };
const nonEmpty: Schema = { type: "string", minLength: 1 };

function object(properties: Record<string, Schema>, required: readonly string[]): Schema {
  return {
    type: "object",
    properties,
    required: [...required],
    additionalProperties: false,
  };
}

const $defs: Record<string, Schema> = {
  atomicAmount,
  atomicAccumulator,
  reservationState: {
    enum: ["reserved", "committed", "released", "expired", "exposed"],
  },
  reservationRef: object(
    { reservationId: nonEmpty, policyScope: nonEmpty, assetId: nonEmpty },
    ["reservationId", "policyScope", "assetId"],
  ),
  reservation: object(
    {
      reservationId: nonEmpty,
      policyScope: nonEmpty,
      requestFingerprint: { type: "string" },
      assetId: nonEmpty,
      amountAtomic: ref("atomicAmount"),
      createdAtEpochMs: epochMs,
      expiresAtEpochMs: epochMs,
      state: ref("reservationState"),
    },
    [
      "reservationId",
      "policyScope",
      "requestFingerprint",
      "assetId",
      "amountAtomic",
      "createdAtEpochMs",
      "expiresAtEpochMs",
      "state",
    ],
  ),
  entry: object(
    {
      reservationId: nonEmpty,
      requestFingerprint: { type: "string" },
      assetId: nonEmpty,
      amountAtomic: ref("atomicAmount"),
      committedAtEpochMs: epochMs,
      settlementId: { type: "string" },
    },
    [
      "reservationId",
      "requestFingerprint",
      "assetId",
      "amountAtomic",
      "committedAtEpochMs",
    ],
  ),
  budgetLimits: object(
    { maxPerHourAtomic: ref("atomicAmount"), maxTotalAtomic: ref("atomicAmount") },
    [],
  ),
  budgetState: object(
    {
      storeKind: { type: "string" },
      policyScope: { type: "string" },
      assetId: { type: "string" },
      committedAtomic: ref("atomicAmount"),
      reservedAtomic: ref("atomicAmount"),
      exposedAtomic: ref("atomicAccumulator"),
      cumulativeCommittedAtomic: ref("atomicAccumulator"),
      cumulativeConsumedAtomic: ref("atomicAccumulator"),
      perHourLimitAtomic: ref("atomicAmount"),
      cumulativeLimitAtomic: ref("atomicAmount"),
      availablePerHourAtomic: ref("atomicAmount"),
      availableCumulativeAtomic: ref("atomicAmount"),
      frozen: { type: "boolean" },
      entries: { type: "array", items: ref("entry") },
      reservations: { type: "array", items: ref("reservation") },
    },
    ["storeKind", "committedAtomic", "reservedAtomic", "entries", "reservations"],
  ),
  capabilities: object({ atomicGlobalFreeze: { type: "boolean" } }, ["atomicGlobalFreeze"]),
  recipientPolicy: object(
    {
      tofuEnabled: { type: "boolean" },
      recipientAssertionRequired: { type: "boolean" },
    },
    ["tofuEnabled", "recipientAssertionRequired"],
  ),
  reserveResult: object(
    { reservation: ref("reservation"), recipientPinEstablished: { type: "boolean" } },
    ["reservation", "recipientPinEstablished"],
  ),
  // Exactly `Tx402Error.toJSON()` on the store-error path, or the minimal `{ code, details }` a
  // gateway condition returns. `code` is one of the frozen taxonomy codes — no new identity (§12.5).
  wireError: object(
    {
      name: { type: "string" },
      code: { enum: TX402_ERROR_TAXONOMY.map((descriptor) => descriptor.code) },
      message: { type: "string" },
      retryable: { type: "boolean" },
      retryability: { type: "string" },
      context: { type: "object" },
      details: { type: "object" },
    },
    ["code"],
  ),
};

/** `{ result: <schema> }`. */
function resultEnvelope(result: Schema): Schema {
  return object({ result }, ["result"]);
}
/** `{ error: <Tx402Error.toJSON()> }`. */
const errorEnvelope: Schema = object({ error: ref("wireError") }, ["error"]);
/** A response is a success envelope OR the error envelope. */
function response(result: Schema): Schema {
  return { oneOf: [resultEnvelope(result), errorEnvelope] };
}

const voidResult: Schema = { type: "null" };

/** The request/response schema pair for every method (§12.5). */
const methodSchemas: Record<string, { request: Schema; response: Schema }> = {
  reserve: {
    request: object(
      {
        // Optional (not in the required list below), but non-empty WHEN present (O52): an
        // explicit "" would defeat the store's UUID fallback and matches commit/release/expose,
        // which already require a non-empty reservationId.
        reservationId: nonEmpty,
        requestId: nonEmpty,
        policyScope: nonEmpty,
        requestFingerprint: { type: "string" },
        assetId: nonEmpty,
        amountAtomic: ref("atomicAmount"),
        maxPerHourAtomic: ref("atomicAmount"),
        maxTotalAtomic: ref("atomicAmount"),
        recipientNetwork: { type: "string" },
        recipientCanonical: { type: "string" },
        recipientEnforcement: { enum: ["off", "allowlist", "tofu"] },
        nowEpochMs: epochMs,
      },
      [
        "requestId",
        "policyScope",
        "requestFingerprint",
        "assetId",
        "amountAtomic",
        "maxPerHourAtomic",
        "nowEpochMs",
      ],
    ),
    response: response(ref("reserveResult")),
  },
  commit: {
    request: object(
      {
        ref: ref("reservationRef"),
        committedAtEpochMs: epochMs,
        settlementId: { type: "string" },
      },
      ["ref", "committedAtEpochMs"],
    ),
    response: response(ref("entry")),
  },
  release: {
    request: object({ ref: ref("reservationRef"), nowEpochMs: epochMs }, [
      "ref",
      "nowEpochMs",
    ]),
    response: response(ref("reservation")),
  },
  expose: {
    request: object({ ref: ref("reservationRef"), nowEpochMs: epochMs }, [
      "ref",
      "nowEpochMs",
    ]),
    response: response(ref("reservation")),
  },
  getBudgetState: {
    request: object({ policyScope: nonEmpty, assetId: nonEmpty, nowEpochMs: epochMs }, [
      "policyScope",
      "assetId",
      "nowEpochMs",
    ]),
    response: response(ref("budgetState")),
  },
  listExposed: {
    request: object({ policyScope: nonEmpty, assetId: nonEmpty, nowEpochMs: epochMs }, [
      "policyScope",
      "assetId",
      "nowEpochMs",
    ]),
    response: response({ type: "array", items: ref("reservation") }),
  },
  isFrozen: {
    request: object({ scope: nonEmpty }, ["scope"]),
    response: response({ type: "boolean" }),
  },
  getRecipientPins: {
    request: object({ scope: nonEmpty, network: nonEmpty }, ["scope", "network"]),
    response: response({ type: "array", items: { type: "string" } }),
  },
  getRecipientPolicy: {
    request: object({ scope: nonEmpty }, ["scope"]),
    response: response(ref("recipientPolicy")),
  },
  capabilities: {
    request: object({}, []),
    response: response(ref("capabilities")),
  },
  freeze: {
    request: object({ scope: nonEmpty, nowEpochMs: epochMs }, ["scope", "nowEpochMs"]),
    response: response(voidResult),
  },
  unfreeze: {
    request: object({ scope: nonEmpty, nowEpochMs: epochMs }, ["scope", "nowEpochMs"]),
    response: response(voidResult),
  },
  setRecipientPins: {
    request: object(
      {
        scope: nonEmpty,
        network: nonEmpty,
        recipients: { type: "array", items: { type: "string" } },
        nowEpochMs: epochMs,
      },
      ["scope", "network", "recipients", "nowEpochMs"],
    ),
    response: response(voidResult),
  },
  setBudgetLimits: {
    request: object(
      {
        scope: nonEmpty,
        assetId: nonEmpty,
        limits: ref("budgetLimits"),
        nowEpochMs: epochMs,
      },
      ["scope", "assetId", "limits", "nowEpochMs"],
    ),
    response: response(voidResult),
  },
  getBudgetLimits: {
    request: object({ scope: nonEmpty, assetId: nonEmpty }, ["scope", "assetId"]),
    response: response(ref("budgetLimits")),
  },
  setRecipientAssertionRequired: {
    request: object(
      { scope: nonEmpty, required: { type: "boolean" }, nowEpochMs: epochMs },
      ["scope", "required", "nowEpochMs"],
    ),
    response: response(voidResult),
  },
  setTofuEnabled: {
    request: object(
      { scope: nonEmpty, enabled: { type: "boolean" }, nowEpochMs: epochMs },
      ["scope", "enabled", "nowEpochMs"],
    ),
    response: response(voidResult),
  },
  resolveExposed: {
    request: object(
      {
        ref: ref("reservationRef"),
        outcome: { enum: ["committed", "released"] },
        nowEpochMs: epochMs,
      },
      ["ref", "outcome", "nowEpochMs"],
    ),
    response: response(voidResult),
  },
  resetCumulative: {
    request: object({ scope: nonEmpty, assetId: nonEmpty, nowEpochMs: epochMs }, [
      "scope",
      "assetId",
      "nowEpochMs",
    ]),
    response: response(voidResult),
  },
};

/**
 * The complete wire schema, one JSON Schema document with a `$defs` section and a `methods` map of
 * `{ request, response }` per method. `additionalProperties: false` throughout, so the named-field
 * discipline is enforceable. Exported so an operator can validate a gateway implementation and so
 * the golden can pin it.
 */
export const GATEWAY_WIRE_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: `https://tx402.io/schemas/gateway/v${GATEWAY_PROTOCOL_VERSION}.json`,
  title: "tx402 capability gateway wire protocol",
  version: GATEWAY_PROTOCOL_VERSION,
  $defs,
  methods: methodSchemas,
} as const;

/** Every method the schema covers, in wire order (data plane then admin plane). */
export const GATEWAY_ALL_METHODS: readonly string[] = [
  ...GATEWAY_DATA_METHODS,
  ...GATEWAY_ADMIN_METHODS,
];

/** The `$defs` a `$ref` resolves against — passed to {@link matchesWireSchema}. */
export const GATEWAY_WIRE_DEFS: Record<string, Schema> = $defs;

/** The request-body schema for `method`, or `undefined` if it is not a gateway method. */
export function gatewayRequestSchema(method: string): Schema | undefined {
  return methodSchemas[method]?.request;
}

/** The response-envelope (`oneOf` result/error) schema for `method`, or `undefined`. */
export function gatewayResponseSchema(method: string): Schema | undefined {
  return methodSchemas[method]?.response;
}
