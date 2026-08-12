/**
 * The reference capability gateway's backend-agnostic core (SPEC §12.5). `handleGatewayRequest`
 * turns a `POST /v1/{method}` into a call on the store it fronts and serializes the §12.5 wire
 * response — one function shared by BOTH reference gateways (the Cloudflare Worker fronting a DO,
 * `./worker.ts`; the Node process fronting Redis, `./node.ts`), so the two are byte-identical and
 * the golden pins them both. Isomorphic: web `Request`/`Response` only, no `node:*`/`cloudflare:*`.
 *
 * **The gateway is the durable data/admin boundary (SPEC §9.1).** It holds the raw backend
 * credential server-side (a Redis admin DSN, or the DO admin token via `TX402_DO_ADMIN_SECRET`) and
 * exposes only capabilities to callers, authenticated by an opaque bearer token whose scope it
 * checks PER METHOD: a data token reaches the data methods; an admin method attempted with a data
 * token is refused `403` before the backend is ever touched. This closes the admin-state tampering
 * path (a client cannot unfreeze itself, override a pin, or raise a limit). It does NOT close the
 * compromised-application spending path — that is 0.3.0 (SPEC §1).
 *
 * **Error discipline (SPEC §12.5).** A tx402 typed error the STORE raised (frozen, over-cap,
 * unpinned, a lifecycle/not-found/admin `ConfigurationError`) is a domain outcome and comes back at
 * HTTP 200 as `{ error: Tx402Error.toJSON() }` — the client rethrows the exact typed error. Only
 * UNAVAILABILITY (a store outage, a backend `TransportError`, an unexpected throw) is a `503` with
 * `causeCategory: "gateway-unavailable"`, so `5xx` stays reserved for the transport layer.
 */

import { isTx402Error, TX402_ERROR_CODES } from "../core/errors.js";
import type { RecipientPinStore, SpendStore, SpendStoreAdmin } from "../core/ledger.js";
import { GATEWAY_WIRE_DEFS, gatewayRequestSchema } from "./schema.js";
import { matchesWireSchema } from "./validate.js";
import {
  GATEWAY_PROTOCOL_VERSION,
  GATEWAY_VERSION_HEADER,
  gatewayPlane,
  isGatewayMethod,
  refFromWire,
  type GatewayMethod,
  type GatewayScope,
  type WireReservationRef,
} from "./wire.js";

/** The backend a gateway fronts: a data-plane store, an admin store, and a token→scope resolver. */
export interface GatewayBackend {
  /** The DATA-plane store (no admin credential). Data methods dispatch here. */
  readonly dataStore: SpendStore & RecipientPinStore;
  /** The ADMIN store (holds the raw admin credential). Admin methods dispatch here. */
  readonly adminStore: SpendStoreAdmin;
  /**
   * Maps a bearer token to its scope, or `undefined` for an unknown token (→ `401`). Build the
   * default two-token resolver with {@link bearerTokenScope}; a deployment may plug its own.
   */
  resolveScope(token: string | undefined): GatewayScope | undefined;
}

/** A JSON request body. The golden validates its shape against the wire schema; here it is read. */
type Json = Record<string, unknown>;

/**
 * The request-body ceiling (O51). The Node gateway caps at the socket before it ever builds the
 * `Request` (`node.ts`); the isomorphic core caps here too, so the Worker gateway — which hands
 * the raw platform `Request` straight to {@link handleGatewayRequest} — is held to the SAME 64 KiB
 * limit instead of buffering + parsing up to the Cloudflare platform bound. Single source of truth:
 * `node.ts` imports this constant.
 */
export const GATEWAY_MAX_REQUEST_BODY_BYTES = 64 * 1024;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A condition response (`400/401/403/426/503`) — an existing taxonomy code, per the §12.5 table. */
function conditionResponse(status: number): Response {
  switch (status) {
    case 400:
      return jsonResponse(400, {
        error: {
          code: TX402_ERROR_CODES.configInvalid,
          details: { configPath: "gateway.request", reason: "gateway-bad-request" },
        },
      });
    case 401:
      return jsonResponse(401, {
        error: {
          code: TX402_ERROR_CODES.configInvalid,
          details: { configPath: "gateway.auth", reason: "gateway-unauthorized" },
        },
      });
    case 403:
      return jsonResponse(403, {
        error: {
          code: TX402_ERROR_CODES.configInvalid,
          details: { configPath: "gateway.auth", reason: "admin-credential-required" },
        },
      });
    case 426:
      return jsonResponse(426, {
        error: {
          code: TX402_ERROR_CODES.configInvalid,
          details: { configPath: "gateway.version", reason: "gateway-version-unsupported" },
        },
      });
    default:
      return jsonResponse(503, {
        error: {
          code: TX402_ERROR_CODES.transport,
          details: { causeCategory: "gateway-unavailable" },
        },
      });
  }
}

/** The `{method}` a `.../v1/{method}` path routes to, or `undefined` if the path is not a v1 method. */
function routeMethod(
  pathname: string,
): { method: string; versionSegment: string } | undefined {
  const parts = pathname.split("/").filter((segment) => segment.length > 0);
  if (parts.length < 2) return undefined;
  const method = parts[parts.length - 1] as string;
  const versionSegment = parts[parts.length - 2] as string;
  return { method, versionSegment };
}

/** The bearer token from an `Authorization: Bearer <token>` header, or `undefined`. */
function bearerToken(request: Request): string | undefined {
  const header = request.headers.get("authorization");
  if (header === null) return undefined;
  const match = /^Bearer (.+)$/u.exec(header);
  return match?.[1];
}

/** Whether the `TX402-Gateway-Version` header names an unknown major (→ `426`). Absent is tolerated. */
function versionRejected(request: Request): boolean {
  const header = request.headers.get(GATEWAY_VERSION_HEADER);
  if (header === null) return false;
  const major = Number.parseInt(header, 10);
  return !Number.isInteger(major) || major !== GATEWAY_PROTOCOL_VERSION;
}

/**
 * Whether the request declares `Content-Type: application/json` (SPEC §12.5). A `charset` parameter
 * is tolerated (`application/json; charset=utf-8`); a missing or non-JSON media type is a `400`, so
 * an arbitrary body can never reach the store just because it happened to parse as JSON (O23).
 */
function isJsonContentType(request: Request): boolean {
  const header = request.headers.get("content-type");
  if (header === null) return false;
  const mediaType = header.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json";
}

async function dispatch(
  method: GatewayMethod,
  body: Json,
  backend: GatewayBackend,
): Promise<unknown> {
  const data = backend.dataStore;
  const admin = backend.adminStore;
  const ref = (): WireReservationRef => body.ref as WireReservationRef;
  switch (method) {
    // ── data plane ──
    case "reserve":
      return data.reserve(body as unknown as Parameters<SpendStore["reserve"]>[0]);
    case "commit":
      return data.commit({
        reservationId: ref().reservationId,
        policyScope: ref().policyScope,
        assetId: ref().assetId,
        committedAtEpochMs: body.committedAtEpochMs as number,
        ...(body.settlementId === undefined
          ? {}
          : { settlementId: body.settlementId as string }),
      });
    case "release":
      return data.release(refFromWire(ref()), body.nowEpochMs as number);
    case "expose":
      return data.expose(refFromWire(ref()), body.nowEpochMs as number);
    case "getBudgetState":
      return data.getBudgetState({
        policyScope: body.policyScope as string,
        assetId: body.assetId as string,
        nowEpochMs: body.nowEpochMs as number,
      });
    case "listExposed":
      return data.listExposed({
        policyScope: body.policyScope as string,
        assetId: body.assetId as string,
        nowEpochMs: body.nowEpochMs as number,
      });
    case "isFrozen":
      return data.isFrozen(body.scope as string);
    case "getRecipientPins":
      return data.getRecipientPins(body.scope as string, body.network as string);
    case "getRecipientPolicy":
      return data.getRecipientPolicy(body.scope as string);
    case "capabilities":
      return { atomicGlobalFreeze: data.capabilities.atomicGlobalFreeze };
    // ── admin plane ──
    case "freeze":
      return admin.freeze(body.scope as string, body.nowEpochMs as number);
    case "unfreeze":
      return admin.unfreeze(body.scope as string, body.nowEpochMs as number);
    case "setRecipientPins":
      return admin.setRecipientPins(
        body.scope as string,
        body.network as string,
        body.recipients as string[],
        body.nowEpochMs as number,
      );
    case "setBudgetLimits":
      return admin.setBudgetLimits(
        body.scope as string,
        body.assetId as string,
        body.limits as Parameters<SpendStoreAdmin["setBudgetLimits"]>[2],
        body.nowEpochMs as number,
      );
    case "getBudgetLimits":
      return admin.getBudgetLimits(body.scope as string, body.assetId as string);
    case "setRecipientAssertionRequired":
      return admin.setRecipientAssertionRequired(
        body.scope as string,
        body.required as boolean,
        body.nowEpochMs as number,
      );
    case "setTofuEnabled":
      return admin.setTofuEnabled(
        body.scope as string,
        body.enabled as boolean,
        body.nowEpochMs as number,
      );
    case "resolveExposed":
      return admin.resolveExposed(
        refFromWire(ref()),
        body.outcome as "committed" | "released",
        body.nowEpochMs as number,
      );
    case "resetCumulative":
      return admin.resetCumulative(
        body.scope as string,
        body.assetId as string,
        body.nowEpochMs as number,
      );
  }
}

/**
 * Serve one `POST /v1/{method}` against the fronted backend (SPEC §12.5). The gates run in order —
 * version (`426`) → routable method + `POST` (`400`) → known token (`401`) → admin scope for an
 * admin method (`403`) → JSON object body (`400`) → dispatch — so no request reaches the backend
 * without a valid credential of sufficient scope.
 */
export async function handleGatewayRequest(
  request: Request,
  backend: GatewayBackend,
): Promise<Response> {
  if (versionRejected(request)) return conditionResponse(426);

  const route = routeMethod(new URL(request.url).pathname);
  if (
    request.method !== "POST" ||
    route === undefined ||
    route.versionSegment !== `v${GATEWAY_PROTOCOL_VERSION}` ||
    !isGatewayMethod(route.method)
  ) {
    return conditionResponse(400);
  }
  const method = route.method;

  const scope = backend.resolveScope(bearerToken(request));
  if (scope === undefined) return conditionResponse(401);
  if (gatewayPlane(method) === "admin" && scope !== "admin") return conditionResponse(403);

  // Content-Type must be application/json (SPEC §12.5), so a non-JSON body cannot slip through.
  if (!isJsonContentType(request)) return conditionResponse(400);

  // Bound the request body (O51): a declared over-cap Content-Length is refused cheaply; a
  // lying/absent one is caught by the actual byte length before the JSON is parsed. Matches the
  // Node gateway's 64 KiB → 400 (`node.ts`), so both transports reject an oversized body.
  const declaredLength = Number(request.headers.get("content-length") ?? "");
  if (Number.isFinite(declaredLength) && declaredLength > GATEWAY_MAX_REQUEST_BODY_BYTES) {
    return conditionResponse(400);
  }
  let body: Json;
  try {
    const raw = await request.arrayBuffer();
    if (raw.byteLength > GATEWAY_MAX_REQUEST_BODY_BYTES) return conditionResponse(400);
    const parsed: unknown = JSON.parse(new TextDecoder().decode(raw));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return conditionResponse(400);
    }
    body = parsed as Json;
  } catch {
    return conditionResponse(400);
  }

  // Enforce the method's named-field request schema BEFORE dispatch: a missing/mistyped/extra field
  // or an over-width (>78-digit) input amount is a 400, never an `undefined`/coerced arg on the store
  // (O23 — e.g. `POST /v1/freeze {}` reaching `isFrozen(undefined)`).
  const requestSchema = gatewayRequestSchema(method);
  if (
    requestSchema === undefined ||
    !matchesWireSchema(requestSchema, body, GATEWAY_WIRE_DEFS)
  ) {
    return conditionResponse(400);
  }

  try {
    const result = await dispatch(method, body, backend);
    // A void admin op returns `undefined` → `{ result: null }`; everything else its value (§12.5).
    return jsonResponse(200, { result: result ?? null });
  } catch (error) {
    // A DOMAIN refusal round-trips at 200 as the exact typed error; only UNAVAILABILITY is 5xx —
    // a backend TransportError or any non-tx402 throw is an outage (SPEC §12.5).
    if (isTx402Error(error) && error.code !== TX402_ERROR_CODES.transport) {
      return jsonResponse(200, { error: error.toJSON() });
    }
    return conditionResponse(503);
  }
}

/** A constant-time string compare, so token matching does not leak length/prefix by timing. */
function timingSafeEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const max = Math.max(a.length, b.length);
  for (let index = 0; index < max; index += 1) {
    diff |= (a.charCodeAt(index) || 0) ^ (b.charCodeAt(index) || 0);
  }
  return diff === 0;
}

/**
 * The default two-token scope resolver (SPEC §12.5): the admin token → `admin`, the data token →
 * `data`, anything else → `undefined` (an unknown token is `401`). Tokens are opaque bearer strings,
 * never a Redis/DO credential; the compare is constant-time. An empty configured token is ignored
 * (so an unset admin token cannot be matched by an empty bearer).
 */
export function bearerTokenScope(tokens: {
  readonly dataToken: string;
  readonly adminToken: string;
}): (token: string | undefined) => GatewayScope | undefined {
  return (token) => {
    if (token === undefined || token.length === 0) return undefined;
    if (tokens.adminToken.length > 0 && timingSafeEqual(token, tokens.adminToken)) {
      return "admin";
    }
    if (tokens.dataToken.length > 0 && timingSafeEqual(token, tokens.dataToken)) {
      return "data";
    }
    return undefined;
  };
}
