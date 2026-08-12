/**
 * The gateway wire golden (SPEC §12.5, ADR-023/024). `tools/gateway-golden` generates and
 * drift-checks `core-spec/gateway/golden.json`; this suite pins the two properties that make the
 * golden meaningful:
 *
 *  1. **Schema conformance** — every committed request/response body validates against the embedded
 *     `GATEWAY_WIRE_SCHEMA` (ajv 2020-12), so the named-field discipline and the nested
 *     `ReservationRef` triple are enforceable, not just documented.
 *  2. **Client mapping** — for every response fixture the `httpGatewaySpendStore` client raises the
 *     EXACT typed error the golden records (an existing taxonomy code — no `TX402_GATEWAY_FORBIDDEN`)
 *     or returns the success value. The Python client is held to the same golden in
 *     `tests/test_gateway_store.py`, so the two clients are interoperable.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

import { HttpGatewaySpendStore, type GatewayFetch } from "../src/gateway/index.js";

const goldenPath = fileURLToPath(
  new URL("../../../core-spec/gateway/golden.json", import.meta.url),
);
const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as {
  protocolVersion: number;
  schema: Record<string, unknown> & { $id: string; methods: Record<string, unknown> };
  requests: { op: string; scope: string; path: string; body: unknown }[];
  responses: {
    condition: string;
    status: number;
    body: unknown;
    outcome: {
      kind: "raise" | "result";
      name?: string;
      code?: string;
      retryable?: boolean;
      details?: unknown;
    };
  }[];
};

// `ajv/dist/2020.js` ships loose types (its default export resolves to `any`); pin the small
// surface we use so the type-aware linter has real types rather than unsafe `any`.
type ValidateFn = ((data: unknown) => boolean) & { errors?: unknown };
interface AjvLike {
  addSchema(schema: unknown, key?: string): unknown;
  compile(schema: unknown): ValidateFn;
  errorsText(errors?: unknown): string;
}
const AjvCtor = Ajv2020 as unknown as new (options: {
  strict: boolean;
  allErrors: boolean;
}) => AjvLike;
const ajv: AjvLike = new AjvCtor({ strict: false, allErrors: true });
ajv.addSchema(golden.schema, "gateway");
const validator = (pointer: string): ValidateFn =>
  ajv.compile({ $ref: `${golden.schema.$id}#/${pointer}` });

const CAPS = Object.freeze({ atomicGlobalFreeze: false });
function cannedFetch(status: number, body: unknown): GatewayFetch {
  return () => Promise.resolve({ status, json: () => Promise.resolve(body) });
}
function client(fetch: GatewayFetch): HttpGatewaySpendStore {
  return new HttpGatewaySpendStore({
    baseUrl: "http://gw",
    token: "t",
    capabilities: CAPS,
    fetch,
  });
}

const ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const SCOPE = "merchant.example";

describe("gateway wire golden (SPEC §12.5)", () => {
  it("declares protocol version 1 and one request fixture per schema method", () => {
    expect(golden.protocolVersion).toBe(1);
    const methods = Object.keys(golden.schema.methods);
    expect(golden.requests.map((request) => request.op).sort()).toEqual(
      [...methods].sort(),
    );
  });

  it("every request body validates against its method's request schema", () => {
    for (const request of golden.requests) {
      const validate = validator(`methods/${request.op}/request`);
      expect(
        validate(request.body),
        `${request.op} request: ${ajv.errorsText(validate.errors)}`,
      ).toBe(true);
    }
  });

  // The success fixtures each name a representative method whose response schema they must satisfy.
  const SUCCESS_METHOD: Record<string, string> = {
    "reserve-success": "reserve",
    "commit-success": "commit",
    "void-success": "freeze",
    "capabilities-success": "capabilities",
  };

  it("every response body validates against a method response schema (success) or the error envelope", () => {
    const errorEnvelope = {
      type: "object",
      required: ["error"],
      properties: { error: { $ref: `${golden.schema.$id}#/$defs/wireError` } },
      additionalProperties: false,
    };
    const validateError = ajv.compile(errorEnvelope);
    for (const response of golden.responses) {
      if (response.outcome.kind === "result") {
        const method = SUCCESS_METHOD[response.condition];
        expect(method, `no method mapped for ${response.condition}`).toBeDefined();
        const validate = validator(`methods/${method}/response`);
        expect(
          validate(response.body),
          `${response.condition}: ${ajv.errorsText(validate.errors)}`,
        ).toBe(true);
      } else {
        expect(
          validateError(response.body),
          `${response.condition}: ${ajv.errorsText(validateError.errors)}`,
        ).toBe(true);
      }
    }
  });

  it("the client raises the exact typed error each error fixture records", async () => {
    for (const response of golden.responses) {
      if (response.outcome.kind !== "raise") continue;
      const c = client(cannedFetch(response.status, response.body));
      let error: unknown;
      try {
        await c.isFrozen(SCOPE);
      } catch (caught) {
        error = caught;
      }
      const typed = error as {
        name: string;
        code: string;
        retryable: boolean;
        details: unknown;
      };
      expect(typed, `${response.condition} did not raise`).toBeInstanceOf(Error);
      expect(typed.name, response.condition).toBe(response.outcome.name);
      expect(typed.code, response.condition).toBe(response.outcome.code);
      expect(typed.retryable, response.condition).toBe(response.outcome.retryable);
      expect(typed.details, response.condition).toEqual(response.outcome.details);
    }
  });

  it("the client returns the success value each result fixture records", async () => {
    const byCondition = new Map(golden.responses.map((r) => [r.condition, r]));
    const reserve = byCondition.get("reserve-success")!;
    const reserved = await client(cannedFetch(200, reserve.body)).reserve({
      reservationId: "res-1",
      requestId: "req-1",
      policyScope: SCOPE,
      requestFingerprint: `sha256:${"0".repeat(64)}`,
      assetId: ASSET,
      amountAtomic: "1500",
      maxPerHourAtomic: "1000000",
      nowEpochMs: 1_800_000_000_000,
    });
    expect(reserved.reservation.state).toBe("reserved");
    expect(reserved.recipientPinEstablished).toBe(false);

    const caps = byCondition.get("capabilities-success")!;
    expect(await client(cannedFetch(200, caps.body)).requestCapabilities()).toEqual({
      atomicGlobalFreeze: false,
    });

    const voidFixture = byCondition.get("void-success")!;
    await expect(
      client(cannedFetch(200, voidFixture.body)).freeze(SCOPE, 1_800_000_000_000),
    ).resolves.toBeUndefined();
  });
});
