/**
 * O39 — the dependency-free runtime validator agrees with `ajv`.
 *
 * `matchesWireSchema` (`gateway/validate.ts`) is the gateway's actual security boundary: it runs
 * where `ajv` cannot (the `tx402/gateway` subpath ships no runtime dependency), validating every
 * request before dispatch (O23) and every response envelope before trust (O24). `validate.ts`'s
 * docstring claims a `gateway-validate.test.ts` pins that this hand-written validator AGREES with
 * `ajv` (2020-12) on every committed golden fixture — this file is that test. It compares the two
 * validators' verdicts over the FULL cross-product of every method schema × every golden body (so it
 * exercises ACCEPT *and* REJECT, most cross pairs being rejections), for requests AND responses, and
 * adds targeted reject mutations. Divergence on any pair fails the suite.
 */

import { readFileSync } from "node:fs";

import Ajv2020 from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

import {
  GATEWAY_ALL_METHODS,
  GATEWAY_WIRE_DEFS,
  GATEWAY_WIRE_SCHEMA,
  gatewayRequestSchema,
  gatewayResponseSchema,
} from "../src/gateway/schema.js";
import { matchesWireSchema } from "../src/gateway/validate.js";

const golden = JSON.parse(
  readFileSync(new URL("../../../core-spec/gateway/golden.json", import.meta.url), "utf8"),
) as {
  requests: { op: string; body: unknown }[];
  responses: { condition: string; body: unknown }[];
};

// ajv 2020-12 over a plain-object copy of the SAME embedded schema the runtime validator reads (the
// copy also proves `schema.ts` is what ajv sees). `strict:false` mirrors the golden suite: the
// document carries a custom `methods`/`version` vocabulary ajv rightly ignores.
type ValidateFn = ((data: unknown) => boolean) & { errors?: unknown };
interface AjvLike {
  addSchema(schema: unknown, key?: string): unknown;
  compile(schema: unknown): ValidateFn;
  errorsText(errors?: unknown): string;
}
const AjvCtor = Ajv2020 as unknown as new (options: { strict: boolean }) => AjvLike;
const ajv: AjvLike = new AjvCtor({ strict: false });
const wireSchema = JSON.parse(JSON.stringify(GATEWAY_WIRE_SCHEMA)) as { $id: string };
ajv.addSchema(wireSchema, "gateway");
const ajvRequest = (method: string): ValidateFn =>
  ajv.compile({ $ref: `${wireSchema.$id}#/methods/${method}/request` });
const ajvResponse = (method: string): ValidateFn =>
  ajv.compile({ $ref: `${wireSchema.$id}#/methods/${method}/response` });

/** Assert the two validators return the SAME boolean for `body` against `schema`. */
function expectParity(
  ajvValidate: ValidateFn,
  schema: Record<string, unknown>,
  body: unknown,
  label: string,
): void {
  const ajvVerdict = ajvValidate(body);
  const wireVerdict = matchesWireSchema(schema, body, GATEWAY_WIRE_DEFS);
  expect(
    wireVerdict,
    `${label}: matchesWireSchema=${String(wireVerdict)} ajv=${String(ajvVerdict)} (${ajv.errorsText(
      ajvValidate.errors,
    )})`,
  ).toBe(ajvVerdict);
}

const reserveBody = golden.requests.find((request) => request.op === "reserve")!
  .body as Record<string, unknown>;

describe("O39 — matchesWireSchema agrees with ajv over the gateway golden (accept + reject)", () => {
  it("agrees on every request body against every method's request schema", () => {
    for (const method of GATEWAY_ALL_METHODS) {
      const schema = gatewayRequestSchema(method)!;
      const validate = ajvRequest(method);
      for (const { op, body } of golden.requests) {
        expectParity(validate, schema, body, `request '${op}' vs ${method}/request`);
      }
    }
  });

  it("agrees on every response body against every method's response schema", () => {
    for (const method of GATEWAY_ALL_METHODS) {
      const schema = gatewayResponseSchema(method)!;
      const validate = ajvResponse(method);
      for (const { condition, body } of golden.responses) {
        expectParity(
          validate,
          schema,
          body,
          `response '${condition}' vs ${method}/response`,
        );
      }
    }
  });

  // Targeted mutations both validators MUST reject — the exact O23/O24/O37 shapes the wire contract
  // turns away. Each pairs an ajv verdict with a matchesWireSchema verdict; both must be `false`.
  const REJECTIONS: {
    label: string;
    kind: "request" | "response";
    method: string;
    body: unknown;
  }[] = [
    {
      label: "extra top-level request field",
      kind: "request",
      method: "isFrozen",
      body: { scope: "s", extra: 1 },
    },
    {
      label: "missing required request field",
      kind: "request",
      method: "isFrozen",
      body: {},
    },
    {
      label: "wrong type for a string field",
      kind: "request",
      method: "isFrozen",
      body: { scope: 5 },
    },
    {
      label: "over-width (>78-digit) input amount",
      kind: "request",
      method: "reserve",
      body: { ...reserveBody, amountAtomic: "9".repeat(79) },
    },
    {
      label: "non-integer epoch",
      kind: "request",
      method: "reserve",
      body: { ...reserveBody, nowEpochMs: 1.5 },
    },
    {
      label: "string 'false' where a boolean result is required",
      kind: "response",
      method: "isFrozen",
      body: { result: "false" },
    },
    {
      label: "both error and result keys in one envelope",
      kind: "response",
      method: "isFrozen",
      body: { error: { code: "TX402_TRANSPORT" }, result: true },
    },
    {
      label: "extra key in the result envelope",
      kind: "response",
      method: "isFrozen",
      body: { result: true, extra: 1 },
    },
    {
      label: "unknown error code",
      kind: "response",
      method: "isFrozen",
      body: { error: { code: "TX402_MADE_UP" } },
    },
  ];

  for (const { label, kind, method, body } of REJECTIONS) {
    it(`both validators reject: ${label}`, () => {
      const schema =
        kind === "request" ? gatewayRequestSchema(method)! : gatewayResponseSchema(method)!;
      const validate = kind === "request" ? ajvRequest(method) : ajvResponse(method);
      expect(validate(body), `ajv should reject ${label}`).toBe(false);
      expect(
        matchesWireSchema(schema, body, GATEWAY_WIRE_DEFS),
        `matchesWireSchema should reject ${label}`,
      ).toBe(false);
    });
  }
});
