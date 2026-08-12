/**
 * A tiny, dependency-free JSON-Schema-subset validator for the capability-gateway wire protocol
 * (SPEC §12.5). `ajv` is a dev-only dependency (it validates the golden in tests), so it is NOT
 * available to consumers of the `tx402/gateway` subpath at runtime — the gateway therefore cannot
 * import it. This validator covers exactly the keyword subset the wire schema in `./schema.ts` uses
 * (`type`, `properties`, `required`, `additionalProperties: false`, `$ref`, `pattern`, `minLength`,
 * `maxLength`, `minimum`, `enum`, `items`, `oneOf`), so the same schema that pins the golden also
 * enforces the wire contract at runtime:
 *
 * - a gateway validates each request body against `methods[method].request` BEFORE dispatch, so a
 *   missing/mistyped/extra field or an over-width amount is a `400` instead of reaching the store as
 *   an `undefined` argument (O23); and
 * - a client validates each response envelope against `methods[method].response`, so a mistyped
 *   result (a string `"false"` where a boolean is required) or a malformed error is rejected as a
 *   protocol violation instead of being coerced (O24).
 *
 * It is intentionally structural (no format/number-bound features beyond `minimum`, no `$id`
 * resolution): the schema is closed and known, and `test/gateway-validate.test.ts` pins that this
 * validator agrees with `ajv` (2020-12) on ACCEPT and REJECT over the full cross-product of every
 * method's request AND response schema × every committed golden body, plus targeted reject mutations
 * (extra field, over-width amount, string-for-boolean, two-key envelope). It is the security
 * boundary, so a divergence from `ajv` — in either direction — fails that suite (O23/O24/O39).
 */

type Schema = Record<string, unknown>;

function resolveRef(schema: Schema, defs: Record<string, Schema>): Schema {
  const ref = schema["$ref"];
  if (typeof ref === "string" && ref.startsWith("#/$defs/")) {
    const target = defs[ref.slice("#/$defs/".length)];
    return target ?? {};
  }
  return schema;
}

/**
 * Whether `value` satisfies `schemaIn` under `defs` ($defs for `$ref` resolution). Returns a boolean
 * only — the gateway needs a yes/no decision, not a path. Unknown keywords are ignored (an empty or
 * type-less schema accepts anything), which is safe because the wire schema uses only the subset
 * documented above.
 */
export function matchesWireSchema(
  schemaIn: Schema,
  value: unknown,
  defs: Record<string, Schema>,
): boolean {
  const schema = resolveRef(schemaIn, defs);

  const oneOf = schema["oneOf"];
  if (Array.isArray(oneOf)) {
    return oneOf.some((sub) => matchesWireSchema(sub as Schema, value, defs));
  }

  const enumValues = schema["enum"];
  if (Array.isArray(enumValues)) {
    return enumValues.some((allowed) => allowed === value);
  }

  switch (schema["type"] as string | undefined) {
    case "null":
      return value === null;
    case "boolean":
      return typeof value === "boolean";
    case "integer": {
      if (typeof value !== "number" || !Number.isInteger(value)) return false;
      const minimum = schema["minimum"];
      if (typeof minimum === "number" && value < minimum) return false;
      return true;
    }
    case "string": {
      if (typeof value !== "string") return false;
      const minLength = schema["minLength"];
      if (typeof minLength === "number" && value.length < minLength) return false;
      const maxLength = schema["maxLength"];
      if (typeof maxLength === "number" && value.length > maxLength) return false;
      const pattern = schema["pattern"];
      if (typeof pattern === "string" && !new RegExp(pattern, "u").test(value))
        return false;
      return true;
    }
    case "array": {
      if (!Array.isArray(value)) return false;
      const items = schema["items"];
      if (items === undefined) return true;
      return value.every((element) => matchesWireSchema(items as Schema, element, defs));
    }
    case "object": {
      if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
      const object = value as Record<string, unknown>;
      const properties = (schema["properties"] as Record<string, Schema> | undefined) ?? {};
      const required = (schema["required"] as string[] | undefined) ?? [];
      for (const key of required) {
        if (!(key in object)) return false;
      }
      if (schema["additionalProperties"] === false) {
        for (const key of Object.keys(object)) {
          if (!(key in properties)) return false;
        }
      }
      for (const [key, propertySchema] of Object.entries(properties)) {
        if (key in object && !matchesWireSchema(propertySchema, object[key], defs)) {
          return false;
        }
      }
      return true;
    }
    default:
      // No `type` (and no `enum`/`oneOf`): e.g. `{ type: "object" }` handled above; a bare `{}`
      // accepts any value (used for free-form `context`/`details`).
      return true;
  }
}
