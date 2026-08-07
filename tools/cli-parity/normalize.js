/**
 * Shared normalization for the cross-language CLI `--json` parity check (PLAN.md O107).
 *
 * Imported by `tools/cli-parity/index.js` (which generates and checks the golden from the
 * TypeScript CLI) and by `packages/tx402/test/cli-json-parity.test.ts` (which re-derives it
 * from the TypeScript *source*). The Python pin in
 * `packages/tx402-python/tests/test_cli_json_parity.py` reproduces the same set by hand and
 * carries a note that the two must not drift.
 *
 * The keys erased here are exactly those the SDK does not promise to reproduce byte for byte
 * across languages: request and reservation identifiers, wall-clock durations, the
 * latency-derived health score (SPEC §6.4 makes it a function of a fresh probe), the
 * merchant's own response body, and the ephemeral origins in a blocked redirect. Everything
 * else — exit code, route identity, settlement, and the whole of `error` including
 * `error.context` — is compared verbatim, because that is the document the two CLIs promise.
 */

export const VOLATILE_KEYS = new Set([
  "requestId",
  "reservationId",
  "elapsedMs",
  "headerHash",
  "healthScore",
  "body",
  "fromOrigin",
  "toOrigin",
]);

/** @param {unknown} value @returns {unknown} */
export function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const [key, inner] of Object.entries(value)) {
      out[key] =
        VOLATILE_KEYS.has(key) || /EpochMs$/u.test(key) ? "<normalized>" : normalize(inner);
    }
    return out;
  }
  return value;
}
