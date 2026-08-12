/**
 * The Redis Lua atoms MUST be byte-identical across the two SDKs: the TypeScript source
 * `src/redis/lua.ts` and the transcribed Python copy `tx402/stores/_lua.py` are the ONE source of
 * truth for Redis behaviour, addressed by `EVALSHA` — so a single divergent byte would give the two
 * SDKs different `SCRIPT LOAD` shas and silently different semantics. This guard makes that
 * invariant a test (previously it was a manual re-verification, S7b), so the `SET_LIMITS` atom added
 * in S13b — and every future atom — cannot drift.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as lua from "../src/redis/lua.js";

const sha1 = (text: string): string => createHash("sha1").update(text).digest("hex");

describe("Redis Lua atoms are byte-identical across the TS and Python SDKs (§12.2)", () => {
  it("every exported script has an identical sha1 in _lua.py", () => {
    const pySource = readFileSync(
      new URL("../../tx402-python/src/tx402/stores/_lua.py", import.meta.url),
      "utf8",
    );
    // Extract each `NAME = r"""<value>"""` raw string; the captured text IS the script value
    // (leading/trailing newline included), so its sha1 must match the TS export exactly.
    const pyScripts = new Map<string, string>();
    const pattern = /(\w+)\s*=\s*r"""([\s\S]*?)"""/gu;
    for (
      let match = pattern.exec(pySource);
      match !== null;
      match = pattern.exec(pySource)
    ) {
      pyScripts.set(match[1] as string, match[2] as string);
    }

    const tsScripts = Object.entries(lua).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    );
    expect(tsScripts.length).toBeGreaterThanOrEqual(8); // reserve…listExposed + setLimits

    for (const [name, tsText] of tsScripts) {
      const pyText = pyScripts.get(name);
      expect(pyText, `_lua.py is missing the ${name} script`).toBeDefined();
      expect(
        sha1(pyText as string),
        `${name} Lua drifted between the TS and Python SDKs`,
      ).toBe(sha1(tsText));
    }
  });
});
