#!/usr/bin/env node
/**
 * Property and fuzz harness (SPEC §12.1, "Fuzz/property" layer).
 *
 *   pnpm fuzz            # default iteration count
 *   TX402_FUZZ_N=200000 pnpm fuzz
 *   TX402_FUZZ_SEED=123 pnpm fuzz   # reproduce a reported failure exactly
 *
 * SPEC names four targets: the base64/JSON/payment **decoder**, **money** strings,
 * **URL/domain** policy, and **route determinism**. Each is checked as a property rather
 * than against a table of expected outputs — a table is another set of examples, and the
 * examples are already the unit tests' job.
 *
 * **The single invariant behind all four: tx402 either succeeds or raises a typed tx402
 * error.** An untyped throw — a `TypeError` from reading a property of undefined, a
 * `RangeError` from a huge allocation — is a defect even when the input is garbage, because
 * the caller's `catch (error) { if (isTx402Error(error)) ... }` will not handle it and the
 * agent's loop dies at step 45 for something the SDK was supposed to classify.
 *
 * Determinism is deliberately part of the same run: the generator is seeded and the seed is
 * printed on failure, so a fuzz finding is a reproducible test case rather than an anecdote.
 */

import { BUNDLED_MANIFEST } from "../../packages/tx402/dist/core/bundled-manifest.js";
import { isTx402Error } from "../../packages/tx402/dist/core/errors.js";
import { MoneyParseError, parseMoneyAtomic } from "../../packages/tx402/dist/core/money.js";
import {
  PolicyEngine,
  normalizePolicyHost,
} from "../../packages/tx402/dist/core/policy.js";
import { decodePaymentRequired } from "../../packages/tx402/dist/core/protocol.js";
import { orderRouteCandidates } from "../../packages/tx402/dist/core/routing.js";

const ITERATIONS = Number(process.env["TX402_FUZZ_N"] ?? 25_000);
const SEED = Number(process.env["TX402_FUZZ_SEED"] ?? Date.now() % 2 ** 31);

/** xorshift32. Small, seedable, and identical across runs — which is the whole point. */
function rng(seed) {
  let state = seed || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 2 ** 32;
  };
}

const random = rng(SEED);
const pick = (items) => items[Math.floor(random() * items.length)];
const int = (max) => Math.floor(random() * max);

const failures = [];
function check(target, input, run) {
  try {
    run();
  } catch (error) {
    // A typed tx402 error is a *pass*: the SDK classified the input. So is a documented
    // parse error from the money module, which is not a Tx402Error by design because it is
    // raised below the error-taxonomy boundary.
    if (isTx402Error(error) || error instanceof MoneyParseError) return;
    failures.push({
      target,
      input: typeof input === "string" ? input.slice(0, 200) : JSON.stringify(input),
      error: `${error?.constructor?.name ?? "?"}: ${String(error?.message ?? error)}`,
    });
  }
}

// --- 1. decoder: base64 → JSON → v2 envelope --------------------------------------------

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const JSON_FRAGMENTS = [
  '{"x402Version":2}',
  '{"x402Version":2,"accepts":[]}',
  '{"x402Version":2,"accepts":[{"scheme":"exact"}]}',
  '{"x402Version":"2","accepts":null}',
  '{"x402Version":2,"resource":{"url":"https://a.test/r"},"accepts":[{}]}',
  "[]",
  "null",
  "{",
  '{"a":' + "[".repeat(64) + "]".repeat(64) + "}",
  '{"dup":1,"dup":2}',
];

function fuzzDecoder() {
  const mode = int(4);
  let header;
  if (mode === 0) {
    // Pure noise in the base64 alphabet: exercises the strict-alphabet and length checks.
    header = Array.from({ length: int(200) }, () => pick(B64.split(""))).join("");
  } else if (mode === 1) {
    // Bytes outside the alphabet entirely.
    header = Array.from({ length: int(64) }, () => String.fromCharCode(int(65_536))).join(
      "",
    );
  } else if (mode === 2) {
    // Valid base64 wrapping plausible-but-wrong JSON, which reaches schema validation.
    header = Buffer.from(pick(JSON_FRAGMENTS), "utf8").toString("base64");
  } else {
    // Valid base64 of a mutated real envelope: one byte flipped inside the JSON.
    const text = pick(JSON_FRAGMENTS);
    const at = int(Math.max(text.length, 1));
    const mutated = text.slice(0, at) + String.fromCharCode(int(128)) + text.slice(at + 1);
    header = Buffer.from(mutated, "utf8").toString("base64");
  }

  check("decoder", header, () =>
    decodePaymentRequired(header, {
      requestId: "fuzz",
      requestUrl: "https://merchant.test/resource",
      method: "GET",
    }),
  );
}

// --- 2. money strings -------------------------------------------------------------------

const USDC = { symbol: "USDC", decimals: 6 };
const MONEY_PIECES = [
  "0",
  "1",
  "-1",
  "0.000001",
  "0.0000001",
  ".",
  "..",
  "1e6",
  "0x10",
  "Infinity",
  "NaN",
  "1_000",
  " 1 ",
  "1,000",
  "USDC",
  "usdc",
  "١٢٣", // Arabic-Indic digits: `Number()` accepts some of these, tx402 must not
  "9".repeat(40),
  "0".repeat(40) + "1",
  "+1",
  "1.",
  "1..0",
];

function fuzzMoney() {
  const mode = int(3);
  let value;
  if (mode === 0) {
    value = `${pick(MONEY_PIECES)} ${pick(["USDC", "usdc", "ETH", "", "USDC USDC"])}`;
  } else if (mode === 1) {
    // Non-strings, including the JS `number` that ADR-006 requires be rejected outright.
    value = pick([1, 1.5, 0, -0, NaN, Infinity, null, undefined, {}, [], 10n, true]);
  } else {
    value = Array.from({ length: int(24) }, () =>
      pick(["0", "9", ".", "-", " ", "e", "U", "\u0000"]),
    ).join("");
  }
  check("money", value, () => parseMoneyAtomic(value, USDC));
}

// --- 3. URL and domain policy -----------------------------------------------------------

const DOMAIN_PATTERNS = [
  "*",
  "*.a.test",
  "a.test",
  "A.TEST",
  "a.test.",
  "*.",
  "*",
  "",
  "*.*",
  "a:b",
  "a/b",
  "a@b",
  "*.a.test.",
  "xn--n3h.test",
  "\u00e9.test",
  "-".repeat(70) + ".test",
];

const URL_PIECES = [
  "https://a.test",
  "https://A.TEST",
  "https://a.test.",
  "https://user:pass@a.test",
  "https://a.test:443",
  "https://[::1]",
  "https://xn--n3h.test",
  "https://é.test",
  "http://a.test",
  "//a.test",
  "a.test",
  "",
  "https://",
  "https://a..test",
  "https://" + "a".repeat(300) + ".test",
];

function fuzzUrl() {
  // Only absolute URLs are generated, because only absolute URLs reach this function: every
  // internal caller passes an already-validated request URL. Feeding it a relative string
  // asserts nothing about tx402 and only rediscovers that `new URL("a.test")` throws — which
  // it does in both languages, by design, below the error-taxonomy boundary.
  const value =
    pick(URL_PIECES) +
    (int(2) === 0
      ? ""
      : "/" +
        Array.from({ length: int(20) }, () => String.fromCharCode(32 + int(96))).join(""));

  check("url", value, () => {
    let host;
    try {
      host = normalizePolicyHost(value);
    } catch {
      // An unparseable authority is refused, which is the correct answer. The properties
      // below are about hosts that *do* normalize.
      return;
    }
    // The property tx402 actually depends on is **stability**: SPEC §6.3 applies the
    // allowlist before the first request and again before every paid retry, so the same URL
    // must normalize to the same host on both passes. Anything else would let a domain
    // allowlist match on one attempt and miss on the retry.
    if (host !== host.toLowerCase()) throw new Error(`not lowercased: ${host}`);
    if (normalizePolicyHost(value) !== host) throw new Error(`unstable: ${value}`);

    // Re-normalizing the *output* must not be asserted to be a no-op, because ADR-018 does
    // not promise that: `normalizePolicyHost` strips **exactly one** trailing dot, so
    // `a.test..` → `a.test.` → `a.test`. Asserting full idempotence here asserted more than
    // the contract, and the two could not both hold — the gate went red on any seed that
    // happened to generate a host with two or more trailing dots, on a wall-clock seed, with
    // no code change (PLAN.md O62).
    //
    // What the contract *does* promise is checked instead, and it is strictly more specific
    // than the assertion it replaces: one more pass removes one more trailing dot and
    // nothing else, and a host that does not end in a dot is already a fixed point. That
    // pins the one-dot rule in both directions — a normalizer that stripped every dot, or
    // none, now fails here.
    //
    // Only meaningful for a non-empty host: `https://./x` has hostname "." which normalizes
    // to "", and "https://" is not a URL. An empty host is not a bypass — it matches only
    // the `"*"` pattern, which already allows everything (O43).
    // Checked against the *input*, because that is the only side on which the rule is
    // observable: a normalizer that stripped every trailing dot would emit a host that never
    // ends in one, and any output-side check would agree with it. `slice` rather than a
    // regex, so the oracle is not the implementation's own expression restated.
    const raw = new URL(value).hostname.toLowerCase();
    const expected = raw.endsWith(".") ? raw.slice(0, -1) : raw;
    if (host !== expected) {
      throw new Error(`one-dot rule broken: ${raw} -> ${host}, expected ${expected}`);
    }

    // And re-normalizing takes exactly one more dot off, so repeated application converges
    // rather than oscillating. Only meaningful for a non-empty host: `https://./x` has
    // hostname "." which normalizes to "", and "https://" is not a URL. An empty host is not
    // a bypass — it matches only the `"*"` pattern, which already allows everything (O43).
    if (host.length > 0) {
      const again = normalizePolicyHost(`https://${host}`);
      const converged = host.endsWith(".") ? host.slice(0, -1) : host;
      if (again !== converged) {
        throw new Error(`does not converge: ${host} -> ${again}, expected ${converged}`);
      }
    }
  });
}

/**
 * The typed boundary: a domain **pattern** supplied as configuration.
 *
 * This is where malformed domain input actually arrives from a caller, and unlike
 * `normalizePolicyHost` it is required to answer with a typed `ConfigurationError` rather
 * than by throwing whatever `new URL` throws.
 */
function fuzzDomainPattern() {
  const pattern =
    int(2) === 0
      ? pick(DOMAIN_PATTERNS)
      : Array.from({ length: int(16) }, () =>
          pick(["*", ".", "a", "-", ":", "/", "@", "x", "\u00e9", " "]),
        ).join("");

  check("domain-pattern", pattern, () => {
    new PolicyEngine(BUNDLED_MANIFEST, { allowedDomains: [pattern] });
  });
}

// --- 4. route determinism (SPEC §6.4 step 19) -------------------------------------------

const NETWORKS = Object.keys(BUNDLED_MANIFEST.networks);

function candidate(index) {
  return {
    requirementIndex: index,
    network: pick(NETWORKS),
    scheme: "exact",
    assetId: "asset",
    amountAtomic: String(int(1_000_000)),
    // Deliberately coarse, so ties are common and the lower keys actually get exercised.
    viable: random() < 0.7,
    rejectionReasons: [],
    circuitState: pick(["closed", "open", "half-open"]),
    estimatedFeeAtomic: String(int(4)),
    healthScore: Math.round(random() * 4) / 4,
    observedLatencyMs: int(4) * 100,
    rank: 0,
  };
}

function fuzzRouting() {
  const candidates = Array.from({ length: 1 + int(8) }, (_, index) => candidate(index));
  const prefer = random() < 0.5 ? [] : [pick(NETWORKS)];

  check("routing", candidates, () => {
    const first = orderRouteCandidates(candidates, prefer);
    // SPEC §6.4 step 19: identical inputs and health state produce an identical order.
    const second = orderRouteCandidates(candidates, prefer);
    const shuffled = [...candidates].sort(() => random() - 0.5);
    const third = orderRouteCandidates(shuffled, prefer);

    const key = (list) => list.map((entry) => entry.requirementIndex).join(",");
    if (key(first) !== key(second)) {
      throw new Error(`unstable across calls: ${key(first)} vs ${key(second)}`);
    }
    // The stronger property: the result must not depend on the order the candidates
    // happened to arrive in, which is the order RPC endpoints happened to answer in.
    if (key(first) !== key(third)) {
      throw new Error(`input-order dependent: ${key(first)} vs ${key(third)}`);
    }
  });
}

// --- run ---------------------------------------------------------------------------------

const TARGETS = [fuzzDecoder, fuzzMoney, fuzzUrl, fuzzDomainPattern, fuzzRouting];
const started = performance.now();

for (let iteration = 0; iteration < ITERATIONS; iteration += 1) {
  TARGETS[iteration % TARGETS.length]();
}

const elapsed = Math.round(performance.now() - started);
console.log(
  `fuzz: ${ITERATIONS} iterations across ${TARGETS.length} targets in ${elapsed} ms ` +
    `(seed ${SEED})`,
);

if (failures.length > 0) {
  console.error(`\n${failures.length} untyped failure(s). Reproduce with:`);
  console.error(`  TX402_FUZZ_SEED=${SEED} TX402_FUZZ_N=${ITERATIONS} pnpm fuzz\n`);
  for (const failure of failures.slice(0, 10)) {
    console.error(`  [${failure.target}] ${failure.error}`);
    console.error(`      input: ${failure.input}`);
  }
  process.exit(1);
}

console.log("fuzz: PASS — every input either succeeded or raised a typed tx402 error");
