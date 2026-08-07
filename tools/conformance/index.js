#!/usr/bin/env node
/**
 * Conformance fixture index builder and integrity checker (ADR-005, SEC-007).
 *
 *   tx402-conformance build   rewrite core-spec/conformance/index.json from the vectors
 *   tx402-conformance check   verify the index matches what is on disk (CI, exit 1 on drift)
 *
 * The index exists so that the runners have something to trust. A runner that merely
 * globbed the vectors directory would silently pass if a vector were deleted, and would
 * silently execute one that had been edited — neither is acceptable for artifacts SEC-007
 * requires to be integrity-checked before release.
 *
 * `build` also validates every vector against `conformance-vector.schema.json`, so a
 * malformed fixture is caught here rather than as a confusing failure inside two different
 * language runners.
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../..");
const schemasDir = path.join(repoRoot, "core-spec/schemas");
const conformanceDir = path.join(repoRoot, "core-spec/conformance");
const vectorsDir = path.join(conformanceDir, "vectors");
const indexPath = path.join(conformanceDir, "index.json");

/** The format generation of index.json itself. Bumped only if its shape changes. */
const FORMAT_VERSION = 1;

/** @param {string} file */
function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/**
 * Hashes the file's exact bytes, not a re-serialization of its contents. Reformatting a
 * vector is a change to the fixture set and should be visible as one.
 *
 * @param {string} file
 */
function hashFile(file) {
  return `sha256:${createHash("sha256").update(readFileSync(file)).digest("hex")}`;
}

/** @param {string} dir @returns {string[]} repo-relative paths, sorted */
function findVectors(dir) {
  /** @type {string[]} */
  const found = [];
  for (const entry of readdirSync(dir).sort()) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      found.push(...findVectors(full));
    } else if (entry.endsWith(".json")) {
      found.push(full);
    }
  }
  return found;
}

/* ------------------------------------------------------------------------------------- */
/* Prose claims about how many vectors there are (PLAN.md open item **O59**)              */
/* ------------------------------------------------------------------------------------- */

/**
 * The failure this exists to stop. ADR-016 took the suite from 65 to 67 vectors at S15b and
 * updated the index, the runners, and one README. Seven other release-facing documents went
 * on telling readers there were 65 — including the parity guarantee in `VERSIONING.md` and
 * the dependency-bump promise in `SECURITY.md` — and the S15c audit found them by hand
 * (O59). A number that appears in eight documents and is derived in none of them is a
 * number that will go stale again.
 *
 * Only **release-facing prose** is scanned. `PLAN.md` and `adr/` are deliberately excluded:
 * they are dated records, and "65 vectors" written about S8 is true and must stay.
 *
 * If a document ever needs to state a historical count, write it so the number is not
 * adjacent to the noun — "65 at the freeze" passes, "65 vectors" does not. The check is
 * intentionally literal; a fuzzy one would be a check nobody trusts.
 */
const CLAIM_FILES = [
  "README.md",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "VERSIONING.md",
  "core-spec/conformance/README.md",
  "packages/tx402/README.md",
  "packages/tx402-python/README.md",
];

/** Directories whose Markdown/MDX pages are scanned in full. */
const CLAIM_DIRS = ["docs/src/content/docs"];

/**
 * A count claim is a 2–4 digit number followed, within a bounded window, by the noun
 * `(conformance )?(vectors|fixtures)`. The window is **structural, not a vocabulary**: any
 * run of letters, whitespace (newlines included), and the continuation markers `>`, `*`,
 * `-` — but no digit and no clause punctuation — so it spans adjectives the check has never
 * seen and a blockquote or list wrap without an allowlist to keep current.
 *
 * That allowlist is the bug this had. Its predecessor enumerated `frozen|shared|
 * cross-language` and matched `conformance` with `\s+`, so `packages/tx402-python/
 * README.md`'s "67 language-neutral … conformance fixtures" escaped twice over —
 * `language-neutral` was not in the list, and the claim wrapped onto a `> ` continuation
 * line that `\s+` cannot cross. The stale number shipped to PyPI while this gate stayed
 * green (O106). Widening the allowlist is what the project has done five times before
 * (O72→O77, O79→O82, O81→O85, O85's guard→O95, ADR-023's principle→O104); the sixth writer
 * picks a sixth adjective. A structural window ends that.
 *
 * The group captures the count. The quantifier is a single bounded lazy class — no nested
 * repetition — so it cannot backtrack catastrophically; a naive nested version was measured
 * to hang.
 */
const CLAIM_RE = /\b(\d{2,4})[A-Za-z\s>*-]{0,60}?(?:vectors|fixtures)\b/giu;

/**
 * The independent half of the guard (the "gate proved something" assertion). A *counting
 * context* uses the same structural window as `CLAIM_RE` but a wider span, so it is a strict
 * superset: whatever `CLAIM_RE` parses, this also spans, and then some. A line that trips
 * this but yields no parsed claim is a phrasing the extractor dropped — filler longer than
 * `CLAIM_RE`'s window — and `claimProblems` fails loud on it rather than reporting a green
 * line that proved nothing.
 *
 * The window keeps `CLAIM_RE`'s class rather than "any character", on purpose: the two
 * documented near-misses — `core-spec/conformance/README.md`'s "M0 vectors" (no two-digit
 * number) and its "six `policy.host-normalization` vectors, added at S15b" (the digit sits
 * behind a code span) — must stay uncaught, exactly as the audit measured. A broader class
 * would flag the `S15b` line and fail on prose that states no count.
 */
const COUNTING_CONTEXT_RE = /\b\d{2,4}[A-Za-z\s>*-]{0,100}?(?:vectors|fixtures)\b/giu;

/** @param {string} dir @returns {string[]} absolute paths to prose files, sorted */
function findProse(dir) {
  /** @type {string[]} */
  const found = [];
  for (const entry of readdirSync(dir).sort()) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) found.push(...findProse(full));
    else if (entry.endsWith(".md") || entry.endsWith(".mdx")) found.push(full);
  }
  return found;
}

/** @param {string} text @param {number} index @returns {number} 1-based line of `index` */
function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

/**
 * Every count claim the structural matcher recognizes, agreeing or not. Recording the
 * agreeing ones too is what lets the caller assert a scanned counting context actually
 * produced a match, rather than reporting success for a file whose only claim slipped past.
 *
 * @param {string} text
 * @returns {{claimed: number, line: number, quote: string}[]}
 */
function findClaims(text) {
  const lines = text.split("\n");
  /** @type {{claimed: number, line: number, quote: string}[]} */
  const claims = [];
  for (const match of text.matchAll(CLAIM_RE)) {
    const line = lineOf(text, match.index);
    claims.push({ claimed: Number(match[1]), line, quote: (lines[line - 1] ?? "").trim() });
  }
  return claims.sort((left, right) => left.line - right.line);
}

/**
 * @param {string} text
 * @param {number} expected
 * @returns {{claimed: number, line: number, quote: string}[]} every disagreeing claim
 */
function staleClaims(text, expected) {
  return findClaims(text).filter((claim) => claim.claimed !== expected);
}

/**
 * Lines that put a number beside the noun but yielded no parseable claim — the silent-escape
 * signature. Returned so the caller can fail on them instead of trusting the extractor's
 * silence.
 *
 * @param {string} text
 * @returns {{line: number, quote: string}[]}
 */
function unmatchedCountingContexts(text) {
  const lines = text.split("\n");
  const claimedLines = new Set(findClaims(text).map((claim) => claim.line));
  /** @type {{line: number, quote: string}[]} */
  const unmatched = [];
  for (const match of text.matchAll(COUNTING_CONTEXT_RE)) {
    const line = lineOf(text, match.index);
    // A claim matched on this line accounts for the context; only an unaccounted-for line is
    // evidence the extractor dropped something.
    if (!claimedLines.has(line))
      unmatched.push({ line, quote: (lines[line - 1] ?? "").trim() });
  }
  return unmatched;
}

/** @param {number} expected @returns {string[]} human-readable problems */
function claimProblems(expected) {
  const files = [
    ...CLAIM_FILES.map((file) => path.join(repoRoot, file)),
    ...CLAIM_DIRS.flatMap((dir) => findProse(path.join(repoRoot, dir))),
  ];
  /** @type {string[]} */
  const problems = [];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    const relative = path.relative(repoRoot, file);
    for (const stale of staleClaims(text, expected)) {
      problems.push(`  ${relative}:${stale.line} claims ${stale.claimed}: ${stale.quote}`);
    }
    // The gate must prove it matched something: a counting context that produced no claim on
    // its line is a phrasing the matcher could not parse, and it fails loud here rather than
    // passing silent (O106).
    for (const context of unmatchedCountingContexts(text)) {
      problems.push(
        `  ${relative}:${context.line} states a vector count the matcher could not parse ` +
          `(rephrase so a 2-4 digit number sits beside "conformance vectors"): ${context.quote}`,
      );
    }
  }
  return problems;
}

function buildValidator() {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  for (const entry of readdirSync(schemasDir)) {
    if (entry.endsWith(".schema.json")) {
      ajv.addSchema(readJson(path.join(schemasDir, entry)));
    }
  }
  return ajv.getSchema("https://tx402.dev/schemas/v1/conformance-vector.schema.json");
}

function collect() {
  const validate = buildValidator();
  if (!validate) throw new Error("conformance-vector.schema.json did not compile");

  const seenIds = new Map();
  const entries = [];

  for (const file of findVectors(vectorsDir)) {
    const relative = path.relative(conformanceDir, file);
    const vector = readJson(file);

    // `$schema` is an editor affordance on the fixture files; it is not part of the format.
    const { $schema: _schema, ...document } = vector;

    if (!validate(document)) {
      const detail = (validate.errors ?? [])
        .map((error) => `      ${error.instancePath || "/"} ${error.message}`)
        .join("\n");
      throw new Error(`${relative} does not match the vector schema:\n${detail}`);
    }

    const previous = seenIds.get(document.id);
    if (previous) {
      throw new Error(`Duplicate vector id ${document.id} in ${relative} and ${previous}`);
    }
    seenIds.set(document.id, relative);

    entries.push({
      id: document.id,
      kind: document.kind,
      milestone: document.milestone,
      file: relative.split(path.sep).join("/"),
      sha256: hashFile(file),
    });
  }

  entries.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  return { formatVersion: FORMAT_VERSION, vectors: entries };
}

function summarize(index) {
  /** @type {Record<string, number>} */
  const byMilestone = {};
  for (const vector of index.vectors) {
    byMilestone[vector.milestone] = (byMilestone[vector.milestone] ?? 0) + 1;
  }
  const counts = Object.entries(byMilestone)
    .sort()
    .map(([milestone, count]) => `${milestone}:${count}`)
    .join("  ");
  console.log(`  ${index.vectors.length} vectors   ${counts}`);
}

function build() {
  const index = collect();
  writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`);
  console.log(`Wrote ${path.relative(repoRoot, indexPath)}`);
  summarize(index);
  return 0;
}

function check() {
  const rebuilt = collect();
  let onDisk;
  try {
    onDisk = readJson(indexPath);
  } catch {
    console.error(
      "FAIL  core-spec/conformance/index.json is missing. Run: tx402-conformance build",
    );
    return 1;
  }

  const expected = new Map(rebuilt.vectors.map((vector) => [vector.id, vector]));
  const actual = new Map((onDisk.vectors ?? []).map((vector) => [vector.id, vector]));
  const problems = [];

  for (const [id, vector] of expected) {
    const recorded = actual.get(id);
    if (!recorded) {
      problems.push(`  added but not indexed:   ${id} (${vector.file})`);
    } else if (recorded.sha256 !== vector.sha256) {
      problems.push(`  content changed:         ${id} (${vector.file})`);
    } else if (recorded.kind !== vector.kind || recorded.milestone !== vector.milestone) {
      problems.push(`  kind or milestone moved: ${id}`);
    }
  }
  for (const id of actual.keys()) {
    if (!expected.has(id)) problems.push(`  indexed but missing:     ${id}`);
  }

  if (onDisk.formatVersion !== FORMAT_VERSION) {
    problems.push(
      `  index formatVersion is ${onDisk.formatVersion}, expected ${FORMAT_VERSION}`,
    );
  }

  if (problems.length > 0) {
    console.error("FAIL  conformance index is out of date:");
    console.error(problems.join("\n"));
    console.error("\n      Run: node tools/conformance/index.js build");
    return 1;
  }

  const stale = claimProblems(rebuilt.vectors.length);
  if (stale.length > 0) {
    console.error(
      `FAIL  documentation claims a vector count other than ${rebuilt.vectors.length}:`,
    );
    console.error(stale.join("\n"));
    return 1;
  }

  // Report what was actually verified, not how many files were opened. The old wording —
  // "${CLAIM_FILES.length} documents … agree" — printed unconditionally, so a claim that
  // matched no pattern was indistinguishable from a claim that agreed (O106).
  const matched = claimMatchCount();
  console.log("OK    conformance index matches the vectors on disk");
  console.log(
    `OK    ${matched} documented vector-count claims all read ${rebuilt.vectors.length}`,
  );
  summarize(rebuilt);
  return 0;
}

/** @returns {number} count claims the matcher actually parsed across every scanned file */
function claimMatchCount() {
  const files = [
    ...CLAIM_FILES.map((file) => path.join(repoRoot, file)),
    ...CLAIM_DIRS.flatMap((dir) => findProse(path.join(repoRoot, dir))),
  ];
  return files.reduce(
    (total, file) => total + findClaims(readFileSync(file, "utf8")).length,
    0,
  );
}

/**
 * Proves the claims check can fail, on fixtures rather than on the repository.
 *
 * A gate that has only ever been observed passing is not evidence of anything — the S15
 * audit's O48. Every case here is a string the scanner must classify, including the ones it
 * must *not* flag, because a check that fires on historical prose gets deleted.
 */
function selftest() {
  // The real suite is 73; a case is flagged if its number disagrees with that, or if it puts
  // a number beside the noun in a way the matcher cannot parse into a claim at all.
  const EXPECTED = 73;
  const filler = "adjective ".repeat(8); // ~80 chars: past CLAIM_RE's window, inside the guard's

  /** @type {[string, string, boolean][]} name, text, expected-to-be-flagged */
  const cases = [
    ["plain claim", "held to 65 conformance vectors today", true],
    ["frozen claim", "**65 frozen conformance vectors** in `core-spec/`", true],
    ["shared claim", "identical behaviour by 65 shared conformance vectors", true],
    ["cross-language claim", "replays all 65 cross-language conformance vectors", true],
    ["bare noun", "holds 65 vectors that both SDKs execute", true],
    ["fixtures spelling", "the 65 conformance fixtures are frozen", true],
    // The class bug itself: an adjective the old allowlist never enumerated.
    ["novel adjective", "65 language-neutral conformance fixtures", true],
    // The exact O106 escape: an unlisted adjective *and* a wrap onto a `> ` continuation.
    ["blockquote-wrapped (O106)", "67 language-neutral\n> conformance fixtures", true],
    ["list-wrapped", "65 shared\n- conformance vectors", true],
    // The guard, not the extractor: a count buried behind filler longer than CLAIM_RE's
    // window still trips COUNTING_CONTEXT_RE, so it must fail loud rather than pass silent.
    ["over-window filler (guard)", `73 ${filler}conformance vectors`, true],
    ["correct count", "All 73 conformance vectors execute in both languages", false],
    ["historical, detached", "73 vectors across M0–M6 — 65 at the freeze", false],
    ["unrelated number", "a 65-byte EVM signature, and 65,537 decoded bytes", false],
    ["unrelated noun", "65 requests per hour", false],
    // The two repository near-misses that must stay uncaught (core-spec/conformance/README).
    [
      "near-miss, code span",
      "the six `policy.host-normalization` vectors, added at S15b",
      false,
    ],
    ["near-miss, one digit", "M0 vectors must execute; M1 is Stage A only", false],
  ];

  let failures = 0;
  for (const [name, text, shouldFlag] of cases) {
    const flagged =
      staleClaims(text, EXPECTED).length > 0 || unmatchedCountingContexts(text).length > 0;
    if (flagged !== shouldFlag) {
      failures += 1;
      console.error(
        `FAIL  ${name}: expected ${shouldFlag ? "a finding" : "no finding"}, got the opposite`,
      );
    }
  }

  if (failures > 0) {
    console.error(`FAIL  ${failures} of ${cases.length} claim self-tests behaved wrongly`);
    return 1;
  }
  console.log(`OK    ${cases.length} claim self-tests behave as specified`);
  return 0;
}

const USAGE = `tx402-conformance — fixture index tooling (ADR-005, SEC-007)

Usage:
  tx402-conformance build      rewrite core-spec/conformance/index.json
  tx402-conformance check      fail if the index, the vectors, or the documented count disagree
  tx402-conformance selftest   prove the documented-count check can fail`;

try {
  const command = process.argv[2];
  if (command === "build") process.exitCode = build();
  else if (command === "check") process.exitCode = check();
  else if (command === "selftest") process.exitCode = selftest();
  else if (command === undefined || command === "-h" || command === "--help") {
    console.log(USAGE);
  } else {
    console.error(`Unknown command: ${command}\n\n${USAGE}`);
    process.exitCode = 2;
  }
} catch (error) {
  console.error(
    `tx402-conformance: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
}
