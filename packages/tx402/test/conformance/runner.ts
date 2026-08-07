/**
 * TypeScript conformance runner (ADR-005).
 *
 * Implements the two-stage contract in `core-spec/conformance/README.md`. The Python runner
 * at `packages/tx402-python/tests/conformance/runner.py` is a direct counterpart — the two
 * are kept structurally parallel on purpose, so that a reviewer comparing them can see at a
 * glance that neither language is quietly skipping something.
 *
 * This file is test-only. Nothing it imports — `ajv` in particular — may reach the SDK's
 * core import path, which is size-gated by ADR-008.
 */

import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Ajv2020 } from "ajv/dist/2020.js";
import type { ValidateFunction } from "ajv";
import ajvFormats from "ajv-formats";

/**
 * `ajv-formats` is CommonJS with `module.exports = formatsPlugin`. Node's ESM interop hands
 * back the function, but TypeScript reads the package's `export default` declaration as the
 * module namespace. Reconcile the two once, here, rather than at the call site.
 */
const addFormats = ajvFormats as unknown as (ajv: Ajv2020) => void;

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(here, "../../../..");
const SCHEMAS_DIR = path.join(REPO_ROOT, "core-spec/schemas");
const CONFORMANCE_DIR = path.join(REPO_ROOT, "core-spec/conformance");

/**
 * The milestone this language implements through.
 *
 * Every vector at or below it must have a Stage B handler; the runner fails otherwise.
 * Raising this constant is how a milestone is claimed, and it cannot be raised without
 * registering the handlers.
 */
export const IMPLEMENTED_THROUGH: Milestone = "M6";

export type Milestone = "M0" | "M1" | "M2" | "M3" | "M4" | "M5" | "M6" | "M7" | "M8";

const MILESTONE_ORDER: readonly Milestone[] = [
  "M0",
  "M1",
  "M2",
  "M3",
  "M4",
  "M5",
  "M6",
  "M7",
  "M8",
];

export function milestoneIsImplemented(milestone: Milestone): boolean {
  return MILESTONE_ORDER.indexOf(milestone) <= MILESTONE_ORDER.indexOf(IMPLEMENTED_THROUGH);
}

/* ------------------------------------------------------------------------------------- */
/* Index and vector loading                                                                */
/* ------------------------------------------------------------------------------------- */

export interface IndexEntry {
  id: string;
  kind: string;
  milestone: Milestone;
  file: string;
  sha256: string;
}

export interface ConformanceVector {
  id: string;
  kind: string;
  milestone: Milestone;
  title: string;
  description?: string;
  spec: string[];
  input?: unknown;
  expected?: unknown;
}

export interface LoadedVector {
  entry: IndexEntry;
  /** The vector with `$schema` stripped — that key is an editor affordance, not format. */
  vector: ConformanceVector;
  /** SHA-256 of the file's exact bytes, for comparison against the index. */
  actualSha256: string;
}

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(file, "utf8"));
}

/**
 * Loads the index and every vector it names.
 *
 * Deliberately reads through the index rather than globbing: a vector removed from disk but
 * left in the index must fail loudly, and one added to disk but never indexed must not run.
 */
export function loadVectors(): LoadedVector[] {
  const index = readJson(path.join(CONFORMANCE_DIR, "index.json")) as {
    formatVersion: number;
    vectors: IndexEntry[];
  };

  if (index.formatVersion !== 1) {
    throw new Error(`Unsupported conformance index formatVersion ${index.formatVersion}`);
  }

  return index.vectors.map((entry) => {
    const file = path.join(CONFORMANCE_DIR, entry.file);
    const bytes = readFileSync(file);
    const { $schema: _schema, ...vector } = JSON.parse(bytes.toString("utf8")) as Record<
      string,
      unknown
    >;

    return {
      entry,
      vector: vector as unknown as ConformanceVector,
      actualSha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
    };
  });
}

/* ------------------------------------------------------------------------------------- */
/* Schema registry                                                                         */
/* ------------------------------------------------------------------------------------- */

const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);
for (const entry of readdirSync(SCHEMAS_DIR)) {
  if (entry.endsWith(".schema.json")) {
    ajv.addSchema(readJson(path.join(SCHEMAS_DIR, entry)) as object);
  }
}

/** Compiled validator for a schema `$id` under `https://tx402.dev/schemas/v1/`. */
export function schema(name: string): ValidateFunction {
  const validate = ajv.getSchema(`https://tx402.dev/schemas/v1/${name}.schema.json`);
  if (!validate) throw new Error(`No such schema: ${name}`);
  return validate;
}

/** Renders ajv errors as something a human can act on. */
export function describeErrors(validate: ValidateFunction): string {
  return (validate.errors ?? [])
    .map((error) => `${error.instancePath || "/"} ${error.message ?? ""}`)
    .join("; ");
}

/* ------------------------------------------------------------------------------------- */
/* Stage A — validate the vector itself                                                    */
/* ------------------------------------------------------------------------------------- */

const commonSchema = readJson(path.join(SCHEMAS_DIR, "common.schema.json")) as {
  $defs: { errorCode: { enum: string[] } };
};

/** The frozen code list, read from the schema rather than from the SDK, so that a rename in
 * the implementation cannot silently redefine what the fixtures are checked against. */
const ERROR_CODES = new Set(commonSchema.$defs.errorCode.enum);

/**
 * Collects every `errorCode` a vector expects, wherever it appears in its `expected` shape.
 *
 * Walks rather than reading a fixed path because the expectation shapes differ per kind and
 * will keep differing; a walk cannot fall out of date with a new kind.
 */
function collectErrorCodes(value: unknown, found: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) collectErrorCodes(item, found);
  } else if (typeof value === "object" && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      if (key === "errorCode" && typeof item === "string") found.push(item);
      else collectErrorCodes(item, found);
    }
  }
  return found;
}

export interface StageAResult {
  problems: string[];
}

/**
 * Validates a vector against the frozen schemas and taxonomy.
 *
 * Runs for every vector regardless of milestone. This is what catches a fixture that
 * expects a renamed error code or a normalized shape that no longer validates — long
 * before the code that would produce either exists.
 */
export function stageA(loaded: LoadedVector): StageAResult {
  const problems: string[] = [];
  const { entry, vector, actualSha256 } = loaded;

  if (actualSha256 !== entry.sha256) {
    problems.push(
      `content hash mismatch — the file changed without the index being rebuilt ` +
        `(run: node tools/conformance/index.js build)`,
    );
  }

  if (vector.id !== entry.id)
    problems.push(`id ${vector.id} does not match index id ${entry.id}`);
  if (vector.kind !== entry.kind)
    problems.push(`kind ${vector.kind} does not match the index`);
  if (vector.milestone !== entry.milestone) {
    problems.push(`milestone ${vector.milestone} does not match the index`);
  }

  const validateVector = schema("conformance-vector");
  if (!validateVector(vector)) {
    problems.push(`does not match the vector schema: ${describeErrors(validateVector)}`);
  }

  for (const code of collectErrorCodes(vector.expected)) {
    if (!ERROR_CODES.has(code)) {
      problems.push(`expects error code ${code}, which is not in the frozen taxonomy`);
    }
  }

  // A vector claiming a valid decode must describe a shape the normalized schema accepts.
  const expected = vector.expected as
    { outcome?: string; normalized?: unknown } | undefined;
  if (vector.kind === "protocol.decode-payment-required" && expected?.outcome === "valid") {
    const validateNormalized = schema("normalized-payment-required");
    if (!validateNormalized(expected.normalized)) {
      problems.push(
        `expected.normalized is not a valid NormalizedPaymentRequired: ${describeErrors(validateNormalized)}`,
      );
    }
  }

  return { problems };
}

/* ------------------------------------------------------------------------------------- */
/* Stage B — handler registry                                                              */
/* ------------------------------------------------------------------------------------- */

/**
 * Executes the implementation against a vector.
 *
 * Handlers throw on mismatch — the test harness surfaces the message. Returning a boolean
 * would lose the diff, which is the only genuinely useful part of a conformance failure.
 */
export type StageBHandler = (vector: ConformanceVector) => void | Promise<void>;

const handlers = new Map<string, StageBHandler>();

export function registerHandler(kind: string, handler: StageBHandler): void {
  handlers.set(kind, handler);
}

export function handlerFor(kind: string): StageBHandler | undefined {
  return handlers.get(kind);
}

/** Kinds at or below {@link IMPLEMENTED_THROUGH} that have no handler. Must be empty. */
export function missingHandlers(vectors: LoadedVector[]): string[] {
  const missing = new Set<string>();
  for (const { vector } of vectors) {
    if (milestoneIsImplemented(vector.milestone) && !handlers.has(vector.kind)) {
      missing.add(`${vector.kind} (required by ${vector.milestone})`);
    }
  }
  return [...missing].sort();
}
