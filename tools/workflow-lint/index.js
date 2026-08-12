#!/usr/bin/env node
/**
 * Catches GitHub Actions workflow errors that are invisible until a run fails.
 *
 *   node tools/workflow-lint/index.js
 *
 * **Why this exists.** S13's first push produced a run that completed as `failure` with
 * **zero jobs**, no check runs, and no annotations reachable through the API. The cause was
 * one expression: `name: ${{ matrix.os }} (Node ${{ env.NODE_VERSION_DEFAULT }}, …)`. A
 * job-level `name` may not read the `env` context, and GitHub treats that as an *invalid
 * workflow* rather than as an empty interpolation — so the whole file is rejected before any
 * job is created. From the outside that looks nothing like a syntax error: there is no failing
 * step to read, because there is no step.
 *
 * A workflow is the one file in this repository whose mistakes cannot be found by running it
 * locally, which is exactly why it deserves a local check.
 *
 * Checks, in order of how much time each would have saved:
 *
 * 1. **Context restrictions** on `name`, `runs-on`, and `if` at job level. GitHub's allowed
 *    set there is `github`, `needs`, `strategy`, `matrix`, `vars`, `inputs` — notably not
 *    `env` and not `secrets`.
 * 2. **The file parses as YAML at all.**
 * 3. **Every job has `runs-on` and `steps`**, since a job missing either is also rejected
 *    wholesale rather than reported per-job.
 * 4. **A matrix expression refers to a key the matrix declares**, which catches a renamed
 *    matrix axis leaving a dangling `${{ matrix.node }}`.
 * 5. **Any job holding `id-token: write` uses only SHA-pinned actions** (PLAN.md O48). Such
 *    a job can exchange the repository's OIDC identity for publish rights on npm and PyPI,
 *    so an action referenced by a mutable tag is a third party who can rewrite what runs
 *    with those rights. This check is what stops a later edit reintroducing `@v7`: it is
 *    the easy, natural thing to type, and it looks fine in review.
 */

import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const WORKFLOWS = join(ROOT, ".github", "workflows");

// Declared as a dependency of this tool rather than resolved transitively. pnpm's strict
// node_modules layout does not hoist, so a transitive `require` works only by accident of
// what something else happened to install — and would fail in CI, which is the one place
// this check has to run.
const yaml = require("js-yaml");

/** Contexts GitHub permits in job-level `name`, `runs-on`, and `if`. */
const JOB_LEVEL_CONTEXTS = new Set([
  "github",
  "needs",
  "strategy",
  "matrix",
  "vars",
  "inputs",
]);

const CONTEXT = /\$\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z0-9_-]+)/g;

/**
 * Whether a job can mint a publishing credential. `id-token: write` grants the OIDC token used to
 * publish to npm/PyPI; `write-all` grants it (and everything else) too, so both are publish-capable.
 * Both the SHA-pinning check and the O30 gate-dependency check must use this same definition — the
 * O30 check once keyed only on `id-token: write`, so a `write-all` publish job slipped past the
 * `needs:` requirement (O41i).
 */
function isPublishPrivileged(job) {
  const permissions = job?.permissions ?? {};
  return permissions === "write-all" || permissions?.["id-token"] === "write";
}

const problems = [];

for (const file of readdirSync(WORKFLOWS).filter((name) => /\.ya?ml$/u.test(name))) {
  const path = join(WORKFLOWS, file);
  let document;
  try {
    document = yaml.load(readFileSync(path, "utf8"));
  } catch (error) {
    problems.push(`${file}: does not parse as YAML — ${error.message}`);
    continue;
  }

  const jobs = document?.jobs ?? {};
  for (const [id, job] of Object.entries(jobs)) {
    if (job?.["runs-on"] === undefined) {
      problems.push(`${file}: job "${id}" has no runs-on`);
    }
    if (!Array.isArray(job?.steps) && job?.uses === undefined) {
      problems.push(`${file}: job "${id}" has neither steps nor uses`);
    }

    for (const field of ["name", "runs-on", "if"]) {
      const value = job?.[field];
      if (typeof value !== "string") continue;
      for (const [, context] of value.matchAll(CONTEXT)) {
        if (!JOB_LEVEL_CONTEXTS.has(context)) {
          problems.push(
            `${file}: job "${id}" reads the "${context}" context in its \`${field}\`, ` +
              `which GitHub rejects as an invalid workflow (allowed: ` +
              `${[...JOB_LEVEL_CONTEXTS].join(", ")}). The run will complete as a failure ` +
              `with zero jobs and no readable error.`,
          );
        }
      }
    }

    // A job that can mint a publishing credential may not run a mutable reference.
    const privileged = isPublishPrivileged(job);
    if (privileged) {
      for (const step of Array.isArray(job?.steps) ? job.steps : []) {
        const uses = step?.uses;
        if (typeof uses !== "string" || uses.startsWith("./")) continue;
        const reference = uses.split("@")[1] ?? "";
        if (!/^[0-9a-f]{40}$/u.test(reference)) {
          problems.push(
            `${file}: job "${id}" has id-token: write and uses "${uses}", which is not ` +
              "pinned to a 40-character commit SHA. A moved tag in a job that can publish " +
              "is a supply-chain compromise with release rights.",
          );
        }
      }
    }

    const axes = new Set(Object.keys(job?.strategy?.matrix ?? {}));
    if (axes.size > 0) {
      const serialized = JSON.stringify(job);
      for (const [, context, key] of serialized.matchAll(CONTEXT)) {
        // `include`/`exclude` add keys this check cannot see, so only complain when the
        // matrix declares neither — otherwise a legitimate `include`-only axis is a
        // false positive, and a linter that cries wolf gets disabled.
        if (
          context === "matrix" &&
          !axes.has(key) &&
          !axes.has("include") &&
          !axes.has("exclude")
        ) {
          problems.push(
            `${file}: job "${id}" refers to \`matrix.${key}\`, which its matrix does not ` +
              `declare (has: ${[...axes].join(", ")})`,
          );
        }
      }
    }
  }

  // O30: a published release must re-run the durable/gateway gates ON THE TAGGED COMMIT. In the
  // release workflow, every publish job (one holding `id-token: write`) must `needs` those gate
  // jobs — and the gate jobs must exist — so the gate cannot be silently dropped by editing the
  // `needs` list. Only release.yml publishes, so only it is held to this.
  if (file === "release.yml") {
    const REQUIRED_GATES = ["durable-store", "durable-object", "gateway-golden"];
    for (const gate of REQUIRED_GATES) {
      if (jobs[gate] === undefined) {
        problems.push(`${file}: required release gate job "${gate}" is not defined (O30)`);
      }
    }
    for (const [id, job] of Object.entries(jobs)) {
      if (!isPublishPrivileged(job)) continue;
      const declared = job?.needs;
      const needs = Array.isArray(declared)
        ? declared
        : declared === undefined
          ? []
          : [declared];
      const missing = REQUIRED_GATES.filter((gate) => !needs.includes(gate));
      if (missing.length > 0) {
        problems.push(
          `${file}: publish job "${id}" does not \`needs\` the durable/gateway gate(s) ` +
            `${missing.join(", ")} — a tag could publish without proving the durable adapters ` +
            `or the gateway on the tagged commit (O30)`,
        );
      }
    }
  }
}

if (problems.length > 0) {
  console.error("GitHub Actions workflow problems:\n");
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}

console.log(
  "OK    workflows parse, use valid job-level contexts, and pin every action in a " +
    "publish-capable job",
);
