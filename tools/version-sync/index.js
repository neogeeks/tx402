#!/usr/bin/env node
/**
 * One version, five places, checked (PLAN.md open item **O51**).
 *
 *   node tools/version-sync/index.js build   # write the generated version modules
 *   node tools/version-sync/index.js check   # fail if anything disagrees
 *
 * **The failure this exists to stop.** Both CLIs printed a literal `0.0.0` in a template
 * string, and nothing compared that literal against anything. The release workflow checked
 * the git tag against `package.json` and `pyproject.toml` and stopped there, and its
 * registry smoke ran `tx402 --version` without looking at the output. A correctly tagged
 * and correctly published 0.1.0 would therefore have shipped two binaries that identified
 * themselves as 0.0.0 — and a version string is the first thing anyone pastes into a bug
 * report, so it is the one string that must not be able to lie.
 *
 * **Why generated files rather than reading package metadata at runtime.** Node can read
 * its own `package.json` and Python has `importlib.metadata`, but neither works uniformly:
 * a bundled or vendored CLI has no resolvable `package.json`, and `importlib.metadata`
 * raises for a source tree that was never installed. A file emitted from the single source
 * of truth works in every case, costs nothing at runtime, and — because `check` runs
 * inside `pnpm check` and in CI — cannot go stale without failing the build. It is the same
 * contract `core-spec/conformance/index.json` and the generated docs pages already have.
 *
 * **The source of truth is `packages/tx402/package.json`.** Not the tag: a tag is created
 * after the fact and cannot be consulted while developing. `check` compares, in order:
 *
 *   1. `packages/tx402/package.json`            — the source of truth
 *   2. `packages/tx402-python/pyproject.toml`   — must equal it
 *   3. `packages/tx402/src/version.ts`          — generated
 *   4. `packages/tx402-python/src/tx402/_version.py` — generated
 *   5. `--expect <version>`                     — optional; the release workflow passes the
 *                                                 tag here, so the tag joins the same check
 *                                                 instead of having its own weaker one
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

const NPM_MANIFEST = join(ROOT, "packages/tx402/package.json");
const PYPROJECT = join(ROOT, "packages/tx402-python/pyproject.toml");
const TS_TARGET = join(ROOT, "packages/tx402/src/version.ts");
const PY_TARGET = join(ROOT, "packages/tx402-python/src/tx402/_version.py");

/** SemVer, including the pre-release and build forms a release candidate needs. */
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$/u;

/** @param {string} file */
function read(file) {
  return readFileSync(file, "utf8");
}

/** The npm version: the one source of truth. */
function sourceVersion() {
  const version = JSON.parse(read(NPM_MANIFEST)).version;
  if (typeof version !== "string" || !SEMVER.test(version)) {
    throw new Error(`packages/tx402/package.json version is not semver: ${version}`);
  }
  return version;
}

/**
 * The `version = "..."` of `[project]`, without a TOML parser.
 *
 * Deliberately anchored to the start of a line and to the first occurrence, so a `version`
 * key inside a dependency table cannot be mistaken for the project's own.
 */
function pyprojectVersion() {
  const match = /^version = "([^"]+)"$/mu.exec(read(PYPROJECT));
  if (match?.[1] === undefined) throw new Error("pyproject.toml has no [project] version");
  return match[1];
}

/** @param {string} version */
function tsModule(version) {
  return `/**
 * GENERATED FILE — DO NOT EDIT.
 *
 * Emitted by \`node tools/version-sync/index.js build\` from \`packages/tx402/package.json\`,
 * which is the single source of truth for the released version (PLAN.md O51). Editing this
 * by hand reintroduces exactly the defect it exists to prevent; \`pnpm version:check\` fails
 * if it is stale.
 */

/** The published package version, identical to \`package.json\` and to \`pyproject.toml\`. */
export const PACKAGE_VERSION = "${version}";
`;
}

/** @param {string} version */
function pyModule(version) {
  // Backticks are escaped throughout: this is a template literal emitting reST, and reST
  // marks literals with double backticks.
  const quotes = '"'.repeat(3);
  return `${quotes}GENERATED FILE — DO NOT EDIT.

Emitted by \`\`node tools/version-sync/index.js build\`\` from
\`\`packages/tx402/package.json\`\`, which is the single source of truth for the released
version (PLAN.md O51). Editing this by hand reintroduces exactly the defect it exists to
prevent; \`\`pnpm version:check\`\` fails if it is stale.
${quotes}

from __future__ import annotations

from typing import Final

#: The published package version, identical to \`\`pyproject.toml\`\` and \`\`package.json\`\`.
PACKAGE_VERSION: Final = "${version}"
`;
}

function build() {
  const version = sourceVersion();
  const declared = pyprojectVersion();
  if (declared !== version) {
    throw new Error(
      `pyproject.toml declares ${declared} but package.json declares ${version}. ` +
        "Change both; this tool does not rewrite a hand-maintained manifest.",
    );
  }
  writeFileSync(TS_TARGET, tsModule(version));
  writeFileSync(PY_TARGET, pyModule(version));
  console.log(`tx402-version-sync: wrote ${version} to 2 generated modules`);
}

/** @param {string | undefined} expected */
function check(expected) {
  const version = sourceVersion();
  /** @type {string[]} */
  const problems = [];

  const declared = pyprojectVersion();
  if (declared !== version) {
    problems.push(`pyproject.toml declares ${declared}, expected ${version}`);
  }
  if (read(TS_TARGET) !== tsModule(version)) {
    problems.push(
      `packages/tx402/src/version.ts is stale — run \`pnpm version:sync\` (expected ${version})`,
    );
  }
  if (read(PY_TARGET) !== pyModule(version)) {
    problems.push(
      `packages/tx402-python/src/tx402/_version.py is stale — run \`pnpm version:sync\` (expected ${version})`,
    );
  }
  if (expected !== undefined) {
    const normalized = expected.startsWith("v") ? expected.slice(1) : expected;
    if (normalized !== version) {
      problems.push(`--expect ${expected} does not match the package version ${version}`);
    }
  }

  if (problems.length > 0) {
    for (const problem of problems) console.error(`tx402-version-sync: ${problem}`);
    process.exitCode = 1;
    return;
  }
  console.log(
    `OK    version ${version} agrees across package.json, pyproject.toml, and both generated modules` +
      (expected === undefined ? "" : ` and the supplied ${expected}`),
  );
}

const [command = "check", ...rest] = process.argv.slice(2);
const expectIndex = rest.indexOf("--expect");
const expected = expectIndex === -1 ? undefined : rest[expectIndex + 1];

if (command === "build") {
  build();
} else if (command === "check") {
  check(expected);
} else {
  console.error(`tx402-version-sync: unknown command ${JSON.stringify(command)}`);
  console.error("usage: version-sync <build|check> [--expect <version>]");
  process.exitCode = 2;
}
