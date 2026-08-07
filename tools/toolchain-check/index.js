#!/usr/bin/env node
/**
 * The toolchain contract, checked (PLAN.md open item **O60**).
 *
 *   node tools/toolchain-check/index.js check      # fail if the declarations disagree
 *   node tools/toolchain-check/index.js selftest   # prove each rule can fail
 *
 * **The failure this exists to stop.** The repository declared `node >=20.19.0`,
 * `CONTRIBUTING.md` started developers on "Node 20+", and `pnpm check` — the one command
 * the contributing guide names as the gate — ended with `pnpm docs:build`, which is Astro,
 * which refuses anything below 22.12.0. So the advertised one-command gate could not
 * complete in a checkout that satisfied the repository's own stated requirement. It failed
 * *last*, after twelve minutes of green checks, with an error about a tool most of those
 * checks have nothing to do with.
 *
 * There are two runtimes in this repository and conflating them is what went wrong:
 *
 *  - **The published SDK's runtime.** `packages/tx402/package.json` — what a user needs to
 *    `npm install tx402`. This is Node 20.19+ and S15d does not move it. CI proves it by
 *    running the whole TypeScript suite on Node 20 as well as 22.
 *  - **The workspace's runtime.** The root `package.json` — what a *contributor* needs to
 *    run the aggregate gate, which includes building the documentation site. This is
 *    whatever Astro requires, and it is now declared as such.
 *
 * Each rule below is derived from a file rather than written down twice, because the whole
 * finding is that a number written down twice goes stale:
 *
 *  1. The running Node satisfies the **root** floor — checked first in `pnpm check`, so an
 *     unsupported runtime is reported in a second with a fix, not in twelve minutes with a
 *     stack trace.
 *  2. `docs/package.json`'s floor is at least **the installed Astro's own** floor. An Astro
 *     upgrade that raises its requirement fails here instead of failing the docs build.
 *  3. The **root** floor is at least the docs floor, because `pnpm check` builds the docs.
 *  4. The **SDK** floor is not silently dragged upward with the workspace's, and the major
 *     it names still appears in the CI matrix — so "we still support Node 20" stays a
 *     tested claim rather than a leftover string.
 */

import { readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

const ROOT_MANIFEST = join(ROOT, "package.json");
const DOCS_MANIFEST = join(ROOT, "docs/package.json");
const SDK_MANIFEST = join(ROOT, "packages/tx402/package.json");
const ASTRO_MANIFEST = join(ROOT, "docs/node_modules/astro/package.json");
const CI_WORKFLOW = join(ROOT, ".github/workflows/ci.yml");

/** @param {string} file */
function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/**
 * Parses the one range form this repository uses, and refuses every other.
 *
 * A general semver range parser is a dependency, and a hand-rolled one is a bug. Every
 * `engines.node` here is `>=X.Y.Z`; anything else should be a deliberate decision that
 * arrives with its own check rather than something this function silently mis-reads.
 *
 * @param {string} range
 * @param {string} source
 * @returns {[number, number, number]}
 */
export function floorOf(range, source) {
  const match = /^>=\s*(\d+)\.(\d+)\.(\d+)$/u.exec(range.trim());
  if (!match) {
    throw new Error(
      `${source} declares node "${range}", which is not the supported ">=X.Y.Z" form`,
    );
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** @param {number[]} left @param {number[]} right @returns {number} */
export function compare(left, right) {
  for (let index = 0; index < 3; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

/** @param {string} version e.g. `v20.19.5` @returns {[number, number, number]} */
export function parseVersion(version) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/u.exec(version);
  if (!match) throw new Error(`Unrecognized Node version: ${version}`);
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/**
 * The Node majors the CI TypeScript matrix runs.
 *
 * Read with a regex rather than a YAML parser for the same reason `version-sync` reads
 * `pyproject.toml` with one: a parser is a dependency, and the line this cares about is
 * pinned by `workflow-lint` to a single shape.
 *
 * @param {string} yaml
 * @returns {number[]}
 */
export function ciNodeMajors(yaml) {
  const match = /^\s*node:\s*\[([^\]]*)\]/mu.exec(yaml);
  if (!match?.[1]) throw new Error("ci.yml has no `node: [...]` matrix");
  return match[1]
    .split(",")
    .map((entry) => Number(entry.trim().replace(/["']/gu, "")))
    .filter((major) => Number.isInteger(major));
}

/**
 * Every rule, as data, so `selftest` can drive them without a repository.
 *
 * @param {{
 *   running: [number, number, number],
 *   root: [number, number, number],
 *   docs: [number, number, number],
 *   astro: [number, number, number],
 *   sdk: [number, number, number],
 *   ciMajors: number[],
 * }} input
 * @returns {string[]} problems, empty when the contract holds
 */
export function contractProblems(input) {
  const show = (/** @type {number[]} */ version) => version.join(".");
  /** @type {string[]} */
  const problems = [];

  if (compare(input.running, input.root) < 0) {
    problems.push(
      `  this Node is v${show(input.running)}, and the workspace requires >=${show(input.root)}.\n` +
        `      The aggregate gate builds the documentation site, which needs it. The published\n` +
        `      SDK still supports Node >=${show(input.sdk)} and CI proves it on that runtime — this\n` +
        `      floor is the contributor toolchain, not the package.`,
    );
  }
  if (compare(input.docs, input.astro) < 0) {
    problems.push(
      `  docs/package.json declares node >=${show(input.docs)} but the installed Astro requires` +
        ` >=${show(input.astro)}`,
    );
  }
  if (compare(input.root, input.docs) < 0) {
    problems.push(
      `  package.json declares node >=${show(input.root)} but \`pnpm check\` builds the docs,` +
        ` which need >=${show(input.docs)}`,
    );
  }
  if (compare(input.sdk, input.root) > 0) {
    problems.push(
      `  packages/tx402 declares node >=${show(input.sdk)}, above the workspace's >=${show(input.root)}.` +
        ` The published floor must not follow the toolchain upward.`,
    );
  }
  if (!input.ciMajors.includes(input.sdk[0])) {
    problems.push(
      `  packages/tx402 supports Node ${input.sdk[0]}, which the CI matrix [${input.ciMajors.join(", ")}]` +
        ` does not run. An untested support claim is not a support claim.`,
    );
  }
  return problems;
}

function check() {
  const root = floorOf(readJson(ROOT_MANIFEST).engines.node, "package.json");
  const docs = floorOf(readJson(DOCS_MANIFEST).engines.node, "docs/package.json");
  const sdk = floorOf(readJson(SDK_MANIFEST).engines.node, "packages/tx402/package.json");
  /** @type {[number, number, number]} */
  let astro;
  try {
    astro = floorOf(readJson(ASTRO_MANIFEST).engines.node, "astro");
  } catch (error) {
    if (/** @type {NodeJS.ErrnoException} */ (error).code !== "ENOENT") throw error;
    console.error(
      `FAIL  ${relative(ROOT, ASTRO_MANIFEST)} is missing. Run: pnpm install --frozen-lockfile`,
    );
    return 1;
  }

  const problems = contractProblems({
    running: parseVersion(process.version),
    root,
    docs,
    astro,
    sdk,
    ciMajors: ciNodeMajors(readFileSync(CI_WORKFLOW, "utf8")),
  });

  if (problems.length > 0) {
    console.error("FAIL  the toolchain contract does not hold:");
    console.error(problems.join("\n"));
    return 1;
  }

  console.log(
    `OK    toolchain: workspace >=${root.join(".")} (Astro), published SDK >=${sdk.join(".")}, ` +
      `running ${process.version}`,
  );
  return 0;
}

/**
 * Every rule, shown failing on a fixture rather than only ever observed passing (O48).
 */
function selftest() {
  /** @type {[number, number, number]} */
  const v20 = [20, 19, 5];
  /** @type {[number, number, number]} */
  const v22 = [22, 12, 0];
  /** @type {[number, number, number]} */
  const v24 = [24, 0, 0];
  const sound = {
    running: v22,
    root: v22,
    docs: v22,
    astro: v22,
    sdk: v20,
    ciMajors: [20, 22],
  };

  /** @type {[string, Partial<typeof sound>, boolean][]} */
  const cases = [
    ["a sound contract", {}, false],
    ["the running Node is below the workspace floor", { running: v20 }, true],
    ["a newer Astro than the docs package admits", { astro: v24 }, true],
    ["a workspace floor below the docs it builds", { root: v20, running: v20 }, true],
    ["an SDK floor dragged above the workspace", { sdk: v24 }, true],
    ["an SDK claiming a major CI never runs", { ciMajors: [22] }, true],
    [
      "a workspace ahead of the SDK, which is the point",
      { root: v24, running: v24 },
      false,
    ],
  ];

  let failures = 0;
  for (const [name, overrides, shouldFail] of cases) {
    const problems = contractProblems({ ...sound, ...overrides });
    if (problems.length > 0 !== shouldFail) {
      failures += 1;
      console.error(
        `FAIL  ${name}: expected ${shouldFail ? "a finding" : "no finding"}, got ${problems.length}`,
      );
    }
  }

  const malformed = ["^22.12.0", "22.x", ">=22", ""];
  for (const range of malformed) {
    let threw = false;
    try {
      floorOf(range, "fixture");
    } catch {
      threw = true;
    }
    if (!threw) {
      failures += 1;
      console.error(`FAIL  the range ${JSON.stringify(range)} was accepted`);
    }
  }

  if (failures > 0) {
    console.error(`FAIL  ${failures} toolchain self-tests behaved wrongly`);
    return 1;
  }
  console.log(
    `OK    ${cases.length + malformed.length} toolchain self-tests behave as specified`,
  );
  return 0;
}

const USAGE = `tx402-toolchain — the workspace/SDK runtime contract (PLAN.md O60)

Usage:
  tx402-toolchain check      fail if the declared runtimes disagree with each other
  tx402-toolchain selftest   prove each rule can fail`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const command = process.argv[2];
    if (command === "check") process.exitCode = check();
    else if (command === "selftest") process.exitCode = selftest();
    else if (command === undefined || command === "-h" || command === "--help") {
      console.log(USAGE);
    } else {
      console.error(`Unknown command: ${command}\n\n${USAGE}`);
      process.exitCode = 2;
    }
  } catch (error) {
    console.error(
      `tx402-toolchain: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exitCode = 1;
  }
}
