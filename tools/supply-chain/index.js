#!/usr/bin/env node
/**
 * Supply-chain release gates (SPEC §12.4).
 *
 *   node tools/supply-chain/index.js sbom          # emit CycloneDX SBOMs + licence report
 *   node tools/supply-chain/index.js audit         # vulnerability + licence policy gates
 *   node tools/supply-chain/index.js reproducible  # build twice, compare digests
 *   node tools/supply-chain/index.js all
 *
 * SPEC §12.4 requires "package signatures/provenance, SBOMs, license checks, and
 * reproducible build verification complete" before release. Provenance is the release
 * workflow's job (OIDC trusted publishing); the other three are here.
 *
 * **Everything is scoped to what actually ships.** The workspace has a large dev tree —
 * vitest, Astro, eslint, esbuild — and none of it reaches a user. SPEC §12.4's wording is
 * "no critical or high-severity unresolved security issue in **reachable production code**",
 * so dev-only findings are reported and do not fail the gate. Conflating the two produces a
 * gate nobody can keep green, which is a gate that gets disabled.
 *
 * **What "ships" means changed at S15b.** The audit's O48 found the npm inventory listing
 * exactly two components — `@x402/core` and `zod` — because it read the published package's
 * *production* dependencies, and every chain runtime is an optional peer. But a user who
 * follows the documented Base install has `viem` and `@x402/evm` on disk and in their
 * process, so an advisory in either reaches them. The inventory is now built per **install
 * variant**, from the same contract `tools/install-contract` publishes and smokes, and the
 * Python side exports its extras rather than only the core requirement set.
 *
 * **The gates fail closed.** Also O48: an npm audit that produced no parseable JSON was
 * recorded as "no findings", an unavailable `pip-audit` left the PyPI tree unscanned with a
 * note, and every Python advisory was non-blocking whatever its severity. A scanner that
 * did not run is not a clean scan, and a gate that cannot tell the difference is not a
 * gate. Anything that prevents a check from reaching a verdict is now a **problem**, and
 * `node tools/supply-chain/index.js selftest` runs crafted scanner output through the
 * classifiers to prove each blocking path actually blocks.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { contract as installContract } from "../install-contract/index.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const OUT = join(ROOT, "sbom");

/**
 * Licences acceptable in a **shipped** dependency.
 *
 * Permissive and weak-copyleft-with-file-scope only. A strong copyleft licence in the
 * production tree would impose terms on everyone who installs tx402, which is a licensing
 * decision rather than a dependency choice — so it fails the gate and needs a human.
 */
const ALLOWED_LICENSES = new Set([
  "MIT",
  "ISC",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "0BSD",
  "Unlicense",
  "CC0-1.0",
  "BlueOak-1.0.0",
  "Python-2.0",
  "PSF-2.0",
  "MPL-2.0",
  "MIT-0",
  // The historical CPython licence, still declared by `regex`. Permissive, and the licence
  // CPython itself was distributed under before Python-2.0.
  "CNRI-Python",
  // Legacy free-text spellings that predate SPDX identifiers. Kept deliberately short:
  // every entry here is a licence someone read, not a wildcard.
  "BSD",
  "Apache 2.0",
  "Apache License 2.0",
  "Public Domain",
]);

/**
 * Licences for packages whose own metadata declares none, read by hand from the source.
 *
 * These are the packages the S15b widening of the inventory surfaced as UNKNOWN. An UNKNOWN
 * licence blocks — it must, or the gate would pass a package nobody has checked — so the
 * only way past it is a human reading the licence and recording where they read it. The
 * entry says *where*, not just *what*, because "someone said MIT once" is not evidence.
 */
const DECLARED_ELSEWHERE = new Map([
  [
    "pypi:solders",
    {
      license: "Apache-2.0",
      source: "https://github.com/kevinheavey/solders — LICENSE, Apache-2.0",
    },
  ],
  [
    "pypi:jsonalias",
    {
      license: "MIT",
      source: "https://github.com/kevinheavey/jsonalias — LICENSE, MIT",
    },
  ],
]);

/**
 * Evaluates a simple SPDX expression against the allowlist.
 *
 * `cryptography` ships "Apache-2.0 OR BSD-3-Clause" — a genuine choice of two acceptable
 * licences, which a string comparison against the allowlist rejects even though either
 * operand alone would pass. `OR` therefore needs only one acceptable operand; `AND` needs
 * all of them, because an `AND` imposes every listed licence at once.
 *
 * Parenthesised expressions are not parsed. They are rare, and a licence expression this
 * tool cannot read must fail rather than be guessed at.
 */
function licenseAcceptable(expression) {
  const value = expression.trim().replace(/^\(|\)$/gu, "");
  if (value.includes("(")) return false;
  // A comma is free text, not SPDX — `pycryptodome` declares "BSD, Public Domain". What it
  // means is ambiguous, so it is read the conservative way: **every** listed licence must
  // be acceptable, as though the package imposed all of them.
  if (value.includes(",")) {
    return value.split(",").every((part) => licenseAcceptable(part));
  }
  if (/ OR /iu.test(value)) {
    return value.split(/ OR /iu).some((part) => licenseAcceptable(part));
  }
  if (/ AND /iu.test(value)) {
    return value.split(/ AND /iu).every((part) => licenseAcceptable(part));
  }
  return ALLOWED_LICENSES.has(value.replace(/-only$|-or-later$/u, ""));
}

const run = (command, args, options = {}) =>
  execFileSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });

/** `pnpm audit` exits non-zero when it finds anything, which is not an execution failure. */
function runAllowingFailure(command, args, options = {}) {
  try {
    return run(command, args, options);
  } catch (error) {
    return String(error.stdout ?? "");
  }
}

const problems = [];
const notes = [];

/**
 * The install variants a user can actually choose, taken from the install contract so the
 * inventory and the documented commands cannot disagree (O47, O48).
 */
const INSTALL_VARIANTS = installContract().map((entry) => ({
  id: entry.id,
  label: entry.label,
  packages: entry.packages,
}));

/**
 * Python extras, mirroring the npm variants. `pyproject.toml` owns the names; this maps
 * each variant onto them so both languages are inventoried the same way.
 */
const PYTHON_VARIANTS = [
  { id: "core", label: "core only", extras: [] },
  { id: "evm", label: "Base / EVM", extras: ["evm"] },
  { id: "solana", label: "Solana", extras: ["svm"] },
  { id: "all", label: "both chains", extras: ["evm", "svm"] },
];

/**
 * Advisories a human has read and accepted, with a reason and an expiry.
 *
 * The file is the *only* way past a blocking finding, which is the point: before S15b a
 * Python advisory of any severity was appended as a note and the gate stayed green, so
 * "accepted" and "unnoticed" were indistinguishable. An entry that has expired blocks
 * again, so an acceptance cannot outlive the judgement behind it.
 */
function acceptedAdvisories() {
  const file = join(OUT, "accepted-advisories.json");
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return new Map();
    problems.push(
      `sbom/accepted-advisories.json exists and does not parse: ${String(error.message)}`,
    );
    return new Map();
  }
  const today = new Date().toISOString().slice(0, 10);
  const accepted = new Map();
  for (const entry of parsed.accepted ?? []) {
    if (typeof entry.id !== "string" || typeof entry.reason !== "string") {
      problems.push("sbom/accepted-advisories.json entry needs both `id` and `reason`");
      continue;
    }
    if (typeof entry.expires !== "string" || entry.expires < today) {
      problems.push(
        `advisory acceptance for ${entry.id} has expired (${String(entry.expires)}); ` +
          "re-read it or fix the dependency",
      );
      continue;
    }
    accepted.set(entry.id, entry);
  }
  return accepted;
}

// --- dependency inventory ------------------------------------------------------------------

/**
 * Every npm install variant, resolved to the components a user of that variant has on disk.
 *
 * The workspace declares each optional peer as a devDependency too — that is how the test
 * suite can import `tx402/evm` at all — so the resolved trees are already here and no
 * network call is needed. Walking from the *named peer roots* rather than from the whole
 * dev tree is what keeps vitest and Astro out of a user-facing inventory.
 */
function npmVariantTrees() {
  const raw = run("pnpm", ["--filter", "tx402", "list", "--depth", "Infinity", "--json"]);
  const parsed = JSON.parse(raw);
  const root = parsed[0];
  if (root === undefined) {
    problems.push("npm inventory: `pnpm list` returned no tx402 entry; tree not resolved");
    return [];
  }

  /** @param {Record<string, any> | undefined} dependencies */
  const collect = (dependencies, found = new Map()) => {
    for (const [name, info] of Object.entries(dependencies ?? {})) {
      const key = `${name}@${info.version ?? "?"}`;
      if (!found.has(key)) {
        found.set(key, { name, version: info.version ?? "0.0.0", path: info.path });
      }
      collect(info.dependencies, found);
    }
    return found;
  };

  const production = collect(root.dependencies);
  const declared = { ...root.devDependencies, ...root.dependencies };

  return INSTALL_VARIANTS.map((variant) => {
    const found = new Map(production);
    for (const peer of variant.packages) {
      const info = declared[peer];
      if (info === undefined) {
        // Fail closed. A variant whose packages are not resolvable here has an inventory
        // that is silently short, which is exactly the shape of the defect O48 recorded.
        problems.push(
          `npm inventory: install variant "${variant.id}" names ${peer}, which is not ` +
            "resolved in this workspace; its components cannot be inventoried",
        );
        continue;
      }
      found.set(`${peer}@${info.version ?? "?"}`, {
        name: peer,
        version: info.version ?? "0.0.0",
        path: info.path,
      });
      collect(info.dependencies, found);
    }
    return { variant, components: [...found.values()] };
  });
}

/**
 * The Python runtime tree for one extra set, from the lockfile rather than the environment.
 *
 * @param {string[]} extras
 */
function pythonProductionTree(extras = []) {
  const raw = run(
    "uv",
    [
      "export",
      "--no-dev",
      "--no-hashes",
      "--format",
      "requirements-txt",
      ...extras.flatMap((extra) => ["--extra", extra]),
    ],
    {
      cwd: join(ROOT, "packages/tx402-python"),
    },
  );
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#") && !line.startsWith("-e"))
    .map((line) => {
      // A requirements line may carry an environment marker — `cffi==2.1.0 ; platform...`
      // — which is not part of the version and must not end up in a purl.
      const [requirement] = line.split(";");
      const [name, version] = requirement.split("==");
      return { name: name.split("[")[0].trim(), version: (version ?? "0.0.0").trim() };
    })
    .filter((entry) => entry.name.length > 0);
}

function npmLicenseOf(component) {
  try {
    const manifest = JSON.parse(readFileSync(join(component.path, "package.json"), "utf8"));
    if (typeof manifest.license === "string") return manifest.license;
    if (manifest.license?.type !== undefined) return String(manifest.license.type);
    if (Array.isArray(manifest.licenses)) {
      return manifest.licenses.map((entry) => entry.type).join(" OR ");
    }
  } catch {
    /* fall through to unknown */
  }
  return "UNKNOWN";
}

/**
 * Python licences, read from installed metadata in one call.
 *
 * `uv pip show` does not print a licence at all, and the field moved: modern packaging puts
 * an SPDX string in `License-Expression`, older packages put free text in `License`, and
 * some only carry a `License :: OSI Approved :: …` classifier. All three are consulted, in
 * that order, because relying on any one of them alone reports most of the tree as UNKNOWN.
 */
function pythonLicenses(names) {
  const script = `
import json
from importlib.metadata import metadata

CLASSIFIER = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}

out = {}
for name in json.loads(input()):
    try:
        meta = metadata(name)
    except Exception:
        out[name] = "NOT-INSTALLED"
        continue
    value = meta.get("License-Expression") or meta.get("License") or ""
    value = value.strip()
    if not value or chr(10) in value:
        for classifier in meta.get_all("Classifier") or []:
            if classifier in CLASSIFIER:
                value = CLASSIFIER[classifier]
                break
    out[name] = value or "UNKNOWN"
print(json.dumps(out))
`;
  try {
    const raw = run("uv", ["run", "python", "-c", script], {
      cwd: join(ROOT, "packages/tx402-python"),
      input: JSON.stringify(names),
      stdio: ["pipe", "pipe", "pipe"],
    });
    return JSON.parse(raw.trim().split("\n").at(-1));
  } catch (error) {
    notes.push(
      `python licence lookup failed: ${String(error.stderr ?? error.message).slice(-400)}`,
    );
    return Object.fromEntries(names.map((name) => [name, "UNKNOWN"]));
  }
}

// --- 1. SBOM ---------------------------------------------------------------------------------

/**
 * The declared licence, or the hand-read one when the package declares nothing.
 *
 * @param {string} ecosystem @param {string} name @param {string} declared
 */
function resolveDeclaredLicense(ecosystem, name, declared) {
  if (declared !== "UNKNOWN") return declared;
  const known = DECLARED_ELSEWHERE.get(`${ecosystem}:${name}`);
  if (known === undefined) return declared;
  notes.push(
    `licence: ${name} declares none; read as ${known.license} from ${known.source}`,
  );
  return known.license;
}

function cycloneDx(name, version, components) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      // No timestamp. A timestamp would make two SBOMs of the same tree differ, which
      // defeats the reproducible-build gate that compares them.
      component: { type: "library", name, version, purl: `pkg:generic/${name}@${version}` },
      tools: [{ vendor: "tx402", name: "tools/supply-chain" }],
    },
    components: components
      .map((component) => ({
        type: "library",
        name: component.name,
        version: component.version,
        purl: component.purl,
        licenses: [{ license: { id: component.license } }],
      }))
      .sort((a, b) => a.purl.localeCompare(b.purl)),
  };
}

function buildSboms() {
  mkdirSync(OUT, { recursive: true });

  const npmVersion = JSON.parse(
    readFileSync(join(ROOT, "packages/tx402/package.json"), "utf8"),
  ).version;

  /** @type {{ ecosystem: string, variant: string, label: string, components: any[] }[]} */
  const inventories = [];

  for (const { variant, components } of npmVariantTrees()) {
    inventories.push({
      ecosystem: "npm",
      variant: variant.id,
      label: variant.label,
      components: components.map((component) => ({
        name: component.name,
        version: component.version,
        purl: `pkg:npm/${component.name}@${component.version}`,
        license: resolveDeclaredLicense("npm", component.name, npmLicenseOf(component)),
      })),
    });
  }

  for (const variant of PYTHON_VARIANTS) {
    const tree = pythonProductionTree(variant.extras);
    const licenses = pythonLicenses(tree.map((component) => component.name));
    inventories.push({
      ecosystem: "pypi",
      variant: variant.id,
      label: variant.label,
      components: tree.map((component) => ({
        name: component.name,
        version: component.version,
        purl: `pkg:pypi/${component.name}@${component.version}`,
        license: resolveDeclaredLicense(
          "pypi",
          component.name,
          licenses[component.name] ?? "UNKNOWN",
        ),
      })),
    });
  }

  for (const inventory of inventories) {
    writeFileSync(
      join(OUT, `tx402-${inventory.ecosystem}-${inventory.variant}.cdx.json`),
      `${JSON.stringify(
        cycloneDx(
          `tx402 (${inventory.ecosystem}, ${inventory.variant})`,
          npmVersion,
          inventory.components,
        ),
        null,
        2,
      )}\n`,
    );
  }

  const row = (component) =>
    `| \`${component.name}\` | ${component.version} | ${component.license} |`;
  const section = (inventory) => [
    `### ${inventory.ecosystem === "npm" ? "npm" : "PyPI"} — \`${inventory.variant}\` (${inventory.label})`,
    "",
    `${inventory.components.length} components.`,
    "",
    "| Package | Version | Licence |",
    "| --- | --- | --- |",
    ...inventory.components.map(row),
    "",
  ];

  writeFileSync(
    join(OUT, "LICENSES.md"),
    [
      "# Third-party licences",
      "",
      "Generated by `node tools/supply-chain/index.js sbom`. **Do not hand-edit.**",
      "",
      "Only dependencies that reach a user are listed. The development tree — vitest,",
      "Astro, eslint, ruff, mypy — is not distributed and is deliberately excluded.",
      "",
      "**One section per install variant.** Chain support is optional in both languages, so",
      "what a user has on disk depends on which install they ran. Listing only the core",
      "install would omit every chain runtime — the audit finding O48 — and an advisory in a",
      "package a documented install puts in the user's process reaches that user whether or",
      "not the core install needed it.",
      "",
      "tx402 itself is Apache-2.0.",
      "",
      "## npm (`tx402`)",
      "",
      ...inventories.filter((entry) => entry.ecosystem === "npm").flatMap(section),
      "## PyPI (`tx402`)",
      "",
      ...inventories.filter((entry) => entry.ecosystem === "pypi").flatMap(section),
    ].join("\n"),
  );

  const counts = inventories
    .map((entry) => `${entry.ecosystem}/${entry.variant}:${entry.components.length}`)
    .join(" ");
  console.log(`  SBOM: ${inventories.length} inventories → sbom/  (${counts})`);
  return inventories;
}

// --- 2. licence policy + vulnerabilities -----------------------------------------------------

function licenseGate(inventories) {
  const seen = new Map();
  for (const inventory of inventories) {
    for (const component of inventory.components) {
      seen.set(`${inventory.ecosystem}:${component.name}@${component.version}`, component);
    }
  }
  for (const component of seen.values()) {
    if (component.license === "NOT-INSTALLED") {
      // A dependency conditional on an interpreter this machine is not running — for
      // example `exceptiongroup ; python_full_version < "3.11"` on CPython 3.13. Its
      // metadata genuinely cannot be read here, so reporting it as an unacceptable licence
      // would be a false finding. CI's 3.10 leg resolves it.
      notes.push(
        `licence: ${component.name}@${component.version} is not installed for this ` +
          `interpreter, so its licence was not read here`,
      );
      continue;
    }
    if (!licenseAcceptable(component.license)) {
      problems.push(
        `licence: ${component.name}@${component.version} is "${component.license}", ` +
          `which is not on the shipped-dependency allowlist`,
      );
    }
  }
  console.log(`  licences: ${seen.size} distinct shipped components checked`);
}

/**
 * Decides what one `pnpm audit --json` payload means. Pure, so `selftest` can drive it.
 *
 * `shipped` is the whole question. A path rooted at `tx402` reaches a user; a path rooted
 * at `tools__size-gate>esbuild` reaches nobody. The **second** input is the set of package
 * names any documented install puts on a user's disk: an advisory in `viem` has no path
 * through `tx402`'s production dependencies, because `viem` is an optional peer, and
 * before S15b that made it invisible to this gate.
 *
 * @param {string} raw
 * @param {Set<string>} shippedNames
 */
export function classifyNpmAudit(raw, shippedNames) {
  const found = { problems: [], notes: [] };
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Fail closed. "The scanner produced nothing I could read" is not "the tree is clean",
    // and treating them alike is what made this gate unable to fail (O48).
    found.problems.push(
      "npm audit produced no parseable JSON; the npm tree was not scanned",
    );
    return found;
  }
  const advisories = parsed.advisories;
  if (advisories === undefined || typeof advisories !== "object") {
    found.problems.push(
      "npm audit JSON has no `advisories` object; the npm tree was not scanned",
    );
    return found;
  }

  for (const advisory of Object.values(advisories)) {
    const severity = String(advisory.severity ?? "unknown");
    const module = String(advisory.module_name ?? "unknown");
    const paths = (advisory.findings ?? []).flatMap((finding) => finding.paths ?? []);
    const shipped =
      paths.some((path) => path.startsWith("tx402>") || path === "tx402") ||
      shippedNames.has(module);
    const line =
      `${module}: ${advisory.title} (${severity})` +
      (shipped ? "" : " [dev-only, not shipped]");
    if (!shipped) {
      found.notes.push(`vulnerability (non-blocking): ${line}`);
      continue;
    }
    // SPEC §12.4 blocks on critical and high only. Moderate and low are recorded so the
    // audit session sees them, without making the gate un-keepable. An *unknown* severity
    // blocks: it is a finding nobody has graded.
    if (severity === "critical" || severity === "high" || severity === "unknown") {
      found.problems.push(`vulnerability: ${line}`);
    } else {
      found.notes.push(`vulnerability (non-blocking): ${line}`);
    }
  }
  return found;
}

/**
 * Decides what one `pip-audit -f json` payload means. Pure, so `selftest` can drive it.
 *
 * **Every finding blocks unless it has been accepted in writing.** pip-audit does not
 * report a severity, so there is no honest way to apply SPEC §12.4's critical/high filter
 * on this side; the previous code resolved that by making *nothing* block, which meant a
 * critical advisory in a shipped Python dependency would have been a line of console output
 * and a green gate (O48). Blocking by default with an expiring, reasoned allowlist puts the
 * judgement on a human and keeps it visible in the diff.
 *
 * @param {string} raw
 * @param {Map<string, any>} accepted
 */
export function classifyPythonAudit(raw, accepted) {
  const found = { problems: [], notes: [] };
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    found.problems.push(
      "pip-audit produced no parseable JSON; the PyPI tree was not scanned",
    );
    return found;
  }
  if (!Array.isArray(parsed.dependencies)) {
    found.problems.push(
      "pip-audit JSON has no `dependencies` array; the PyPI tree was not scanned",
    );
    return found;
  }
  for (const dependency of parsed.dependencies) {
    for (const vulnerability of dependency.vulns ?? []) {
      const id = String(vulnerability.id ?? "unknown");
      const line = `python vulnerability: ${dependency.name}@${dependency.version} ${id}`;
      const waiver = accepted.get(id);
      if (waiver !== undefined) {
        found.notes.push(`${line} — accepted until ${waiver.expires}: ${waiver.reason}`);
      } else {
        found.problems.push(line);
      }
    }
  }
  return found;
}

function vulnerabilityGate(inventories) {
  // Every package name any documented install puts on a user's disk, so an advisory in an
  // optional peer is not invisible merely because it has no path through `tx402`.
  const shippedNames = new Set(
    inventories
      .filter((entry) => entry.ecosystem === "npm")
      .flatMap((entry) => entry.components.map((component) => component.name)),
  );

  // `pnpm --filter` implies `--recursive`, and `pnpm audit` rejects that, so the audit runs
  // at the workspace root and findings are filtered afterwards.
  const npm = classifyNpmAudit(
    runAllowingFailure("pnpm", ["audit", "--prod", "--json"]),
    shippedNames,
  );
  problems.push(...npm.problems);
  notes.push(...npm.notes);

  const accepted = acceptedAdvisories();
  // Every extra, not just the core requirement set: a user who ran `pip install tx402[svm]`
  // has `solders` in their process.
  for (const variant of PYTHON_VARIANTS) {
    const python = classifyPythonAudit(
      runAllowingFailure(
        "uv",
        [
          "run",
          "--with",
          "pip-audit",
          ...variant.extras.flatMap((extra) => ["--extra", extra]),
          "pip-audit",
          "-f",
          "json",
          "--progress-spinner",
          "off",
        ],
        { cwd: join(ROOT, "packages/tx402-python") },
      ),
      accepted,
    );
    problems.push(...python.problems.map((line) => `[${variant.id}] ${line}`));
    notes.push(...python.notes.map((line) => `[${variant.id}] ${line}`));
  }

  console.log(
    `  vulnerabilities: npm (${shippedNames.size} shipped names) + ` +
      `${PYTHON_VARIANTS.length} PyPI variants scanned`,
  );
}

// --- 3. reproducible build --------------------------------------------------------------------

/** sha256 over every emitted file, keyed by path, so ordering cannot hide a difference. */
function digestTree(directory) {
  const entries = [];
  const walk = (current, prefix) => {
    for (const name of readdirSync(current).sort()) {
      const full = join(current, name);
      const relative = prefix === "" ? name : `${prefix}/${name}`;
      if (statSync(full).isDirectory()) walk(full, relative);
      else {
        entries.push(
          `${relative}  ${createHash("sha256").update(readFileSync(full)).digest("hex")}`,
        );
      }
    }
  };
  walk(directory, "");
  return {
    manifest: entries,
    digest: createHash("sha256").update(entries.join("\n")).digest("hex"),
  };
}

function reproducibleGate() {
  const dist = join(ROOT, "packages/tx402/dist");

  rmSync(dist, { recursive: true, force: true });
  run("pnpm", ["--filter", "tx402", "build"]);
  const first = digestTree(dist);

  rmSync(dist, { recursive: true, force: true });
  run("pnpm", ["--filter", "tx402", "build"]);
  const second = digestTree(dist);

  if (first.digest === second.digest) {
    console.log(
      `  reproducible build: identical across two clean builds (${first.digest.slice(0, 16)}…)`,
    );
  } else {
    const differing = first.manifest.filter(
      (line, index) => line !== second.manifest[index],
    );
    problems.push(
      `reproducible build: two clean builds differ (${differing.length} file(s), first: ` +
        `${differing[0] ?? "path set differs"})`,
    );
  }

  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, "build-digest.txt"), first.manifest.join("\n") + "\n");
}

// --- run ----------------------------------------------------------------------------------------

/**
 * Negative fixtures: crafted scanner output, run through the real classifiers.
 *
 * A gate that has only ever seen a clean tree has never been observed to fail, which is
 * how O48's checks came to be unable to. Each case below is a way a scan can go wrong;
 * every one of them must produce a blocking problem, and the two that must *not* block —
 * a dev-only advisory and a moderate shipped one — are asserted too, so "fail closed" does
 * not quietly become "fail on everything".
 */
function selftest() {
  const shipped = new Set(["viem", "@x402/core"]);
  const never = new Map();
  /** @type {{ label: string, blocks: boolean, actual: number }[]} */
  const results = [];

  const expect = (label, blocks, found) =>
    results.push({ label, blocks, actual: found.problems.length });

  expect("npm audit emitted nothing", true, classifyNpmAudit("", shipped));
  expect(
    "npm audit emitted a bare error string",
    true,
    classifyNpmAudit("ENOTFOUND", shipped),
  );
  expect("npm audit JSON without advisories", true, classifyNpmAudit("{}", shipped));
  expect(
    "critical advisory in a shipped optional peer",
    true,
    classifyNpmAudit(
      JSON.stringify({
        advisories: {
          1: { module_name: "viem", title: "seeded", severity: "critical", findings: [] },
        },
      }),
      shipped,
    ),
  );
  expect(
    "ungraded advisory in a shipped package",
    true,
    classifyNpmAudit(
      JSON.stringify({
        advisories: { 1: { module_name: "viem", title: "seeded", findings: [] } },
      }),
      shipped,
    ),
  );
  expect(
    "moderate advisory in a shipped package",
    false,
    classifyNpmAudit(
      JSON.stringify({
        advisories: {
          1: { module_name: "viem", title: "seeded", severity: "moderate", findings: [] },
        },
      }),
      shipped,
    ),
  );
  expect(
    "critical advisory in a dev-only package",
    false,
    classifyNpmAudit(
      JSON.stringify({
        advisories: {
          1: {
            module_name: "esbuild",
            title: "seeded",
            severity: "critical",
            findings: [{ paths: ["tools__size-gate>esbuild"] }],
          },
        },
      }),
      shipped,
    ),
  );

  expect("pip-audit emitted nothing", true, classifyPythonAudit("", never));
  expect("pip-audit JSON without dependencies", true, classifyPythonAudit("{}", never));
  expect(
    "any pip-audit finding, ungraded",
    true,
    classifyPythonAudit(
      JSON.stringify({
        dependencies: [{ name: "seeded", version: "1.0.0", vulns: [{ id: "PYSEC-0000" }] }],
      }),
      never,
    ),
  );
  expect(
    "a pip-audit finding accepted in writing",
    false,
    classifyPythonAudit(
      JSON.stringify({
        dependencies: [{ name: "seeded", version: "1.0.0", vulns: [{ id: "PYSEC-0000" }] }],
      }),
      new Map([["PYSEC-0000", { expires: "2999-01-01", reason: "fixture" }]]),
    ),
  );

  let failed = 0;
  for (const result of results) {
    const ok = result.blocks ? result.actual > 0 : result.actual === 0;
    if (!ok) failed += 1;
    console.log(
      `  ${ok ? "OK  " : "FAIL"}  ${result.blocks ? "blocks" : "passes"}: ${result.label}`,
    );
  }
  if (failed > 0) {
    problems.push(`${failed} of ${results.length} gate self-tests behaved incorrectly`);
    return;
  }
  console.log(`  selftest: ${results.length} negative fixtures behave as specified`);
}

const command = process.argv[2] ?? "all";
console.log(`tx402 supply-chain gates (SPEC §12.4) — ${command}\n`);

let inventory;
if (command === "sbom" || command === "audit" || command === "all")
  inventory = buildSboms();
if (command === "audit" || command === "all") {
  licenseGate(inventory);
  vulnerabilityGate(inventory);
}
if (command === "selftest" || command === "audit" || command === "all") selftest();
if (command === "reproducible" || command === "all") reproducibleGate();

if (notes.length > 0) {
  console.log("\nNotes (non-blocking):");
  for (const note of notes) console.log(`  - ${note}`);
}

if (problems.length > 0) {
  console.error(`\n${problems.length} blocking finding(s):`);
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}

console.log("\nsupply-chain: PASS");
