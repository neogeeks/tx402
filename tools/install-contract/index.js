#!/usr/bin/env node
/**
 * The npm install contract, declared once and smoked from a clean environment (**O47**).
 *
 *   node tools/install-contract/index.js print   # the contract, as JSON
 *   node tools/install-contract/index.js check   # the READMEs and docs quote it correctly
 *   node tools/install-contract/index.js smoke   # pack, install into empty dirs, import
 *
 * **The failure this exists to stop.** `npm install tx402` was the only install command in
 * the root README, the package README, and the quickstart, and the quickstart said the
 * adapters ship in the same package and nothing else is needed. That is false, and it is
 * false *by design*: the chain runtimes are optional peer dependencies, so npm is
 * explicitly told not to install them, which is what keeps `import "tx402"` free of
 * `viem`, `@solana/kit`, and the two upstream chain packages. The S15 audit packed the
 * tarball, installed it into an empty directory, and found that `tx402` imported while
 * `tx402/evm`, `tx402/solana`, and `tx402/signers` all failed. Everything in the
 * repository stayed green because the workspace hoists dev dependencies and the release
 * smoke imported only the core entry point and the CLI.
 *
 * **npm has no extras.** Python can write `pip install tx402[evm]`; npm cannot. The
 * resolution is therefore a *documented* contract plus a gate that proves the
 * documentation is sufficient — not a change to the dependency policy, which SPEC §3.2 and
 * ADR-009 settle deliberately: a core install that drags in two chain runtimes is a
 * different product.
 *
 * **The contract is derived, not restated.** `REQUIRES` below names packages; their
 * version ranges come from `peerDependencies` in `packages/tx402/package.json`, so a bump
 * cannot leave a stale range in three READMEs. `check` compares the emitted commands
 * against what the documents actually contain, and fails on any drift.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const PACKAGE_DIR = join(ROOT, "packages/tx402");

/**
 * Which optional peers each advertised entry point needs **at import time**.
 *
 * `tx402/signers` lists only `viem`: `privateKeyToEvmSigner` imports `viem/accounts`
 * eagerly, while `keypairToSolanaSigner` reaches `@solana/kit` through a lazy
 * `await import` and so cannot break the module's own load. Anyone calling it is paying on
 * Solana and has the Solana row's packages already.
 */
const REQUIRES = {
  tx402: [],
  "tx402/evm": ["@x402/evm", "viem"],
  "tx402/solana": ["@x402/svm", "@solana/kit", "@solana-program/token"],
  "tx402/signers": ["viem"],
};

/** The one install every documented path starts from, in document order. */
const VARIANTS = [
  { id: "core", entryPoints: ["tx402"], label: "core only — protocol, policy, CLI" },
  { id: "evm", entryPoints: ["tx402", "tx402/evm", "tx402/signers"], label: "Base / EVM" },
  {
    id: "solana",
    // `tx402/signers` is in this row, and that is why `viem` appears in a Solana install.
    // The module loads `viem/accounts` eagerly for `privateKeyToEvmSigner`, so importing
    // it for `keypairToSolanaSigner` pulls viem in too. A Solana-only caller who supplies
    // their own `SolanaSigner` — which SEC-001 prefers anyway — needs neither.
    entryPoints: ["tx402", "tx402/solana", "tx402/signers"],
    label: "Solana",
  },
  {
    id: "all",
    entryPoints: ["tx402", "tx402/evm", "tx402/solana", "tx402/signers"],
    label: "both chains",
  },
];

function manifest() {
  return JSON.parse(readFileSync(join(PACKAGE_DIR, "package.json"), "utf8"));
}

/** @param {string[]} packages */
function withRanges(packages) {
  const peers = manifest().peerDependencies ?? {};
  return packages.map((name) => {
    const range = peers[name];
    if (range === undefined) {
      throw new Error(
        `${name} is named in the install contract but is not a peerDependency of tx402`,
      );
    }
    return `${name}@${range}`;
  });
}

/** The contract: every variant with the exact command that satisfies it. */
export function contract() {
  return VARIANTS.map((variant) => {
    const packages = [
      ...new Set(variant.entryPoints.flatMap((entry) => REQUIRES[entry] ?? [])),
    ].sort();
    return {
      ...variant,
      packages,
      command: ["npm install tx402", ...withRanges(packages)].join(" "),
      /** The same install without version ranges — what a README shows a human. */
      readableCommand: ["npm install tx402", ...packages].join(" "),
    };
  });
}

/** Documents that must quote the contract, and the variants each is responsible for. */
const DOCUMENTS = [
  { file: "README.md", variants: ["core", "evm", "solana"] },
  { file: "packages/tx402/README.md", variants: ["core", "evm", "solana"] },
  { file: "docs/src/content/docs/start/quickstart.mdx", variants: ["evm", "solana"] },
  // The error a caller reaches when the peers are missing quotes the same commands.
  { file: "packages/tx402/src/core/client.ts", variants: ["evm", "solana"] },
];

function check() {
  const byId = new Map(contract().map((entry) => [entry.id, entry]));
  /** @type {string[]} */
  const problems = [];

  for (const { file, variants } of DOCUMENTS) {
    const text = readFileSync(join(ROOT, file), "utf8");
    for (const id of variants) {
      const entry = byId.get(id);
      if (entry === undefined) throw new Error(`unknown variant ${id}`);
      if (!text.includes(entry.readableCommand)) {
        problems.push(
          `${file} does not contain the ${id} install: ${entry.readableCommand}`,
        );
      }
    }
    // A bare `npm install tx402` on its own line is the exact claim the audit found: it
    // reads as sufficient for everything. It is only allowed as the core row, which the
    // check above already requires, so what is forbidden is it appearing as the *last*
    // word of a fenced block that also mentions a chain entry point.
    if (/```(?:bash|sh)\nnpm install tx402\n```/u.test(text) && variants.length > 1) {
      problems.push(
        `${file} presents a bare "npm install tx402" block; every chain path needs its peers`,
      );
    }
  }

  if (problems.length > 0) {
    for (const problem of problems) console.error(`tx402-install-contract: ${problem}`);
    process.exitCode = 1;
    return;
  }
  console.log(`OK    ${DOCUMENTS.length} documents quote the install contract exactly`);
}

/**
 * Packs the real tarball and installs it into an empty directory per variant.
 *
 * Deliberately `npm`, not `pnpm`, and deliberately outside the workspace: the audit's
 * finding was hidden precisely because the workspace hoists dev dependencies, so a smoke
 * that runs anywhere near `node_modules` proves nothing.
 */
function smoke() {
  console.log("tx402-install-contract: packing…");
  const packed = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--pack-destination", tmpdir()], {
      cwd: PACKAGE_DIR,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    }),
  );
  const tarball = join(tmpdir(), packed[0].filename);

  let failures = 0;
  for (const variant of contract()) {
    const dir = mkdtempSync(join(tmpdir(), `tx402-install-${variant.id}-`));
    try {
      writeFileSync(
        join(dir, "package.json"),
        `${JSON.stringify({ name: "tx402-install-smoke", private: true, type: "module" }, null, 2)}\n`,
      );
      const packages = [tarball, ...withRanges(variant.packages)];
      execFileSync("npm", ["install", "--no-audit", "--no-fund", ...packages], {
        cwd: dir,
        encoding: "utf8",
        stdio: ["ignore", "ignore", "inherit"],
      });

      // One process per variant, importing every entry point that variant advertises.
      const probe = variant.entryPoints
        .map((entry) => `await import(${JSON.stringify(entry)});`)
        .join("\n");
      writeFileSync(
        join(dir, "probe.mjs"),
        `${probe}\nconsole.log("imported ${variant.entryPoints.join(", ")}");\n`,
      );
      const output = execFileSync(process.execPath, ["probe.mjs"], {
        cwd: dir,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "inherit"],
      });

      // The negative half, and the one that would have caught O47 in the first place: on
      // the *core* install the chain entry points must fail to load. Without this the four
      // rows above could all be satisfied by a package that bundled everything, and the
      // contract would be documentation rather than a fact about the artifact.
      if (variant.id === "core") {
        for (const entry of ["tx402/evm", "tx402/solana", "tx402/signers"]) {
          writeFileSync(
            join(dir, "negative.mjs"),
            `await import(${JSON.stringify(entry)});\n`,
          );
          const loaded = execFileSync(
            process.execPath,
            [
              "-e",
              `import("./negative.mjs").then(()=>console.log("LOADED"),()=>console.log("FAILED"))`,
            ],
            { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
          ).trim();
          if (loaded !== "FAILED") {
            throw new Error(
              `${entry} loaded on a core-only install; the documented per-chain rows are then untrue`,
            );
          }
        }
        console.log(
          "      core install correctly refuses tx402/evm, tx402/solana and tx402/signers",
        );
      }
      // The CLI is part of the advertised surface and resolves through `bin`.
      const version = execFileSync(
        process.execPath,
        [join(dir, "node_modules", ".bin", "tx402"), "--version"],
        { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
      );
      console.log(
        `OK    ${variant.id.padEnd(7)} ${variant.label}\n      ${output.trim()}\n      ${version.trim()}`,
      );
    } catch (error) {
      failures += 1;
      console.error(
        `FAIL  ${variant.id} (${variant.label}) — ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  rmSync(tarball, { force: true });

  if (failures > 0) {
    console.error(
      `tx402-install-contract: ${failures} of ${VARIANTS.length} documented installs cannot load their entry points`,
    );
    process.exitCode = 1;
    return;
  }
  console.log(
    `OK    all ${VARIANTS.length} documented installs load every entry point they advertise`,
  );
}

// Guarded so `contract()` can be imported by `tools/supply-chain`, which builds its
// inventory from exactly these variants: a module that ran a gate on import would make one
// tool's exit status depend on the other's.
const invokedDirectly =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);

const command = process.argv[2] ?? "check";
if (!invokedDirectly) {
  // imported for `contract()`
} else if (command === "print") {
  console.log(JSON.stringify(contract(), null, 2));
} else if (command === "check") {
  check();
} else if (command === "smoke") {
  smoke();
} else {
  console.error(`tx402-install-contract: unknown command ${JSON.stringify(command)}`);
  console.error("usage: install-contract <print|check|smoke>");
  process.exitCode = 2;
}
