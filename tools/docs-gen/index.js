#!/usr/bin/env node
/**
 * Generates the parts of the documentation site that must not be written by hand.
 *
 *   node tools/docs-gen/index.js build   # emit the generated pages
 *   node tools/docs-gen/index.js check   # fail if what is on disk is stale
 *
 * **Why generate rather than write.** The error reference is a table of fifteen error
 * codes, their retryability, their required context keys, and the CLI exit code each maps
 * to. Every one of those facts already exists in shipped source — `TX402_ERROR_TAXONOMY`
 * in `core/errors.ts` and `EXIT_CODE_BY_ERROR` in `cli/exit-codes.ts` — and a
 * hand-written copy is a second source of truth that drifts silently. A user reading
 * "exit code 4" in the docs and getting 5 from the binary is a worse failure than no docs
 * at all, because it costs them the time to disbelieve the documentation.
 *
 * `check` runs in CI, so a change to the taxonomy or to the exit-code map that is not
 * followed by a regenerate fails the build. That is the same contract
 * `core-spec/conformance/index.json` and the bundled manifests already have.
 *
 * The generated files carry a "do not edit" banner and are excluded from prettier, for
 * the same reason the bundled manifest is: reformatting a generated file only puts the
 * formatter and the generator in a loop.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const DOCS = join(ROOT, "docs", "src", "content", "docs");

/**
 * The "do not edit" notice, placed *after* the frontmatter.
 *
 * Astro requires the `---` block to be the first bytes of the file, so the banner cannot
 * lead. It is an MDX comment rather than a visible admonition because it is addressed to
 * whoever opens the file, not to whoever reads the page.
 */
const BANNER = `{/*
  GENERATED FILE — DO NOT EDIT.

  Emitted by \`node tools/docs-gen/index.js build\` from the shipped source named in each
  section. Edit the source and regenerate; \`pnpm docs:check\` fails if this file is stale.
*/}`;

/** Human-readable gloss for each retryability value (ADR-011's six-value classification). */
const RETRYABILITY_GLOSS = {
  no: "Never. The condition will not change on its own.",
  conditional:
    "Only after the underlying condition changes — fund the wallet, fix the signer.",
  "after-correction":
    "Only after the clock is corrected. tx402 never adjusts the system clock.",
  "no-automatic-retry":
    "**Never automatically.** Money may have moved. Reconcile with the merchant first.",
  "app-dependent":
    "The caller decides; tx402 has no way to know whether the resource is idempotent.",
  "caller-policy":
    "Yes, under the caller's own backoff policy. This is the only `retryable: true` row.",
};

/** What the operator has to change, per exit code. Mirrors `cli/exit-codes.ts`'s prose. */
const EXIT_CODE_MEANING = {
  0: [
    "success",
    "The call completed. Under `--json`, `ok` may still be `false` if the merchant answered non-2xx.",
  ],
  2: ["usage / config", "The invocation or the environment is wrong. Fix the command."],
  3: ["policy", "tx402's own guardrail refused. Raise the cap or accept the refusal."],
  4: ["liquidity", "The wallet cannot cover it. Fund it."],
  5: [
    "protocol",
    "This client and this merchant cannot agree on the challenge. Nothing local helps.",
  ],
  6: ["signer", "The key or the signing device failed."],
  7: ["transport", "The network failed. Retryable under caller policy."],
  8: [
    "ambiguous payment",
    "Money may have moved and tx402 cannot tell. **Never retry blindly.**",
  ],
  9: [
    "resource failure",
    "The resource was not delivered. Read `context.paid` — it is `false` when the merchant refused the settlement and no money moved, and `true` when it settled and delivery then failed.",
  ],
};

async function load() {
  // Imported from built ESM rather than parsed out of source: the generator must read the
  // same values the shipped package exports, not a plausible transcription of them.
  const dist = join(ROOT, "packages", "tx402", "dist");
  const errors = await import(pathToFileURL(join(dist, "index.js")).href);
  const cli = await import(pathToFileURL(join(dist, "cli", "exit-codes.js")).href);
  const client = clientMethods(errors, join(dist, "core", "client.d.ts"));
  return { errors, cli, client };
}

/**
 * The methods a constructed client actually carries, with the signatures it ships.
 *
 * Existence comes from a **real client instance**, for the same reason the tables above read
 * the built package: a list of methods transcribed by hand is a second source of truth. The
 * signature comes from the shipped `.d.ts`, which is the file a reader's editor loads.
 *
 * This exists because the API page listed only top-level module exports, so `inspect`,
 * `plan`, `getBudgetState` and `queryBudgetState` — the entire client surface, and the only
 * way to reconcile a settlement from code — appeared nowhere on the documentation site
 * (PLAN.md O71).
 *
 * @param {Record<string, unknown>} errors the built core entry point
 * @param {string} declarationPath
 */
function clientMethods(errors, declarationPath) {
  const instance = errors["createTx402Client"]({});
  const names = Object.keys(instance).filter((key) => typeof instance[key] === "function");

  let declarations = "";
  try {
    declarations = readFileSync(declarationPath, "utf8");
  } catch {
    declarations = "";
  }

  return names.map((name) => {
    // The declaration line for this member, if the interface is where we expect it. A
    // missing match degrades to the bare name rather than failing the build: the page is
    // still correct, just less specific.
    const match = new RegExp(`^\\s*${name}\\((.*)$`, "mu").exec(declarations);
    if (match === null) return { name, signature: `${name}(…)` };
    return { name, signature: `${name}(${match[1]}`.trim().replace(/;$/u, "") };
  });
}

function table(rows) {
  const widths = rows[0].map((_, column) =>
    Math.max(...rows.map((row) => String(row[column]).length)),
  );
  const render = (row) =>
    `| ${row.map((cell, index) => String(cell).padEnd(widths[index])).join(" | ")} |`;
  const divider = `| ${widths.map((width) => "-".repeat(width)).join(" | ")} |`;
  return [render(rows[0]), divider, ...rows.slice(1).map(render)].join("\n");
}

function errorsPage({ errors, cli }) {
  const { TX402_ERROR_TAXONOMY } = errors;
  const { EXIT_CODE_BY_ERROR, EXIT_CODES } = cli;

  const byExitCode = new Map();
  for (const [code, exit] of Object.entries(EXIT_CODE_BY_ERROR)) {
    if (!byExitCode.has(exit)) byExitCode.set(exit, []);
    byExitCode.get(exit).push(code);
  }

  const summary = table([
    ["Code", "Class", "Exit", "Retryable"],
    ...TX402_ERROR_TAXONOMY.map((entry) => [
      `\`${entry.code}\``,
      `\`${entry.className}\``,
      String(EXIT_CODE_BY_ERROR[entry.code]),
      entry.retryable ? "yes" : "no",
    ]),
  ]);

  const exitTable = table([
    ["Exit", "Meaning", "What to do"],
    ...Object.entries(EXIT_CODE_MEANING).map(([code, [name, action]]) => [
      code,
      name,
      action,
    ]),
  ]);

  const detail = TX402_ERROR_TAXONOMY.map((entry) => {
    const exit = EXIT_CODE_BY_ERROR[entry.code];
    const [exitName] = EXIT_CODE_MEANING[exit];
    const details = entry.requiredDetails.map((key) => `\`${key}\``).join(", ");
    return `### \`${entry.code}\`

\`${entry.className}\` · exit **${exit}** (${exitName}) · \`retryable: ${entry.retryable}\`

**Retryability:** \`${entry.retryability}\` — ${RETRYABILITY_GLOSS[entry.retryability]}

**Always carries**: ${details || "_nothing beyond the shared context_"}

These keys are guaranteed present in \`error.details\`, so a handler can read them without
an existence check. Everything in \`details\` is redaction-safe by construction: identifiers,
atomic amounts, and categories, never a signature, a key, or an authorization payload.`;
  }).join("\n\n");

  const grouped = [...byExitCode.entries()]
    .sort(([a], [b]) => a - b)
    .map(
      ([exit, codes]) => `- **${exit}** — ${codes.map((code) => `\`${code}\``).join(", ")}`,
    )
    .join("\n");

  return `---
title: Error reference
description: Every tx402 error code, what it carries, whether it is retryable, and the CLI exit code it maps to.
sidebar:
  order: 2
---

${BANNER}

tx402 raises **${TX402_ERROR_TAXONOMY.length} typed errors** and the CLI reports them
through **${Object.keys(EXIT_CODES).length} exit codes**. Both tables below are
generated from the shipped source — \`TX402_ERROR_TAXONOMY\` and \`EXIT_CODE_BY_ERROR\` — so a
code documented here is a code the binary actually returns.

Every error is an instance of \`Tx402Error\` (TypeScript) or \`Tx402Error\` (Python) and answers
to \`isTx402Error\` / \`is_tx402_error\`. Catch by class when you want one, by predicate when you
want all of them.

## At a glance

<div class="exit-codes">

${summary}

</div>

## Exit codes

A shell script's \`if [ $? -eq 3 ]\` is a public API, so this mapping is stable and changing a
row is a breaking change. The grouping principle is **what the operator has to change to make
it work** — not error severity, and not which layer raised it.

Exit \`1\` is deliberately never used: it is the runtime's own crash code, and conflating "tx402
refused" with "the interpreter died" would make a script unable to tell them apart.

<div class="exit-codes">

${exitTable}

</div>

Grouped the other way — which errors produce which code:

${grouped}

:::caution[Exit 8 is the one to handle specially]
Exit 8 means the signature reached the merchant and tx402 could not determine the outcome. Two
codes produce it, and they are exactly the two that can only be reached **after** a signature
was transmitted: \`TX402_PAYMENT_AMBIGUOUS\` — a timeout, a 5xx, a connection reset, a
same-origin redirect it declined to follow, or a \`PAYMENT-RESPONSE\` that is present and does
not decode — and \`TX402_REDIRECT_BLOCKED\`, a cross-origin redirect refused after the merchant
already had the signature. In both cases the budget reservation
is deliberately **retained** until its TTL rather than released, so the same money cannot be
spent twice against the hourly cap. Retrying without reconciling against the merchant can pay
twice.
:::

## Every error in detail

${detail}
`;
}

function apiPage({ errors, client }) {
  const exported = Object.keys(errors).sort((a, b) => a.localeCompare(b));
  const isType = (name) => /^[A-Z]/.test(name) && !name.startsWith("TX402_");
  const constants = exported.filter((name) => /^[A-Z0-9_]+$/.test(name));
  const classes = exported.filter(
    (name) =>
      isType(name) && !constants.includes(name) && typeof errors[name] === "function",
  );
  const functions = exported.filter((name) => /^[a-z]/.test(name));

  const list = (names) =>
    names.length === 0 ? "_none_" : names.map((name) => `- \`${name}\``).join("\n");

  return `---
title: TypeScript API surface
description: Every value the tx402 core entry point exports, generated from the built package.
sidebar:
  order: 3
---

${BANNER}

Generated from the built \`tx402\` package's own exports, so this list cannot claim a symbol the
package does not ship. Signatures and per-symbol documentation live in the bundled \`.d.ts\`
files, which your editor reads directly — this page answers "what is available and from where".

## \`tx402\` — the core entry point

Importing this path **must not load a chain library**, and a package-contract test asserts it.
\`viem\`, \`@solana/kit\`, \`@x402/evm\`, and \`@x402/svm\` are reached through a lazy \`import()\`
only when a payment on that family is actually planned.

### Functions

${list(functions)}

### Classes and constructors

${list(classes)}

### Constants

${list(constants)}

## The client itself

\`createTx402Client(config)\` returns an object carrying these methods. They are read from a
constructed instance, so this list cannot claim a method the package does not ship.

${client.map(({ signature }) => `- \`${signature}\``).join("\n")}

\`fetch\` is the one most code calls. The other five are what you reach for when a payment has
to be reasoned about rather than simply made: \`plan\` answers "what would this cost" without
signing or reserving, \`inspect\` returns the raw challenge, and \`getBudgetState\` /
\`queryBudgetState\` read the spend ledger — the latter for any scope, including one written by
another process. Reconciling a settlement from code starts with \`plan\` and ends with
\`queryBudgetState\`.

## Optional subpath exports

| Import | Loads | Use when |
| ------ | ----- | -------- |
| \`tx402/evm\` | \`viem\`, \`@x402/evm\` | You pay on an EVM network and want the bundled adapter. |
| \`tx402/solana\` | \`@solana/kit\`, \`@x402/svm\` | You pay on Solana and want the bundled adapter. |
| \`tx402/signers\` | \`viem/accounts\`, and \`@solana/kit\` lazily | Development only. \`privateKeyToEvmSigner\` wraps a raw hex key as an \`EvmSigner\`; \`keypairToSolanaSigner\` wraps a keypair as a \`SolanaSigner\`. |

The Python package mirrors this split with extras: \`pip install tx402\` is the core,
\`tx402[evm]\`, \`tx402[svm]\`, and \`tx402[all]\` add the chain libraries. \`import tx402\` loads no
chain library in either language.
`;
}

async function main() {
  const command = process.argv[2] ?? "build";
  if (command !== "build" && command !== "check") {
    console.error(`unknown command ${JSON.stringify(command)} — use build or check`);
    process.exit(2);
  }

  const loaded = await load();
  const outputs = [
    [join(DOCS, "reference", "errors.mdx"), errorsPage(loaded)],
    [join(DOCS, "reference", "api-typescript.mdx"), apiPage(loaded)],
  ];

  let stale = 0;
  for (const [path, content] of outputs) {
    const relative = path.slice(ROOT.length + 1);
    if (command === "build") {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content);
      console.log(`  wrote ${relative}`);
      continue;
    }
    let current = "";
    try {
      current = readFileSync(path, "utf8");
    } catch {
      current = "";
    }
    const same =
      createHash("sha256").update(current).digest("hex") ===
      createHash("sha256").update(content).digest("hex");
    if (same) {
      console.log(`  OK    ${relative}`);
    } else {
      stale += 1;
      console.error(`  STALE ${relative}`);
    }
  }

  if (stale > 0) {
    console.error(
      `\n${stale} generated page(s) are stale. Run \`pnpm docs:generate\` and commit the result.`,
    );
    process.exit(1);
  }
  console.log(
    command === "build" ? "\nGenerated pages written." : "\nGenerated pages are current.",
  );
}

await main();
