/**
 * The five operator verbs: `freeze`, `unfreeze`, `budget`, `pins`,
 * `rotate-recipient`.
 *
 * Each verb resolves the configured store (SPEC §9.1, {@link resolveSpendStore}) for its plane,
 * performs one admin- or data-plane operation, and reports the result — a concise line on
 * stdout, or exactly one JSON object under `--json` (the shapes are SPEC §10's table, byte-for
 * byte identical to the Python CLI's; the cross-language golden pins that). Exit numbers are
 * **reused**: `0` success, `2` usage/config (including an admin verb run without an
 * admin credential — `admin-credential-required`), `7` a store outage. No new exit number.
 *
 * The stdout/stderr contract is the same as `tx402 call`: the *result* goes to
 * stdout (the JSON object, or the human summary); every warning — including the §6.7
 * freeze-before-rotate advisory — goes to stderr, so `tx402 budget … --json > out.json` stays a
 * clean artifact.
 */

import { BUNDLED_MANIFEST } from "../core/bundled-manifest.js";
import { TransportError, isTx402Error } from "../core/errors.js";
import { canonicalizeRecipient } from "../core/ledger.js";
import { normalizePolicyHost } from "../core/policy.js";
import type {
  BudgetOptions,
  FreezeOptions,
  PinsOptions,
  RotateRecipientOptions,
} from "./args.js";
import { EXIT_CODES, UsageError, exitCodeFor, type ExitCode } from "./exit-codes.js";
import type { CliIo } from "./run.js";
import { resolveSpendStore } from "./store-config.js";

/** Schema version of a verb's `--json` document. Shares the `call` document's version. */
const JSON_SCHEMA_VERSION = 1;

/** A parsed operator verb, as produced by {@link parseArgs}. */
export type VerbCommand =
  | { readonly kind: "freeze"; readonly options: FreezeOptions }
  | { readonly kind: "unfreeze"; readonly options: FreezeOptions }
  | { readonly kind: "budget"; readonly options: BudgetOptions }
  | { readonly kind: "pins"; readonly options: PinsOptions }
  | { readonly kind: "rotate-recipient"; readonly options: RotateRecipientOptions };

/**
 * O53 defence-in-depth. A store-read failure that is not already a typed tx402 error is an
 * unclassified infrastructure failure on the data-plane read path — surface it as a retryable
 * `TransportError` (exit 7), never let the top-level catch map it to exit 2 (usage). The store
 * adapters already type a known outage (that is the primary O53 fix); this narrow guard, wrapping
 * only the store-read section of a data verb, stops a FUTURE unwrapped read from regressing
 * `cli.mdx`'s exit-7 contract (INV-7 — a policy-infrastructure failure never silently reclassifies).
 * A tx402 error (a refusal, or an already-typed transport error) passes through unchanged.
 */
function reclassifyStoreRead(error: unknown): never {
  if (isTx402Error(error)) throw error;
  throw new TransportError("The spend store is unreachable", {
    context: { requestId: "spend-store", phase: "policy" },
    // Coarse category only (SEC-003) — never the DSN or the store-library internal message.
    details: { causeCategory: "spend-store-unavailable" },
  });
}

/** Dispatches one operator verb and returns its exit code. Never throws (mirrors `run`). */
export async function runVerb(io: CliIo, parsed: VerbCommand): Promise<ExitCode> {
  const json = parsed.options.json;
  try {
    switch (parsed.kind) {
      case "freeze":
        return await runFreeze(io, parsed.options, true);
      case "unfreeze":
        return await runFreeze(io, parsed.options, false);
      case "budget":
        return await runBudget(io, parsed.options);
      case "pins":
        return await runPins(io, parsed.options);
      case "rotate-recipient":
        return await runRotateRecipient(io, parsed.options);
    }
  } catch (error) {
    return renderVerbError(io, json, error);
  }
}

// ── freeze / unfreeze (admin) ─────────────────────────────────────────────────────────────────

async function runFreeze(
  io: CliIo,
  options: FreezeOptions,
  freeze: boolean,
): Promise<ExitCode> {
  const scope = normalizeScope(options.target);
  const now = Date.now();
  const resolved = await resolveSpendStore(io.env, "admin");
  try {
    if (freeze) await resolved.store.freeze(scope, now);
    else await resolved.store.unfreeze(scope, now);
  } finally {
    await resolved.dispose();
  }

  if (options.json) {
    io.stdout(
      renderJson({
        ok: true,
        exitCode: EXIT_CODES.success,
        scope,
        frozen: freeze,
      }),
    );
  } else {
    io.stdout(`${freeze ? "froze" : "unfroze"} ${scope}\n`);
  }
  return EXIT_CODES.success;
}

// ── budget (data) ─────────────────────────────────────────────────────────────────────────────

async function runBudget(io: CliIo, options: BudgetOptions): Promise<ExitCode> {
  const scope = normalizeScope(options.target);
  const assetId = resolveAssetId(options.network, options.asset);
  const maxPerHour = parseAtomicFlag(options.maxPerHour, "--max-per-hour");
  const maxTotal = parseAtomicFlag(options.maxTotal, "--max-total");
  const now = Date.now();

  const resolved = await resolveSpendStore(io.env, "data");
  let state;
  try {
    state = await resolved.store.getBudgetState({
      policyScope: scope,
      assetId,
      nowEpochMs: now,
    });
  } catch (error) {
    reclassifyStoreRead(error); // O53: an unclassified store-read failure is a transport outage.
  } finally {
    await resolved.dispose();
  }

  // Availability precedence (SPEC §10 P1-8b): administered limits first, then the value-flags,
  // then neither → null with limitSource "unknown". The per-request `--max-spend` cap is NOT a
  // source here — it never derives per-hour/cumulative availability.
  const committed = state.committedAtomic;
  const reserved = state.reservedAtomic;
  const exposed = state.exposedAtomic ?? "0";
  const cumulativeCommitted = state.cumulativeCommittedAtomic ?? "0";
  const cumulativeConsumed = state.cumulativeConsumedAtomic ?? "0";

  let limitSource: "administered" | "value-flags" | "unknown";
  let perHourLimit: string | null;
  let cumulativeLimit: string | null;
  let availablePerHour: string | null;
  let availableCumulative: string | null;

  if (state.perHourLimitAtomic !== undefined || state.cumulativeLimitAtomic !== undefined) {
    limitSource = "administered";
    perHourLimit = state.perHourLimitAtomic ?? null;
    cumulativeLimit = state.cumulativeLimitAtomic ?? null;
    availablePerHour = state.availablePerHourAtomic ?? null;
    availableCumulative = state.availableCumulativeAtomic ?? null;
  } else if (maxPerHour !== undefined || maxTotal !== undefined) {
    limitSource = "value-flags";
    // Per-hour consumed is committed + reserved + exposed; cumulative consumed is reported
    // directly. Availability clamps at zero (a cap below current consumption yields 0, never a
    // negative), mirroring the administered computation in `MemorySpendStore`.
    const perHourConsumed = addAtomic(addAtomic(committed, reserved), exposed);
    perHourLimit = maxPerHour ?? null;
    cumulativeLimit = maxTotal ?? null;
    availablePerHour =
      maxPerHour === undefined ? null : subClamp(maxPerHour, perHourConsumed);
    availableCumulative =
      maxTotal === undefined ? null : subClamp(maxTotal, cumulativeConsumed);
  } else {
    limitSource = "unknown";
    perHourLimit = null;
    cumulativeLimit = null;
    availablePerHour = null;
    availableCumulative = null;
  }

  const document = {
    ok: true,
    exitCode: EXIT_CODES.success,
    scope,
    network: options.network,
    asset: assetId,
    committedAtomic: committed,
    reservedAtomic: reserved,
    exposedAtomic: exposed,
    cumulativeCommittedAtomic: cumulativeCommitted,
    cumulativeConsumedAtomic: cumulativeConsumed,
    limitSource,
    perHourLimitAtomic: perHourLimit,
    cumulativeLimitAtomic: cumulativeLimit,
    availablePerHourAtomic: availablePerHour,
    availableCumulativeAtomic: availableCumulative,
    frozen: state.frozen ?? false,
  };

  if (options.json) {
    io.stdout(renderJson(document));
  } else {
    renderBudgetHuman(io, document);
  }
  return EXIT_CODES.success;
}

// ── pins (data) ───────────────────────────────────────────────────────────────────────────────

async function runPins(io: CliIo, options: PinsOptions): Promise<ExitCode> {
  const scope = normalizeScope(options.target);
  const resolved = await resolveSpendStore(io.env, "data");
  let recipients: readonly string[];
  let policy: { tofuEnabled: boolean; recipientAssertionRequired: boolean };
  try {
    recipients = await resolved.store.getRecipientPins(scope, options.network);
    // Report the scope's recipient policy state too (§6.1), so an operator can see WHY a TOFU
    // route fails closed — whether the store enables TOFU claims and whether it requires the
    // recipient to be asserted. Every store the `pins` verb targets exposes this (O21).
    policy = await resolved.store.getRecipientPolicy(scope);
  } catch (error) {
    reclassifyStoreRead(error); // O53: an unclassified store-read failure is a transport outage.
  } finally {
    await resolved.dispose();
  }

  if (options.json) {
    io.stdout(
      renderJson({
        ok: true,
        exitCode: EXIT_CODES.success,
        scope,
        network: options.network,
        recipients: [...recipients],
        tofuEnabled: policy.tofuEnabled,
        recipientAssertionRequired: policy.recipientAssertionRequired,
      }),
    );
  } else {
    renderRecipientsHuman(io, scope, options.network, recipients, policy);
  }
  return EXIT_CODES.success;
}

// ── rotate-recipient (admin) ──────────────────────────────────────────────────────────────────

async function runRotateRecipient(
  io: CliIo,
  options: RotateRecipientOptions,
): Promise<ExitCode> {
  const scope = normalizeScope(options.target);
  const now = Date.now();
  // Canonicalize the new set exactly as `reserve` will compare it (SPEC §6.4): eip155 →
  // lowercase hex, base58 → verbatim. A clean allowlist is stored, not a mixed-case one.
  const recipients = options.to.map((address) =>
    canonicalizeRecipient(options.network, address),
  );

  const resolved = await resolveSpendStore(io.env, "admin");
  try {
    // §6.7 freeze-before-rotate advisory. On raw Redis the pin and budget keys share one
    // backend, so the in-reserve assertion already makes rotation race-free — no warning. A
    // gateway hides its backend topology, so the CLI cannot confirm the pins and budgets are
    // co-located; it conservatively warns when the scope is not currently frozen.
    if (resolved.kind !== "redis" && !(await resolved.store.isFrozen(scope))) {
      io.stderr(
        `warning: ${scope} is not frozen. If the pin store is a separate backend from the ` +
          `spend store, freeze the scope before rotating so no reserve races the rotation, ` +
          `then unfreeze.\n`,
      );
    }
    await resolved.store.setRecipientPins(scope, options.network, recipients, now);
  } finally {
    await resolved.dispose();
  }

  if (options.json) {
    io.stdout(
      renderJson({
        ok: true,
        exitCode: EXIT_CODES.success,
        scope,
        network: options.network,
        recipients,
      }),
    );
  } else {
    renderRecipientsHuman(io, scope, options.network, recipients);
  }
  return EXIT_CODES.success;
}

// ── shared helpers ────────────────────────────────────────────────────────────────────────────

/**
 * Normalizes a verb's target to a policy scope. `"*"` (the whole-store freeze sentinel) passes
 * through; a bare host is wrapped as `https://<host>` because {@link normalizePolicyHost}
 * requires an absolute URL (it discards the scheme/path, keeping only the normalized host).
 */
function normalizeScope(target: string): string {
  if (target === "*") return "*";
  return normalizePolicyHost(target.includes("://") ? target : `https://${target}`);
}

/**
 * Resolves the `{scope, asset}` key's asset id (CAIP-19, SPEC §3.1). `--asset` is a token
 * address/mint the network's family formats (`erc20:` for eip155, `token:` otherwise); a value
 * already containing `/` is treated as a full asset id. Absent ⇒ the network's canonical asset
 * from the bundled manifest (`assets[0]`), so `budget https://m --network eip155:8453` works.
 */
function resolveAssetId(network: string, asset: string | undefined): string {
  const namespace = network.startsWith("eip155:") ? "erc20" : "token";
  if (asset !== undefined) {
    return asset.includes("/") ? asset : `${network}/${namespace}:${asset}`;
  }
  const manifestNetwork = BUNDLED_MANIFEST.networks[network];
  const first = manifestNetwork?.assets[0];
  if (first === undefined) {
    throw new UsageError(
      `Cannot infer a default asset for ${network}; pass --asset <address>.`,
    );
  }
  const reference = "address" in first ? first.address : first.mint;
  return `${network}/${namespace}:${reference}`;
}

/**
 * Parses a `--max-per-hour`/`--max-total` value-flag. Atomic integer units (the smallest
 * denomination), the same units `budget` reports — so the caps and the balances read in one
 * scale, and parsing needs no asset metadata (it works for any asset, known or not).
 */
function parseAtomicFlag(value: string | undefined, flag: string): string | undefined {
  if (value === undefined) return undefined;
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new UsageError(`${flag} takes atomic integer units, e.g. ${flag} 5000000`);
  }
  return value;
}

function addAtomic(a: string, b: string): string {
  return (BigInt(a) + BigInt(b)).toString();
}

/** `max(0, minuend − subtrahend)`, as an atomic string. */
function subClamp(minuend: string, subtrahend: string): string {
  const difference = BigInt(minuend) - BigInt(subtrahend);
  return (difference > 0n ? difference : 0n).toString();
}

/** One JSON object, pretty-printed with the schema version, matching the `call` document. */
function renderJson(fields: Record<string, unknown>): string {
  return `${JSON.stringify({ schemaVersion: JSON_SCHEMA_VERSION, ...fields }, null, 2)}\n`;
}

/** Stringifies a redaction-safe scalar (string/number/boolean/null) for human output. */
function scalarText(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function renderBudgetHuman(io: CliIo, document: Record<string, unknown>): void {
  const line = (label: string, value: unknown) =>
    io.stdout(`${label.padEnd(20)}${scalarText(value)}\n`);
  line("scope", document["scope"]);
  line("network", document["network"]);
  line("asset", document["asset"]);
  line("committed", document["committedAtomic"]);
  line("reserved", document["reservedAtomic"]);
  line("exposed", document["exposedAtomic"]);
  line("cumulative", document["cumulativeConsumedAtomic"]);
  line("per-hour limit", document["perHourLimitAtomic"]);
  line("per-hour available", document["availablePerHourAtomic"]);
  line("cumulative limit", document["cumulativeLimitAtomic"]);
  line("cumulative avail.", document["availableCumulativeAtomic"]);
  line("limit source", document["limitSource"]);
  line("frozen", document["frozen"]);
}

function renderRecipientsHuman(
  io: CliIo,
  scope: string,
  network: string,
  recipients: readonly string[],
  policy?: { tofuEnabled: boolean; recipientAssertionRequired: boolean },
): void {
  io.stdout(`scope     ${scope}\n`);
  io.stdout(`network   ${network}\n`);
  if (policy !== undefined) {
    io.stdout(`tofu enabled          ${policy.tofuEnabled}\n`);
    io.stdout(`assertion required    ${policy.recipientAssertionRequired}\n`);
  }
  if (recipients.length === 0) {
    io.stdout("recipients  (none)\n");
    return;
  }
  for (const recipient of recipients) io.stdout(`recipient ${recipient}\n`);
}

/**
 * Renders a verb failure and returns its exit code. A typed store/config error keeps its exact
 * exit (config → 2, transport/outage → 7); anything else is exit 2. Under `--json` a minimal
 * `{code, message, details}` error object is emitted (deterministic and byte-identical across
 * languages — no volatile context), otherwise a `code: message` line to stderr.
 */
function renderVerbError(io: CliIo, json: boolean, error: unknown): ExitCode {
  const code = exitCodeFor(error);
  if (json) {
    const errorField = isTx402Error(error)
      ? { code: error.code, message: error.message, details: { ...error.details } }
      : error instanceof UsageError
        ? { code: "TX402_CLI_USAGE", message: error.message, details: {} }
        : { code: "TX402_CLI_USAGE", message: String(error), details: {} };
    io.stdout(
      `${JSON.stringify(
        {
          schemaVersion: JSON_SCHEMA_VERSION,
          ok: false,
          exitCode: code,
          error: errorField,
        },
        null,
        2,
      )}\n`,
    );
  } else if (isTx402Error(error)) {
    io.stderr(`${error.code}: ${error.message}\n`);
    for (const [key, value] of Object.entries(error.details)) {
      if (value !== undefined) io.stderr(`  ${key.padEnd(20)}${scalarText(value)}\n`);
    }
  } else if (error instanceof UsageError) {
    io.stderr(`tx402: ${error.message}\n`);
  } else {
    io.stderr(`tx402: ${String(error)}\n`);
  }
  return code;
}
