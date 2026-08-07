/**
 * `tx402 call` — the CLI's testable core (SPEC §11).
 *
 * Every effect is injected through {@link CliIo}, so the whole command surface — exit codes,
 * the stdout/stderr split, `--json` shape, the dry-run signer guarantee — is exercised in
 * process by the test suite rather than by spawning a shell and matching on text.
 *
 * **The stdout/stderr contract is load-bearing** (SPEC §11). stdout carries the response
 * body, or exactly one JSON object under `--json`, and nothing else ever. Every diagnostic,
 * warning and error goes to stderr. That is what makes `tx402 call … > out.json` produce a
 * usable file even when the call emitted warnings, and it is why the SDK itself is forbidden
 * from writing to the console at all (SPEC §10) — the CLI renders from the structured event
 * stream instead.
 */

import {
  CHAIN_INSTALL_COMMANDS,
  createTx402Client,
  type PaymentPlan,
  type Tx402Client,
  type Tx402Logger,
} from "../core/client.js";
import { chainFamily } from "../core/chain.js";
import { isTx402Error, type Tx402Error, type Tx402ErrorDetails } from "../core/errors.js";
import type { Tx402Signers } from "../core/signers.js";
import { formatMoneyDecimal } from "../core/money.js";
import { PACKAGE_NAME, PROJECT_URLS } from "../meta.js";
import { PACKAGE_VERSION } from "../version.js";
import { parseArgs, type CallOptions } from "./args.js";
import { EXIT_CODES, UsageError, exitCodeFor, type ExitCode } from "./exit-codes.js";

/** Schema version of the `--json` document. Bumped only on a breaking shape change. */
export const JSON_SCHEMA_VERSION = 1;

/** Documented development-key variables (SPEC §11). Never flags. */
export const DEV_KEY_ENV = {
  evm: "TX402_DEV_PRIVATE_KEY",
  solana: "TX402_DEV_SOLANA_KEYPAIR",
} as const;

/**
 * Every effect the CLI has, in one injectable object.
 *
 * Declared as function-typed properties rather than method shorthand so they can be passed
 * around detached — `parseArgs(io.argv, io.readFile)` — without `this` binding surprises.
 */
export interface CliIo {
  readonly argv: readonly string[];
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly readFile: (path: string) => string;
  /** Injected so tests can supply signers without touching a real key. */
  readonly createClient?: typeof createTx402Client;
}

const USAGE = `${PACKAGE_NAME} — resilient x402 buyer client

Usage:
  tx402 call <URL> [options]

Options:
  --method <METHOD>     HTTP method (default: GET)
  --body @<file>        Request body, read from a file
  --max-spend <MONEY>   Per-request cap, e.g. "0.10 USDC"
  --network <CAIP2>     Allow only this network. Required to pay on a testnet:
                        the default policy allows production networks only.
  --dry-run             Parse, evaluate policy, and plan routes. Never signs.
                        Needs a configured key — planning reads your balance.
  --json                Emit one JSON object on stdout
  --timeout <MS>        Paid-retry timeout in whole milliseconds
  -h, --help            Show this message
  -v, --version         Show version

Exit codes:
  0 success   2 usage/config   3 policy    4 liquidity   5 protocol
  6 signer    7 transport      8 ambiguous payment       9 resource failure

Signing keys are never accepted as flags. For development only, tx402 reads
${DEV_KEY_ENV.evm} and ${DEV_KEY_ENV.solana}; prefer an external signer.

Docs: ${PROJECT_URLS.documentation}`;

/**
 * A missing optional chain package, as distinct from a malformed key.
 *
 * These two failures arrive at the same `catch` and mean opposite things: one is fixed by
 * installing a package, the other by correcting an environment variable. Reporting the
 * first as the second is what sent a reader off to regenerate a key that was already
 * correct, while the real cause — an uninstalled chain row — went unmentioned (O77).
 */
function isMissingChainPackage(error: unknown): boolean {
  return (
    error instanceof Error && (error as { code?: unknown }).code === "ERR_MODULE_NOT_FOUND"
  );
}

/** Collects the structured event stream so `--json` can report real timings. */
function collectingLogger(events: Record<string, unknown>[]): Tx402Logger {
  const push = (event: Readonly<Record<string, unknown>>) => {
    events.push({ ...event });
  };
  return { debug: push, info: push, warn: push, error: push };
}

/**
 * Builds signers from the documented environment variables, warning first.
 *
 * The warning is unconditional and goes to stderr on every run that uses one of these, not
 * once per session and not behind a verbosity flag. A key in an environment variable is a
 * key any child process and any crash reporter can read, and the operator should be told
 * every single time — SPEC §11 requires the warning, and habituation is the failure mode
 * that a once-per-session warning would introduce.
 */
async function resolveSigners(io: CliIo, dryRun: boolean): Promise<Tx402Signers> {
  const evmKey = io.env[DEV_KEY_ENV.evm];
  const solanaKey = io.env[DEV_KEY_ENV.solana];
  if (evmKey === undefined && solanaKey === undefined) return {};

  const warn = (variable: string) =>
    io.stderr(
      `warning: using a development signing key from ${variable}. ` +
        `Anything that can read this process's environment can read the key. ` +
        `Use an external signer for anything but a low-balance test wallet.\n`,
    );

  /**
   * Reports a chain whose signer could not be built because its packages are absent.
   *
   * Skipped rather than fatal, and this is the whole of O77: a key exported for a chain
   * you did not install must not take down a request that never needed that chain. The
   * signer is simply not offered, which can only ever remove a payment option — never
   * redirect one — and a route that does need it still fails by name further in.
   */
  const skip = (variable: string, family: string) =>
    io.stderr(
      `warning: ${variable} is set, but ${family}'s optional chain packages are not ` +
        `installed, so that signer was not loaded. ` +
        `Run: ${CHAIN_INSTALL_COMMANDS[family] ?? "the chain's install command"}\n`,
    );

  // Loaded lazily so the CLI's help and usage paths never pull in a chain library, and so a
  // dry run against a machine without `viem` installed still works. `Tx402Signers` is
  // readonly, so each signer is resolved into a local and the object is built once.
  let evm: Tx402Signers["evm"];
  let solana: Tx402Signers["solana"];

  if (evmKey !== undefined) {
    warn(DEV_KEY_ENV.evm);
    try {
      // `tx402/signers` imports `viem/accounts` at module scope, so on a bare install this
      // rejects here rather than at the call — which is how a raw ERR_MODULE_NOT_FOUND,
      // quoting an absolute path and an internal `dist/` path, used to reach the operator
      // (O79). It is inside the try for exactly that reason.
      const { privateKeyToEvmSigner } = await import("../signers/index.js");
      const signer = privateKeyToEvmSigner(evmKey as `0x${string}`);

      // SPEC §11: --dry-run MUST NOT invoke a signer. Enforced structurally rather than by
      // trusting the code path, so that any future edit which reaches signing on this path
      // fails loudly instead of quietly producing a signature during a "dry" run.
      evm = dryRun
        ? {
            kind: "evm",
            getAddress: () => signer.getAddress(),
            signTypedData: () => {
              throw new Error("tx402: --dry-run must never produce a signature");
            },
          }
        : signer;
    } catch (error) {
      if (!isMissingChainPackage(error)) {
        // The thrown message is not forwarded — a key-validation error tends to quote its input.
        throw new UsageError(
          `${DEV_KEY_ENV.evm} is not a 0x-prefixed 32-byte hex private key`,
        );
      }
      skip(DEV_KEY_ENV.evm, "eip155");
    }
  }

  if (solanaKey !== undefined) {
    warn(DEV_KEY_ENV.solana);
    try {
      const { keypairToSolanaSigner } = await import("../signers/index.js");
      // `@solana/kit` is imported inside this call, so a missing Solana install surfaces
      // from here rather than from the import above.
      const signer = await keypairToSolanaSigner(solanaKey);

      solana = dryRun
        ? {
            kind: "solana",
            getPublicKey: () => signer.getPublicKey(),
            signTransaction: () => {
              throw new Error("tx402: --dry-run must never produce a signature");
            },
          }
        : signer;
    } catch (error) {
      if (!isMissingChainPackage(error)) {
        throw new UsageError(
          `${DEV_KEY_ENV.solana} is not a JSON array of 64 Solana keypair bytes`,
        );
      }
      skip(DEV_KEY_ENV.solana, "solana");
    }
  }

  return {
    ...(evm === undefined ? {} : { evm }),
    ...(solana === undefined ? {} : { solana }),
  };
}

function renderPlanHuman(io: CliIo, plan: PaymentPlan): void {
  if (plan.paymentRequired === undefined) {
    io.stderr(`no payment required — resource answered ${plan.response.status}\n`);
    return;
  }
  const selected = plan.selected;
  io.stderr(`request-id      ${plan.requestId}\n`);
  io.stderr(`requirements    ${plan.paymentRequired.requirements.length}\n`);
  if (selected === undefined) {
    io.stderr("no viable route\n");
    return;
  }
  io.stderr(`would pay       ${selected.amountAtomic} atomic on ${selected.network}\n`);
  io.stderr(`scheme          ${selected.scheme}\n`);
  io.stderr(`asset           ${selected.assetId}\n`);
  io.stderr(`health/rank     ${selected.healthScore.toFixed(2)} / ${selected.rank}\n`);
  io.stderr(`candidates      ${plan.candidates?.length ?? 0}\n`);
  io.stderr("dry run — nothing was signed and no budget was reserved\n");
}

/**
 * Recovers the inspection and route facts from the structured event stream.
 *
 * `fetch` returns a `Response`, not a plan, so on the paying path these are not available
 * as return values — but SPEC §11 requires `--json` to report both. Rather than widen the
 * SDK's return type for the CLI's benefit, they are read back out of the SPEC §10 events
 * the run already emitted. Those events are redaction-safe by construction, so nothing
 * reaches the JSON document that could not already be logged.
 */
function fromEvents(events: readonly Record<string, unknown>[]) {
  const find = (name: string) => events.find((event) => event["event"] === name);
  const required = find("payment.required");
  const planned = find("route.planned");
  return {
    inspection:
      required === undefined
        ? null
        : {
            requirementCount: required["requirementCount"],
            headerHash: required["headerHash"],
          },
    route:
      planned === undefined
        ? null
        : {
            network: planned["selectedNetwork"],
            scheme: planned["selectedScheme"],
            healthScore: planned["selectedHealthScore"],
            rank: planned["selectedRank"],
            candidateCount: planned["candidateCount"],
          },
  };
}

/**
 * What `--json` reports about the money, once a signature has left the process.
 *
 * `status` reuses the SDK's own disposition vocabulary rather than inventing a second one:
 * `committed` is the ledger's `paid: true`, `unknown` is its `paid: "unknown"`. The whole
 * object is `null` when no signature was ever produced, which is the honest answer for a
 * dry run and for every policy or protocol refusal — those never reach a signer.
 */
interface SettlementReport {
  readonly status: "committed" | "unknown";
  readonly transaction: string | null;
  readonly payer: string | null;
}

/** The payer address on the chain the route selected, or `null` when it cannot be known. */
async function payerAddress(
  signers: Tx402Signers,
  network: string | undefined,
): Promise<string | null> {
  if (network === undefined) return null;
  const family = chainFamily(network);
  if (family === "eip155" && signers.evm !== undefined) {
    return signers.evm.getAddress();
  }
  if (family === "solana" && signers.solana !== undefined) {
    return signers.solana.getPublicKey();
  }
  return null;
}

/**
 * Reads the settlement facts back out of the ledger after the call (O74).
 *
 * **Why this is read from the ledger and not from the event stream.** SPEC §10's
 * `payment.completed` carries `settlementIdHash`, deliberately: events are the thing that
 * ends up in a log aggregator, and a settlement identifier there is a payment graph handed
 * to whoever runs the aggregator. The **raw** identifier belongs to the buyer and is kept on
 * their own `SpendEntry` (SPEC §5.3), which is process-local. `--json` on the buyer's own
 * stdout is that same trust boundary, so the raw value is correct here and the hash stays
 * correct in the events. Neither side changes; only this reader is new. See ADR-019.
 */
async function settlementFor(
  client: Tx402Client,
  signers: Tx402Signers,
  events: readonly Record<string, unknown>[],
  status: SettlementReport["status"],
): Promise<SettlementReport | null> {
  // `budget.reserved` is emitted immediately before the signer is reachable, so its
  // presence is the precise test for "money is in play". A merchant that answered 200
  // outright never reserves, and reporting a settlement for that call would be a lie.
  const reserved = events.find((event) => event["event"] === "budget.reserved");
  if (reserved === undefined) return null;

  // Matched by reservation id rather than by taking the newest entry, so this stays correct
  // against a shared spend store that another process is also writing to.
  const reservationId = reserved["reservationId"];
  const entry = client
    .getBudgetState()
    .entries.find((candidate) => candidate.reservationId === reservationId);

  const planned = events.find((event) => event["event"] === "route.planned");
  const selected = planned?.["selectedNetwork"];
  const payer = await payerAddress(
    signers,
    typeof selected === "string" ? selected : undefined,
  );
  return {
    status,
    // Null when the reservation never committed (an ambiguous outcome), and also when the
    // merchant supplied no settlement identifier — the pinned protocol marks
    // PAYMENT-RESPONSE optional and that case commits with a warning (SPEC §6.7).
    transaction: entry?.settlementId ?? null,
    payer,
  };
}

/** The `--json` document (SPEC §11: schema version, inspection, route, timings, error). */
function jsonDocument(fields: {
  ok: boolean;
  exitCode: ExitCode;
  requestId?: string;
  status?: number;
  dryRun: boolean;
  plan?: PaymentPlan;
  body?: string;
  error?: Tx402Error | UsageError;
  settlement?: SettlementReport;
  elapsedMs: number;
  events: Record<string, unknown>[];
}): string {
  const { plan, error } = fields;
  // A dry run has the plan in hand and reports it directly; the paying path reconstructs
  // the same facts from the event stream, so both produce the same document shape.
  const recovered = fromEvents(fields.events);
  return `${JSON.stringify(
    {
      schemaVersion: JSON_SCHEMA_VERSION,
      ok: fields.ok,
      exitCode: fields.exitCode,
      dryRun: fields.dryRun,
      ...(fields.requestId === undefined ? {} : { requestId: fields.requestId }),
      inspection:
        plan?.paymentRequired === undefined
          ? recovered.inspection
          : {
              status: plan.response.status,
              requirementCount: plan.paymentRequired.requirements.length,
              headerHash: plan.paymentRequired.headerHash,
            },
      route:
        plan?.selected === undefined
          ? recovered.route
          : {
              network: plan.selected.network,
              scheme: plan.selected.scheme,
              assetId: plan.selected.assetId,
              amountAtomic: plan.selected.amountAtomic,
              healthScore: plan.selected.healthScore,
              rank: plan.selected.rank,
              candidateCount: plan.candidates?.length ?? 0,
            },
      ...(fields.status === undefined ? {} : { status: fields.status }),
      ...(fields.body === undefined ? {} : { body: fields.body }),
      // Always present, so `null` means "nothing was ever signed" rather than "this build
      // does not report settlement" — an absent key cannot distinguish those.
      settlement: fields.settlement ?? null,
      timings: { elapsedMs: fields.elapsedMs, events: fields.events.length },
      // `toJSON` on Tx402Error deliberately omits `cause` (SEC-003), so this cannot carry a
      // signer payload or a URL with credentials into a log aggregator.
      error:
        error === undefined
          ? null
          : isTx402Error(error)
            ? error.toJSON()
            : { code: "TX402_CLI_USAGE", message: error.message },
    },
    null,
    2,
  )}\n`;
}

/**
 * Renders `error.details` to stderr, under the message it explains.
 *
 * Without this the printed remedy for the most common first error was not followable: exit
 * `5` says "No allowed payment network was offered" and the documentation says to copy a
 * value out of `offeredNetworks`, but that key reached the operator **only** under `--json`.
 * A remedy the default output cannot carry is not a remedy (O75).
 *
 * Printing the whole of `details` rather than special-casing one code is deliberate. SPEC §8
 * makes every error's required keys part of its contract, and `details` is redaction-safe by
 * construction — identifiers, atomic amounts and categories, never a signature, a key or an
 * authorization payload. So the general rule is both safe and the one that keeps the next
 * error's documented remedy followable without another edit here.
 */
function renderDetailsHuman(io: CliIo, details: Tx402ErrorDetails): void {
  for (const [key, value] of Object.entries(details)) {
    if (value === undefined) continue;
    const rendered = Array.isArray(value)
      ? value
          .map((item) => (typeof item === "string" ? item : JSON.stringify(item)))
          .join(", ")
      : typeof value === "string" || typeof value === "number" || typeof value === "boolean"
        ? String(value)
        : JSON.stringify(value);
    io.stderr(`  ${key.padEnd(28)}${rendered}\n`);
  }
}

/**
 * Runs one CLI invocation and returns its exit code.
 *
 * Never throws and never calls `process.exit`: the caller owns the process. That is what
 * lets the test suite assert on exit codes directly.
 */
export async function run(io: CliIo): Promise<ExitCode> {
  const startedAt = Date.now();
  const events: Record<string, unknown>[] = [];
  let options: CallOptions | undefined;
  // Held outside the try so the failure path can still report what it knows about the
  // money: exit 8 and exit 9 both mean a signature left this process (O74).
  let client: Tx402Client | undefined;
  let signers: Tx402Signers | undefined;

  try {
    const parsed = parseArgs(io.argv, io.readFile);
    if (parsed.kind === "help") {
      io.stdout(`${USAGE}\n`);
      return EXIT_CODES.success;
    }
    if (parsed.kind === "version") {
      io.stdout(`${PACKAGE_NAME} ${PACKAGE_VERSION}\n`);
      return EXIT_CODES.success;
    }
    options = parsed.options;

    // One policy object, built once. Spreading `{ policy: … }` per flag would make the last
    // flag win and silently drop the other — `--max-spend` quietly ignored because
    // `--network` was also given is exactly the kind of guardrail failure that only shows up
    // as an unexpectedly large payment.
    const policy = {
      ...(options.maxSpend === undefined ? {} : { maxPerRequest: options.maxSpend }),
      ...(options.network === undefined ? {} : { allowedNetworks: [options.network] }),
    };

    const create = io.createClient ?? createTx402Client;
    signers = await resolveSigners(io, options.dryRun);
    client = create({
      signers,
      logger: collectingLogger(events),
      ...(Object.keys(policy).length === 0 ? {} : { policy }),
      ...(options.timeoutMs === undefined
        ? {}
        : { timeouts: { paymentRetryMs: options.timeoutMs } }),
      // Localhost over plain HTTP is allowed so the documented local-merchant walkthrough
      // works; every other host is still required to be HTTPS by the SDK.
      allowInsecureLocalhost: true,
    });

    const init = {
      method: options.method,
      ...(options.body === undefined ? {} : { body: options.body }),
    };

    if (options.dryRun) {
      const plan = await client.plan(options.url, init);
      const elapsedMs = Date.now() - startedAt;
      if (options.json) {
        io.stdout(
          jsonDocument({
            ok: true,
            exitCode: EXIT_CODES.success,
            requestId: plan.requestId,
            dryRun: true,
            plan,
            elapsedMs,
            events,
          }),
        );
      } else {
        renderPlanHuman(io, plan);
      }
      return EXIT_CODES.success;
    }

    const response = await client.fetch(options.url, init);
    const body = await response.text();
    const elapsedMs = Date.now() - startedAt;

    if (options.json) {
      // A delivered resource means the ledger committed, so this reports the real
      // settlement identifier and the address that paid it.
      const settlement = await settlementFor(client, signers ?? {}, events, "committed");
      io.stdout(
        jsonDocument({
          ok: response.ok,
          exitCode: EXIT_CODES.success,
          dryRun: false,
          status: response.status,
          body,
          ...(settlement === null ? {} : { settlement }),
          elapsedMs,
          events,
        }),
      );
    } else {
      // The body, and only the body. A caller redirecting stdout gets a clean artifact.
      io.stdout(body);
    }
    return EXIT_CODES.success;
  } catch (error) {
    const code = exitCodeFor(error);
    const elapsedMs = Date.now() - startedAt;

    // Exactly the two failures where money is in play — exit 8 and exit 9. The disposition
    // comes from the error's own `paid` context rather than from the exit code, so the CLI
    // cannot drift out of step with what the SDK actually concluded.
    const paid = isTx402Error(error) ? error.context.paid : undefined;
    const settlement =
      client === undefined || paid === undefined || paid === false
        ? undefined
        : ((await settlementFor(
            client,
            signers ?? {},
            events,
            paid === true ? "committed" : "unknown",
          )) ?? undefined);

    if (options?.json === true) {
      io.stdout(
        jsonDocument({
          ok: false,
          exitCode: code,
          dryRun: options.dryRun,
          elapsedMs,
          events,
          ...(settlement === undefined ? {} : { settlement }),
          ...(isTx402Error(error) || error instanceof UsageError ? { error } : {}),
        }),
      );
    } else if (isTx402Error(error)) {
      io.stderr(`${error.code}: ${error.message}\n`);
      renderDetailsHuman(io, error.details);

      // **One line of advice, derived from `paid` rather than from the error code.**
      //
      // This was previously two renderers that could each speak: an advisory keyed on
      // `TX402_PAYMENT_AMBIGUOUS`, and the settlement block's own header. An ambiguous
      // payment therefore said "the payment may have settled" twice, and — the half that
      // actually mattered — `TX402_REDIRECT_BLOCKED` said it once *without* the "do not
      // retry" instruction, though it is the other code reachable only after a signature
      // was transmitted and is exactly as dangerous.
      //
      // `paid` is the field that carries "money may have moved", so keying on it is what
      // stops the two exit-8 codes drifting apart again. It is also why this advisory
      // survives when no settlement object could be built.
      const advisory =
        paid === "unknown"
          ? "the payment may have settled — do not retry without checking the merchant\n"
          : settlement?.status === "committed"
            ? "the payment settled — the resource is what failed\n"
            : undefined;
      if (advisory !== undefined) io.stderr(advisory);

      // The two outcomes that tell someone to reconcile are the two that must hand them
      // what to reconcile *with*, without making them re-run the call under `--json` — a
      // re-run of a payment is the one thing this advice exists to prevent (O74).
      if (settlement !== undefined) {
        if (settlement.payer !== null)
          io.stderr(`  payer${" ".repeat(23)}${settlement.payer}\n`);
        if (settlement.transaction !== null) {
          io.stderr(`  settlement${" ".repeat(18)}${settlement.transaction}\n`);
        }
      }
    } else if (error instanceof UsageError) {
      io.stderr(`tx402: ${error.message}\n\n${USAGE}\n`);
    } else {
      io.stderr(`tx402: ${String(error)}\n`);
    }
    return code;
  }
}

/** Re-exported so the error reference and tests share one source. */
export { EXIT_CODES, formatMoneyDecimal };
