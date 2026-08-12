/**
 * Argument parsing for `tx402 call` (SPEC §11) and the five operator verbs (SPEC §10).
 *
 * Hand-rolled rather than pulled from a CLI framework. The whole dependency budget for this
 * package is spent on the protocol and chain libraries (ADR-008), and the surface here is a
 * handful of commands with a small flag set — a parser for that is smaller than the code
 * needed to configure a framework, and it cannot grow a transitive dependency behind our back.
 *
 * **No flag accepts a private key, and none ever will** (SPEC §11, SEC-001). Anything on a
 * command line lands in shell history, in `ps` output, and in CI logs. Development keys come
 * from documented environment variables only, and only after an explicit warning. The
 * operator verbs are the same: a store credential is never a flag — it comes from
 * `TX402_SPEND_STORE_TOKEN` / `TX402_SPEND_STORE_ADMIN` (SPEC §9.1).
 */

import { UsageError } from "./exit-codes.js";

export interface CallOptions {
  readonly url: string;
  readonly method: string;
  /** Literal body, already read from disk if `@file` was used. */
  readonly body?: string;
  readonly bodyPath?: string;
  readonly maxSpend?: string;
  readonly network?: string;
  readonly dryRun: boolean;
  readonly json: boolean;
  readonly timeoutMs?: number;
}

/** `freeze`/`unfreeze` (SPEC §10, admin plane): a single scope, `<host | "*">`. */
export interface FreezeOptions {
  /** The raw positional (`<host | "*">`); normalized to a policy scope by the verb handler. */
  readonly target: string;
  readonly json: boolean;
}

/** `budget` (SPEC §10, data plane): a scope + network, with optional asset and cap flags. */
export interface BudgetOptions {
  readonly target: string;
  readonly network: string;
  /** Token address/mint; absent ⇒ the network's canonical asset (SPEC §10). */
  readonly asset?: string;
  /** `--max-per-hour` / `--max-total` value-flags (SPEC §10 P1-8b). Atomic caps or human money. */
  readonly maxPerHour?: string;
  readonly maxTotal?: string;
  readonly json: boolean;
}

/** `pins` (SPEC §10, data plane): a scope + network. */
export interface PinsOptions {
  readonly target: string;
  readonly network: string;
  readonly json: boolean;
}

/** `rotate-recipient` (SPEC §10, admin plane): a scope + network + the new recipient set. */
export interface RotateRecipientOptions {
  readonly target: string;
  readonly network: string;
  /** The `--to <addr…>` set (at least one), canonicalized by the verb handler (SPEC §6.4). */
  readonly to: readonly string[];
  readonly json: boolean;
}

export type ParsedCommand =
  | { readonly kind: "help" }
  | { readonly kind: "version" }
  | { readonly kind: "call"; readonly options: CallOptions }
  | { readonly kind: "freeze"; readonly options: FreezeOptions }
  | { readonly kind: "unfreeze"; readonly options: FreezeOptions }
  | { readonly kind: "budget"; readonly options: BudgetOptions }
  | { readonly kind: "pins"; readonly options: PinsOptions }
  | { readonly kind: "rotate-recipient"; readonly options: RotateRecipientOptions };

/**
 * Flags that take a value. Used to give a precise error when the value is missing. `--to` is
 * NOT here: it is variadic (`--to <addr…>`) and parsed specially by {@link parseVerb}.
 */
const VALUE_FLAGS = new Set([
  "--method",
  "--body",
  "--max-spend",
  "--network",
  "--timeout",
  // 0.2.0 operator verbs (SPEC §10).
  "--asset",
  "--max-per-hour",
  "--max-total",
]);

/** The five operator verbs (SPEC §10). Everything else that is not `call` is a usage error. */
const VERBS = new Set(["freeze", "unfreeze", "budget", "pins", "rotate-recipient"]);

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

/**
 * Parses argv (already sliced past the node binary and script path).
 *
 * `readFile` is injected so the parser stays synchronous and testable without touching a
 * real filesystem. `--body @file` is resolved here rather than later so that a missing file
 * is a usage error before any network request is made — a dry run that first pays a round
 * trip to the merchant and only then discovers the body is unreadable wastes the operator's
 * time and the merchant's.
 */
export function parseArgs(
  argv: readonly string[],
  readFile: (path: string) => string,
): ParsedCommand {
  if (argv.length === 0) return { kind: "help" };
  if (argv.includes("-h") || argv.includes("--help")) return { kind: "help" };
  if (argv.includes("-v") || argv.includes("--version")) return { kind: "version" };

  const [command, ...rest] = argv;
  if (command !== undefined && VERBS.has(command)) {
    return parseVerb(command, rest);
  }
  if (command !== "call") {
    throw new UsageError(
      `Unknown command ${JSON.stringify(command)}. Commands are "call" and the operator ` +
        `verbs freeze, unfreeze, budget, pins, rotate-recipient.`,
    );
  }

  let url: string | undefined;
  let method = "GET";
  let body: string | undefined;
  let bodyPath: string | undefined;
  let maxSpend: string | undefined;
  let network: string | undefined;
  let dryRun = false;
  let json = false;
  let timeoutMs: number | undefined;

  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index] as string;

    if (VALUE_FLAGS.has(argument)) {
      const value = rest[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new UsageError(`${argument} requires a value`);
      }
      index += 1;

      switch (argument) {
        case "--method":
          method = value.toUpperCase();
          if (!METHODS.has(method)) {
            throw new UsageError(`Unsupported --method ${JSON.stringify(value)}`);
          }
          break;
        case "--body":
          if (!value.startsWith("@")) {
            throw new UsageError(
              "--body takes @<file>. An inline body is refused so a secret cannot be " +
                "captured in shell history.",
            );
          }
          bodyPath = value.slice(1);
          if (bodyPath === "") throw new UsageError("--body @<file> needs a filename");
          try {
            body = readFile(bodyPath);
          } catch {
            // The underlying message is not forwarded: it quotes an absolute path, which
            // ends up in CI logs more often than anyone intends.
            throw new UsageError(`Cannot read --body file ${JSON.stringify(bodyPath)}`);
          }
          break;
        case "--max-spend":
          maxSpend = value;
          break;
        case "--network":
          network = value;
          break;
        case "--timeout": {
          // Rejected rather than coerced. `--timeout 10s` silently becoming 10 ms is the
          // kind of thing that only surfaces as a flaky timeout in production.
          if (!/^\d+$/u.test(value)) {
            throw new UsageError(
              "--timeout takes whole milliseconds, e.g. --timeout 10000",
            );
          }
          timeoutMs = Number.parseInt(value, 10);
          if (timeoutMs <= 0) throw new UsageError("--timeout must be greater than zero");
          break;
        }
      }
      continue;
    }

    switch (argument) {
      case "--dry-run":
        dryRun = true;
        continue;
      case "--json":
        json = true;
        continue;
      default:
        break;
    }

    if (argument.startsWith("-")) {
      // Catches `--private-key` and friends explicitly rather than letting an unknown flag
      // be silently treated as the URL.
      throw new UsageError(`Unknown option ${JSON.stringify(argument)}`);
    }
    if (url !== undefined) {
      throw new UsageError("Only one URL may be given");
    }
    url = argument;
  }

  if (url === undefined) throw new UsageError("tx402 call requires a URL");

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new UsageError(`${JSON.stringify(url)} is not an absolute URL`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new UsageError("URL must be http or https");
  }
  if (parsed.username !== "" || parsed.password !== "") {
    // Credentials in a URL would be logged by anything that echoes the argv.
    throw new UsageError("URL must not embed credentials");
  }

  return {
    kind: "call",
    options: {
      url,
      method,
      ...(body === undefined ? {} : { body }),
      ...(bodyPath === undefined ? {} : { bodyPath }),
      ...(maxSpend === undefined ? {} : { maxSpend }),
      ...(network === undefined ? {} : { network }),
      dryRun,
      json,
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    },
  };
}

/**
 * Parses an operator verb (SPEC §10): `freeze`/`unfreeze`/`budget`/`pins`/`rotate-recipient`.
 *
 * Each verb takes one required positional (its target scope) and a small flag set. The store
 * credential is NEVER a flag (SPEC §9.1) — the verb handler reads it from the environment. The
 * shared value-flag handling below mirrors {@link parseArgs}; `--to` is the one variadic flag,
 * collecting every following non-flag token as the new recipient set.
 */
function parseVerb(command: string, rest: readonly string[]): ParsedCommand {
  let target: string | undefined;
  let network: string | undefined;
  let asset: string | undefined;
  let maxPerHour: string | undefined;
  let maxTotal: string | undefined;
  const to: string[] = [];
  let json = false;

  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index] as string;

    if (argument === "--to") {
      // Variadic: everything up to the next `--flag` is a recipient (SPEC §10 `--to <addr…>`).
      let cursor = index + 1;
      while (cursor < rest.length && !(rest[cursor] as string).startsWith("--")) {
        to.push(rest[cursor] as string);
        cursor += 1;
      }
      if (to.length === 0)
        throw new UsageError("--to requires at least one recipient address");
      index = cursor - 1;
      continue;
    }

    if (VALUE_FLAGS.has(argument)) {
      const value = rest[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new UsageError(`${argument} requires a value`);
      }
      index += 1;
      switch (argument) {
        case "--network":
          network = value;
          break;
        case "--asset":
          asset = value;
          break;
        case "--max-per-hour":
          maxPerHour = value;
          break;
        case "--max-total":
          maxTotal = value;
          break;
        default:
          // A `call`-only value flag (`--method`/`--body`/`--max-spend`/`--timeout`) on a verb.
          throw new UsageError(`${JSON.stringify(argument)} is not valid for ${command}`);
      }
      continue;
    }

    if (argument === "--json") {
      json = true;
      continue;
    }
    if (argument.startsWith("-")) {
      throw new UsageError(`Unknown option ${JSON.stringify(argument)}`);
    }
    if (target !== undefined) {
      throw new UsageError(`${command} takes a single target, not two`);
    }
    target = argument;
  }

  if (target === undefined) {
    const shape =
      command === "freeze" || command === "unfreeze" ? '<host | "*">' : "<url | host>";
    throw new UsageError(`tx402 ${command} requires a target ${shape}`);
  }

  switch (command) {
    case "freeze":
    case "unfreeze":
      // The network/asset/cap flags are meaningless for a whole-scope freeze.
      rejectFlags(command, { network, asset, maxPerHour, maxTotal }, to);
      return { kind: command, options: { target, json } };
    case "budget": {
      if (network === undefined) throw new UsageError("budget requires --network <caip2>");
      if (to.length > 0) throw new UsageError("--to is not valid for budget");
      return {
        kind: "budget",
        options: {
          target,
          network,
          ...(asset === undefined ? {} : { asset }),
          ...(maxPerHour === undefined ? {} : { maxPerHour }),
          ...(maxTotal === undefined ? {} : { maxTotal }),
          json,
        },
      };
    }
    case "pins": {
      if (network === undefined) throw new UsageError("pins requires --network <caip2>");
      rejectFlags("pins", { asset, maxPerHour, maxTotal }, to);
      return { kind: "pins", options: { target, network, json } };
    }
    case "rotate-recipient": {
      if (network === undefined) {
        throw new UsageError("rotate-recipient requires --network <caip2>");
      }
      if (to.length === 0) throw new UsageError("rotate-recipient requires --to <addr…>");
      rejectFlags("rotate-recipient", { asset, maxPerHour, maxTotal }, []);
      return { kind: "rotate-recipient", options: { target, network, to, json } };
    }
    default:
      // Unreachable: `command` is one of VERBS by construction.
      throw new UsageError(`Unknown command ${JSON.stringify(command)}`);
  }
}

/** Rejects flags a verb does not accept, so a mistyped invocation fails loudly not silently. */
function rejectFlags(
  command: string,
  flags: Readonly<Record<string, string | undefined>>,
  to: readonly string[],
): void {
  for (const [name, value] of Object.entries(flags)) {
    if (value !== undefined) {
      throw new UsageError(
        `--${name.replace(/[A-Z]/gu, (c) => `-${c.toLowerCase()}`)} is not valid for ${command}`,
      );
    }
  }
  if (to.length > 0) throw new UsageError(`--to is not valid for ${command}`);
}
