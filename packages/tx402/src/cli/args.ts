/**
 * Argument parsing for `tx402 call` (SPEC §11).
 *
 * Hand-rolled rather than pulled from a CLI framework. The whole dependency budget for this
 * package is spent on the protocol and chain libraries (ADR-008), and the surface here is
 * one command with eight flags — a parser for that is smaller than the code needed to
 * configure a framework, and it cannot grow a transitive dependency behind our back.
 *
 * **No flag accepts a private key, and none ever will** (SPEC §11, SEC-001). Anything on a
 * command line lands in shell history, in `ps` output, and in CI logs. Development keys come
 * from documented environment variables only, and only after an explicit warning.
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

export type ParsedCommand =
  | { readonly kind: "help" }
  | { readonly kind: "version" }
  | { readonly kind: "call"; readonly options: CallOptions };

/** Flags that take a value. Used to give a precise error when the value is missing. */
const VALUE_FLAGS = new Set([
  "--method",
  "--body",
  "--max-spend",
  "--network",
  "--timeout",
]);

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
  if (command !== "call") {
    throw new UsageError(
      `Unknown command ${JSON.stringify(command)}. The only command is "call".`,
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
