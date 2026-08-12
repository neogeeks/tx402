/**
 * U9 (S14e) / O53≡U12 (S14g/S14h): an operator verb against an unreachable raw-Redis store must
 * exit `7` (`TX402_TRANSPORT`, retryable), NOT `2` (`TX402_CLI_USAGE`) — the exit-code contract in
 * `cli.mdx` ("a verb whose store is unreachable raises a TransportError … exactly as a reserve
 * against that store would"). `budget` was covered by U9; S14i extends this to `pins` (json AND
 * non-json), which the S14f fix left exiting `2` because its recipient-pin read methods were left
 * unwrapped. Drives the real CLI in process against a port where nothing listens (no live Redis
 * needed). Also asserts the raw ioredis internals do not leak (ADR-023 — a test that RUNS it).
 */

import { describe, expect, it } from "vitest";

import { EXIT_CODES } from "../src/cli/exit-codes.js";
import { run, type CliIo } from "../src/cli/run.js";

const DEAD_STORE = "redis://127.0.0.1:6399"; // nothing listens here

async function cli(argv: string[], env: Record<string, string>) {
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIo = {
    argv,
    env,
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    readFile: () => {
      throw new Error("no filesystem in this harness");
    },
  };
  const code = await run(io);
  return { code, out: out.join(""), err: err.join("") };
}

describe("CLI operator verb against an unreachable store (U9)", () => {
  it("`budget` exits 7 with a typed TX402_TRANSPORT error, not exit 2 usage", async () => {
    const { code, out, err } = await cli(
      ["budget", "api.merchant.example", "--network", "eip155:8453", "--json"],
      { TX402_SPEND_STORE: DEAD_STORE },
    );

    expect(code).toBe(EXIT_CODES.transport); // 7, not EXIT_CODES.usage (2)

    const parsed = JSON.parse(out) as {
      exitCode: number;
      error: { code: string; details?: Record<string, string> } | null;
    };
    expect(parsed.exitCode).toBe(EXIT_CODES.transport);
    // A store outage classified as transport (exit 7), NOT TX402_CLI_USAGE (exit 2).
    expect(parsed.error?.code).toBe("TX402_TRANSPORT");
    expect(parsed.error?.details?.["causeCategory"]).toBe("spend-store-unavailable");

    // The raw ioredis internal / DSN must not leak into stdout or stderr (SEC-003).
    for (const stream of [out, err]) {
      expect(stream).not.toContain("MaxRetriesPerRequestError");
      expect(stream).not.toContain("ECONNREFUSED");
      expect(stream).not.toContain("6399");
      expect(stream).not.toContain("[ioredis]");
    }
  });

  it("`pins --json` exits 7 with a typed TX402_TRANSPORT error, not exit 2 usage (O53)", async () => {
    const { code, out, err } = await cli(
      ["pins", "api.merchant.example", "--network", "eip155:8453", "--json"],
      { TX402_SPEND_STORE: DEAD_STORE },
    );

    expect(code).toBe(EXIT_CODES.transport); // 7, not EXIT_CODES.usage (2) — the O53 regression

    const parsed = JSON.parse(out) as {
      exitCode: number;
      error: { code: string; details?: Record<string, string> } | null;
    };
    expect(parsed.exitCode).toBe(EXIT_CODES.transport);
    expect(parsed.error?.code).toBe("TX402_TRANSPORT");
    expect(parsed.error?.details?.["causeCategory"]).toBe("spend-store-unavailable");

    for (const stream of [out, err]) {
      expect(stream).not.toContain("MaxRetriesPerRequestError");
      expect(stream).not.toContain("ECONNREFUSED");
      expect(stream).not.toContain("6399");
      expect(stream).not.toContain("[ioredis]");
      expect(stream).not.toContain("Connection is closed");
    }
  });

  it("`pins` (non-json) exits 7 and prints TX402_TRANSPORT to stderr, no raw leak (O53)", async () => {
    const { code, out, err } = await cli(
      ["pins", "api.merchant.example", "--network", "eip155:8453"],
      { TX402_SPEND_STORE: DEAD_STORE },
    );

    expect(code).toBe(EXIT_CODES.transport);
    expect(err).toContain("TX402_TRANSPORT");
    // A store outage is NOT a usage error: the bare `tx402: Error: …` usage line must not appear.
    expect(err).not.toContain("tx402: Error:");
    for (const stream of [out, err]) {
      expect(stream).not.toContain("MaxRetriesPerRequestError");
      expect(stream).not.toContain("ECONNREFUSED");
      expect(stream).not.toContain("6399");
      expect(stream).not.toContain("[ioredis]");
      expect(stream).not.toContain("Connection is closed");
    }
  });
});
