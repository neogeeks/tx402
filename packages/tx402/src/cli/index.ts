#!/usr/bin/env node
/**
 * tx402 CLI entry point — "Wireshark for HTTP 402".
 *
 * Bundled into the `tx402` package via the `bin` field so that `npx tx402` resolves with no
 * second install (ADR-009). This file is a **separate build entry**: it is not reachable
 * from the core import path and its dependencies never count against the ADR-008 size gate.
 *
 * Deliberately thin. Everything testable lives in `run.ts` behind an injected IO object, so
 * this module holds only the two things that genuinely need the real process: binding to the
 * actual streams, and setting an exit code.
 */

import { readFileSync } from "node:fs";

import { run } from "./run.js";

/**
 * `process.exitCode` rather than `process.exit()`.
 *
 * `process.exit()` terminates immediately and can truncate a large body still buffered in
 * the stdout pipe — piping to a file would silently lose the tail. Setting the code lets
 * Node drain its streams and exit on its own.
 */
run({
  argv: process.argv.slice(2),
  env: process.env,
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
  readFile: (path) => readFileSync(path, "utf8"),
})
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    // `run` is written not to throw, so reaching here is a defect in the CLI itself rather
    // than a failed payment. Exit 2 keeps it out of the payment-outcome exit codes, which a
    // script may act on.
    process.stderr.write(`tx402: internal error: ${String(error)}\n`);
    process.exitCode = 2;
  });
