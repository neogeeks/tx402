#!/usr/bin/env node
/**
 * Performance gates (SPEC §12.3), measured exactly as the specification defines them.
 *
 *   pnpm perf
 *   TX402_PERF_SCALE=0.1 pnpm perf     # shorten a local smoke run
 *
 * Four gates, all blocking:
 *
 *   | Gate                | Limit      | What is measured                                |
 *   |---------------------|------------|-------------------------------------------------|
 *   | non-402 overhead    | p95 <15 ms | added latency vs the native transport            |
 *   | budget rejection    | p95 <2 ms  | in-memory policy refusal, excl. construction     |
 *   | memory stability    | stable     | retained heap after 100 000 mixed requests       |
 *
 * The fourth SPEC §12.3 gate — 402 decision overhead, p95 <150 ms from complete challenge
 * to before the signer call — is **not** duplicated here. It is T-008 in the test suite,
 * where the RPC stub with controlled latency already lives; measuring it a second time
 * against a different fixture would produce a second number for the same gate, and the two
 * would eventually disagree.
 *
 * Two methodology points that decide whether the numbers mean anything:
 *
 * **Everything is warmed.** SPEC §12.3 says "10,000 warmed requests" for the non-402 gate,
 * and the reason generalises: V8 deoptimises the first few hundred calls through any path,
 * so an unwarmed p95 measures the JIT rather than tx402. The decision gate is the sharpest
 * case — the first call through it also opens a circuit and pays a connection.
 *
 * **The comparison is against the same server, in the same process.** The non-402 gate is a
 * *difference*, and a difference is only meaningful if everything except tx402 is held
 * fixed. An in-process HTTP server on loopback removes the network from both sides.
 */

import { createServer } from "node:http";

import { createTx402Client } from "../../packages/tx402/dist/index.js";
import { isTx402Error } from "../../packages/tx402/dist/core/errors.js";
import { MemorySpendStore } from "../../packages/tx402/dist/core/ledger.js";

const SCALE = Number(process.env["TX402_PERF_SCALE"] ?? 1);
const scaled = (n) => Math.max(50, Math.round(n * SCALE));

const results = [];
function gate(name, limit, unit, value, extra = "") {
  const pass = value < limit;
  results.push({ name, limit, unit, value, pass, extra });
  const status = pass ? "PASS" : "FAIL";
  console.log(
    `  ${status}  ${name.padEnd(22)} ${value.toFixed(3)} ${unit} ` +
      `(gate <${limit} ${unit})${extra === "" ? "" : `  ${extra}`}`,
  );
}

function percentile(samples, p) {
  const sorted = [...samples].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, index)];
}

/** An in-process origin. Answers 200 always — the non-402 gate needs no payment. */
async function plainServer() {
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"ok":true}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}/resource`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// --- 1. non-402 overhead ------------------------------------------------------------------

async function nonPaidOverhead() {
  const origin = await plainServer();
  const tx402 = createTx402Client({ allowInsecureLocalhost: true });

  const WARMUP = scaled(2_000);
  const RUNS = scaled(10_000);

  const measure = async (call, count, collect) => {
    for (let index = 0; index < count; index += 1) {
      const started = performance.now();
      const response = await call();
      await response.text();
      collect?.(performance.now() - started);
    }
  };

  const native = () => fetch(origin.url);
  const wrapped = () => tx402.fetch(origin.url);

  // Warm both paths before either is measured, and warm them in the same order they will be
  // measured in, so neither benefits from the other's warm sockets.
  await measure(native, WARMUP);
  await measure(wrapped, WARMUP);

  const nativeSamples = [];
  const wrappedSamples = [];
  await measure(native, RUNS, (ms) => nativeSamples.push(ms));
  await measure(wrapped, RUNS, (ms) => wrappedSamples.push(ms));

  await origin.close();

  const added = percentile(wrappedSamples, 95) - percentile(nativeSamples, 95);
  gate(
    "non-402 overhead",
    15,
    "ms",
    Math.max(0, added),
    `native p95 ${percentile(nativeSamples, 95).toFixed(2)} ms, ` +
      `tx402 p95 ${percentile(wrappedSamples, 95).toFixed(2)} ms, n=${RUNS}`,
  );
}

// --- 2. budget rejection ------------------------------------------------------------------

async function budgetRejection() {
  // SPEC §12.3: "excludes client construction". The client is built once, outside the loop.
  const tx402 = createTx402Client({
    allowInsecureLocalhost: true,
    policy: { maxPerRequest: "0.000001 USDC", maxPerHour: "0.000001 USDC" },
  });

  const { encodePaymentRequiredHeader } = await import("@x402/core/http");
  const { BUNDLED_MANIFEST } =
    await import("../../packages/tx402/dist/core/bundled-manifest.js");
  const network = BUNDLED_MANIFEST.networks["eip155:8453"];

  // The challenge is built *after* the port is known. tx402 validates `resource.url`'s
  // origin against the URL actually requested (SPEC §6.2), so a placeholder origin is
  // rejected as `resource-origin-mismatch` before policy is ever reached — which would have
  // measured the decoder instead of the budget gate.
  let challenge = "";
  const server = createServer((_request, response) => {
    response.writeHead(402, { "PAYMENT-REQUIRED": challenge });
    response.end("{}");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/resource`;

  challenge = encodePaymentRequiredHeader({
    x402Version: 2,
    resource: { url },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:8453",
        asset: network.assets[0].address,
        // Far above the cap, so the refusal is decided by policy and nothing else runs.
        amount: "5000000",
        payTo: "0x2222222222222222222222222222222222222222",
        maxTimeoutSeconds: 60,
        extra: { name: "USDC", version: network.assets[0].eip712Version },
      },
    ],
  });

  const WARMUP = scaled(500);
  const RUNS = scaled(5_000);
  const samples = [];

  for (let index = 0; index < WARMUP + RUNS; index += 1) {
    const started = performance.now();
    try {
      await tx402.fetch(url);
    } catch (error) {
      if (!isTx402Error(error) || error.code !== "TX402_POLICY_BUDGET") throw error;
    }
    if (index >= WARMUP) samples.push(performance.now() - started);
  }

  await new Promise((resolve) => server.close(resolve));

  // The measured span includes one loopback round trip for the 402 itself, which the gate's
  // 2 ms does not budget for. Subtracting it would mean reporting a number nobody can
  // reproduce, so the raw figure is reported and the round trip is stated alongside.
  gate(
    "budget rejection",
    2,
    "ms",
    percentile(samples, 95),
    `n=${RUNS}, incl. loopback 402`,
  );
}

// --- 3. memory stability ------------------------------------------------------------------

async function memoryStability() {
  if (typeof globalThis.gc !== "function") {
    console.log(
      "  SKIP  memory stability      run with --expose-gc to measure retained heap",
    );
    return;
  }

  const origin = await plainServer();
  const tx402 = createTx402Client({
    allowInsecureLocalhost: true,
    spendStore: new MemorySpendStore(),
  });

  const TOTAL = scaled(100_000);

  // Settle the heap before the baseline, or the baseline captures module initialisation.
  for (let index = 0; index < 2_000; index += 1)
    await (await tx402.fetch(origin.url)).text();
  globalThis.gc();
  const baseline = process.memoryUsage().heapUsed;

  for (let index = 0; index < TOTAL; index += 1) {
    await (await tx402.fetch(origin.url)).text();
  }

  globalThis.gc();
  const after = process.memoryUsage().heapUsed;
  await origin.close();

  const growthMb = (after - baseline) / 1024 / 1024;
  // "Stable" is not "zero": the health LRU holds up to 128 entries and the ledger holds
  // unexpired reservations, both bounded. A leak shows up as growth proportional to the
  // request count, which at 100 000 requests would be far more than a few megabytes.
  gate(
    "memory growth",
    8,
    "MiB",
    growthMb,
    `over ${TOTAL} requests, baseline ${(baseline / 1024 / 1024).toFixed(1)} MiB`,
  );
}

// --- run ------------------------------------------------------------------------------------

console.log(
  `tx402 performance gates (SPEC §12.3)${SCALE === 1 ? "" : `  scale=${SCALE}`}\n`,
);

await nonPaidOverhead();
await budgetRejection();
await memoryStability();

const failed = results.filter((result) => !result.pass);
console.log(
  `\n${results.length - failed.length}/${results.length} gates pass` +
    (failed.length === 0 ? "" : ` — FAILED: ${failed.map((r) => r.name).join(", ")}`),
);
if (failed.length > 0) process.exit(1);
