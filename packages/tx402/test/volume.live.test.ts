/**
 * T-019 — 50 Base Sepolia + 50 Solana Devnet calls (SPEC §12.2).
 *
 * > **Expected:** Zero SDK-caused signature failures or unhandled exceptions.
 *
 * Skipped unless the corresponding key is set, so it never runs in ordinary CI. Both legs
 * need a funded, dedicated, low-balance wallet:
 *
 * ```sh
 * . tools/live-env.sh
 * pnpm --filter tx402 exec vitest run test/volume.live.test.ts --testTimeout 600000
 * ```
 *
 * **What this measures that the single-call live suites do not.** One green call proves the
 * path exists. Fifty prove it does not degrade: that nonces stay unique across a run, that
 * the ledger's rolling window and reservation TTLs behave under repetition, that the health
 * index converges rather than oscillating, and that nothing accumulates — the failure modes
 * that only appear on the fortieth call are exactly the ones an agent running a long
 * autonomous loop will hit first.
 *
 * **Settlement is deliberately not exercised here.** ADR-002 puts `/verify` and `/settle` on
 * the merchant, so the buyer SDK has no settlement path to test, and settling a hundred real
 * transfers to measure the buyer's own resilience would spend testnet funds to learn nothing
 * about the buyer. `tools/ttv` settles for real against the public facilitator, once, which
 * is where that question belongs. Everything up to and including the signature here is
 * genuine: live chain identity, live balances, the caller's real key.
 *
 * The price is deliberately below the per-request cap and the run total deliberately below
 * the hourly cap, because this suite is testing the SDK's stability, not its guardrails —
 * those have their own tests, and a run that failed at call 31 because it hit its own budget
 * would be reporting the wrong thing.
 */

import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client, type Tx402Logger } from "../src/core/client.js";
import { isTx402Error } from "../src/core/errors.js";
import { keypairToSolanaSigner } from "../src/signers/index.js";
import type {
  EvmManifestAsset,
  EvmManifestNetwork,
  SvmManifestAsset,
  SvmManifestNetwork,
} from "../src/core/manifest.js";

const EVM_KEY = process.env.TX402_BASE_SEPOLIA_PRIVATE_KEY;
const SVM_KEY = process.env.TX402_SOLANA_DEVNET_KEYPAIR;

/**
 * A keyed RPC endpoint for one network, when the environment supplies one (ADR-015).
 *
 * The manifest ships keyless public endpoints, and a keyless public endpoint has a per-IP
 * quota: at S12 the Solana leg delivered 8 of 50 and then 429'd, because each Solana payment
 * costs five Devnet requests and both manifest endpoints exhaust at roughly forty from one
 * address (PLAN.md open item O35). Pacing did not help — pacing at 600 ms and at 2 000 ms
 * produced the identical cutoff, which is what identified it as a quota rather than a rate.
 *
 * The suite reads the environment and passes the value **in**; the SDK never reads the
 * environment itself. Returns `{}` when unset, so the signed manifest still decides by
 * default and this cannot silently change what an unconfigured run measures.
 */
function rpcOverrideFor(networkId: string, variable: string) {
  const url = process.env[variable];
  return url === undefined ? {} : { routing: { rpcOverrides: { [networkId]: [url] } } };
}

/** SPEC §12.2 says fifty per network. Overridable only to shorten a local smoke run. */
const CALLS = Number.parseInt(process.env.TX402_VOLUME_CALLS ?? "50", 10);

/**
 * Delay between calls, in milliseconds.
 *
 * Pacing, not padding — and deliberately **not** enough to rescue the Solana leg, because
 * the thing blocking it is a request quota rather than a rate. See PLAN.md open item O35:
 * each Solana payment costs five Devnet RPC requests, and the manifest's two free keyless
 * endpoints both start returning 429 after roughly forty requests from one IP, whether
 * those arrive over two seconds or over sixteen. Raising this number does not change the
 * outcome, which is how we know it is a quota.
 *
 * Base Sepolia's endpoints sustain fifty calls comfortably; the default is applied to both
 * legs so the two are measured the same way.
 */
const DELAY_MS = Number.parseInt(process.env.TX402_VOLUME_DELAY_MS ?? "600", 10);

const pace = () => new Promise((resolve) => setTimeout(resolve, DELAY_MS));

const BASE_ID = "eip155:84532";
const SOLANA_ID = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/** 0.0001 USDC per call: 50 calls is 0.005 USDC, well inside a lightly funded wallet. */
const PRICE_ATOMIC = "100";

interface RunOutcome {
  readonly ok: number;
  readonly failures: { call: number; code: string; message: string }[];
  readonly nonces: Set<string>;
  readonly signatureHashes: Set<string>;
  readonly durationsMs: number[];
}

function percentile(values: readonly number[], fraction: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor(sorted.length * fraction));
  return sorted[index] ?? 0;
}

function report(label: string, outcome: RunOutcome): void {
  const { durationsMs } = outcome;
  const mean = durationsMs.reduce((sum, value) => sum + value, 0) / durationsMs.length;
  // Written to stderr rather than asserted: these are the numbers a human wants after a
  // volume run, and turning latency into an assertion would make the suite fail for a slow
  // testnet rather than for a defect in tx402.
  console.error(
    `\n${label}: ${outcome.ok}/${CALLS} delivered  ` +
      `mean ${mean.toFixed(0)} ms  p50 ${percentile(durationsMs, 0.5)} ms  ` +
      `p95 ${percentile(durationsMs, 0.95)} ms  max ${Math.max(...durationsMs)} ms`,
  );
  for (const failure of outcome.failures) {
    console.error(`  call ${failure.call}: ${failure.code} — ${failure.message}`);
  }
}

/** Collects the SPEC §10 stream so nonce uniqueness can be checked without touching keys. */
function nonceCollector(nonces: Set<string>): Tx402Logger {
  const push = (event: Readonly<Record<string, unknown>>) => {
    const requestId = event["requestId"];
    if (event["event"] === "sign.started" && typeof requestId === "string") {
      nonces.add(requestId);
    }
  };
  return { debug: push, info: push, warn: push, error: push };
}

describe.skipIf(EVM_KEY === undefined)("T-019 volume — Base Sepolia (live, opt-in)", () => {
  let merchant: Awaited<ReturnType<typeof createTestMerchant>> | undefined;
  let outcome: RunOutcome;

  beforeAll(async () => {
    const network = BUNDLED_MANIFEST.networks[BASE_ID] as EvmManifestNetwork;
    const usdc = network.assets[0] as EvmManifestAsset;
    const { privateKeyToEvmSigner } = await import("../src/signers/index.js");
    const signer = privateKeyToEvmSigner(EVM_KEY as `0x${string}`);

    merchant = await createTestMerchant({
      scenario: "pay-once",
      requirements: [
        {
          scheme: "exact",
          network: BASE_ID,
          asset: usdc.address,
          amount: PRICE_ATOMIC,
          payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
          maxTimeoutSeconds: 120,
          extra: { name: "USDC", version: usdc.eip712Version },
        },
      ],
    });

    const nonces = new Set<string>();
    const tx402 = createTx402Client({
      signers: { evm: signer },
      policy: {
        // Comfortably above `CALLS * PRICE_ATOMIC`, so the run cannot fail on its own cap.
        maxPerRequest: "0.01 USDC",
        maxPerHour: "1.00 USDC",
        allowedNetworks: [BASE_ID],
      },
      logger: nonceCollector(nonces),
      allowInsecureLocalhost: true,
      ...rpcOverrideFor(BASE_ID, "TX402_BASE_SEPOLIA_RPC_URL"),
    });

    const failures: RunOutcome["failures"] = [];
    const durationsMs: number[] = [];
    let ok = 0;

    for (let call = 1; call <= CALLS; call += 1) {
      const started = performance.now();
      try {
        const response = await tx402.fetch(`${merchant.url}/resource?call=${call}`);
        expect(response.status).toBe(200);
        ok += 1;
      } catch (error) {
        failures.push({
          call,
          code: isTx402Error(error) ? error.code : "UNTYPED",
          message: error instanceof Error ? error.message : String(error),
        });
      }
      durationsMs.push(Math.round(performance.now() - started));
      if (call < CALLS) await pace();
    }

    const signatureHashes = new Set(
      merchant.requests
        .map((entry) => entry.signatureHash)
        .filter((hash): hash is string => typeof hash === "string"),
    );
    outcome = { ok, failures, nonces, signatureHashes, durationsMs };
    report("Base Sepolia", outcome);
  }, 900_000);

  afterAll(async () => {
    await merchant?.close();
  });

  it("delivers every call with no untyped exception", () => {
    // An untyped failure is the one this test exists to catch: a typed error is tx402
    // reporting a condition it understands, an untyped one is tx402 breaking.
    expect(outcome.failures.filter((entry) => entry.code === "UNTYPED")).toEqual([]);
    expect(outcome.ok).toBe(CALLS);
  });

  it("signs every attempt freshly, with no reuse across the run", () => {
    // The merchant hashes each PAYMENT-SIGNATURE it receives; the header itself is never
    // retained (SEC-003). A digest answers "were these all different?" without keeping
    // anything sensitive, and a repeat would mean an authorization was replayed.
    expect(outcome.signatureHashes.size).toBe(CALLS);
  });

  it("gives every request its own diagnostic identity", () => {
    expect(outcome.nonces.size).toBe(CALLS);
  });

  it("does not degrade as the run progresses", () => {
    // Memory and state leaks show up as a tail that grows. Comparing the last ten calls
    // against the first ten catches accumulation without asserting an absolute latency,
    // which a shared testnet cannot promise.
    const first = outcome.durationsMs.slice(0, 10);
    const last = outcome.durationsMs.slice(-10);
    const mean = (values: number[]) => values.reduce((a, b) => a + b, 0) / values.length;
    expect(mean(last)).toBeLessThan(mean(first) * 3 + 500);
  });
});

describe.skipIf(SVM_KEY === undefined)(
  "T-019 volume — Solana Devnet (live, opt-in)",
  () => {
    let merchant: Awaited<ReturnType<typeof createTestMerchant>> | undefined;
    let outcome: RunOutcome;

    beforeAll(async () => {
      const network = BUNDLED_MANIFEST.networks[SOLANA_ID] as SvmManifestNetwork;
      const usdc = network.assets[0] as SvmManifestAsset;
      const { generateKeyPairSigner } = await import("@solana/kit");
      // The shipped convenience adapter, not a hand-rolled one. A volume suite that builds
      // its own signer proves the volume behaviour of code no user runs.
      const signer = await keypairToSolanaSigner(SVM_KEY as string);
      const feePayer = (await generateKeyPairSigner()).address.toString();

      merchant = await createTestMerchant({
        scenario: "pay-once",
        requirements: [
          {
            scheme: "exact",
            network: SOLANA_ID,
            asset: usdc.mint,
            amount: PRICE_ATOMIC,
            payTo: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
            maxTimeoutSeconds: 120,
            extra: { feePayer },
          },
        ],
      });

      const nonces = new Set<string>();
      const tx402 = createTx402Client({
        signers: { solana: signer },
        policy: {
          maxPerRequest: "0.01 USDC",
          maxPerHour: "1.00 USDC",
          allowedNetworks: [SOLANA_ID],
        },
        logger: nonceCollector(nonces),
        allowInsecureLocalhost: true,
        ...rpcOverrideFor(SOLANA_ID, "TX402_SOLANA_DEVNET_RPC_URL"),
      });

      const failures: RunOutcome["failures"] = [];
      const durationsMs: number[] = [];
      let ok = 0;

      for (let call = 1; call <= CALLS; call += 1) {
        const started = performance.now();
        try {
          const response = await tx402.fetch(`${merchant.url}/resource?call=${call}`);
          expect(response.status).toBe(200);
          ok += 1;
        } catch (error) {
          failures.push({
            call,
            code: isTx402Error(error) ? error.code : "UNTYPED",
            message: error instanceof Error ? error.message : String(error),
          });
        }
        durationsMs.push(Math.round(performance.now() - started));
      }

      const signatureHashes = new Set(
        merchant.requests
          .map((entry) => entry.signatureHash)
          .filter((hash): hash is string => typeof hash === "string"),
      );
      outcome = { ok, failures, nonces, signatureHashes, durationsMs };
      report("Solana Devnet", outcome);
    }, 900_000);

    afterAll(async () => {
      await merchant?.close();
    });

    it("delivers every call with no untyped exception", () => {
      expect(outcome.failures.filter((entry) => entry.code === "UNTYPED")).toEqual([]);
      expect(outcome.ok).toBe(CALLS);
    });

    it("signs every attempt freshly, with no reuse across the run", () => {
      expect(outcome.signatureHashes.size).toBe(CALLS);
    });

    it("gives every request its own diagnostic identity", () => {
      expect(outcome.nonces.size).toBe(CALLS);
    });

    it("does not degrade as the run progresses", () => {
      const first = outcome.durationsMs.slice(0, 10);
      const last = outcome.durationsMs.slice(-10);
      const mean = (values: number[]) => values.reduce((a, b) => a + b, 0) / values.length;
      expect(mean(last)).toBeLessThan(mean(first) * 3 + 500);
    });
  },
);
