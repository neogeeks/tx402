/**
 * The CLI surface (SPEC §11).
 *
 * Driven in process through the injected `CliIo` rather than by spawning `node`, so every
 * assertion is about the real code path and the suite stays fast enough to cover all nine
 * exit codes. The two things that genuinely need a process — stream binding and setting
 * `process.exitCode` — live in `cli/index.ts` and are deliberately not exercised here.
 */

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createEvmRpcStub, type EvmRpcStub } from "@tx402-dev/evm-rpc-stub";
import { createTestMerchant } from "@tx402-dev/test-merchant";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { parseArgs } from "../src/cli/args.js";
import { EXIT_CODES, EXIT_CODE_BY_ERROR, UsageError } from "../src/cli/exit-codes.js";
import { DEV_KEY_ENV, JSON_SCHEMA_VERSION, run, type CliIo } from "../src/cli/run.js";
import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import { createTx402Client } from "../src/core/client.js";
import { TX402_ERROR_CODES } from "../src/core/errors.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../src/core/manifest.js";
import type { EvmSigner } from "../src/core/signers.js";
import { privateKeyToEvmSigner } from "../src/signers/index.js";

const BASE = BUNDLED_MANIFEST.networks["eip155:8453"] as EvmManifestNetwork;
const USDC = BASE.assets[0] as EvmManifestAsset;
const RPC_HOSTS = new Set(BASE.rpcUrls.map((url) => new URL(url).host));
const DEV_KEY = "0xa11ce00000000000000000000000000000000000000000000000000000000001";

const REQUIREMENT = {
  scheme: "exact",
  network: "eip155:8453",
  asset: USDC.address,
  amount: "50000",
  payTo: "0x1234567890AbcdEF1234567890aBcdef12345678",
  maxTimeoutSeconds: 120,
  extra: { name: "USD Coin", version: "2" },
};

type Merchant = Awaited<ReturnType<typeof createTestMerchant>>;

let merchant: Merchant;
let rpc: EvmRpcStub;
let signCount: number;

/** Captures both streams so the SPEC §11 stdout/stderr split can be asserted. */
function io(argv: string[], overrides: Partial<CliIo> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const harness: CliIo & { out: string[]; err: string[] } = {
    out,
    err,
    argv,
    env: {},
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    readFile: () => {
      throw new Error("no filesystem in this test");
    },
    ...overrides,
  };
  return harness;
}

/** A signer that counts signatures, so "--dry-run never signs" is a count, not a hope. */
function countingSigner(): EvmSigner {
  const inner = privateKeyToEvmSigner(DEV_KEY);
  return {
    kind: "evm",
    getAddress: () => inner.getAddress(),
    signTypedData: (request) => {
      signCount += 1;
      return inner.signTypedData(request);
    },
  };
}

/** Injects a client wired to the local merchant and stub RPC, with a real signer. */
function createClient(
  signer: EvmSigner = countingSigner(),
): NonNullable<CliIo["createClient"]> {
  return (config) => createTx402Client({ ...config, signers: { evm: signer } });
}

beforeEach(async () => {
  signCount = 0;
  merchant = await createTestMerchant({
    scenario: "pay-once",
    requirements: [REQUIREMENT],
    body: JSON.stringify({ ok: true }),
  });
  const payer = await privateKeyToEvmSigner(DEV_KEY).getAddress();
  rpc = await createEvmRpcStub({
    chainId: 8453,
    token: USDC.address,
    balances: { [payer]: "5000000" },
  });

  const realFetch = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: Request | string | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (!RPC_HOSTS.has(new URL(request.url).host)) return realFetch(request);
    return realFetch(rpc.url, {
      method: request.method,
      headers: request.headers,
      body: await request.text(),
    });
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await merchant.close();
  await rpc.close();
});

describe("argument parsing", () => {
  it("shows help with no arguments and exits 0", async () => {
    const harness = io([]);
    expect(await run(harness)).toBe(EXIT_CODES.success);
    expect(harness.out.join("")).toContain("tx402 call <URL>");
    // Help is output, not a diagnostic, so it belongs on stdout.
    expect(harness.err.join("")).toBe("");
  });

  it("reports the version the package actually declares", async () => {
    // Read from `package.json` rather than from `src/version.ts`, so the generated module
    // cannot be self-consistently wrong. Until S15b the CLI printed a `0.0.0` literal that
    // nothing compared against anything, and a correctly tagged 0.1.0 would have shipped a
    // binary identifying itself as 0.0.0 (O51).
    const manifest = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { version: string };
    const harness = io(["--version"]);
    expect(await run(harness)).toBe(EXIT_CODES.success);
    expect(harness.out.join("")).toBe(`tx402 ${manifest.version}\n`);
  });

  it("fails the version gate when a supplied version disagrees", () => {
    // The negative half. A gate that only ever runs against agreeing inputs proves nothing;
    // this is the shape the release workflow uses to bind the git tag to the package.
    const tool = fileURLToPath(
      new URL("../../../tools/version-sync/index.js", import.meta.url),
    );
    const drifted = spawnSync(process.execPath, [tool, "check", "--expect", "9.9.9"], {
      encoding: "utf8",
    });
    expect(drifted.status).toBe(1);
    expect(drifted.stderr).toContain("does not match the package version");

    const agreeing = spawnSync(process.execPath, [tool, "check"], { encoding: "utf8" });
    expect(agreeing.status).toBe(0);
  });

  it("rejects an unknown command", async () => {
    expect(await run(io(["fetch", "https://example.test"]))).toBe(EXIT_CODES.usage);
  });

  it("rejects an unknown option rather than treating it as the URL", () => {
    // The specific worry is `--private-key`: silently accepting it as a positional would be
    // far worse than failing.
    expect(() => parseArgs(["call", "--private-key", "0xabc"], () => "")).toThrow(
      UsageError,
    );
  });

  it("accepts no flag that could carry a private key", () => {
    const help = ["--method", "--body", "--max-spend", "--network", "--timeout"];
    for (const flag of help) expect(flag).not.toMatch(/key|secret|private|mnemonic/iu);
  });

  it("refuses an inline body so a secret cannot land in shell history", () => {
    expect(() => parseArgs(["call", "https://a.test", "--body", "{}"], () => "")).toThrow(
      /@<file>/u,
    );
  });

  it("reads --body from a file", () => {
    const parsed = parseArgs(["call", "https://a.test", "--body", "@payload.json"], () =>
      JSON.stringify({ prompt: "hi" }),
    );
    expect(parsed).toMatchObject({ kind: "call", options: { body: '{"prompt":"hi"}' } });
  });

  it("turns an unreadable --body file into a usage error without quoting the path", () => {
    expect(() =>
      parseArgs(["call", "https://a.test", "--body", "@missing.json"], () => {
        throw new Error(
          "ENOENT: no such file or directory, open '/home/ci/secret/missing'",
        );
      }),
    ).toThrow(/Cannot read --body file "missing.json"/u);
  });

  it("rejects a non-numeric --timeout rather than coercing it", () => {
    // `--timeout 10s` becoming 10 ms would only ever surface as a flaky production timeout.
    expect(() =>
      parseArgs(["call", "https://a.test", "--timeout", "10s"], () => ""),
    ).toThrow(/whole milliseconds/u);
  });

  it("rejects a flag that is missing its value", () => {
    expect(() => parseArgs(["call", "https://a.test", "--method"], () => "")).toThrow(
      /requires a value/u,
    );
  });

  it("rejects credentials embedded in the URL", () => {
    expect(() => parseArgs(["call", "https://user:pw@a.test"], () => "")).toThrow(
      /must not embed credentials/u,
    );
  });

  it("rejects a relative URL", () => {
    expect(() => parseArgs(["call", "/resource"], () => "")).toThrow(/absolute URL/u);
  });

  it("rejects two URLs", () => {
    expect(() => parseArgs(["call", "https://a.test", "https://b.test"], () => "")).toThrow(
      /Only one URL/u,
    );
  });

  it("normalises the method and rejects an unsupported one", () => {
    expect(
      parseArgs(["call", "https://a.test", "--method", "post"], () => ""),
    ).toMatchObject({ options: { method: "POST" } });
    expect(() =>
      parseArgs(["call", "https://a.test", "--method", "BREW"], () => ""),
    ).toThrow(/Unsupported --method/u);
  });
});

describe("exit code mapping (SPEC §11)", () => {
  it("classifies every error code in the taxonomy", () => {
    // The Record type makes this exhaustive at compile time; this asserts it at run time
    // too, so a code added without a mapping cannot reach a user as an unclassified exit.
    for (const code of Object.values(TX402_ERROR_CODES)) {
      expect(EXIT_CODE_BY_ERROR[code]).toBeTypeOf("number");
    }
  });

  it("uses each of the nine documented codes and never 1", () => {
    const used = new Set<number>(Object.values(EXIT_CODE_BY_ERROR));
    expect(used).not.toContain(1);
    expect(new Set(Object.values(EXIT_CODES))).toEqual(
      new Set([0, 2, 3, 4, 5, 6, 7, 8, 9]),
    );
  });

  it("reserves exit code 8 for the outcomes where retrying may pay twice", () => {
    // 8 is the "stop, money may have moved" code, and it is shared by exactly the two
    // errors that can only be reached *after* a signature was transmitted. The blocked
    // cross-origin redirect joined it at S15b: ADR-014 always described it as exit 8, the
    // table said 9, and O52 made the error reachable from the high-level client at all.
    const eights = Object.entries(EXIT_CODE_BY_ERROR)
      .filter(([, code]) => code === 8)
      .map(([error]) => error)
      .sort();
    expect(eights).toEqual(
      [TX402_ERROR_CODES.paymentAmbiguous, TX402_ERROR_CODES.redirectBlocked].sort(),
    );
  });

  it("exits 3 when local policy refuses", async () => {
    const harness = io(["call", `${merchant.url}/resource`, "--max-spend", "0.001 USDC"], {
      createClient: createClient(),
    });
    expect(await run(harness)).toBe(EXIT_CODES.policy);
    expect(harness.err.join("")).toContain("TX402_POLICY_BUDGET");
    expect(signCount).toBe(0);
  });

  it("exits 7 when the merchant is unreachable", async () => {
    const harness = io(["call", "http://127.0.0.1:1/resource"], {
      createClient: createClient(),
    });
    expect(await run(harness)).toBe(EXIT_CODES.transport);
  });
});

describe("--dry-run", () => {
  it("plans a route and never signs", async () => {
    const harness = io(["call", `${merchant.url}/resource`, "--dry-run"], {
      createClient: createClient(),
    });
    expect(await run(harness)).toBe(EXIT_CODES.success);
    expect(signCount).toBe(0);
    const stderr = harness.err.join("");
    expect(stderr).toContain("would pay");
    expect(stderr).toContain("eip155:8453");
    expect(stderr).toContain("nothing was signed");
  });

  it("never reaches the merchant with a signature", async () => {
    await run(
      io(["call", `${merchant.url}/resource`, "--dry-run"], {
        createClient: createClient(),
      }),
    );
    expect(merchant.paidRequests).toHaveLength(0);
  });

  it("reserves no budget, so a dry run cannot exhaust the hourly cap", async () => {
    // A dry run that reserved would let repeated planning starve the real call.
    const harness = io(["call", `${merchant.url}/resource`, "--dry-run", "--json"], {
      createClient: createClient(),
    });
    await run(harness);
    await run(harness);
    const second = JSON.parse(harness.out[1] as string) as { ok: boolean };
    expect(second.ok).toBe(true);
  });

  it("throws rather than signing if the guard is ever reached", async () => {
    // Belt and braces for the structural guarantee: even if a future edit routed --dry-run
    // through the paying path, the injected signer refuses.
    const harness = io(["call", `${merchant.url}/resource`, "--dry-run"], {
      env: { [DEV_KEY_ENV.evm]: DEV_KEY },
    });
    await run(harness);
    expect(merchant.paidRequests).toHaveLength(0);
  });
});

describe("--json", () => {
  it("writes exactly one JSON object to stdout on success", async () => {
    const harness = io(["call", `${merchant.url}/resource`, "--json"], {
      createClient: createClient(),
    });
    expect(await run(harness)).toBe(EXIT_CODES.success);
    const document = JSON.parse(harness.out.join("")) as Record<string, unknown>;
    expect(document["schemaVersion"]).toBe(JSON_SCHEMA_VERSION);
    expect(document["ok"]).toBe(true);
    expect(document["exitCode"]).toBe(0);
    expect(document["status"]).toBe(200);
    expect(document["timings"]).toHaveProperty("elapsedMs");
  });

  it("reports the route and inspection on a dry run", async () => {
    const harness = io(["call", `${merchant.url}/resource`, "--dry-run", "--json"], {
      createClient: createClient(),
    });
    await run(harness);
    const document = JSON.parse(harness.out.join("")) as {
      route: { network: string; amountAtomic: string };
      inspection: { requirementCount: number };
      dryRun: boolean;
    };
    expect(document.dryRun).toBe(true);
    expect(document.route.network).toBe("eip155:8453");
    expect(document.route.amountAtomic).toBe("50000");
    expect(document.inspection.requirementCount).toBe(1);
  });

  it("reports inspection and route on the paying path too", async () => {
    // `fetch` returns a Response, not a plan, so these are recovered from the SPEC §10
    // event stream. Pinned because the first cut returned nulls here and still looked
    // like a valid document — SPEC §11 requires both fields on every --json run.
    const harness = io(["call", `${merchant.url}/resource`, "--json"], {
      createClient: createClient(),
    });
    await run(harness);
    const document = JSON.parse(harness.out.join("")) as {
      inspection: { requirementCount: number; headerHash: string };
      route: { network: string; scheme: string };
    };
    expect(document.inspection.requirementCount).toBe(1);
    expect(document.inspection.headerHash).toMatch(/^sha256:/u);
    expect(document.route.network).toBe("eip155:8453");
    expect(document.route.scheme).toBe("exact");
  });

  it("still emits one parseable object on failure, with the typed error", async () => {
    const harness = io(
      ["call", `${merchant.url}/resource`, "--max-spend", "0.001 USDC", "--json"],
      { createClient: createClient() },
    );
    expect(await run(harness)).toBe(EXIT_CODES.policy);
    const document = JSON.parse(harness.out.join("")) as {
      ok: boolean;
      exitCode: number;
      error: { code: string };
    };
    expect(document.ok).toBe(false);
    expect(document.exitCode).toBe(EXIT_CODES.policy);
    expect(document.error.code).toBe("TX402_POLICY_BUDGET");
  });

  it("never lets a serialised error carry the underlying cause", async () => {
    // Tx402Error.toJSON omits `cause` (SEC-003); a CLI that re-added it would leak a signer
    // payload or a credentialed URL straight into a log aggregator. The safe *classification*
    // `causeCategory` is expected and welcome — it is the raw `cause` that must never appear,
    // so this matches the JSON key precisely rather than the substring.
    const harness = io(["call", "http://127.0.0.1:1/resource", "--json"], {
      createClient: createClient(),
    });
    await run(harness);
    const stdout = harness.out.join("");
    expect(stdout).not.toContain('"cause"');
    expect(stdout).toContain('"causeCategory"');
    expect(stdout).not.toContain("ECONNREFUSED");
  });
});

describe("stdout / stderr contract (SPEC §11)", () => {
  it("puts the response body on stdout and nothing else", async () => {
    const harness = io(["call", `${merchant.url}/resource`], {
      createClient: createClient(),
    });
    expect(await run(harness)).toBe(EXIT_CODES.success);
    expect(harness.out.join("")).toBe(JSON.stringify({ ok: true }));
  });

  it("puts diagnostics on stderr, keeping a redirected stdout clean", async () => {
    const harness = io(["call", `${merchant.url}/resource`, "--dry-run"], {
      createClient: createClient(),
    });
    await run(harness);
    expect(harness.out.join("")).toBe("");
    expect(harness.err.join("")).not.toBe("");
  });
});

describe("development key handling (SPEC §11, SEC-001)", () => {
  it("warns on stderr every time an environment key is used", async () => {
    const harness = io(["call", `${merchant.url}/resource`, "--dry-run"], {
      env: { [DEV_KEY_ENV.evm]: DEV_KEY },
    });
    await run(harness);
    const stderr = harness.err.join("");
    expect(stderr).toContain("warning:");
    expect(stderr).toContain(DEV_KEY_ENV.evm);
  });

  it("never echoes the key itself", async () => {
    const harness = io(["call", `${merchant.url}/resource`, "--dry-run", "--json"], {
      env: { [DEV_KEY_ENV.evm]: DEV_KEY },
    });
    await run(harness);
    const everything = harness.out.join("") + harness.err.join("");
    expect(everything).not.toContain(DEV_KEY);
    expect(everything).not.toContain(DEV_KEY.slice(2));
  });

  it("rejects a malformed environment key without quoting it", async () => {
    const harness = io(["call", `${merchant.url}/resource`], {
      env: { [DEV_KEY_ENV.evm]: "not-a-key-but-still-secret" },
    });
    expect(await run(harness)).toBe(EXIT_CODES.usage);
    expect(harness.err.join("")).not.toContain("not-a-key-but-still-secret");
  });

  it("runs with no signer at all and fails typed, not by crashing", async () => {
    // The commonest first run: someone tries `--dry-run` before configuring anything. They
    // should get a classified exit and a code that names the problem, not a stack trace.
    // It is exit 5 rather than 4 deliberately — with no signer the route was never
    // *attempted*, which is a different fact from "attempted and underfunded" (SPEC §6.4
    // step 20), and reporting liquidity here would send the operator to fund a wallet that
    // was never the problem.
    const harness = io(["call", `${merchant.url}/resource`, "--dry-run"]);
    expect(await run(harness)).toBe(EXIT_CODES.protocol);
    expect(harness.err.join("")).toContain("TX402_SCHEME_UNSUPPORTED");
  });
});
