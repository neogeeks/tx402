/**
 * S13b audit-finding regressions (TypeScript, ADR-023 — tests that RUN the behaviour). Each block
 * fails against the pre-fix code at f680b16 and passes after the S13b remediation.
 *
 *  - O22 — a gateway client refuses a plaintext http:// URL to a non-loopback host, and never
 *    follows a redirect (so a bearer is never sent in the clear or forwarded to another host).
 *  - O23 — the gateway validates the named-field request schema + Content-Type BEFORE dispatch, so
 *    `POST /v1/freeze {}` is a 400 instead of `isFrozen(undefined) === true`, and an over-width
 *    (>78-digit) input amount is rejected.
 *  - O24 — the client validates the response envelope: a string `"false"` is not coerced to `true`,
 *    a `TX402_CONFIG_INVALID` missing `configPath` is refused, and an unknown code is a protocol
 *    violation (identically to Python — no divergent base-error fallback).
 *  - O25 — the Node gateway refuses an unauthenticated or oversized body before buffering it.
 */

import { readdirSync, readFileSync } from "node:fs";
import { connect } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, describe, expect, it } from "vitest";

import { ConfigurationError } from "../src/core/errors.js";
import { MemorySpendStore } from "../src/core/ledger.js";
import { redactDsn, resolveSpendStore } from "../src/cli/store-config.js";
import { run, type CliIo } from "../src/cli/run.js";
import {
  HttpGatewaySpendStore,
  bearerTokenScope,
  createGatewayServer,
  handleGatewayRequest,
  type GatewayBackend,
  type GatewayFetch,
} from "../src/gateway/index.js";
import {
  GATEWAY_ALL_METHODS,
  GATEWAY_WIRE_DEFS,
  gatewayRequestSchema,
  gatewayResponseSchema,
} from "../src/gateway/schema.js";
import { matchesWireSchema } from "../src/gateway/validate.js";
import { GATEWAY_VERSION_HEADER } from "../src/gateway/wire.js";

const golden = JSON.parse(
  readFileSync(new URL("../../../core-spec/gateway/golden.json", import.meta.url), "utf8"),
) as {
  requests: { op: string; body: unknown }[];
  responses: { condition: string; body: unknown }[];
};

const ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const FP = `sha256:${"0".repeat(64)}`;
const NOW = 1_800_000_000_000;
const SCOPE = "merchant.example";
const DATA_TOKEN = "data-token-abc";
const ADMIN_TOKEN = "admin-token-xyz";
const CAPS = Object.freeze({ atomicGlobalFreeze: true });

function memoryBackend(): { backend: GatewayBackend; store: MemorySpendStore } {
  const store = new MemorySpendStore();
  return {
    store,
    backend: {
      dataStore: store,
      adminStore: store,
      resolveScope: bearerTokenScope({ dataToken: DATA_TOKEN, adminToken: ADMIN_TOKEN }),
    },
  };
}

/** POST a raw body to the gateway core with explicit header control (to probe the request gates). */
function postRaw(
  backend: GatewayBackend,
  method: string,
  bodyText: string,
  opts: { token?: string; contentType?: string | null } = {},
): Promise<Response> {
  const headers: Record<string, string> = { [GATEWAY_VERSION_HEADER]: "1" };
  if (opts.token !== undefined) headers.authorization = `Bearer ${opts.token}`;
  const contentType =
    opts.contentType === undefined ? "application/json" : opts.contentType;
  if (contentType !== null) headers["content-type"] = contentType;
  return handleGatewayRequest(
    new Request(`http://gw/v1/${method}`, { method: "POST", headers, body: bodyText }),
    backend,
  );
}

async function reason(response: Response): Promise<string | undefined> {
  const body = (await response.json()) as { error?: { details?: { reason?: string } } };
  return body.error?.details?.reason;
}

/** A client whose transport returns exactly `body` at `status` — to probe response validation. */
function fixedResponseClient(status: number, body: unknown): HttpGatewaySpendStore {
  const fetch: GatewayFetch = () =>
    Promise.resolve({ status, json: () => Promise.resolve(body) });
  return new HttpGatewaySpendStore({
    baseUrl: "http://gw",
    token: DATA_TOKEN,
    capabilities: CAPS,
    fetch,
  });
}

describe("O23/O24 — the runtime validator agrees with the golden (ajv parity)", () => {
  it("accepts every committed request fixture against its method schema", () => {
    for (const { op, body } of golden.requests) {
      const schema = gatewayRequestSchema(op);
      expect(schema, `request schema for ${op}`).toBeDefined();
      expect(
        matchesWireSchema(schema as Record<string, unknown>, body, GATEWAY_WIRE_DEFS),
        `request fixture ${op} should validate`,
      ).toBe(true);
    }
  });

  it("accepts every committed response fixture against some method's response schema", () => {
    for (const { condition, body } of golden.responses) {
      const accepted = GATEWAY_ALL_METHODS.some((method) =>
        matchesWireSchema(
          gatewayResponseSchema(method) as Record<string, unknown>,
          body,
          GATEWAY_WIRE_DEFS,
        ),
      );
      expect(accepted, `response fixture ${condition} should validate`).toBe(true);
    }
  });
});

describe("O22 — gateway transport is HTTPS by default, redirects refused", () => {
  it("refuses a plaintext http:// URL to a non-loopback host (real transport)", () => {
    let caught: unknown;
    try {
      new HttpGatewaySpendStore({
        baseUrl: "http://collector.invalid/gw",
        token: DATA_TOKEN,
        capabilities: CAPS,
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ConfigurationError);
    expect(caught).toMatchObject({
      code: "TX402_CONFIG_INVALID",
      details: { reason: "https-required" },
    });
  });

  it("permits https:// to any host and plaintext http:// only to loopback", () => {
    expect(
      () =>
        new HttpGatewaySpendStore({
          baseUrl: "https://gw.example",
          token: "t",
          capabilities: CAPS,
        }),
    ).not.toThrow();
    expect(
      () =>
        new HttpGatewaySpendStore({
          baseUrl: "http://127.0.0.1:8787",
          token: "t",
          capabilities: CAPS,
        }),
    ).not.toThrow();
  });

  it("sets redirect:'error' on the real fetch so a 3xx cannot forward the bearer", async () => {
    let seenRedirect: string | undefined;
    const fetch: GatewayFetch = (_input, init) => {
      seenRedirect = init.redirect;
      return Promise.resolve({
        status: 200,
        json: () => Promise.resolve({ result: false }),
      });
    };
    const client = new HttpGatewaySpendStore({
      baseUrl: "https://gw.example",
      token: DATA_TOKEN,
      capabilities: CAPS,
      fetch,
    });
    await client.isFrozen(SCOPE);
    expect(seenRedirect).toBe("error");
  });
});

describe("O23 — gateway enforces the request schema + Content-Type before dispatch", () => {
  it("rejects POST /v1/freeze {} as 400 instead of freezing scope `undefined`", async () => {
    const { backend, store } = memoryBackend();
    const response = await postRaw(backend, "freeze", "{}", { token: ADMIN_TOKEN });
    expect(response.status).toBe(400);
    expect(await reason(response)).toBe("gateway-bad-request");
    // The store was never touched: no scope (and certainly not `undefined`) is frozen.
    expect(await store.isFrozen(SCOPE)).toBe(false);
    expect(await store.isFrozen(undefined as unknown as string)).toBe(false);
  });

  it("rejects isFrozen {} (missing scope), wrong types, and extra fields", async () => {
    const { backend } = memoryBackend();
    expect((await postRaw(backend, "isFrozen", "{}", { token: DATA_TOKEN })).status).toBe(
      400,
    );
    expect(
      (await postRaw(backend, "isFrozen", '{"scope":123}', { token: DATA_TOKEN })).status,
    ).toBe(400);
    expect(
      (await postRaw(backend, "isFrozen", '{"scope":"x","extra":1}', { token: DATA_TOKEN }))
        .status,
    ).toBe(400);
  });

  it("rejects a reserve whose amount exceeds 78 digits (input cap, not an accumulator)", async () => {
    const { backend } = memoryBackend();
    const overWidth = JSON.stringify({
      reservationId: "r1",
      requestId: "r1",
      policyScope: SCOPE,
      requestFingerprint: FP,
      assetId: ASSET,
      amountAtomic: "1".repeat(79),
      maxPerHourAtomic: "1000",
      nowEpochMs: NOW,
    });
    expect(
      (await postRaw(backend, "reserve", overWidth, { token: DATA_TOKEN })).status,
    ).toBe(400);
  });

  it("rejects a missing or non-JSON Content-Type", async () => {
    const { backend } = memoryBackend();
    expect(
      (
        await postRaw(backend, "isFrozen", '{"scope":"x"}', {
          token: DATA_TOKEN,
          contentType: null,
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await postRaw(backend, "isFrozen", '{"scope":"x"}', {
          token: DATA_TOKEN,
          contentType: "text/plain",
        })
      ).status,
    ).toBe(400);
  });

  it("tolerates a charset parameter on the Content-Type", async () => {
    const { backend } = memoryBackend();
    const ok = await postRaw(backend, "isFrozen", '{"scope":"x"}', {
      token: DATA_TOKEN,
      contentType: "application/json; charset=utf-8",
    });
    expect(ok.status).toBe(200);
  });
});

describe("O24 — the client validates the response envelope (no coercion)", () => {
  it("refuses a string 'false' where a boolean is required (no truthiness coercion)", async () => {
    const client = fixedResponseClient(200, { result: "false" });
    await expect(client.isFrozen(SCOPE)).rejects.toMatchObject({
      details: { reason: "gateway-invalid-response" },
    });
  });

  it("refuses a TX402_CONFIG_INVALID error missing details.configPath", async () => {
    const client = fixedResponseClient(200, {
      error: { code: "TX402_CONFIG_INVALID", details: { reason: "x" } },
    });
    await expect(client.isFrozen(SCOPE)).rejects.toBeInstanceOf(ConfigurationError);
    await expect(client.isFrozen(SCOPE)).rejects.toMatchObject({
      details: { reason: "gateway-invalid-response" },
    });
  });

  it("refuses an unknown error code as a protocol violation (aligned with Python)", async () => {
    const client = fixedResponseClient(200, {
      error: { code: "TX402_MADE_UP", details: {} },
    });
    await expect(client.isFrozen(SCOPE)).rejects.toMatchObject({
      details: { reason: "gateway-invalid-response" },
    });
  });

  it("still round-trips a well-formed boolean and a valid typed error", async () => {
    expect(await fixedResponseClient(200, { result: true }).isFrozen(SCOPE)).toBe(true);
    await expect(
      fixedResponseClient(200, {
        error: {
          code: "TX402_CONFIG_INVALID",
          details: { configPath: "gateway.request", reason: "gateway-bad-request" },
        },
      }).isFrozen(SCOPE),
    ).rejects.toBeInstanceOf(ConfigurationError);
  });
});

/**
 * Stream a large authenticated body at the live gateway over a raw TCP socket and report how many
 * bytes were uploaded before the server stopped reading. This is the ONLY signal that isolates
 * `MAX_REQUEST_BODY_BYTES`: the status code cannot (O36) — an oversized body is 400'd by O23's
 * schema regardless of the cap, and a premature half-close is 400'd by Node's own `clientError`,
 * so every path is a 400 either way. But *how far the upload gets* does isolate it. With the cap,
 * the gateway refuses (declared-length arm) or overflows (buffering arm) and drains-then-cuts the
 * socket within ~one drain cap (256 KiB) — the client's writes fail (EPIPE/ECONNRESET) after well
 * under 1 MiB. Without the cap, the server buffers the whole declared body, so the client uploads
 * every byte before any response. `chunked:true` exercises the overflow arm (no Content-Length);
 * `chunked:false` the declared-length header gate. Terminating early — whether by reset, close, or a
 * 400 — is the point, so any of those resolves with the bytes sent so far; a timeout bounds the run.
 */
function bytesUploadedBeforeRefusal(
  port: number,
  opts: { totalBytes: number; chunked: boolean },
): Promise<number> {
  return new Promise((resolve) => {
    const socket = connect(port, "127.0.0.1");
    const CHUNK = 64 * 1024;
    let sent = 0;
    let bodyEnded = false;
    let settled = false;
    const settle = (): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(sent);
    };
    // A server that stops reading resets the socket; the client sees EPIPE/ECONNRESET on write, or a
    // response, or a close. All three mean "the server stopped" — record how far we got.
    socket.setTimeout(15_000, settle);
    socket.on("error", settle);
    socket.on("close", settle);
    socket.on("data", settle);
    const pump = (): void => {
      while (!settled && !bodyEnded && sent < opts.totalBytes) {
        const n = Math.min(CHUNK, opts.totalBytes - sent);
        const frame = opts.chunked
          ? `${n.toString(16)}\r\n${"x".repeat(n)}\r\n`
          : "x".repeat(n);
        sent += n;
        let flushed: boolean;
        try {
          flushed = socket.write(frame);
        } catch {
          settle(); // writing to a reset socket throws on some platforms — that is a "server stopped"
          return;
        }
        if (!flushed) {
          socket.once("drain", pump); // respect backpressure instead of spinning
          return;
        }
      }
      if (sent >= opts.totalBytes && !bodyEnded) {
        bodyEnded = true;
        if (opts.chunked) socket.write("0\r\n\r\n");
      }
    };
    socket.on("connect", () => {
      const framing = opts.chunked
        ? "Transfer-Encoding: chunked"
        : `Content-Length: ${opts.totalBytes}`;
      socket.write(
        `POST /v1/isFrozen HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${port}\r\n` +
          `Authorization: Bearer ${DATA_TOKEN}\r\n` +
          `${GATEWAY_VERSION_HEADER}: 1\r\n` +
          `Content-Type: application/json\r\n` +
          `${framing}\r\n\r\n`,
      );
      pump();
    });
  });
}

describe("O25/O36 — the Node gateway caps request bodies mid-stream (isolated from O23)", () => {
  const server = createGatewayServer(memoryBackend().backend);
  let base = "";
  let port = 0;
  const listening = new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address !== null && typeof address === "object") {
        port = address.port;
        base = `http://127.0.0.1:${port}`;
      }
      resolve();
    });
  });
  afterAll(() => new Promise<void>((done) => server.close(() => done())));

  // A caller that streams 64 MiB. With the cap, the server stops reading within a drain cap; without
  // it, the whole body is buffered. The 16 MiB assertion sits an order of magnitude above the real
  // cut-off (~0.5–0.8 MiB locally) and far below the full body, so OS socket buffering cannot move it.
  const STREAM_BYTES = 64 * 1024 * 1024;
  const REFUSAL_CEILING = 16 * 1024 * 1024;

  it("returns 401 for a request with no bearer, without buffering the body", async () => {
    await listening;
    const response = await fetch(`${base}/v1/isFrozen`, {
      method: "POST",
      headers: { "content-type": "application/json", [GATEWAY_VERSION_HEADER]: "1" },
      body: JSON.stringify({ scope: SCOPE }),
    });
    expect(response.status).toBe(401);
  });

  it("stops reading an authenticated over-cap body while it is still uploading — buffering arm, no declared length (O36)", async () => {
    // The memory-safety heart of O25: an AUTHENTICATED caller with a lying/absent Content-Length
    // cannot force the gateway to buffer an unbounded body. The status is a useless signal here (400
    // both ways), so we assert the server stopped reading long before the 64 MiB finished uploading.
    // Falsifiability: set MAX_REQUEST_BODY_BYTES = 512 * 1024 * 1024 in gateway/node.ts and the
    // gateway buffers the whole stream — bytesSent becomes the full 64 MiB and this FAILS. The pre-fix
    // `{scope,pad}` test could not see this (its 400 came from O23's extra-field check, cap or no cap).
    await listening;
    const uploaded = await bytesUploadedBeforeRefusal(port, {
      totalBytes: STREAM_BYTES,
      chunked: true,
    });
    expect(uploaded).toBeLessThan(REFUSAL_CEILING);
  });

  it("refuses a declared over-cap Content-Length before the body is uploaded — header arm (O36)", async () => {
    // The declared-length gate (node.ts:117). A 64 MiB Content-Length is refused from the header
    // alone, so the server drains-and-cuts within a drain cap rather than reading the declared body.
    // Same falsifiability knob: raise MAX_REQUEST_BODY_BYTES past 64 MiB and the gate stops firing,
    // the server reads the whole body, and bytesSent climbs to the full 64 MiB.
    await listening;
    const uploaded = await bytesUploadedBeforeRefusal(port, {
      totalBytes: STREAM_BYTES,
      chunked: false,
    });
    expect(uploaded).toBeLessThan(REFUSAL_CEILING);
  });

  it("still serves a normal authenticated request", async () => {
    await listening;
    const response = await fetch(`${base}/v1/isFrozen`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        [GATEWAY_VERSION_HEADER]: "1",
        authorization: `Bearer ${DATA_TOKEN}`,
      },
      body: JSON.stringify({ scope: SCOPE }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ result: false });
  });
});

describe("O22 — the CLI store resolver requires HTTPS for a remote gateway", () => {
  it("refuses a plaintext http:// gateway to a non-loopback host", async () => {
    const error = await resolveSpendStore(
      { TX402_SPEND_STORE: "http://collector.invalid/gw", TX402_SPEND_STORE_TOKEN: "t" },
      "data",
    ).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ConfigurationError);
    expect((error as ConfigurationError).details).toMatchObject({
      reason: "https-required",
    });
  });

  it("allows plaintext http:// to a loopback host (dev) — it fails on connect, not the scheme", async () => {
    const error = await resolveSpendStore(
      { TX402_SPEND_STORE: "http://127.0.0.1:59997", TX402_SPEND_STORE_TOKEN: "t" },
      "data",
    ).catch((caught: unknown) => caught);
    // Loopback http is permitted, so the resolver gets PAST the scheme gate and fails to connect.
    expect((error as { details?: { reason?: string } }).details?.reason).not.toBe(
      "https-required",
    );
  });
});

describe("O16 — the rendered lifecycle guidance is money-safe (no expiry/retry hazard)", () => {
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const doc = (rel: string): string => readFileSync(join(repo, rel), "utf8");
  const SURFACES = [
    "README.md",
    "docs/src/content/docs/guides/lifecycle.mdx",
    "docs/src/content/docs/operations/running.mdx",
    "docs/src/content/docs/reference/configuration.mdx",
    "docs/src/content/docs/reference/errors.mdx",
    "docs/src/content/docs/security/index.mdx",
  ];

  it("no page describes the exposed hold as expiring at a TTL, or advises a fresh-client retry", () => {
    for (const rel of SURFACES) {
      const text = doc(rel);
      expect(
        text,
        `${rel} must not describe the hold as retained-until-its-TTL`,
      ).not.toMatch(/retained\**\s+until its (?:120-second )?TTL/iu);
      expect(text, `${rel} must not advise retrying with a fresh client`).not.toMatch(
        /with a fresh client/iu,
      );
    }
  });

  it("the lifecycle guidance names the EXPOSE fence and the non-expiring exposed hold", () => {
    const lifecycle = doc("docs/src/content/docs/guides/lifecycle.mdx");
    expect(lifecycle).toMatch(/EXPOSE fence/u);
    expect(lifecycle).toMatch(
      /never expires|does not expire|stops expiring|no longer expires/iu,
    );
    expect(doc("README.md")).toMatch(/EXPOSE fence/u);
  });

  it("the failure-mode table labels the after-transmission reservation `exposed`, never `retained` (O41a)", () => {
    // `retained` is not a reservation state (the states are reserved/committed/released/expired/
    // exposed); it invited the expiry misreading O16 corrected. The prose says the hold moves to
    // `exposed`, so the table cell must too. The O16 `/retained…until its TTL/` regex above misses a
    // bare `**retained**` cell, so this guards the cell directly.
    const lifecycle = doc("docs/src/content/docs/guides/lifecycle.mdx");
    expect(
      lifecycle,
      "no failure-mode cell may label a reservation `retained`",
    ).not.toMatch(/\|\s*\*\*retained\*\*\s*\|/u);
    expect(lifecycle, "the after-transmission hold is `exposed`").toMatch(
      /\|\s*\*\*exposed\*\*\s*\|/u,
    );
  });

  it("the reconciliation runbook says a terminal-resolution retry RAISES, not a silent no-op", () => {
    const recon = doc("docs/src/content/docs/operations/exposed-reconciliation.mdx");
    expect(recon).toMatch(/reservation-already-terminal/u);
    expect(recon).not.toMatch(/is a no-op/u);
  });
});

describe("O5/O40 — the money-safety promise is scoped to cooperating/induced spend (no overspend overclaim)", () => {
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const doc = (rel: string): string => readFileSync(join(repo, rel), "utf8");
  // The O5 rescope: 0.2.0 bounds a COOPERATING client's spend and INDUCED spend against a signing
  // boundary; it does NOT stop a fully compromised process (that is the 0.3.0 verifying-signer work).
  // No reader surface may re-introduce the absolute overclaim ("a wallet it can't overspend") that O5
  // corrected. The O16 doc-guard and the O33 citation guard never assert this wording, so a
  // regression here is invisible without a dedicated guard.
  const OVERSPEND_OVERCLAIM =
    /(?:can(?:'|’)?t|can\s?not|cannot|never)\s+(?:be\s+)?overspen[dt]/iu;
  const SURFACES = [
    "README.md",
    "docs/src/content/docs/security/index.mdx",
    "docs/src/content/docs/security/keys.mdx",
  ];

  it("no reader surface claims a wallet that cannot be overspent", () => {
    for (const rel of SURFACES) {
      expect(
        doc(rel),
        `${rel} must not overclaim an un-overspendable wallet (O5)`,
      ).not.toMatch(OVERSPEND_OVERCLAIM);
    }
  });

  it("the README scopes the caps to a cooperating client and names the 0.3.0 compromised-process gap", () => {
    const readme = doc("README.md");
    expect(readme).toMatch(/cooperating/iu); // `_cooperating_` in the README (markdown emphasis)
    expect(readme).toMatch(/compromised process/iu);
    expect(readme).toMatch(/0\.3\.0.*verifying-signer|verifying-signer.*0\.3\.0/isu);
  });

  it("the security model scopes the 0.2.0 guarantee to cooperating clients, not a compromised process", () => {
    const security = doc("docs/src/content/docs/security/index.mdx");
    expect(security).toMatch(/cooperating/iu);
    expect(security).toMatch(/compromised process/iu);
    // keys.mdx frames a cap as bounding INDUCED spend against a signing boundary (not overspend-proof).
    expect(doc("docs/src/content/docs/security/keys.mdx")).toMatch(/induced spend/iu);
  });
});

describe("O33 — no reader-facing surface cites an unpublished internal document", () => {
  // Runtime-printed help, and the packed SDK source, must not reference PLAN/PRD/session/audit
  // process docs (which do not ship) — the reasoning is inlined instead (PLAN §9).
  // Process-doc references that do not ship: PLAN/PRD/old-SPEC.md, and session identifiers
  // (S1, S7b, S15d, …). SPEC §/ADR-NNN/bare O-item design cross-references are RETAINED — they
  // point at durable design records (and the reasoning is inlined), not at process docs (O33).
  const PROCESS_CITATION =
    /PLAN\.md|PLAN-\d|PLAN\s*§|\bPRD\b|PRD-phase|SPEC\.md|\bS\d{1,2}[a-d]?\b|audit'?s? O\d+/u;
  const HELP_CITATION = /SPEC\s*§|ADR-\d{3}|SEC-\d{3}|PLAN\.md|\bPRD\b/u;

  it("the CLI --help output cites no internal document", async () => {
    const out: string[] = [];
    const io: CliIo = {
      argv: ["--help"],
      env: {},
      stdout: (text) => out.push(text),
      stderr: () => {},
      readFile: () => {
        throw new Error("no fs");
      },
    };
    await run(io);
    const help = out.join("");
    expect(help).toContain("Operator verbs"); // the help actually rendered
    expect(help).not.toMatch(HELP_CITATION);
  });

  it("the packed SDK source (dist inputs) cites no PLAN/PRD/session process document", () => {
    const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
    const roots = [
      join(repo, "packages", "tx402", "src"),
      join(repo, "packages", "tx402-python", "src"),
    ];
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (/\.(ts|py)$/u.test(entry.name)) {
          const source = readFileSync(full, "utf8");
          for (const [index, lineText] of source.split("\n").entries()) {
            if (PROCESS_CITATION.test(lineText)) {
              offenders.push(
                `${full.slice(repo.length + 1)}:${index + 1}: ${lineText.trim()}`,
              );
            }
          }
        }
      }
    };
    for (const root of roots) walk(root);
    expect(
      offenders,
      `process-doc citations in packed source:\n${offenders.join("\n")}`,
    ).toEqual([]);
  });
});

describe("O28 — a credential-bearing DSN never escapes into an error", () => {
  it("redactDsn masks userinfo in schemed and scheme-less DSNs", () => {
    expect(redactDsn("redis://user:s3cr3t@host:6379/0")).toBe("redis://***@host:6379/0");
    expect(redactDsn("user:s3cr3t@host:6379")).toBe("***@host:6379");
    expect(redactDsn("redis://host:6379/0")).toBe("redis://host:6379/0"); // nothing to mask
    // O41l: an unencoded `@` inside the password must NOT leave its suffix (`ss@host`) in the clear —
    // the mask runs to the LAST `@` before the host, not the first.
    expect(redactDsn("redis://user:p@ss@host:6379/0")).toBe("redis://***@host:6379/0");
    expect(redactDsn("rediss://u:a@b@c@d.example:6379")).toBe(
      "rediss://***@d.example:6379",
    );
  });

  it("an unsupported DSN error never contains the seeded secret", async () => {
    const error = await resolveSpendStore(
      { TX402_SPEND_STORE: "weirdscheme://user:s3cr3t@host:9999" },
      "data",
    ).catch((caught: unknown) => caught);
    const serialized = `${(error as Error).message}\n${JSON.stringify(
      (error as ConfigurationError).details,
    )}`;
    expect(serialized).not.toContain("s3cr3t");
    expect((error as ConfigurationError).details).toMatchObject({
      reason: "unsupported-store-dsn",
    });
  });
});
