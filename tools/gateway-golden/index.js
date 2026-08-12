#!/usr/bin/env node
/**
 * Capability-gateway golden — the drift-checked artifact that pins the §12.5 wire contract
 * byte-for-byte (SPEC-0.2.0 §12.5, ADR-024; the sibling of the CLI `--json` golden).
 *
 *   node tools/gateway-golden/index.js [build|check]    (default: check)
 *
 * The golden (`core-spec/gateway/golden.json`) is GENERATED from the reference client + wire module
 * (`packages/tx402/dist/gateway`), never hand-edited, and holds three things:
 *   - **requests** — the exact `POST /v1/{method}` the `httpGatewaySpendStore` client emits for a
 *     canonical call of every method: the path, the version + auth headers, and the named-field JSON
 *     body with the nested `ReservationRef` triple. The Python client's `tests/test_gateway_store.py`
 *     asserts it emits byte-identical requests, so the two clients interoperate with any gateway.
 *   - **responses** — every success/void shape and every error condition, with the EXACT typed error
 *     the client raises (name + existing taxonomy code + details). There is no `TX402_GATEWAY_FORBIDDEN`
 *     — every gateway condition maps to an existing code (§12.5), so a gateway-backed store is
 *     byte-identical to a direct one.
 *   - **schema** — the full JSON Schema for every request/response (`GATEWAY_WIRE_SCHEMA`), pinned
 *     here so the wire contract and its schema move together; `test/gateway-golden.test.ts` validates
 *     every fixture against it (ajv).
 *
 * `check` regenerates all three from the built client and fails on any drift from the committed file.
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path, { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  HttpGatewaySpendStore,
  GATEWAY_WIRE_SCHEMA,
  GATEWAY_PROTOCOL_VERSION,
  GATEWAY_VERSION_HEADER,
  GATEWAY_PATH_PREFIX,
  gatewayMethodPath,
  gatewayPlane,
  deserializeTx402Error,
  gatewayConditionError,
} from "../../packages/tx402/dist/gateway/index.js";
import {
  BudgetExceededError,
  ConfigurationError,
  RecipientUnpinnedError,
  SpendScopeFrozenError,
} from "../../packages/tx402/dist/core/errors.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../..");
const goldenPath = path.join(repoRoot, "core-spec/gateway/golden.json");

// ── canonical inputs (fixed, so the golden is deterministic) ──────────────────────────────────
const TOKEN = "golden-token";
const SCOPE = "merchant.example";
const ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const NETWORK = "eip155:8453";
const RECIPIENT = `0x${"1".repeat(40)}`;
const FP = `sha256:${"0".repeat(64)}`;
const NOW = 1_800_000_000_000;
const REF = { reservationId: "res-1", policyScope: SCOPE, assetId: ASSET };

/** The whole method set as a client call, in wire order (data plane then admin plane). */
const REQUEST_CALLS = [
  [
    "reserve",
    (c) =>
      c.reserve({
        reservationId: "res-1",
        requestId: "req-1",
        policyScope: SCOPE,
        requestFingerprint: FP,
        assetId: ASSET,
        amountAtomic: "1500",
        maxPerHourAtomic: "1000000",
        maxTotalAtomic: "5000000",
        recipientNetwork: NETWORK,
        recipientCanonical: RECIPIENT,
        recipientEnforcement: "tofu",
        nowEpochMs: NOW,
      }),
  ],
  [
    "commit",
    (c) =>
      c.commit({
        reservationId: "res-1",
        policyScope: SCOPE,
        assetId: ASSET,
        committedAtEpochMs: NOW + 10,
        settlementId: "0xsettlement",
      }),
  ],
  ["release", (c) => c.release(REF, NOW + 5)],
  ["expose", (c) => c.expose(REF, NOW + 5)],
  [
    "getBudgetState",
    (c) => c.getBudgetState({ policyScope: SCOPE, assetId: ASSET, nowEpochMs: NOW }),
  ],
  [
    "listExposed",
    (c) => c.listExposed({ policyScope: SCOPE, assetId: ASSET, nowEpochMs: NOW }),
  ],
  ["isFrozen", (c) => c.isFrozen(SCOPE)],
  ["getRecipientPins", (c) => c.getRecipientPins(SCOPE, NETWORK)],
  ["getRecipientPolicy", (c) => c.getRecipientPolicy(SCOPE)],
  ["capabilities", (c) => c.requestCapabilities()],
  ["freeze", (c) => c.freeze(SCOPE, NOW)],
  ["unfreeze", (c) => c.unfreeze(SCOPE, NOW)],
  ["setRecipientPins", (c) => c.setRecipientPins(SCOPE, NETWORK, [RECIPIENT], NOW)],
  [
    "setBudgetLimits",
    (c) =>
      c.setBudgetLimits(
        SCOPE,
        ASSET,
        { maxPerHourAtomic: "100", maxTotalAtomic: "1000" },
        NOW,
      ),
  ],
  ["getBudgetLimits", (c) => c.getBudgetLimits(SCOPE, ASSET)],
  [
    "setRecipientAssertionRequired",
    (c) => c.setRecipientAssertionRequired(SCOPE, true, NOW),
  ],
  ["setTofuEnabled", (c) => c.setTofuEnabled(SCOPE, true, NOW)],
  ["resolveExposed", (c) => c.resolveExposed(REF, "committed", NOW)],
  ["resetCumulative", (c) => c.resetCumulative(SCOPE, ASSET, NOW)],
];

/** Capture the exact request the client emits for each method (a canned response; decode may throw). */
async function generateRequests() {
  const requests = [];
  for (const [op, invoke] of REQUEST_CALLS) {
    let captured;
    const fetch = (input, init) => {
      const url = new URL(input, "http://gateway.local");
      captured = {
        op,
        method: init.method,
        path: url.pathname,
        headers: init.headers,
        body: JSON.parse(init.body),
      };
      // A benign canned success so the call completes; a decode mismatch is caught below.
      return Promise.resolve({
        status: 200,
        json: () => Promise.resolve({ result: null }),
      });
    };
    const client = new HttpGatewaySpendStore({
      baseUrl: "http://gateway.local",
      token: TOKEN,
      capabilities: { atomicGlobalFreeze: false },
      fetch,
    });
    try {
      await invoke(client);
    } catch {
      // The canned `{ result: null }` does not decode into every return type; the request is what
      // we are capturing, and it was recorded before the client tried to decode.
    }
    if (captured === undefined) throw new Error(`no request captured for ${op}`);
    // Assert the path + plane the wire module declares match what the client emitted.
    if (captured.path !== gatewayMethodPath(op)) {
      throw new Error(`${op}: client path ${captured.path} != ${gatewayMethodPath(op)}`);
    }
    requests.push({
      op,
      scope: gatewayPlane(op),
      method: captured.method,
      path: captured.path,
      headers: captured.headers,
      body: captured.body,
    });
  }
  return requests;
}

/** The typed error a wire payload maps to, as recorded in the golden. */
function raiseOutcome(error) {
  return {
    kind: "raise",
    name: error.name,
    code: error.code,
    retryable: error.retryable,
    details: { ...error.details },
  };
}

/** Every success/void shape and every error condition, with the exact client outcome. */
function generateResponses() {
  const reservation = {
    reservationId: "res-1",
    policyScope: SCOPE,
    requestFingerprint: FP,
    assetId: ASSET,
    amountAtomic: "1500",
    createdAtEpochMs: NOW,
    expiresAtEpochMs: NOW + 120_000,
    state: "reserved",
  };
  const entry = {
    reservationId: "res-1",
    requestFingerprint: FP,
    assetId: ASSET,
    amountAtomic: "1500",
    committedAtEpochMs: NOW + 10,
    settlementId: "0xsettlement",
  };
  const responses = [
    {
      condition: "reserve-success",
      status: 200,
      body: { result: { reservation, recipientPinEstablished: false } },
      outcome: { kind: "result" },
    },
    {
      condition: "commit-success",
      status: 200,
      body: { result: entry },
      outcome: { kind: "result" },
    },
    {
      condition: "void-success",
      status: 200,
      body: { result: null },
      outcome: { kind: "result" },
    },
    {
      condition: "capabilities-success",
      status: 200,
      body: { result: { atomicGlobalFreeze: false } },
      outcome: { kind: "result" },
    },
  ];

  // Domain refusals returned at HTTP 200 as the exact typed error (rethrown by the client).
  const domainErrors = [
    [
      "frozen",
      new SpendScopeFrozenError("Spending is frozen for this scope", {
        context: { requestId: "req-1", phase: "policy", assetId: ASSET, amountAtomic: "1" },
        details: { scope: SCOPE, frozenScope: SCOPE },
      }),
    ],
    [
      "over-cap",
      new BudgetExceededError("Hourly spend limit would be exceeded", {
        context: {
          requestId: "req-1",
          phase: "policy",
          assetId: ASSET,
          amountAtomic: "300",
        },
        details: {
          requestedAtomic: "300",
          capAtomic: "1000",
          committedAtomic: "0",
          reservedAtomic: "800",
          capKind: "per-hour",
        },
      }),
    ],
    [
      "unpinned",
      new RecipientUnpinnedError("The recipient is not pinned for this scope", {
        context: { requestId: "req-1", phase: "policy", assetId: ASSET },
        details: {
          merchantScope: SCOPE,
          reason: "not-allowlisted",
          network: NETWORK,
          presentedRecipient: RECIPIENT,
          expectedRecipients: [`0x${"2".repeat(40)}`],
        },
      }),
    ],
    [
      "reservation-not-found",
      new ConfigurationError("The reservation ref names no record", {
        context: { requestId: "spend-store", phase: "policy", reservationId: "res-1" },
        details: { configPath: "reservationRef", reason: "reservation-not-found" },
      }),
    ],
    [
      "global-freeze-unsupported",
      new ConfigurationError("Atomic global freeze is not supported by this topology", {
        context: { requestId: "spend-store", phase: "policy" },
        details: { configPath: "freeze.global", reason: "global-freeze-unsupported" },
      }),
    ],
  ];
  for (const [condition, error] of domainErrors) {
    const body = { error: error.toJSON() };
    responses.push({
      condition,
      status: 200,
      body,
      outcome: raiseOutcome(deserializeTx402Error(body.error)),
    });
  }

  // Gateway conditions: each maps to an existing taxonomy code by HTTP status (§12.5).
  for (const [condition, status] of [
    ["bad-request", 400],
    ["unauthorized", 401],
    ["admin-required", 403],
    ["version-unsupported", 426],
    ["unavailable", 503],
  ]) {
    responses.push({
      condition,
      status,
      body: conditionBody(status),
      outcome: raiseOutcome(gatewayConditionError(status)),
    });
  }
  return responses;
}

/** The body the reference gateway returns for a condition status (mirrors `gateway.ts`). */
function conditionBody(status) {
  const map = {
    400: { configPath: "gateway.request", reason: "gateway-bad-request" },
    401: { configPath: "gateway.auth", reason: "gateway-unauthorized" },
    403: { configPath: "gateway.auth", reason: "admin-credential-required" },
    426: { configPath: "gateway.version", reason: "gateway-version-unsupported" },
  };
  if (status === 503) {
    return {
      error: { code: "TX402_TRANSPORT", details: { causeCategory: "gateway-unavailable" } },
    };
  }
  return { error: { code: "TX402_CONFIG_INVALID", details: map[status] } };
}

async function generateGolden() {
  return {
    protocolVersion: GATEWAY_PROTOCOL_VERSION,
    versionHeader: GATEWAY_VERSION_HEADER,
    pathPrefix: GATEWAY_PATH_PREFIX,
    requests: await generateRequests(),
    responses: generateResponses(),
    schema: GATEWAY_WIRE_SCHEMA,
  };
}

function serialize(golden) {
  return `${JSON.stringify(golden, null, 2)}\n`;
}

/** Structural completeness: a request for every method, and the schema covers every method. */
function assertComplete(golden) {
  const methods = Object.keys(golden.schema.methods);
  const requestOps = new Set(golden.requests.map((request) => request.op));
  for (const method of methods) {
    if (!requestOps.has(method)) {
      throw new Error(`golden is missing a request fixture for "${method}"`);
    }
  }
  if (requestOps.size !== methods.length) {
    throw new Error(
      `golden has ${requestOps.size} request fixtures but the schema covers ${methods.length} methods`,
    );
  }
}

async function build() {
  const golden = await generateGolden();
  assertComplete(golden);
  mkdirSync(path.dirname(goldenPath), { recursive: true });
  writeFileSync(goldenPath, serialize(golden));
  console.log(
    `Wrote ${path.relative(repoRoot, goldenPath)}  ` +
      `(${golden.requests.length} request fixtures, ${golden.responses.length} response fixtures)`,
  );
  return 0;
}

async function check() {
  const golden = await generateGolden();
  assertComplete(golden);
  const fresh = serialize(golden);
  let committed;
  try {
    committed = readFileSync(goldenPath, "utf8");
  } catch {
    console.error(
      `FAIL  ${path.relative(repoRoot, goldenPath)} is missing. Run:\n` +
        "  node tools/gateway-golden/index.js build",
    );
    return 1;
  }
  if (fresh !== committed) {
    console.error(
      "FAIL  the gateway wire contract no longer matches the committed golden.\n" +
        "      The httpGatewaySpendStore client or the wire schema changed. If intended, run:\n" +
        "  node tools/gateway-golden/index.js build\n" +
        "      and commit the updated core-spec/gateway/golden.json.",
    );
    return 1;
  }
  console.log(
    `OK    gateway wire golden matches (${golden.requests.length} requests, ` +
      `${golden.responses.length} responses, ${Object.keys(golden.schema.methods).length} methods).`,
  );
  return 0;
}

const mode = (process.argv[2] ?? "check").toLowerCase();
if (mode === "build") process.exitCode = await build();
else if (mode === "check") process.exitCode = await check();
else {
  console.error(`unknown mode "${mode}" (expected: build | check)`);
  process.exitCode = 2;
}
