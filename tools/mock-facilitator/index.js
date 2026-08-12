/**
 * Deterministic, offline x402 facilitator stub (`/verify` + `/settle` + `/supported`).
 *
 * PRD-phase1 §27 names this as an explicit Phase-1 deliverable. Today a test merchant settles
 * one of two ways, and neither suits an offline safety proof:
 *
 *   - **merchant-side spoofing** — the merchant fabricates a `PAYMENT-RESPONSE` with no
 *     verify/settle wire at all, so the realistic facilitator path is never exercised; or
 *   - **a real facilitator** — `settleWithFacilitator` POSTs `/verify` then `/settle` to a
 *     live x402 facilitator, which **moves testnet funds** and needs a network and a signer
 *     with a balance.
 *
 * This stub is the third option: it speaks the exact `/verify`+`/settle` wire a real
 * facilitator does (so `tools/test-merchant`'s `facilitatorUrl` path runs unchanged), but it
 * is a pure function of its `mode` and the request — no chain, no network, no clock, no
 * randomness — so an adversarial run settles deterministically and offline and a failing
 * proof fails the same way twice. It is the settlement half of the unified adversarial driver
 * (`tools/adversarial`); the concurrency/failure halves compose it with the RPC stub and the
 * test merchant.
 *
 * The interface is defined by the **merchant**, not the buyer: ADR-002 keeps `/verify` and
 * `/settle` on the merchant, and the buyer SDK never learns a facilitator exists. So the
 * shapes here mirror exactly what `tools/test-merchant/index.js#settleWithFacilitator` sends
 * and reads.
 *
 * @example
 * ```js
 * const facilitator = await createMockFacilitator({ mode: "settle" });
 * const merchant = await createTestMerchant({ facilitatorUrl: facilitator.url });
 * // ... drive a paid call; the merchant verifies+settles against this stub, offline ...
 * await merchant.close();
 * await facilitator.close();
 * ```
 */

import { createServer } from "node:http";
import { once } from "node:events";

/**
 * @typedef {"settle"|"decline"|"invalid"} FacilitatorMode
 *
 * - `settle`  — `/verify` accepts and `/settle` succeeds; the merchant delivers (buyer commits).
 * - `decline` — `/verify` accepts but `/settle` reports `success:false`; the merchant answers
 *               402 and the buyer releases the reservation (a settlement that did not happen
 *               must never leave committed budget behind).
 * - `invalid` — `/verify` reports the authorization invalid, so the merchant never reaches
 *               `/settle`; same buyer-visible outcome as `decline`, a different facilitator
 *               cause.
 */

/** A fixed, obviously-synthetic settlement hash. Deterministic: the same run twice is byte-identical. */
const SETTLEMENT_TRANSACTION = `0xfacade${"0".repeat(58)}`;

/**
 * @typedef {object} MockFacilitatorOptions
 * @property {FacilitatorMode} [mode]   default "settle"
 * @property {string} [feePayer]        advertised in `/supported.kinds[].extra.feePayer` (SVM)
 * @property {string} [transaction]     the settlement hash reported on success; default synthetic
 * @property {number} [port]            default 0 (ephemeral)
 */

/** Reads a request body to a string; the facilitator only ever receives small JSON. */
async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * The payer address, read from the decoded EIP-3009 authorization when present. The merchant
 * forwards the buyer's decoded `paymentPayload`, so this is the real payer — but it is only
 * cosmetic in `PAYMENT-RESPONSE`, so an unrecognized payload simply omits it.
 */
function payerFrom(paymentPayload) {
  const from = paymentPayload?.payload?.authorization?.from;
  return typeof from === "string" ? from : undefined;
}

/**
 * Structurally verify an EIP-3009 exact-scheme authorization and its binding to the requirement
 * (O29). A real facilitator will not settle a malformed or wrongly-bound authorization, so the stub
 * must not either — otherwise a driver where the signer returns a one-byte `0x00` "signature", or a
 * payload that pays the wrong recipient/amount, would false-pass. Crypto-free (offline): it checks
 * field SHAPES (a 65-byte signature, a 20-byte `from`/`to`, a 32-byte nonce) and BINDING (scheme,
 * network, `to === payTo`, `value === amount`). Non-EVM schemes keep the pre-existing accept path,
 * so the SVM callers are unaffected. Returns `{ ok }` or `{ ok:false, reason }`.
 */
function verifyAuthorization(body) {
  const payload = body?.paymentPayload;
  const requirements = body?.paymentRequirements ?? {};
  if (!payload || typeof payload !== "object")
    return { ok: false, reason: "missing-payload" };
  // The decoded PAYMENT-SIGNATURE carries the accepted offer under `.accepted` and the signed
  // authorization + signature under `.payload` (see tools/test-merchant#settleWithFacilitator).
  const accepted = payload.accepted ?? {};
  if (accepted.scheme !== requirements.scheme)
    return { ok: false, reason: "scheme-mismatch" };
  if (accepted.network !== requirements.network)
    return { ok: false, reason: "network-mismatch" };
  const inner = payload.payload;
  const auth = inner?.authorization;
  if (!inner || typeof inner !== "object" || !auth || typeof auth !== "object") {
    return { ok: false, reason: "missing-authorization" };
  }
  // The EVM exact scheme (EIP-3009): enforce field shapes + binding. Other schemes accept as before.
  const network = typeof accepted.network === "string" ? accepted.network : "";
  if (accepted.scheme === "exact" && network.startsWith("eip155:")) {
    const isAddr = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{40}$/u.test(v);
    const isSig = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{130}$/u.test(v); // 65 bytes
    const isNonce = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/u.test(v);
    if (!isSig(inner.signature)) return { ok: false, reason: "signature-malformed" };
    if (!isAddr(auth.from)) return { ok: false, reason: "from-malformed" };
    if (!isAddr(auth.to)) return { ok: false, reason: "to-malformed" };
    if (!isNonce(auth.nonce)) return { ok: false, reason: "nonce-malformed" };
    if (auth.to.toLowerCase() !== String(requirements.payTo ?? "").toLowerCase()) {
      return { ok: false, reason: "recipient-mismatch" };
    }
    if (String(auth.value) !== String(requirements.amount ?? "")) {
      return { ok: false, reason: "amount-mismatch" };
    }
  }
  return { ok: true };
}

/**
 * Starts the stub.
 *
 * @param {MockFacilitatorOptions} [options]
 */
export async function createMockFacilitator(options = {}) {
  const {
    mode: initialMode = "settle",
    feePayer = "MockFaci11tator1111111111111111111111111111",
    transaction = SETTLEMENT_TRANSACTION,
    port = 0,
  } = options;

  /** @type {FacilitatorMode} */
  let mode = initialMode;
  /** @type {{ path: string, body: object }[]} */
  const calls = [];

  const server = createServer((request, response) => {
    void (async () => {
      const path = (request.url ?? "/").split("?")[0];
      const method = request.method ?? "GET";

      /** @param {number} status @param {unknown} payload */
      const json = (status, payload) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(payload));
      };

      if (method === "GET" && path === "/supported") {
        // Read by `cli.js`/`tools/ttv` for the SVM fee payer. Static and network-agnostic:
        // the exact scheme is all any Phase-1 requirement offers.
        json(200, {
          kinds: [{ x402Version: 2, scheme: "exact", extra: { feePayer } }],
        });
        return;
      }

      if (method !== "POST" || (path !== "/verify" && path !== "/settle")) {
        json(404, { error: "not-found", path });
        return;
      }

      const raw = await readBody(request);
      /** @type {any} */
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        json(400, { error: "bad-json" });
        return;
      }
      calls.push({ path, body });

      const requirements = body?.paymentRequirements ?? {};
      const network = typeof requirements.network === "string" ? requirements.network : "";

      if (path === "/verify") {
        if (mode === "invalid") {
          json(200, { isValid: false, invalidReason: "authorization-invalid" });
          return;
        }
        // Even in an accepting mode, a malformed or wrongly-bound authorization is refused — a real
        // facilitator would not settle it, so neither does the stub (O29).
        const check = verifyAuthorization(body);
        if (!check.ok) {
          json(200, { isValid: false, invalidReason: check.reason });
          return;
        }
        json(200, { isValid: true });
        return;
      }

      // path === "/settle"
      if (mode === "decline") {
        json(200, {
          success: false,
          transaction: "",
          network,
          errorReason: "transaction-declined",
        });
        return;
      }
      json(200, {
        success: true,
        transaction,
        network,
        ...(payerFrom(body?.paymentPayload) === undefined
          ? {}
          : { payer: payerFrom(body?.paymentPayload) }),
      });
    })();
  });

  server.listen(port);
  await once(server, "listening");
  const address = server.address();
  const boundPort = typeof address === "object" && address !== null ? address.port : port;

  return {
    url: `http://127.0.0.1:${boundPort}`,
    port: boundPort,
    feePayer,
    calls,
    get mode() {
      return mode;
    },
    /** @param {FacilitatorMode} next */
    setMode(next) {
      mode = next;
    },
    reset() {
      calls.length = 0;
      mode = initialMode;
    },
    async close() {
      server.closeAllConnections?.();
      server.close();
      await once(server, "close");
    },
  };
}
