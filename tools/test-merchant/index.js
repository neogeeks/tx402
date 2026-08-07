/**
 * Deterministic x402 test merchant (SPEC §13).
 *
 * Emits configurable 402 challenges and validates paid retries. Everything it does is a
 * pure function of the scenario and the attempt number — there is no clock, no randomness,
 * and no ambient state — so a failing integration test fails the same way twice.
 *
 * It encodes and decodes through `@x402/core/http` rather than hand-rolling base64. The
 * point of an integration test is to exercise the real envelope; a bespoke encoder here
 * would let tx402 and the test merchant agree on a format that upstream does not speak.
 *
 * Retry validation is the half that is easy to omit and expensive to lack. The server
 * asserts what SPEC §6.7 and ADR-003 require of the buyer and answers `400` with a
 * machine-readable reason when they are violated, so that a bug in tx402's retry path shows
 * up as a clear failure rather than as a passing test.
 *
 * @example
 * ```js
 * const merchant = await createTestMerchant({ scenario: "pay-once" });
 * const response = await fetch(`${merchant.url}/resource`);
 * console.log(merchant.requests.map((r) => r.method));
 * await merchant.close();
 * ```
 */

import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { once } from "node:events";

import {
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
} from "@x402/core/http";

import { DEFAULT_REQUIREMENTS, requireScenario } from "./scenarios.js";

export { DEFAULT_REQUIREMENTS, SCENARIOS } from "./scenarios.js";

/** Buyer-side protocol headers, matching SPEC §6.1 and `@x402/core` 2.20.0. */
const HEADER_PAYMENT_REQUIRED = "payment-required";
const HEADER_PAYMENT_SIGNATURE = "payment-signature";
const HEADER_PAYMENT_RESPONSE = "payment-response";

/**
 * Why a paid retry was rejected. Returned in the `400` body so a test asserts on the reason
 * rather than on a bare status code.
 */
const RETRY_VIOLATIONS = {
  duplicateSignature: "duplicate-payment-signature-header",
  undecodableSignature: "payment-signature-not-decodable",
  versionMismatch: "payment-signature-wrong-protocol-version",
  unofferedRequirement: "accepted-requirement-was-not-offered",
  amountMismatch: "accepted-amount-does-not-match-offer",
  emptyPayload: "payment-signature-carries-no-payload",
};

/**
 * @typedef {object} RecordedRequest
 * @property {number} index          0-based, in arrival order
 * @property {string} method
 * @property {string} path
 * @property {Record<string, string>} headers  lowercased; the raw signature value is dropped
 * @property {string} body
 * @property {boolean} hasSignature
 * @property {number} paidAttempt    how many signed attempts had arrived, including this one
 * @property {number} status         what the server answered, or -1 if it hung
 * @property {string} [violation]    set when retry validation rejected it
 * @property {string} [signatureHash] sha256 of the raw PAYMENT-SIGNATURE header
 * @property {string} [acceptedAmount] the atomic amount the buyer paid against
 */

/**
 * @typedef {object} TestMerchantOptions
 * @property {string} [scenario]                  default "pay-once"
 * @property {object[]} [requirements]            defaults to a single Base USDC requirement
 * @property {number} [port]                      default 0 (ephemeral)
 * @property {string} [body]                      body returned on successful delivery
 * @property {string} [contentType]               default "application/json"
 * @property {string} [settlementId]              deterministic transaction id in PAYMENT-RESPONSE
 * @property {string} [resourceDescription]
 * @property {boolean} [validateRetries]          default true
 * @property {object[]} [rechallengeRequirements] offered instead once a signed attempt has
 *   arrived, so a re-challenge can genuinely differ from the first challenge
 */

/**
 * Copies request headers for the log, dropping the one value that must never be recorded.
 *
 * The signature is an authorization payload. SEC-003 keeps it out of logs and errors, and a
 * test fixture that quietly retained it would be the easiest place for it to leak into CI
 * output. Its *presence* and its decoded, non-sensitive fields are recorded instead.
 *
 * @param {import("node:http").IncomingHttpHeaders} headers
 */
function redactHeaders(headers) {
  /** @type {Record<string, string>} */
  const copy = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const flattened = Array.isArray(value) ? value.join(", ") : value;
    copy[name.toLowerCase()] =
      name.toLowerCase() === HEADER_PAYMENT_SIGNATURE ? "<redacted>" : flattened;
  }
  return copy;
}

/**
 * Reads the request body in full.
 *
 * @param {import("node:http").IncomingMessage} request
 * @returns {Promise<string>}
 */
async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * A one-way digest of the raw signature header.
 *
 * SEC-003 keeps the value itself out of every record, but a test still has to be able to
 * prove that two attempts carried *different* signatures — SPEC §6.7's "the old signature is
 * never reused". A hash settles that question without retaining anything sensitive.
 *
 * @param {string} value
 */
function digest(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

/**
 * Asserts the properties SPEC §6.7 and ADR-003 require of a paid retry.
 *
 * @param {import("node:http").IncomingMessage} request
 * @param {object[]} requirements every requirement this server may have offered
 * @returns {{ ok: true, acceptedAmount: string, signatureHash: string }
 *   | { ok: false, violation: string }}
 */
function validatePaidRetry(request, requirements) {
  const raw = request.headers[HEADER_PAYMENT_SIGNATURE];

  // Node collapses repeated headers into an array, which is exactly how a second
  // PAYMENT-SIGNATURE would arrive. ADR-003 permits precisely one per attempt.
  if (Array.isArray(raw)) {
    return { ok: false, violation: RETRY_VIOLATIONS.duplicateSignature };
  }
  if (typeof raw !== "string" || raw.includes(",")) {
    return { ok: false, violation: RETRY_VIOLATIONS.duplicateSignature };
  }

  let payload;
  try {
    payload = decodePaymentSignatureHeader(raw);
  } catch {
    return { ok: false, violation: RETRY_VIOLATIONS.undecodableSignature };
  }

  if (payload?.x402Version !== 2) {
    return { ok: false, violation: RETRY_VIOLATIONS.versionMismatch };
  }

  const accepted = payload.accepted;
  if (!accepted || typeof accepted !== "object") {
    return { ok: false, violation: RETRY_VIOLATIONS.unofferedRequirement };
  }

  // The buyer must pay against a requirement the merchant actually offered — not a
  // near-miss, and not one carried over from a previous challenge. The amount is part of
  // the match rather than a follow-up comparison, because a re-challenge may re-price the
  // same scheme/network/asset/recipient tuple and paying the *old* price is precisely the
  // defect this check exists to catch.
  const matches = requirements.filter(
    (requirement) =>
      requirement.scheme === accepted.scheme &&
      requirement.network === accepted.network &&
      requirement.asset === accepted.asset &&
      requirement.payTo === accepted.payTo,
  );
  if (matches.length === 0) {
    return { ok: false, violation: RETRY_VIOLATIONS.unofferedRequirement };
  }
  if (!matches.some((requirement) => requirement.amount === accepted.amount)) {
    return { ok: false, violation: RETRY_VIOLATIONS.amountMismatch };
  }

  if (!payload.payload || Object.keys(payload.payload).length === 0) {
    return { ok: false, violation: RETRY_VIOLATIONS.emptyPayload };
  }

  return {
    ok: true,
    acceptedAmount: String(accepted.amount),
    signatureHash: digest(raw),
    // Returned so a merchant configured with `facilitatorUrl` can forward the *decoded*
    // payload rather than re-decoding the header a second time.
    payload,
    accepted,
  };
}

/**
 * Verifies and settles one payment against a real x402 facilitator.
 *
 * ADR-002 puts `/verify` and `/settle` on the **merchant**, never on the buyer, so this
 * lives here and the buyer SDK still never learns a facilitator exists. It is what makes a
 * local test merchant's payment genuinely real: the merchant running on `127.0.0.1` does
 * not make the money fake — settlement does, and this settles on-chain.
 *
 * @param {string} facilitatorUrl
 * @param {object} paymentPayload decoded PAYMENT-SIGNATURE
 * @param {object} paymentRequirements the offer the buyer accepted
 * @returns {Promise<{ success: boolean, transaction: string, network: string,
 *   payer?: string, errorReason?: string }>}
 */
async function settleWithFacilitator(facilitatorUrl, paymentPayload, paymentRequirements) {
  const base = facilitatorUrl.replace(/\/+$/u, "");
  const body = JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements });
  const headers = { "content-type": "application/json" };

  const post = async (path) => {
    const response = await fetch(`${base}${path}`, { method: "POST", headers, body });
    const text = await response.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error(`${path} returned ${response.status}: ${text.slice(0, 300)}`);
    }
    if (!response.ok) {
      throw new Error(`${path} returned ${response.status}: ${text.slice(0, 300)}`);
    }
    return parsed;
  };

  // Verify first, exactly as a real merchant would: settling an invalid authorization
  // wastes the facilitator's gas and tells the buyer nothing useful.
  const verified = await post("/verify");
  if (verified.isValid === false || verified.valid === false) {
    return {
      success: false,
      transaction: "",
      network: paymentRequirements.network,
      errorReason: String(
        verified.invalidReason ?? verified.reason ?? "verification-failed",
      ),
    };
  }

  const settled = await post("/settle");
  return {
    success: settled.success !== false,
    transaction: String(settled.transaction ?? ""),
    network: String(settled.network ?? paymentRequirements.network),
    payer: settled.payer === undefined ? undefined : String(settled.payer),
    errorReason:
      settled.errorReason === undefined ? undefined : String(settled.errorReason),
  };
}

/**
 * Starts a deterministic test merchant.
 *
 * @param {TestMerchantOptions} [options]
 */
export async function createTestMerchant(options = {}) {
  const {
    scenario: scenarioName = "pay-once",
    requirements = [DEFAULT_REQUIREMENTS.base],
    port = 0,
    body = JSON.stringify({ ok: true, resource: "test-merchant" }),
    contentType = "application/json",
    settlementId = "0xtestmerchantsettlement000000000000000000000000000000000000000000",
    resourceDescription = "tx402 test merchant resource",
    validateRetries = true,
    rechallengeRequirements,
    // When set, `deliver` performs a *real* /verify and /settle against this facilitator
    // and reports the on-chain transaction in PAYMENT-RESPONSE. Unset (the default) the
    // merchant reports the deterministic `settlementId`, which is what every offline test
    // wants. See `settleWithFacilitator`.
    facilitatorUrl,
  } = options;

  const scenario = requireScenario(scenarioName);
  /** Every requirement the buyer may legitimately have paid against, across all challenges. */
  const acceptableRequirements = [...requirements, ...(rechallengeRequirements ?? [])];

  /** @type {RecordedRequest[]} */
  const requests = [];
  /** Sockets held open by the `hang` action; closed on shutdown so the process can exit. */
  const hung = new Set();
  let paidAttempts = 0;

  const server = createServer((request, response) => {
    void (async () => {
      const requestBody = await readBody(request);
      const hasSignature = request.headers[HEADER_PAYMENT_SIGNATURE] !== undefined;
      if (hasSignature) paidAttempts += 1;

      /** @type {RecordedRequest} */
      const record = {
        index: requests.length,
        method: request.method ?? "GET",
        path: request.url ?? "/",
        headers: redactHeaders(request.headers),
        body: requestBody,
        hasSignature,
        paidAttempt: paidAttempts,
        status: -1,
      };
      requests.push(record);

      const origin = `http://${request.headers.host ?? `127.0.0.1:${address.port}`}`;

      /** Decoded payload of this request's PAYMENT-SIGNATURE, if it carried one. */
      /** @type {{ payload: object, accepted: object } | undefined} */
      let settlementInput;

      /** @param {number} status @param {Record<string,string>} headers @param {string} payload */
      const send = (status, headers, payload) => {
        record.status = status;
        response.writeHead(status, { "content-type": contentType, ...headers });
        response.end(payload);
      };

      if (hasSignature && validateRetries) {
        const validation = validatePaidRetry(request, acceptableRequirements);
        if (!validation.ok) {
          record.violation = validation.violation;
          send(
            400,
            {},
            JSON.stringify({ error: "retry-validation", reason: validation.violation }),
          );
          return;
        }
        record.signatureHash = validation.signatureHash;
        record.acceptedAmount = validation.acceptedAmount;
        settlementInput = { payload: validation.payload, accepted: validation.accepted };
      }

      const action = scenario.next({ paidAttempt: paidAttempts, hasSignature });

      /**
       * Encodes the PAYMENT-REQUIRED challenge for this request.
       *
       * A re-challenge may offer different terms. SPEC §6.7 requires the buyer to parse the
       * new challenge from scratch, so the fixture has to be able to change.
       */
      const challengeHeader = () =>
        encodePaymentRequiredHeader({
          x402Version: 2,
          resource: { url: `${origin}${record.path}`, description: resourceDescription },
          accepts:
            paidAttempts > 0 && rechallengeRequirements !== undefined
              ? rechallengeRequirements
              : requirements,
        });

      switch (action.type) {
        case "challenge": {
          send(
            402,
            { [HEADER_PAYMENT_REQUIRED]: challengeHeader() },
            JSON.stringify({ error: "payment required" }),
          );
          return;
        }

        case "malformed-challenge": {
          // Not base64 at all: `!` and `~` are outside upstream's accepted alphabet, so this
          // fails at the first decode step rather than deeper in schema validation.
          send(
            402,
            { [HEADER_PAYMENT_REQUIRED]: "!!!not-base64~~~" },
            JSON.stringify({ error: "payment required" }),
          );
          return;
        }

        case "deliver": {
          /** @type {Record<string, string>} */
          const headers = {};

          // A real settlement, when one is configured. The buyer sees no difference — it
          // reads the same PAYMENT-RESPONSE header either way — which is the point: the
          // same code path is exercised whether the money is real or deterministic.
          if (
            facilitatorUrl !== undefined &&
            settlementInput !== undefined &&
            !action.omitPaymentResponse &&
            action.paymentResponse === undefined
          ) {
            let settled;
            try {
              settled = await settleWithFacilitator(
                facilitatorUrl,
                settlementInput.payload,
                settlementInput.accepted,
              );
            } catch (error) {
              // A facilitator that cannot be reached is a merchant-side failure, not a
              // buyer-side one, and the buyer must be told the settlement did not happen
              // rather than being handed a resource it did not pay for.
              record.settlementError = String(
                error instanceof Error ? error.message : error,
              );
              settled = {
                success: false,
                transaction: "",
                network: requirements[0].network,
                errorReason: "facilitator-unreachable",
              };
            }
            record.settlement = settled;
            headers[HEADER_PAYMENT_RESPONSE] = encodePaymentResponseHeader({
              success: settled.success,
              transaction: settled.transaction,
              network: settled.network,
              payer: settled.payer ?? requirements[0].payTo,
              ...(settled.errorReason === undefined
                ? {}
                : { errorReason: settled.errorReason }),
            });

            if (!settled.success) {
              // A failed settlement answers 402, and a 402 without PAYMENT-REQUIRED is not a
              // challenge — it is a malformed response. This fixture used to send one, so the
              // buyer reported `missing-header` and the facilitator's actual `errorReason`
              // (`transaction_simulation_failed`, say) never reached the operator. That cost
              // real debugging time at S13 and looked like a defect in tx402.
              //
              // Re-issuing the challenge alongside the settlement outcome is also what a real
              // merchant must do: it did not get paid, so it is still asking to be paid, and
              // the buyer needs terms to work from.
              headers[HEADER_PAYMENT_REQUIRED] = challengeHeader();
            }

            send(settled.success ? (action.status ?? 200) : 402, headers, body);
            return;
          }

          if (!action.omitPaymentResponse) {
            headers[HEADER_PAYMENT_RESPONSE] =
              action.paymentResponse === "corrupt"
                ? "!!!not-base64~~~"
                : encodePaymentResponseHeader({
                    success: action.paymentResponse !== "unsuccessful",
                    transaction: settlementId,
                    network: requirements[0].network,
                    payer: requirements[0].payTo,
                  });
          }
          send(action.status ?? 200, headers, body);
          return;
        }

        case "redirect": {
          send(action.status ?? 307, { location: action.location ?? "/" }, "");
          return;
        }

        case "status": {
          send(
            action.status ?? 500,
            {},
            JSON.stringify({ error: action.reason ?? "scenario-error" }),
          );
          return;
        }

        case "hang": {
          // Deliberately never respond. The socket is tracked so close() can free it —
          // otherwise the test process would not exit.
          hung.add(response);
          response.on("close", () => hung.delete(response));
          return;
        }

        default:
          send(500, {}, JSON.stringify({ error: `unhandled action ${action.type}` }));
      }
    })();
  });

  server.listen(port, "127.0.0.1");
  await once(server, "listening");

  const address = /** @type {import("node:net").AddressInfo} */ (server.address());
  const url = `http://127.0.0.1:${address.port}`;

  return {
    url,
    origin: url,
    port: address.port,
    scenario: scenarioName,
    requirements,
    /** Every request seen, in order. The signature header value is redacted (SEC-003). */
    requests,
    /** Requests that carried a PAYMENT-SIGNATURE. */
    get paidRequests() {
      return requests.filter((entry) => entry.hasSignature);
    },
    /** Retry-validation violations, if any. Empty is the expected state. */
    get violations() {
      return requests.filter((entry) => entry.violation).map((entry) => entry.violation);
    },
    reset() {
      requests.length = 0;
      paidAttempts = 0;
    },
    async close() {
      for (const held of hung) held.destroy();
      hung.clear();
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    },
  };
}
