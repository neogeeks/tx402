/**
 * SPEC §6.7's completion table, as a pure function (M6).
 *
 * What happens to a reservation after a signature has been transmitted is the single most
 * consequential decision in the SDK, and it is scattered across five clauses of §6.7. This
 * module states it once, as data-in / data-out, for three reasons:
 *
 *  1. **It is the rule Python must reproduce exactly.** `completion.paid-attempt`
 *     conformance vectors drive this function directly, so S10 inherits the table rather
 *     than re-deriving it from prose.
 *  2. **The ordering of the branches is normative.** A 402 is checked before a 5xx check
 *     could ever see it, and the `maxPaidAttempts` boundary is checked *inside* the 402
 *     branch — not as a separate loop guard — so exhaustion is a typed terminal outcome
 *     rather than a loop that quietly stops.
 *  3. **It keeps the money rule out of the control flow.** In `client.ts` the disposition
 *     is looked up and then obeyed; there is no `if` in the request path that can drift
 *     from the specification independently.
 *
 * The asymmetry the table encodes: **before** a signature reaches the merchant, a failure
 * releases the reservation. **After** it does, only evidence that no settlement occurred
 * may release it. A fresh 402 for the same resource is exactly that evidence — the merchant
 * is still asking to be paid — which is why a re-challenge releases while a 5xx retains.
 * Releasing on anything ambiguous would let the same money be spent twice against the
 * hourly cap.
 *
 * **S15b (ADR-016) made that asymmetry actually hold.** Until then the status line was
 * consulted first, so a 403 carrying a successful `PAYMENT-RESPONSE` released the
 * reservation and reported the call unpaid — the audit's O44. Settlement evidence is now
 * read on every status and outranks the status line, and a present-but-undecodable header
 * is its own fourth evidence value rather than being folded into "absent".
 */

import { TX402_ERROR_CODES, type Tx402ErrorCode } from "./errors.js";

/** Raised when the merchant re-challenges on the last permitted signed attempt. */
export const MAX_PAID_ATTEMPTS_REASON = "max-paid-attempts-exhausted";

/**
 * What the merchant's PAYMENT-RESPONSE proves about settlement.
 *
 * Four values, not three. Until S15b `"unknown"` covered both an absent header and one
 * that does not decode, and the audit's O53 showed why that conflation is wrong: SPEC §6.7
 * accepts *missing* metadata because the pinned upstream protocol marks the header
 * optional, and says a 2xx is paid-success "only when any required upstream
 * PAYMENT-RESPONSE parses successfully". A header the merchant chose not to send and a
 * header the merchant sent in a form tx402 cannot read are different facts, and only the
 * first is one the specification forgives. See ADR-016.
 *
 * - `"success"` — decoded, and `success: true`.
 * - `"unsuccessful"` — decoded, and `success: false`. The merchant says it did not settle.
 * - `"absent"` — no header at all. Permitted; a diagnostic warning is emitted.
 * - `"malformed"` — a header is present and does not decode. A protocol violation, and
 *   never evidence in either direction, so it can neither commit nor release.
 */
export type SettlementEvidence = "success" | "unsuccessful" | "absent" | "malformed";

/** How the one signature-bearing request of an attempt ended. */
export type PaidAttemptResult =
  /** The merchant answered. `status` is that answer. */
  | {
      readonly kind: "response";
      readonly status: number;
      readonly settlement: SettlementEvidence;
    }
  /** The answer was a cross-origin redirect, refused by SEC-005 after transmission. */
  | { readonly kind: "redirect-blocked" }
  /** No answer: connection failure, reset, or the tx402 deadline expiring. */
  | { readonly kind: "transport-failure" };

export interface PaidAttemptInput {
  /** 1-based, counting signed retries only — never the initial unpaid request. */
  readonly attempt: number;
  /** `policy.maxPaidAttempts`, already validated to 1–3 (SPEC §4.3). */
  readonly maxPaidAttempts: number;
  readonly result: PaidAttemptResult;
}

/**
 * Terminal, with the outcome unknown. The reservation is held to its TTL.
 *
 * `errorCode` is not always `TX402_PAYMENT_AMBIGUOUS`. The *kind* is the money
 * disposition; the *code* is the public error identity, and SPEC §6.1 names a specific one
 * for a cross-origin redirect. Keeping them as two fields is what let S15b fix O52 without
 * touching what happens to the money.
 */
export interface AmbiguousDisposition {
  readonly kind: "ambiguous";
  readonly reservation: "retained";
  readonly errorCode: Tx402ErrorCode;
  readonly causeCategory: string;
}

/** What the request path must do with the reservation, and what it must report. */
export type PaidAttemptDisposition =
  /** Settlement stands. Commit the reservation and return the response. */
  | { readonly kind: "commit"; readonly reservation: "committed" }
  /** A fresh challenge with attempts remaining. Release, re-plan, re-sign. */
  | { readonly kind: "rechallenge"; readonly reservation: "released" }
  /** Terminal, with proof that no settlement occurred. */
  | {
      readonly kind: "failed";
      readonly reservation: "released";
      readonly errorCode: Tx402ErrorCode;
      readonly reason: string;
    }
  /**
   * The merchant's own metadata reports a successful settlement and the resource response
   * is unusable (SPEC §5.3). The money moved, so the spend is **committed** and the caller
   * is told `paid: true` — the one disposition that both commits and throws.
   */
  | {
      readonly kind: "paid-undelivered";
      readonly reservation: "committed";
      readonly errorCode: Tx402ErrorCode;
      readonly reason: string;
    }
  | AmbiguousDisposition;

/** SPEC §5.3: settlement succeeded, resource unusable. Recorded in ADR-016. */
export const SETTLED_RESOURCE_UNUSABLE_REASON = "settlement-succeeded-resource-unusable";

/** ADR-016: a present PAYMENT-RESPONSE that does not decode is never evidence. */
export const MALFORMED_SETTLEMENT_CAUSE = "settlement-metadata-unparseable";

const COMMIT: PaidAttemptDisposition = Object.freeze({
  kind: "commit",
  reservation: "committed",
});

const RECHALLENGE: PaidAttemptDisposition = Object.freeze({
  kind: "rechallenge",
  reservation: "released",
});

function failed(reason: string): PaidAttemptDisposition {
  return Object.freeze({
    kind: "failed",
    reservation: "released",
    errorCode: TX402_ERROR_CODES.resourceDelivery,
    reason,
  });
}

function paidUndelivered(reason: string): PaidAttemptDisposition {
  return Object.freeze({
    kind: "paid-undelivered",
    reservation: "committed",
    errorCode: TX402_ERROR_CODES.resourceDelivery,
    reason,
  });
}

function ambiguous(
  causeCategory: string,
  errorCode: Tx402ErrorCode = TX402_ERROR_CODES.paymentAmbiguous,
): AmbiguousDisposition {
  return Object.freeze({
    kind: "ambiguous",
    reservation: "retained",
    errorCode,
    causeCategory,
  });
}

function isSuccessStatus(status: number): boolean {
  return status >= 200 && status < 300;
}

/**
 * A transmission that never completed is ambiguous whatever the cause, and the type says
 * so — the request path gets a `causeCategory` without a fallback branch that could never
 * run and could never be covered.
 */
export function classifyPaidAttempt(
  input: PaidAttemptInput & {
    readonly result: { readonly kind: "redirect-blocked" | "transport-failure" };
  },
): AmbiguousDisposition;
/**
 * Decides one signed attempt's outcome (SPEC §6.7). Pure: no clock, no I/O, no state.
 *
 * Branch order is part of the contract and is asserted by the conformance vectors.
 */
export function classifyPaidAttempt(input: PaidAttemptInput): PaidAttemptDisposition;
export function classifyPaidAttempt(input: PaidAttemptInput): PaidAttemptDisposition {
  const { result } = input;

  // Nothing came back. The signature is on the wire either way, so this is the canonical
  // ambiguous case — the one SPEC §6.7 names explicitly.
  if (result.kind === "transport-failure") return ambiguous("transport-after-signature");

  // SEC-005 stopped the *follow-up*, not the original transmission. The merchant already
  // has the signature and may well have settled against it, so the reservation is retained
  // — but the public error is the one SPEC §6.1 names, not a generic ambiguity (O52).
  if (result.kind === "redirect-blocked")
    return ambiguous("redirect-blocked", TX402_ERROR_CODES.redirectBlocked);

  // **Settlement evidence outranks the status line** (SPEC §5.3, O44). A merchant that
  // reports a successful settlement has said the money moved; whether it then managed to
  // hand over the resource is a separate fact. Releasing the reservation here would give
  // back budget for a payment that really happened, and an autonomous caller would be free
  // to pay for the same thing again. This is checked before every status branch precisely
  // so no status can reach a branch that releases.
  if (result.settlement === "success" && !isSuccessStatus(result.status))
    return paidUndelivered(SETTLED_RESOURCE_UNUSABLE_REASON);

  // A present header that does not decode is a protocol violation and is evidence of
  // nothing (ADR-016). It cannot commit — SPEC §6.7 makes parsing a precondition of
  // paid-success — and it must not release, because the merchant plainly attempted to
  // report a settlement. Retention is the only disposition left, on any status.
  if (result.settlement === "malformed") return ambiguous(MALFORMED_SETTLEMENT_CAUSE);

  if (result.status === 402) {
    // Checked here rather than as a loop guard: an exhausted budget of attempts must be a
    // typed terminal error, and this is the only place that knows it was a re-challenge
    // that exhausted it.
    return input.attempt < input.maxPaidAttempts
      ? RECHALLENGE
      : failed(MAX_PAID_ATTEMPTS_REASON);
  }

  // A server error is not a refusal. It says the merchant could not finish telling tx402
  // what happened, which is not the same as saying nothing happened.
  if (result.status >= 500) return ambiguous("server-error");

  // A same-origin redirect reaches here because v0.1 does not follow one (SPEC §6.1's
  // exception is not implemented — see the open item). A redirect is *not* a refusal: the
  // merchant may have settled and be pointing at the delivered resource. Releasing on it
  // would give back budget for money that moved, so it is ambiguous rather than failed.
  if (result.status >= 300 && result.status < 400)
    return ambiguous("redirect-not-followed");

  // Any other non-2xx is the merchant declining the request outright, *without* claiming a
  // settlement — the success case was taken above. Declining is a statement that it did
  // not settle.
  if (!isSuccessStatus(result.status)) return failed("paid-request-rejected");

  // A 2xx whose own PAYMENT-RESPONSE says `success: false` is a merchant contradicting
  // itself. tx402 believes the payment metadata, not the status line.
  if (result.settlement === "unsuccessful") return failed("settlement-unsuccessful");

  // `"success"` and `"absent"` both land here. Absent is permitted because the pinned
  // upstream protocol marks the header optional (SPEC §6.7); a warning is emitted at the
  // read site rather than changing the money.
  return COMMIT;
}
