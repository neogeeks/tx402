/**
 * CLI exit codes and the mapping from tx402's error taxonomy onto them (SPEC §11).
 *
 * SPEC §11 fixes nine exit codes; SPEC §8 fixes fifteen error codes. Collapsing fifteen onto
 * nine is an implementation decision, and it is made here, once, in a table — rather than in
 * a `switch` somewhere in the render path — because a script's `if [ $? -eq 3 ]` is a public
 * API. Changing a row silently changes the meaning of somebody's shell script.
 *
 * The grouping principle is **what the operator has to change to make it work**:
 *
 *  - `2` usage/config — the invocation or the environment is wrong. Fix the command.
 *  - `3` policy — tx402's own guardrail refused. Raise the cap or accept the refusal.
 *  - `4` liquidity — the wallet cannot cover it. Fund it.
 *  - `5` protocol — this client and this merchant cannot agree on the challenge. Nothing
 *    the operator does locally helps; the merchant or the SDK has to change. `CLOCK_SKEW`
 *    sits here rather than under config because it is raised while validating the
 *    challenge's own timestamp, alongside the other challenge-validation failures.
 *  - `6` signer — the key or the signing device failed.
 *  - `7` transport — the network failed. Retryable by caller policy.
 *  - `8` ambiguous payment — money may have moved and tx402 cannot tell. **Never retry
 *    blindly on this one**; it is its own code precisely so a script can stop.
 *  - `9` resource failure — the resource was not delivered. This one covers both halves of a
 *    range and the halves want opposite actions, so the code alone is not enough to act on:
 *    `context.paid` is `false` when the merchant refused the settlement or exhausted the
 *    permitted attempts (no money moved, retrying is safe) and `true` when the payment
 *    settled and delivery then failed (do not retry). The CLI branches on `paid`, never on
 *    the exit code, and a `settlement` object is emitted only in the second case.
 */

import { TX402_ERROR_CODES, isTx402Error, type Tx402ErrorCode } from "../core/errors.js";

/** Normative — SPEC §11. `1` is deliberately unused: it is Node's own crash code. */
export const EXIT_CODES = {
  success: 0,
  usage: 2,
  policy: 3,
  liquidity: 4,
  protocol: 5,
  signer: 6,
  transport: 7,
  ambiguousPayment: 8,
  resourceFailure: 9,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

/**
 * Every error code, mapped. Exhaustive by construction: the `Record` type below fails to
 * compile if a new error code is added to SPEC §8 without being classified here, which is
 * the only reliable way to stop a new error silently exiting as an unclassified failure.
 */
export const EXIT_CODE_BY_ERROR: Record<Tx402ErrorCode, ExitCode> = {
  [TX402_ERROR_CODES.configInvalid]: EXIT_CODES.usage,
  [TX402_ERROR_CODES.reservedHeader]: EXIT_CODES.usage,
  [TX402_ERROR_CODES.nonReplayable]: EXIT_CODES.usage,

  [TX402_ERROR_CODES.policyBudget]: EXIT_CODES.policy,
  [TX402_ERROR_CODES.policyDomain]: EXIT_CODES.policy,

  [TX402_ERROR_CODES.liquidity]: EXIT_CODES.liquidity,

  [TX402_ERROR_CODES.protocolUnsupported]: EXIT_CODES.protocol,
  [TX402_ERROR_CODES.schemeUnsupported]: EXIT_CODES.protocol,
  [TX402_ERROR_CODES.paymentRequiredInvalid]: EXIT_CODES.protocol,
  [TX402_ERROR_CODES.clockSkew]: EXIT_CODES.protocol,

  [TX402_ERROR_CODES.signer]: EXIT_CODES.signer,
  [TX402_ERROR_CODES.transport]: EXIT_CODES.transport,
  [TX402_ERROR_CODES.paymentAmbiguous]: EXIT_CODES.ambiguousPayment,

  [TX402_ERROR_CODES.resourceDelivery]: EXIT_CODES.resourceFailure,
  // Reachable only *after* the signature has been transmitted (SPEC §6.1, ADR-014): the
  // block stops the follow-up request, not the original one, so money may already have
  // moved and the reservation is retained. That is exactly what `8` means, and ADR-014
  // said so in prose while the table said `9`. Corrected at S15b alongside O52, which made
  // this error reachable from the high-level client at all.
  [TX402_ERROR_CODES.redirectBlocked]: EXIT_CODES.ambiguousPayment,
};

/** Raised for a bad invocation, before the SDK is reached. Always exit code 2. */
export class UsageError extends Error {
  override readonly name = "UsageError";
}

/**
 * The exit code for any thrown value.
 *
 * An unrecognised error exits `2` rather than `1`: reaching here means the CLI was asked to
 * do something it could not even classify, which is a usage problem from the caller's side,
 * and `1` is reserved for the runtime crashing under us.
 */
export function exitCodeFor(error: unknown): ExitCode {
  if (error instanceof UsageError) return EXIT_CODES.usage;
  if (isTx402Error(error)) return EXIT_CODE_BY_ERROR[error.code];
  return EXIT_CODES.usage;
}
