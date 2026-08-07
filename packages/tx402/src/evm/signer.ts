/**
 * `EvmSigner` (SPEC §7.1) adapted to upstream's `ClientEvmSigner` (ADR-010 decision 5).
 *
 * The adapter is not a shim. It is the last point at which tx402 can see what is about to be
 * signed, and it is the only point at which the typed data upstream produced can be compared
 * against what policy actually approved. So it does both:
 *
 *  1. **Bridges the shapes.** SPEC's contract is `getAddress(): Promise<0x…>`; upstream reads
 *     a synchronous `address` property. The address is resolved once per signer and cached.
 *  2. **Enforces the plan.** Every field of the EIP-712 message is checked against the
 *     approved requirement before the caller's signer is invoked: chain, token contract,
 *     payer, recipient, amount, and expiry. A mismatch raises `SignerError` and no signature
 *     is requested. This is what makes SPEC §6.6's "must never exceed the merchant bound"
 *     an assertion rather than a comment.
 *  3. **Presents it (SPEC §6.6).** The caller's signer receives the human-readable summary
 *     beside the typed data, so an external wallet can show a person what they approve.
 *
 * Nothing here logs, stores, or returns a signature beyond handing it back to upstream.
 */

import { SignerError, type Tx402ErrorContext } from "../core/errors.js";
import type {
  EvmSigner,
  EvmSignerPresentation,
  EvmTypedDataField,
} from "../core/signers.js";

/** What policy approved, restated in the terms the EIP-712 message uses. */
export interface EvmAuthorizationPlan {
  readonly chainId: number;
  /** Manifest token address. The EIP-712 `verifyingContract` must equal this. */
  readonly verifyingContract: string;
  readonly domainName: string;
  readonly domainVersion: string;
  readonly from: `0x${string}`;
  readonly to: string;
  readonly valueAtomic: string;
  /**
   * `min(60, merchant maxTimeoutSeconds)` (SPEC §6.6).
   *
   * The permitted window is derived from this **at assertion time**, not handed in
   * pre-computed. Upstream reads its own clock inside `createPaymentPayload`; a bound
   * computed even a moment earlier can sit a whole second behind the `validBefore` upstream
   * produces, which would reject a perfectly valid authorization whenever the two reads
   * straddle a second boundary. Reading the clock after upstream has written the message
   * makes `validBefore <= now + lifetime` true by construction rather than by luck.
   *
   * That reading uses `Date.now()` rather than the client's injectable `Tx402Clock`, which is
   * the one place in the SDK where the real clock is deliberate: the value being checked was
   * produced by upstream from `Date.now()`, so comparing it against an injected clock would
   * compare two unrelated timelines and reintroduce exactly the failure this avoids.
   */
  readonly lifetimeSeconds: number;
}

/** Observations the adapter records for the caller. Never includes the signature. */
export interface EvmSigningRecord {
  signCount: number;
  expiresAtEpochMs: number;
}

const EXPECTED_PRIMARY_TYPE = "TransferWithAuthorization";
const NONCE_PATTERN = /^0x[0-9a-fA-F]{64}$/u;

/** Address resolution is cached per signer object, not per client (ADR-010, amended S5). */
const addressCache = new WeakMap<EvmSigner, Promise<`0x${string}`>>();

function signerFailure(
  message: string,
  causeCategory: string,
  context: Tx402ErrorContext,
  cause?: unknown,
): SignerError {
  return new SignerError(message, {
    context,
    details: { signerKind: "evm", causeCategory },
    ...(cause === undefined ? {} : { cause }),
  });
}

/**
 * Resolves and caches a signer's address.
 *
 * ADR-010 decision 5 said "resolve once at client construction". `createTx402Client` is
 * synchronous by SPEC §4.1, so construction cannot await anything; the resolution therefore
 * happens on first use and is memoized for the signer's lifetime. The property upstream
 * reads is still a plain synchronous string, which was the point of the decision.
 */
export async function resolveEvmAddress(
  signer: EvmSigner,
  context: Tx402ErrorContext,
): Promise<`0x${string}`> {
  const cached = addressCache.get(signer);
  if (cached !== undefined) return cached;

  const pending = (async () => {
    const address = await signer.getAddress();
    if (typeof address !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(address)) {
      throw signerFailure(
        "Signer returned a malformed EVM address",
        "address-unavailable",
        context,
      );
    }
    return address;
  })();

  addressCache.set(signer, pending);
  try {
    return await pending;
  } catch (error) {
    // A transient failure must not poison the signer for the process's lifetime.
    addressCache.delete(signer);
    throw error instanceof SignerError
      ? error
      : signerFailure(
          "Signer address lookup failed",
          "address-unavailable",
          context,
          error,
        );
  }
}

function requireString(value: unknown, label: string, context: Tx402ErrorContext): string {
  if (typeof value !== "string") {
    throw signerFailure(`Authorization ${label} is not a string`, "plan-mismatch", context);
  }
  return value;
}

function requireQuantity(
  value: unknown,
  label: string,
  context: Tx402ErrorContext,
): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value)) return BigInt(value);
  throw signerFailure(
    `Authorization ${label} is not an integer quantity`,
    "plan-mismatch",
    context,
  );
}

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

/** Upstream types arrive as `Record<string, unknown>`; narrow before forwarding them on. */
function narrowTypes(
  types: Record<string, unknown>,
  context: Tx402ErrorContext,
): Record<string, readonly EvmTypedDataField[]> {
  const narrowed: Record<string, readonly EvmTypedDataField[]> = {};
  for (const [name, members] of Object.entries(types)) {
    if (
      !Array.isArray(members) ||
      members.some(
        (member) =>
          typeof member !== "object" ||
          member === null ||
          typeof (member as EvmTypedDataField).name !== "string" ||
          typeof (member as EvmTypedDataField).type !== "string",
      )
    ) {
      throw signerFailure(
        "Authorization typed-data definition is malformed",
        "plan-mismatch",
        context,
      );
    }
    narrowed[name] = members as EvmTypedDataField[];
  }
  return narrowed;
}

/**
 * The upstream-facing signer for exactly one authorization.
 *
 * A fresh adapter per payment is deliberate: the plan it enforces describes one requirement,
 * one amount, and one expiry, so it cannot be reused for a different payment even by
 * accident.
 */
export function toClientEvmSigner(input: {
  readonly signer: EvmSigner;
  readonly address: `0x${string}`;
  readonly plan: EvmAuthorizationPlan;
  readonly presentation: Omit<EvmSignerPresentation, "expiresAt">;
  readonly record: EvmSigningRecord;
  readonly context: Tx402ErrorContext;
}): {
  readonly address: `0x${string}`;
  signTypedData(message: {
    domain: Record<string, unknown>;
    types: Record<string, unknown>;
    primaryType: string;
    message: Record<string, unknown>;
  }): Promise<`0x${string}`>;
} {
  const { signer, address, plan, presentation, record, context } = input;

  return {
    address,
    async signTypedData(typedData) {
      if (record.signCount > 0) {
        // ADR-003: one authorization per attempt. A scheme that asked twice would mean two
        // signatures existed for one reservation.
        throw signerFailure(
          "Scheme requested more than one signature for a single authorization",
          "duplicate-signature-request",
          context,
        );
      }

      const { domain, message, primaryType } = typedData;
      if (primaryType !== EXPECTED_PRIMARY_TYPE) {
        throw signerFailure(
          `Unexpected EIP-712 primary type ${String(primaryType)}`,
          "plan-mismatch",
          context,
        );
      }
      if (domain.chainId !== plan.chainId) {
        throw signerFailure(
          "EIP-712 domain chain ID does not match the approved network",
          "plan-mismatch",
          context,
        );
      }
      if (
        !sameAddress(
          requireString(domain.verifyingContract, "verifyingContract", context),
          plan.verifyingContract,
        )
      ) {
        throw signerFailure(
          "EIP-712 verifying contract is not the manifest asset",
          "plan-mismatch",
          context,
        );
      }
      if (domain.name !== plan.domainName || domain.version !== plan.domainVersion) {
        throw signerFailure(
          "EIP-712 domain does not match the offered token domain",
          "plan-mismatch",
          context,
        );
      }
      if (!sameAddress(requireString(message.from, "from", context), plan.from)) {
        throw signerFailure(
          "Authorization payer is not the configured signer",
          "plan-mismatch",
          context,
        );
      }
      if (!sameAddress(requireString(message.to, "to", context), plan.to)) {
        throw signerFailure(
          "Authorization recipient is not the merchant payout address",
          "plan-mismatch",
          context,
        );
      }
      if (requireQuantity(message.value, "value", context) !== BigInt(plan.valueAtomic)) {
        throw signerFailure(
          "Authorization amount is not the approved amount",
          "plan-mismatch",
          context,
        );
      }
      if (requireQuantity(message.validAfter, "validAfter", context) !== 0n) {
        throw signerFailure(
          "Authorization is not valid immediately",
          "plan-mismatch",
          context,
        );
      }
      const validBefore = requireQuantity(message.validBefore, "validBefore", context);
      // Read now, after upstream has produced the message, so this clock is never behind the
      // one upstream used. See `lifetimeSeconds` on the plan for why that matters.
      const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
      if (
        validBefore > nowSeconds + BigInt(plan.lifetimeSeconds) ||
        validBefore <= nowSeconds
      ) {
        throw signerFailure(
          "Authorization lifetime is outside the approved window",
          "plan-mismatch",
          context,
        );
      }
      if (!NONCE_PATTERN.test(requireString(message.nonce, "nonce", context))) {
        // SPEC §6.6 requires a 32-byte nonce. Upstream generates one; this proves it did.
        throw signerFailure(
          "Authorization nonce is not 32 bytes",
          "plan-mismatch",
          context,
        );
      }

      record.signCount += 1;
      record.expiresAtEpochMs = Number(validBefore) * 1000;

      const request = {
        domain,
        types: narrowTypes(typedData.types, context),
        primaryType,
        message,
        presentation: Object.freeze({
          ...presentation,
          expiresAt: new Date(record.expiresAtEpochMs).toISOString(),
        }),
      };

      let signature: `0x${string}`;
      try {
        signature = await signer.signTypedData(request);
      } catch (error) {
        // The signer's own message may embed a key path, a device serial, or the payload.
        throw signerFailure(
          "Signer rejected the authorization",
          "signer-rejected",
          context,
          error,
        );
      }
      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/u.test(signature)) {
        throw signerFailure(
          "Signer returned a malformed signature",
          "malformed-signature",
          context,
        );
      }
      return signature;
    },
  };
}
