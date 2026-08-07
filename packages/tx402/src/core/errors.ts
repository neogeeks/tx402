/**
 * The complete tx402 error taxonomy (SPEC §8).
 *
 * Frozen at M0. The fifteen codes and fifteen class names here are a cross-language
 * contract: `packages/tx402-python/src/tx402/errors.py` declares exactly the same set, and
 * the conformance vector `errors.taxonomy.frozen` fails if either drifts (ADR-005).
 *
 * Two rules that are easy to get wrong, both recorded in ADR-011:
 *
 *  - **`retryable` is derived, not chosen.** SPEC §8's `Retryable` column has six distinct
 *    values, not two, so the boolean alone cannot carry it. The full classification lives
 *    in `retryability`; `retryable` is true only for `caller-policy`, meaning "safe to
 *    retry as-is, without the caller first changing something". `InsufficientLiquidityError`
 *    is retryable *after funding*, `ClockSkewError` *after correction* — neither is
 *    automatically retryable, so both report `retryable === false`.
 *
 *  - **`context` and `details` are different things.** `context` is the fixed diagnostic
 *    envelope from SPEC §8 (`requestId`, `phase`, …), identical across every error.
 *    `details` carries what the §8 "required context" column asks each individual error to
 *    report. Splitting them keeps `Tx402ErrorContext` closed, which is what lets the
 *    redaction snapshot tests (SEC-003) enumerate it exhaustively.
 *
 * Nothing in this module ever holds a signature, a key, an authorization payload, a header
 * value, or a request body. `details` keys are frozen per error code below and are all
 * either identifiers, atomic amounts, or category labels.
 */

/* ------------------------------------------------------------------------------------- */
/* Codes                                                                                   */
/* ------------------------------------------------------------------------------------- */

/**
 * Every tx402 error code (SPEC §8).
 *
 * Adding a code is a minor release; changing or removing one is a breaking change
 * (SPEC §15). Callers are expected to switch on these rather than on class identity,
 * because the code is what survives a serialization boundary.
 */
export const TX402_ERROR_CODES = {
  configInvalid: "TX402_CONFIG_INVALID",
  reservedHeader: "TX402_RESERVED_HEADER",
  nonReplayable: "TX402_NON_REPLAYABLE",
  protocolUnsupported: "TX402_PROTOCOL_UNSUPPORTED",
  schemeUnsupported: "TX402_SCHEME_UNSUPPORTED",
  paymentRequiredInvalid: "TX402_PAYMENT_REQUIRED_INVALID",
  policyBudget: "TX402_POLICY_BUDGET",
  policyDomain: "TX402_POLICY_DOMAIN",
  liquidity: "TX402_LIQUIDITY",
  signer: "TX402_SIGNER",
  clockSkew: "TX402_CLOCK_SKEW",
  paymentAmbiguous: "TX402_PAYMENT_AMBIGUOUS",
  resourceDelivery: "TX402_RESOURCE_DELIVERY",
  redirectBlocked: "TX402_REDIRECT_BLOCKED",
  transport: "TX402_TRANSPORT",
} as const;

export type Tx402ErrorCode = (typeof TX402_ERROR_CODES)[keyof typeof TX402_ERROR_CODES];

/**
 * SPEC §8's `Retryable` column, verbatim rather than collapsed to a boolean.
 *
 * - `no` — the request cannot succeed without a different request.
 * - `conditional` — may succeed later once an external precondition changes (funding,
 *   signer availability). Never retried automatically.
 * - `after-correction` — the caller must fix something first (clock skew).
 * - `no-automatic-retry` — retrying risks paying twice. Requires an idempotency strategy.
 * - `app-dependent` — money moved; whether to retry is a business decision.
 * - `caller-policy` — a plain transport failure. The only classification that is
 *   automatically retryable.
 */
export type Tx402Retryability =
  | "no"
  | "conditional"
  | "after-correction"
  | "no-automatic-retry"
  | "app-dependent"
  | "caller-policy";

/** Request-execution phase (SPEC §8), aligned to the SPEC §6 state machine. */
export type Tx402Phase =
  "initial" | "parse" | "policy" | "route" | "sign" | "retry" | "complete";

/**
 * The fixed diagnostic envelope carried by every tx402 error (SPEC §8).
 *
 * Deliberately closed. Per-error data goes in `details`.
 */
export interface Tx402ErrorContext {
  requestId: string;
  phase: Tx402Phase;
  network?: string;
  scheme?: string;
  amountAtomic?: string;
  assetId?: string;
  /**
   * `"unknown"` is a real third state, not a missing boolean — it is precisely what an
   * ambiguous outcome reports (SPEC §6.7).
   */
  paid?: boolean | "unknown";
  reservationId?: string;
}

/** Redaction-safe per-error data. Values are identifiers, atomic amounts, or categories. */
export type Tx402ErrorDetails = Readonly<Record<string, unknown>>;

/* ------------------------------------------------------------------------------------- */
/* Taxonomy table                                                                          */
/* ------------------------------------------------------------------------------------- */

/** One frozen row of SPEC §8. */
export interface Tx402ErrorDescriptor {
  readonly code: Tx402ErrorCode;
  readonly className: string;
  readonly retryability: Tx402Retryability;
  /** Derived from `retryability`. See {@link isRetryable}. */
  readonly retryable: boolean;
  /** Keys the SPEC §8 "required context" column obliges this error to report. */
  readonly requiredDetails: readonly string[];
}

/**
 * The single derivation rule for `retryable` (ADR-011).
 *
 * Only a transport failure can be retried without the caller doing something first.
 */
function isRetryable(retryability: Tx402Retryability): boolean {
  return retryability === "caller-policy";
}

function descriptor(
  code: Tx402ErrorCode,
  className: string,
  retryability: Tx402Retryability,
  requiredDetails: readonly string[],
): Tx402ErrorDescriptor {
  return Object.freeze({
    code,
    className,
    retryability,
    retryable: isRetryable(retryability),
    requiredDetails: Object.freeze([...requiredDetails]),
  });
}

/**
 * SPEC §8 as data, in specification order.
 *
 * The conformance vector compares against this table field for field, so a change here
 * that is not mirrored in Python and in the fixture fails CI in three places at once.
 */
export const TX402_ERROR_TAXONOMY: readonly Tx402ErrorDescriptor[] = Object.freeze([
  descriptor(TX402_ERROR_CODES.configInvalid, "ConfigurationError", "no", [
    "configPath",
    "reason",
  ]),
  descriptor(TX402_ERROR_CODES.reservedHeader, "ReservedHeaderError", "no", ["headerName"]),
  descriptor(TX402_ERROR_CODES.nonReplayable, "NonReplayableRequestError", "no", [
    "reason",
  ]),
  descriptor(TX402_ERROR_CODES.protocolUnsupported, "UnsupportedProtocolError", "no", [
    "observedVersion",
    "supportedVersions",
  ]),
  descriptor(TX402_ERROR_CODES.schemeUnsupported, "UnsupportedSchemeError", "no", [
    "offeredSchemes",
    "offeredNetworks",
  ]),
  descriptor(
    TX402_ERROR_CODES.paymentRequiredInvalid,
    "InvalidPaymentRequiredError",
    "no",
    ["reason", "schemaPath"],
  ),
  descriptor(TX402_ERROR_CODES.policyBudget, "BudgetExceededError", "no", [
    "requestedAtomic",
    "capAtomic",
    "committedAtomic",
    "reservedAtomic",
    "capKind",
  ]),
  descriptor(TX402_ERROR_CODES.policyDomain, "DomainNotAllowedError", "no", [
    "normalizedHost",
  ]),
  descriptor(TX402_ERROR_CODES.liquidity, "InsufficientLiquidityError", "conditional", [
    "deficits",
  ]),
  descriptor(TX402_ERROR_CODES.signer, "SignerError", "conditional", [
    "signerKind",
    "causeCategory",
  ]),
  descriptor(TX402_ERROR_CODES.clockSkew, "ClockSkewError", "after-correction", [
    "observedSkewMs",
    "thresholdMs",
  ]),
  descriptor(
    TX402_ERROR_CODES.paymentAmbiguous,
    "AmbiguousPaymentError",
    "no-automatic-retry",
    ["reservationExpiresAtEpochMs", "causeCategory"],
  ),
  descriptor(TX402_ERROR_CODES.resourceDelivery, "ResourceDeliveryError", "app-dependent", [
    "status",
    "reason",
  ]),
  descriptor(TX402_ERROR_CODES.redirectBlocked, "PaidRedirectBlockedError", "no", [
    "fromOrigin",
    "toOrigin",
  ]),
  descriptor(TX402_ERROR_CODES.transport, "TransportError", "caller-policy", [
    "causeCategory",
  ]),
]);

/** Descriptor lookup by code. */
export const TX402_ERROR_DESCRIPTORS: ReadonlyMap<Tx402ErrorCode, Tx402ErrorDescriptor> =
  new Map(TX402_ERROR_TAXONOMY.map((entry) => [entry.code, entry]));

/* ------------------------------------------------------------------------------------- */
/* Base class                                                                              */
/* ------------------------------------------------------------------------------------- */

/** Options accepted by every tx402 error constructor. */
export interface Tx402ErrorOptions {
  context: Tx402ErrorContext;
  details?: Tx402ErrorDetails;
  cause?: unknown;
}

/**
 * Base class for every typed tx402 error (SPEC §4.2).
 *
 * `cause` is retained for debugging but is **never** serialized by
 * {@link Tx402Error.toJSON}: the underlying error frequently comes from a signer or an
 * HTTP client and may carry a payload, a URL with credentials, or a stack referencing
 * either. SEC-003 makes that a redaction failure, so the boundary is drawn here once
 * rather than at every log site.
 */
export class Tx402Error extends Error {
  readonly code: Tx402ErrorCode;
  readonly retryable: boolean;
  readonly retryability: Tx402Retryability;
  readonly context: Readonly<Tx402ErrorContext>;
  readonly details: Tx402ErrorDetails;
  override readonly cause: unknown;

  constructor(code: Tx402ErrorCode, message: string, options: Tx402ErrorOptions) {
    super(message);

    const found = TX402_ERROR_DESCRIPTORS.get(code);
    if (!found) {
      // Unreachable through the exported subclasses; guards against a hand-rolled code.
      throw new Error(`Unknown tx402 error code: ${String(code)}`);
    }

    this.name = found.className;
    this.code = code;
    this.retryability = found.retryability;
    this.retryable = found.retryable;
    this.context = Object.freeze({ ...options.context });
    this.details = Object.freeze({ ...(options.details ?? {}) });
    this.cause = options.cause;

    // Subclassing a builtin across a downlevel-compiled boundary can lose the prototype
    // chain, which would silently break `instanceof` for consumers.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** The frozen SPEC §8 row for this error. */
  get descriptor(): Tx402ErrorDescriptor {
    // Non-null: the constructor already rejected unknown codes.
    return TX402_ERROR_DESCRIPTORS.get(this.code) as Tx402ErrorDescriptor;
  }

  /**
   * Redaction-safe serialization for logs and the CLI's `--json` output.
   *
   * Excludes `cause` and `stack` by design — see the class note.
   */
  toJSON(): {
    name: string;
    code: Tx402ErrorCode;
    message: string;
    retryable: boolean;
    retryability: Tx402Retryability;
    context: Tx402ErrorContext;
    details: Tx402ErrorDetails;
  } {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      retryability: this.retryability,
      context: { ...this.context },
      details: { ...this.details },
    };
  }
}

/**
 * Type guard for every tx402 typed error (SPEC §4.1).
 *
 * Checks the shape rather than `instanceof` so that an error crossing a realm boundary —
 * a worker thread, a bundled duplicate of the package — is still recognized. Both are
 * plausible in the agent runtimes this SDK targets.
 */
export function isTx402Error(error: unknown): error is Tx402Error {
  if (error instanceof Tx402Error) return true;
  if (typeof error !== "object" || error === null) return false;

  const candidate = error as { code?: unknown; context?: unknown };
  return (
    typeof candidate.code === "string" &&
    TX402_ERROR_DESCRIPTORS.has(candidate.code as Tx402ErrorCode) &&
    typeof candidate.context === "object" &&
    candidate.context !== null
  );
}

/* ------------------------------------------------------------------------------------- */
/* Subclasses — one per SPEC §8 row                                                        */
/* ------------------------------------------------------------------------------------- */

/** Invalid configuration. Raised synchronously from `createTx402Client` (SPEC §4.1). */
export class ConfigurationError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.configInvalid, message, options);
  }
}

/** The caller supplied a protocol-owned header (SPEC §6.1). */
export class ReservedHeaderError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.reservedHeader, message, options);
  }
}

/**
 * The request body cannot be replayed on the paid retry (SPEC §6.1).
 *
 * Raised *before* the initial request, not after — discovering this after a 402 would
 * mean the caller's stream had already been consumed.
 */
export class NonReplayableRequestError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.nonReplayable, message, options);
  }
}

/** Observed a protocol version this build does not implement (ADR-004). */
export class UnsupportedProtocolError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.protocolUnsupported, message, options);
  }
}

/** No offered scheme/network pair is supported (ADR-004). Reports what was offered. */
export class UnsupportedSchemeError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.schemeUnsupported, message, options);
  }
}

/** The challenge failed strict decoding, schema validation, or origin binding (SPEC §6.2). */
export class InvalidPaymentRequiredError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.paymentRequiredInvalid, message, options);
  }
}

/**
 * The price exceeds a configured cap (SPEC §6.3 steps 10–11).
 *
 * Evaluated entirely locally and before any signer or balance call, which is why T-006
 * asserts a signer-invocation count of zero and a sub-2 ms decision.
 */
export class BudgetExceededError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.policyBudget, message, options);
  }
}

/** The normalized host is not in `policy.allowedDomains` (SPEC §6.3 step 7). */
export class DomainNotAllowedError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.policyDomain, message, options);
  }
}

/** No offered route has sufficient balance (SPEC §6.4 step 20). Reports redacted deficits. */
export class InsufficientLiquidityError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.liquidity, message, options);
  }
}

/**
 * The signer refused, failed, or was unavailable.
 *
 * `causeCategory` is a coarse label — never the signer's own message, which may embed key
 * material or a full transaction (SEC-003).
 */
export class SignerError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.signer, message, options);
  }
}

/** Observed clock skew above the 15 s threshold (SPEC §6.6). The SDK never adjusts the clock. */
export class ClockSkewError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.clockSkew, message, options);
  }
}

/**
 * The signature was transmitted but the outcome is unknown (SPEC §6.7).
 *
 * The reservation is deliberately **retained** until its TTL rather than released: the
 * payment may have settled, and releasing would let it be spent twice against the cap.
 * `context.paid` is `"unknown"`.
 */
export class AmbiguousPaymentError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.paymentAmbiguous, message, options);
  }
}

/**
 * Settlement succeeded but the resource response was unusable (SPEC §5.3).
 *
 * The spend stays committed and `context.paid` is `true`. The money moved regardless of
 * what came back.
 */
export class ResourceDeliveryError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.resourceDelivery, message, options);
  }
}

/** A paid retry attempted a cross-origin redirect (SEC-005). Blocked before transmission. */
export class PaidRedirectBlockedError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.redirectBlocked, message, options);
  }
}

/** A network-level failure. The only automatically retryable error (see {@link isRetryable}). */
export class TransportError extends Tx402Error {
  constructor(message: string, options: Tx402ErrorOptions) {
    super(TX402_ERROR_CODES.transport, message, options);
  }
}
