/**
 * Type declarations for the deterministic test merchant.
 *
 * Hand-written rather than emitted: the implementation is plain JavaScript so it can be
 * spawned by the Python suite without a build step, but every TypeScript integration test
 * from M1 onward talks to it, and those tests are typechecked under `strict`.
 */

/** Requirement sets the merchant can offer, matching the bundled release manifest. */
export declare const DEFAULT_REQUIREMENTS: Readonly<
  Record<
    "base" | "baseSepolia" | "solana" | "solanaDevnet",
    {
      scheme: string;
      network: string;
      asset: string;
      amount: string;
      payTo: string;
      maxTimeoutSeconds: number;
      extra: Record<string, unknown>;
    }
  >
>;

export declare const SCENARIOS: Readonly<
  Record<string, { description: string; covers: readonly string[] }>
>;

/** One request as the merchant saw it. The signature header value is never retained. */
export interface RecordedRequest {
  /** 0-based, in arrival order. */
  index: number;
  method: string;
  path: string;
  /** Lowercased. `payment-signature` reads `<redacted>` — SEC-003. */
  headers: Record<string, string>;
  body: string;
  hasSignature: boolean;
  /** How many signed attempts had arrived, including this one. */
  paidAttempt: number;
  /** What the server answered, or -1 if it deliberately hung. */
  status: number;
  /** Set when retry validation rejected the attempt. */
  violation?: string;
  /**
   * `sha256:<hex>` of the raw PAYMENT-SIGNATURE header, present on a validated paid attempt.
   *
   * The value itself is never retained (SEC-003), but SPEC §6.7's "the old signature is
   * never reused" has to be checkable, and comparing two digests settles it without keeping
   * anything sensitive.
   */
  signatureHash?: string;
  /**
   * The facilitator's answer, present only when `facilitatorUrl` was configured and a
   * signed attempt reached settlement. A real settlement, on a real chain.
   */
  settlement?: {
    success: boolean;
    transaction: string;
    network: string;
    payer?: string;
    errorReason?: string;
  };
  /** Set when the facilitator could not be reached at all, rather than refusing. */
  settlementError?: string;
  /** The atomic amount the buyer's `accepted` requirement named. */
  acceptedAmount?: string;
}

export interface TestMerchantOptions {
  /** Default `"pay-once"`. See `SCENARIOS` for the catalogue. */
  scenario?: string;
  /** Defaults to a single Base USDC requirement. */
  requirements?: Record<string, unknown>[];
  /** Default 0 (ephemeral). */
  port?: number;
  /** Body returned on successful delivery. */
  body?: string;
  contentType?: string;
  /** Deterministic transaction id placed in PAYMENT-RESPONSE. */
  settlementId?: string;
  /**
   * When set, a signed attempt is verified and settled against this **real** x402
   * facilitator instead of being answered with the deterministic `settlementId`.
   *
   * ADR-002 puts `/verify` and `/settle` on the merchant, so the buyer sees no difference
   * and never learns a facilitator exists. That is what makes a local merchant a legitimate
   * fixture for a real payment: the buyer's code path is the shipped one, and the fixture
   * supplies only the counterparty. A failed settlement answers 402 carrying both
   * PAYMENT-RESPONSE and a fresh PAYMENT-REQUIRED.
   */
  facilitatorUrl?: string;
  resourceDescription?: string;
  /**
   * Default true. Turn it off only to test what an unvalidating merchant does — with it on,
   * a malformed retry is answered `400` with a machine-readable reason.
   */
  validateRetries?: boolean;
  /**
   * Offered instead of `requirements` once at least one signed attempt has arrived, so a
   * re-challenge can genuinely differ from the first challenge (SPEC §6.7). A paid attempt
   * is validated against the union of both sets.
   */
  rechallengeRequirements?: Record<string, unknown>[];
}

export interface TestMerchant {
  /** Base URL, e.g. `http://127.0.0.1:54321`. */
  readonly url: string;
  readonly origin: string;
  readonly port: number;
  readonly scenario: string;
  readonly requirements: Record<string, unknown>[];
  /** Every request seen, in order. */
  readonly requests: RecordedRequest[];
  /** Requests that carried a PAYMENT-SIGNATURE. */
  readonly paidRequests: RecordedRequest[];
  /** Retry-validation violations. Empty is the expected state. */
  readonly violations: (string | undefined)[];
  /** Clears the request log and the paid-attempt counter. */
  reset(): void;
  close(): Promise<void>;
}

export declare function createTestMerchant(
  options?: TestMerchantOptions,
): Promise<TestMerchant>;
