/**
 * tx402 — resilient x402 buyer SDK.
 *
 * This is the **core import path**. It is size-gated per ADR-008 and must never pull in a
 * chain adapter, a signer implementation, or CLI code. Chain support lives behind the
 * `tx402/evm` and `tx402/solana` subpath exports; private-key convenience adapters live
 * behind `tx402/signers` and are kept isolated per SEC-001.
 *
 * @example
 * ```ts
 * import { createTx402Client } from "tx402";
 *
 * const client = createTx402Client({
 *   signers: { evm, solana },
 *   policy: {
 *     maxPerRequest: "0.50 USDC",
 *     maxPerHour: "10.00 USDC",
 *     allowedNetworks: ["eip155:8453", "solana:mainnet"],
 *   },
 * });
 *
 * const response = await client.fetch(url, init);
 * ```
 *
 * Feature-complete for v0.1: paid calls on Base and Solana, deterministic multi-route
 * planning over a shared endpoint health index, and a re-challenge loop under
 * `policy.maxPaidAttempts`. The conformance fixtures are frozen against this
 * implementation; the Python SDK is written to match them.
 */

export {
  PACKAGE_NAME,
  X402_PROTOCOL_VERSION,
  PROJECT_URLS,
  PROTOCOL_HEADERS,
  RESERVED_REQUEST_HEADERS,
  REQUEST_ID_HEADER,
} from "./meta.js";

/**
 * Error taxonomy (SPEC §8).
 *
 * Every failure the SDK raises is one of these fifteen classes, and every one carries the
 * same `code` string in TypeScript and in Python. Switch on `error.code` rather than on
 * class identity — the code is what survives a serialization boundary.
 */
export {
  TX402_ERROR_CODES,
  TX402_ERROR_TAXONOMY,
  TX402_ERROR_DESCRIPTORS,
  Tx402Error,
  isTx402Error,
  ConfigurationError,
  ReservedHeaderError,
  NonReplayableRequestError,
  UnsupportedProtocolError,
  UnsupportedSchemeError,
  InvalidPaymentRequiredError,
  BudgetExceededError,
  DomainNotAllowedError,
  InsufficientLiquidityError,
  SignerError,
  ClockSkewError,
  AmbiguousPaymentError,
  ResourceDeliveryError,
  PaidRedirectBlockedError,
  TransportError,
} from "./core/errors.js";

export type {
  Tx402ErrorCode,
  Tx402ErrorContext,
  Tx402ErrorDetails,
  Tx402ErrorDescriptor,
  Tx402ErrorOptions,
  Tx402Phase,
  Tx402Retryability,
} from "./core/errors.js";

/**
 * Release manifest (SPEC §5.4).
 *
 * `BUNDLED_MANIFEST` is the signed manifest shipped with this build. Callers may supply
 * their own through `manifest` in client config; it is verified on identical terms.
 */
export {
  verifyReleaseManifest,
  assertValidReleaseManifest,
  resolveNetwork,
  requireNetwork,
} from "./core/manifest.js";

export type {
  ReleaseManifest,
  ManifestNetwork,
  ManifestAsset,
  EvmManifestNetwork,
  SvmManifestNetwork,
  EvmManifestAsset,
  SvmManifestAsset,
  ManifestSignature,
  ManifestFailureReason,
  ManifestVerificationResult,
  NetworkEnvironment,
  NetworkResolution,
  VerifyManifestOptions,
} from "./core/manifest.js";

export { BUNDLED_MANIFEST } from "./core/bundled-manifest.js";
export { TRUSTED_MANIFEST_KEYS, MANIFEST_SIGNING_DOMAIN } from "./core/trusted-keys.js";

export { createTx402Client } from "./core/client.js";
export type {
  BudgetState,
  PaymentInspection,
  Tx402Client,
  Tx402ClientConfig,
  Tx402Clock,
  Tx402Logger,
  Tx402RequestInfo,
  Tx402RequestInit,
  Tx402Timeouts,
} from "./core/client.js";

/**
 * Signer contracts (SPEC §7.1/§7.2, SEC-001).
 *
 * Declarations only. The implementations live behind `tx402/evm` and `tx402/solana`, and the
 * private-key convenience adapters behind `tx402/signers`.
 */
export { isEvmSigner, isSolanaSigner } from "./core/signers.js";
export type {
  EvmSigner,
  EvmSignerPresentation,
  EvmTypedDataDomain,
  EvmTypedDataField,
  EvmTypedDataRequest,
  SolanaSigner,
  SolanaSignerPresentation,
  SolanaSignRequest,
  Tx402Signers,
} from "./core/signers.js";

/** The core-to-adapter seam (SPEC §3). Chain adapters are loaded lazily; see `core/chain.ts`. */
export {
  BALANCE_TIMEOUT_MS,
  CIRCUIT_OPEN_MS,
  MAX_AUTHORIZATION_SECONDS,
  MAX_PROVIDERS_PER_NETWORK,
  chainFamily,
} from "./core/chain.js";
export type {
  ChainAdapter,
  ChainAdapterContext,
  ChainAdapterLoader,
  ChainAuthorization,
  ChainAuthorizationRequest,
  ChainRoute,
  ChainRouteRequest,
} from "./core/chain.js";

/**
 * Endpoint health and route planning (SPEC §6.4, §6.5).
 *
 * One `HealthIndex` per client scores every RPC endpoint every adapter uses; there is no
 * second circuit anywhere in the SDK. `client.resetHealth()` clears it.
 */
export {
  HealthIndex,
  HEALTH_EWMA_ALPHA,
  HEALTH_FAILURE_WINDOW,
  HEALTH_CONSECUTIVE_FAILURES_TO_OPEN,
  HEALTH_MIN_SAMPLES_FOR_RATE,
  HEALTH_FAILURE_RATE_TO_OPEN,
  HEALTH_OPEN_MS,
  HEALTH_IDLE_RETENTION_MS,
  HEALTH_MAX_ENDPOINTS,
  HEALTH_NEW_ENDPOINT_SCORE,
  HEALTH_LATENCY_REFERENCE_MS,
  HEALTH_LATENCY_PENALTY_MAX,
} from "./core/health.js";
export type { CircuitAdmission, CircuitState, EndpointHealth } from "./core/health.js";

export {
  orderRouteCandidates,
  planRoutes,
  createBalanceProbeCache,
  BALANCE_KEY_SEPARATOR,
} from "./core/routing.js";
export type {
  BalanceProbeCache,
  RouteCandidate,
  RoutePlan,
  RoutePlanRequest,
  RouteProbeOutcome,
  RouteRejectionReason,
} from "./core/routing.js";

export {
  parseMoneyAtomic,
  parsePositiveMoneyAtomic,
  formatMoneyDecimal,
  MoneyParseError,
} from "./core/money.js";
export type { MoneyAssetMetadata, MoneyParseFailureReason } from "./core/money.js";

export {
  fingerprintRequest,
  digestRequestBody,
  normalizeFingerprintUrl,
  REQUEST_FINGERPRINT_DOMAIN,
} from "./core/fingerprint.js";
export type { RequestFingerprintInput } from "./core/fingerprint.js";

export { MemorySpendStore, RESERVATION_TTL_MS, ROLLING_WINDOW_MS } from "./core/ledger.js";
export type {
  SpendStore,
  SpendReservation,
  SpendReservationState,
  SpendEntry,
  SpendTotals,
  ReserveSpendInput,
  CommitSpendInput,
  SpendQuery,
} from "./core/ledger.js";

export { PolicyEngine, normalizePolicyHost } from "./core/policy.js";
export type {
  PolicyConfig,
  RoutingPolicyConfig,
  PolicyDecision,
  PolicyRequirement,
} from "./core/policy.js";

export {
  decodePaymentRequired,
  MAX_PAYMENT_REQUIRED_BYTES,
  MAX_PAYMENT_REQUIRED_DEPTH,
  MAX_PAYMENT_REQUIREMENTS,
} from "./core/protocol.js";
export type {
  DecodePaymentRequiredOptions,
  NormalizedPaymentRequired,
  NormalizedPaymentRequirement,
} from "./core/protocol.js";
