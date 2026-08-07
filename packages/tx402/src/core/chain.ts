/**
 * The seam between the core request loop and a chain adapter (SPEC §3, §6.4, §6.6).
 *
 * Core owns the state machine, the policy gate, and the ledger. It knows nothing about
 * EIP-712, SPL token accounts, or JSON-RPC. A chain adapter answers exactly two questions —
 * *can this requirement be paid?* and *what is the signed authorization?* — and is loaded
 * lazily, so a caller who never pays on EVM never loads `@x402/evm` or `viem`.
 *
 * **Why lazy `import()` rather than a registry the caller populates.** SPEC §4.1's normative
 * example configures `signers: { evm, solana }` and nothing else; requiring a second,
 * adapter-shaped argument would contradict it. The dynamic import keeps that API while
 * keeping the adapters off the size-gated core path — ADR-008 and SPEC §12.3 both exclude
 * optional chain adapters from the core figure, and `tools/size-gate` marks these two module
 * paths external for exactly that reason.
 */

import { HEALTH_OPEN_MS, type HealthIndex } from "./health.js";
import type { ManifestAsset, ManifestNetwork } from "./manifest.js";
import type { PolicyRequirement } from "./policy.js";
import type { BalanceProbeCache } from "./routing.js";

/**
 * Per-provider balance timeout (SPEC §6.4 step 15). Not configurable: it is a bound on the
 * <150 ms decision budget, not a caller preference.
 */
export const BALANCE_TIMEOUT_MS = 600;

/** Maximum RPC providers consulted per network (SPEC §6.4 step 15). */
export const MAX_PROVIDERS_PER_NETWORK = 2;

/**
 * Default authorization lifetime in seconds (SPEC §6.6).
 *
 * The effective lifetime is `min(60, merchant maxTimeoutSeconds)`. It may never exceed the
 * merchant bound, so the merchant's value is a ceiling and this is a cap tx402 applies on
 * top of it.
 */
export const MAX_AUTHORIZATION_SECONDS = 60;

/**
 * Circuit open duration for an RPC endpoint (SPEC §6.5).
 *
 * Re-exported from `core/health.ts` rather than restated: since M5 the circuit lives entirely
 * in the HealthIndex, and two copies of this number could drift apart without any test
 * noticing which one an endpoint was actually using.
 */
export const CIRCUIT_OPEN_MS = HEALTH_OPEN_MS;

/** Everything an adapter needs to score one policy-approved requirement. */
export interface ChainRouteRequest {
  readonly requestId: string;
  /** Canonical CAIP-2 identifier, already resolved through the manifest alias map. */
  readonly networkId: string;
  readonly network: ManifestNetwork;
  /** The manifest asset the requirement was matched to, never the merchant's claim. */
  readonly asset: ManifestAsset;
  readonly requirement: PolicyRequirement;
  readonly signer: unknown;
  readonly nowEpochMs: number;
  /**
   * Deduplicates balance reads across requirements that share a network, asset, and owner
   * (SPEC §6.4 step 15). Supplied by the RoutePlanner for the duration of one planning pass.
   */
  readonly balances?: BalanceProbeCache;
}

/**
 * What an adapter can observe about one requirement (SPEC §5.2).
 *
 * `healthScore` and `rank` are **not** here: they are the RoutePlanner's, computed from the
 * one shared {@link HealthIndex} rather than from anything an adapter keeps. An adapter
 * reports which endpoint answered, and the planner scores it.
 */
export interface ChainRoute {
  readonly requirementIndex: number;
  readonly networkId: string;
  readonly scheme: string;
  readonly assetId: string;
  readonly amountAtomic: string;
  /** `evm:0x…` / `solana:…`. Safe to log — it is a public address. */
  readonly signerId: string;
  readonly balanceAtomic: string;
  readonly viable: boolean;
  /** Stable machine-readable reasons. Never a raw provider message (SEC-003). */
  readonly rejectionReasons: readonly string[];
  /**
   * Buyer-borne fee in atomic units of `assetId`. `"0"` for the exact scheme on both v0.1
   * networks, where the merchant bears settlement cost — but it is an ordering key in SPEC
   * §6.4 step 18, so it is carried explicitly rather than assumed.
   */
  readonly estimatedFeeAtomic?: string;
  /** The health-index key of the endpoint that served the balance, `<caip2>|<host>`. */
  readonly endpointId?: string;
}

/** A route that has been selected, reserved against, and is ready to sign. */
export interface ChainAuthorizationRequest extends ChainRouteRequest {
  /** Normalized host of the resource, for the SPEC §6.6 signer presentation. */
  readonly resourceHost: string;
  /** SEC-009 request fingerprint, presented to the signer as the request hash. */
  readonly requestHash: string;
  /** Upper bound on authorization lifetime, in seconds (SPEC §6.6). */
  readonly maxAuthorizationSeconds: number;
}

/** The upstream payment payload, plus what core needs to bound and account for it. */
export interface ChainAuthorization {
  readonly x402Version: number;
  /**
   * Upstream's scheme payload. **Sensitive** — it contains the signature. It is placed
   * straight into the PAYMENT-SIGNATURE header and is never logged (SEC-003).
   */
  readonly payload: Readonly<Record<string, unknown>>;
  readonly extensions?: Readonly<Record<string, unknown>>;
  /** When the signed authorization stops being valid, from the signed message itself. */
  readonly expiresAtEpochMs: number;
  readonly signerId: string;
}

/**
 * A chain family's implementation of the two questions core asks.
 *
 * One instance is retained per client so its RPC endpoint pools survive across requests. The
 * *health* those pools consult is not theirs: it lives in the client's shared
 * {@link HealthIndex}, which is what `client.resetHealth()` clears (SPEC §4.1).
 */
export interface ChainAdapter {
  /** CAIP-2 namespace this adapter serves, for example `eip155`. */
  readonly family: string;
  planRoute(request: ChainRouteRequest): Promise<ChainRoute>;
  createAuthorization(request: ChainAuthorizationRequest): Promise<ChainAuthorization>;
  /** Clears this adapter's endpoints from the health index. Never touches the ledger. */
  resetHealth(): void;
}

/** Wiring an adapter receives from core. All members are optional for standalone use. */
export interface ChainAdapterContext {
  /** The client's single health index (SPEC §6.5). Adapters never create their own. */
  readonly health?: HealthIndex;
  /**
   * Caller-supplied RPC endpoints replacing the manifest's, keyed by canonical CAIP-2.
   *
   * Already validated and alias-resolved by `PolicyEngine`, so an adapter can index this
   * directly by the network id it was handed (ADR-015).
   */
  readonly rpcOverrides?: Readonly<Record<string, readonly string[]>>;
}

export type ChainAdapterLoader = (
  family: string,
  context?: ChainAdapterContext,
) => Promise<ChainAdapter | undefined>;

/** The CAIP-2 namespace of a canonical network identifier. */
export function chainFamily(networkId: string): string {
  return networkId.slice(0, networkId.indexOf(":"));
}

/**
 * Loads the adapter for a chain family, or `undefined` when tx402 has none.
 *
 * The `import()` calls are what keep `@x402/evm`, `@x402/svm`, `viem`, and `@solana/kit` off
 * the core import path. A missing optional peer dependency surfaces here as a rejected
 * promise; the caller turns it into a `ConfigurationError` naming the package to install.
 */
export const loadChainAdapter: ChainAdapterLoader = async (family, context = {}) => {
  const wiring = {
    ...(context.health === undefined ? {} : { health: context.health }),
    ...(context.rpcOverrides === undefined ? {} : { rpcOverrides: context.rpcOverrides }),
  };
  if (family === "eip155") {
    const evm = await import("../evm/adapter.js");
    return evm.createEvmChainAdapter(wiring);
  }
  if (family === "solana") {
    const svm = await import("../solana/adapter.js");
    return svm.createSvmChainAdapter(wiring);
  }
  return undefined;
};
