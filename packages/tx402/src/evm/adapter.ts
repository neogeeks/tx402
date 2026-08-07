/**
 * The Base / EVM chain adapter (SPEC §7.1, M3).
 *
 * Answers the two questions `core/chain.ts` asks — *can this requirement be paid?* and
 * *what is the signed authorization?* — and nothing else. It never issues the merchant
 * request, never touches the ledger, and is reached only after the policy engine has
 * approved a requirement and, for signing, only after a reservation exists (SEC-002).
 *
 * The authorization itself is produced by upstream's `ExactEvmScheme`, not by tx402: SPEC
 * §3.2 requires audited primitives, and reimplementing EIP-3009 typed data would be exactly
 * the kind of hand-rolled cryptography that forbids. What tx402 keeps for itself is the
 * decision of *what* may be signed — see `plan.ts` — and the enforcement of that decision at
 * the signer boundary — see `signer.ts`.
 */

import { ExactEvmScheme } from "@x402/evm/exact/client";

import {
  MAX_AUTHORIZATION_SECONDS,
  type ChainAdapter,
  type ChainAuthorization,
  type ChainAuthorizationRequest,
  type ChainRoute,
  type ChainRouteRequest,
} from "../core/chain.js";
import {
  ConfigurationError,
  SignerError,
  TransportError,
  type Tx402ErrorContext,
} from "../core/errors.js";
import type { HealthIndex } from "../core/health.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../core/manifest.js";
import { formatMoneyDecimal } from "../core/money.js";
import { isEvmSigner, type EvmSigner } from "../core/signers.js";
import { BALANCE_KEY_SEPARATOR } from "../core/routing.js";
import { planExactEvmAuthorization, type ExactEvmPlan } from "./plan.js";
import {
  EvmRpcError,
  EvmRpcPool,
  type EvmBalanceReading,
  type EvmRpcPoolOptions,
} from "./rpc.js";
import { resolveEvmAddress, toClientEvmSigner } from "./signer.js";

export interface EvmChainAdapterOptions {
  /** Forwarded to every RPC pool. Present so tests can inject a transport and a deadline. */
  readonly rpc?: EvmRpcPoolOptions;
  /** The client's shared health index (SPEC §6.5). Omitted, each pool keeps a private one. */
  readonly health?: HealthIndex;
  /**
   * Caller-supplied RPC endpoints replacing the manifest's, keyed by canonical CAIP-2.
   * Validated and alias-resolved upstream by `PolicyEngine` (ADR-015).
   */
  readonly rpcOverrides?: Readonly<Record<string, readonly string[]>>;
}

function requireEvmNetwork(
  network: ChainRouteRequest["network"],
  context: Tx402ErrorContext,
): EvmManifestNetwork {
  if (!("chainId" in network)) {
    throw new ConfigurationError("Manifest network is not an EVM network", {
      context,
      details: { configPath: "manifest.networks", reason: "not-an-evm-network" },
    });
  }
  return network;
}

function requireEvmAsset(
  asset: ChainRouteRequest["asset"],
  context: Tx402ErrorContext,
): EvmManifestAsset {
  if (!("address" in asset)) {
    throw new ConfigurationError("Manifest asset is not an EVM asset", {
      context,
      details: { configPath: "manifest.networks", reason: "not-an-evm-asset" },
    });
  }
  return asset;
}

function requireEvmSigner(signer: unknown, context: Tx402ErrorContext): EvmSigner {
  if (!isEvmSigner(signer)) {
    throw new ConfigurationError("An EVM route requires an EvmSigner", {
      context,
      details: { configPath: "signers.evm", reason: "missing-evm-signer" },
    });
  }
  return signer;
}

/** RPC failures are reported by category. A provider's own text may name a key (SEC-003). */
function transportFromRpc(error: unknown, context: Tx402ErrorContext): TransportError {
  const category = error instanceof EvmRpcError ? error.failure : "transport";
  return new TransportError("Base RPC is unavailable for route planning", {
    context,
    details: { causeCategory: category },
    cause: error,
  });
}

/**
 * Creates the adapter.
 *
 * One instance is retained per client so its RPC endpoint pools are reused across requests.
 * The pools themselves are stateless since M5: circuit state and health scores live in the
 * client's shared `HealthIndex`, which is what `client.resetHealth()` clears.
 */
export function createEvmChainAdapter(options: EvmChainAdapterOptions = {}): ChainAdapter {
  const pools = new Map<string, EvmRpcPool>();

  const poolFor = (networkId: string, network: EvmManifestNetwork): EvmRpcPool => {
    let pool = pools.get(networkId);
    if (pool === undefined) {
      // ADR-015: a caller-supplied endpoint list replaces the manifest's for this
      // network, and nothing else about the network changes. The chain-identity proof
      // still runs against whatever endpoint is used.
      pool = new EvmRpcPool(options.rpcOverrides?.[networkId] ?? network.rpcUrls, {
        networkId,
        ...(options.health === undefined ? {} : { health: options.health }),
        ...options.rpc,
      });
      pools.set(networkId, pool);
    }
    return pool;
  };

  const prepare = async (
    request: ChainRouteRequest,
    phase: "route" | "sign",
  ): Promise<{
    plan: ExactEvmPlan;
    signer: EvmSigner;
    address: `0x${string}`;
    network: EvmManifestNetwork;
    asset: EvmManifestAsset;
    context: Tx402ErrorContext;
  }> => {
    const context: Tx402ErrorContext = {
      requestId: request.requestId,
      phase,
      network: request.networkId,
      scheme: request.requirement.scheme,
      amountAtomic: request.requirement.amountAtomic,
      assetId: request.requirement.assetId,
    };
    const network = requireEvmNetwork(request.network, context);
    const asset = requireEvmAsset(request.asset, context);
    const signer = requireEvmSigner(request.signer, context);
    const address = await resolveEvmAddress(signer, context);
    const plan = planExactEvmAuthorization({
      requirement: request.requirement,
      networkId: request.networkId,
      network,
      asset,
      payer: address,
      nowEpochMs: request.nowEpochMs,
      maxAuthorizationSeconds: MAX_AUTHORIZATION_SECONDS,
      context,
    });
    return { plan, signer, address, network, asset, context };
  };

  return {
    family: "eip155",

    async planRoute(request: ChainRouteRequest): Promise<ChainRoute> {
      const { plan, address, network, context } = await prepare(request, "route");

      let reading: EvmBalanceReading;
      try {
        const pool = poolFor(request.networkId, network);
        const read = (): Promise<EvmBalanceReading> =>
          pool.readBalance({
            chainId: plan.chainId,
            token: plan.verifyingContract,
            owner: address,
            nowEpochMs: request.nowEpochMs,
          });
        // SPEC §6.4 step 15 dedupes per unique network/asset; the owner joins the key
        // because two configured signers on one network are two different balances.
        reading =
          request.balances === undefined
            ? await read()
            : await request.balances.read(
                [request.networkId, plan.verifyingContract, address].join(
                  BALANCE_KEY_SEPARATOR,
                ),
                read,
              );
      } catch (error) {
        throw transportFromRpc(error, context);
      }

      const required = BigInt(plan.valueAtomic);
      const viable = reading.balanceAtomic >= required;
      return Object.freeze({
        requirementIndex: request.requirement.index,
        networkId: request.networkId,
        scheme: request.requirement.scheme,
        assetId: request.requirement.assetId,
        amountAtomic: request.requirement.amountAtomic,
        signerId: `evm:${address}`,
        balanceAtomic: reading.balanceAtomic.toString(),
        viable,
        rejectionReasons: Object.freeze(viable ? [] : ["insufficient-balance"]),
        // The merchant bears settlement cost for the exact scheme, so the buyer's expected
        // fee is zero. Stated rather than assumed: it is an ordering key (SPEC §6.4).
        estimatedFeeAtomic: "0",
        endpointId: reading.endpointId,
      });
    },

    async createAuthorization(
      request: ChainAuthorizationRequest,
    ): Promise<ChainAuthorization> {
      const { plan, signer, address, asset, context } = await prepare(request, "sign");

      const record = { signCount: 0, expiresAtEpochMs: 0 };

      // The lifetime travels as a duration, not as a pre-computed window. The signer adapter
      // turns it into bounds after upstream has written the message, which is the only
      // ordering under which `validBefore <= now + lifetime` holds by construction.
      const clientSigner = toClientEvmSigner({
        signer,
        address,
        plan: {
          chainId: plan.chainId,
          verifyingContract: plan.verifyingContract,
          domainName: plan.domainName,
          domainVersion: plan.domainVersion,
          from: address,
          to: plan.recipient,
          valueAtomic: plan.valueAtomic,
          lifetimeSeconds: plan.lifetimeSeconds,
        },
        presentation: {
          network: request.networkId,
          assetId: request.requirement.assetId,
          assetSymbol: asset.symbol,
          amountAtomic: plan.valueAtomic,
          amountDecimal: formatMoneyDecimal(plan.valueAtomic, asset.decimals),
          recipient: plan.recipient,
          resourceHost: request.resourceHost,
          domainName: plan.domainName,
          requestHash: request.requestHash,
        },
        record,
        context,
      });

      // Upstream is handed a requirement whose `maxTimeoutSeconds` is already clamped, which
      // is how SPEC §6.6's lifetime bound is applied without reimplementing the scheme. The
      // *offered* requirement still goes on the wire as `accepted`; only the lifetime the
      // authorization is signed for is narrowed.
      const clamped = {
        scheme: request.requirement.scheme,
        network: request.requirement.network as `${string}:${string}`,
        asset: request.requirement.asset,
        amount: request.requirement.amountAtomic,
        payTo: request.requirement.payTo,
        maxTimeoutSeconds: plan.lifetimeSeconds,
        extra: { ...request.requirement.extra },
      };

      let result;
      try {
        result = await new ExactEvmScheme(clientSigner).createPaymentPayload(2, clamped);
      } catch (error) {
        if (error instanceof SignerError) throw error;
        throw new SignerError("Failed to create the Base payment authorization", {
          context,
          details: { signerKind: "evm", causeCategory: "payload-creation-failed" },
          cause: error,
        });
      }

      if (record.signCount !== 1) {
        throw new SignerError("Scheme did not produce exactly one signature", {
          context,
          details: { signerKind: "evm", causeCategory: "unexpected-signature-count" },
        });
      }
      if (
        typeof result.payload !== "object" ||
        result.payload === null ||
        Object.keys(result.payload).length === 0
      ) {
        throw new SignerError("Scheme returned an empty authorization payload", {
          context,
          details: { signerKind: "evm", causeCategory: "empty-payload" },
        });
      }

      return Object.freeze({
        x402Version: result.x402Version,
        payload: result.payload,
        ...(result.extensions === undefined ? {} : { extensions: result.extensions }),
        expiresAtEpochMs: record.expiresAtEpochMs,
        signerId: `evm:${address}`,
      });
    },

    resetHealth(): void {
      for (const pool of pools.values()) pool.resetHealth();
    },
  };
}
