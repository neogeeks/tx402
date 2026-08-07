/** Solana / SVM exact-payment adapter (SPEC §7.2, ADR-010). */

import { ExactSvmScheme } from "@x402/svm/exact/client";

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
import type { SvmManifestAsset, SvmManifestNetwork } from "../core/manifest.js";
import { formatMoneyDecimal } from "../core/money.js";
import { isSolanaSigner, type SolanaSigner } from "../core/signers.js";
import { BALANCE_KEY_SEPARATOR } from "../core/routing.js";
import { planExactSvmAuthorization } from "./plan.js";
import {
  SvmRpcError,
  SvmRpcPool,
  type SvmBalanceReading,
  type SvmRpcPoolOptions,
} from "./rpc.js";
import { resolveSolanaPublicKey, toTransactionSigner } from "./signer.js";

export interface SvmChainAdapterOptions {
  readonly rpc?: SvmRpcPoolOptions;
  /** The client's shared health index (SPEC §6.5, O22). */
  readonly health?: HealthIndex;
  /**
   * Caller-supplied RPC endpoints replacing the manifest's, keyed by canonical CAIP-2.
   * Validated and alias-resolved upstream by `PolicyEngine` (ADR-015).
   */
  readonly rpcOverrides?: Readonly<Record<string, readonly string[]>>;
}

function requireNetwork(
  network: ChainRouteRequest["network"],
  context: Tx402ErrorContext,
): SvmManifestNetwork {
  if (!("genesisHash" in network)) {
    throw new ConfigurationError("Manifest network is not a Solana network", {
      context,
      details: { configPath: "manifest.networks", reason: "not-an-svm-network" },
    });
  }
  return network;
}

function requireAsset(
  asset: ChainRouteRequest["asset"],
  context: Tx402ErrorContext,
): SvmManifestAsset {
  if (!("mint" in asset)) {
    throw new ConfigurationError("Manifest asset is not a Solana asset", {
      context,
      details: { configPath: "manifest.networks", reason: "not-an-svm-asset" },
    });
  }
  return asset;
}

function requireSigner(signer: unknown, context: Tx402ErrorContext): SolanaSigner {
  if (!isSolanaSigner(signer)) {
    throw new ConfigurationError("A Solana route requires a SolanaSigner", {
      context,
      details: { configPath: "signers.solana", reason: "missing-solana-signer" },
    });
  }
  return signer;
}

/**
 * Whether a failure raised inside upstream's payload creation is a transport failure.
 *
 * tx402 does not own this error's type — `@x402/svm` fetches over its own client — so the
 * classification is by evidence rather than by `instanceof`. Three kinds of evidence, in
 * decreasing reliability:
 *
 *   1. A `cause` chain carrying a Node socket/undici error code. `fetch` rejects with a
 *      `TypeError` whose `cause` holds the real one, which is why the chain is walked.
 *   2. A numeric HTTP status at or above 400 hung on the error, which is how most JSON-RPC
 *      clients report a non-2xx.
 *   3. Failing those, an explicit message match — deliberately last, and deliberately
 *      narrow. `429` is listed because it is the case this exists for.
 *
 * Anything unrecognised is **not** a transport failure. A false negative leaves the previous
 * (non-retryable) classification; a false positive would tell a caller to retry a
 * deterministic construction fault forever.
 */
export function isTransportFailure(error: unknown): boolean {
  const NETWORK_CODES = new Set([
    "ECONNREFUSED",
    "ECONNRESET",
    "ENOTFOUND",
    "EAI_AGAIN",
    "ETIMEDOUT",
    "EPIPE",
    "UND_ERR_CONNECT_TIMEOUT",
    "UND_ERR_HEADERS_TIMEOUT",
    "UND_ERR_SOCKET",
  ]);

  for (let current = error, depth = 0; current != null && depth < 5; depth += 1) {
    if (typeof current !== "object") break;
    const candidate = current as { code?: unknown; status?: unknown; cause?: unknown };
    if (typeof candidate.code === "string" && NETWORK_CODES.has(candidate.code))
      return true;
    if (typeof candidate.status === "number" && candidate.status >= 400) return true;
    current = candidate.cause;
  }

  const message = error instanceof Error ? error.message : String(error);
  return /\b(429|too many requests|rate.?limit|fetch failed|network|socket hang up)\b/iu.test(
    message,
  );
}

function transport(error: unknown, context: Tx402ErrorContext): TransportError {
  return new TransportError("Solana RPC is unavailable for payment planning", {
    context,
    details: {
      causeCategory: error instanceof SvmRpcError ? error.failure : "transport",
    },
    cause: error,
  });
}

export function createSvmChainAdapter(options: SvmChainAdapterOptions = {}): ChainAdapter {
  const pools = new Map<string, SvmRpcPool>();
  const poolFor = (networkId: string, network: SvmManifestNetwork): SvmRpcPool => {
    let pool = pools.get(networkId);
    if (pool === undefined) {
      // ADR-015: a caller-supplied endpoint list replaces the manifest's for this
      // network, and nothing else about the network changes. The chain-identity proof
      // still runs against whatever endpoint is used.
      pool = new SvmRpcPool(options.rpcOverrides?.[networkId] ?? network.rpcUrls, {
        networkId,
        ...(options.health === undefined ? {} : { health: options.health }),
        ...options.rpc,
      });
      pools.set(networkId, pool);
    }
    return pool;
  };

  const prepare = async (request: ChainRouteRequest, phase: "route" | "sign") => {
    const context: Tx402ErrorContext = {
      requestId: request.requestId,
      phase,
      network: request.networkId,
      scheme: request.requirement.scheme,
      amountAtomic: request.requirement.amountAtomic,
      assetId: request.requirement.assetId,
    };
    const network = requireNetwork(request.network, context);
    const asset = requireAsset(request.asset, context);
    const signer = requireSigner(request.signer, context);
    const publicKey = await resolveSolanaPublicKey(signer, context);
    const plan = await planExactSvmAuthorization({
      requirement: request.requirement,
      networkId: request.networkId,
      network,
      asset,
      payer: publicKey,
      maxAuthorizationSeconds: MAX_AUTHORIZATION_SECONDS,
      context,
    });
    return { context, network, asset, signer, publicKey, plan };
  };

  return {
    family: "solana",

    async planRoute(request: ChainRouteRequest): Promise<ChainRoute> {
      const { context, network, asset, publicKey } = await prepare(request, "route");
      let reading: SvmBalanceReading;
      try {
        const pool = poolFor(request.networkId, network);
        const read = (): Promise<SvmBalanceReading> =>
          pool.readBalance({
            genesisHash: network.genesisHash,
            mint: asset.mint,
            owner: publicKey,
            decimals: asset.decimals,
            nowEpochMs: request.nowEpochMs,
          });
        // Deduped per unique network/asset/owner for the planning pass (SPEC §6.4 step 15).
        reading =
          request.balances === undefined
            ? await read()
            : await request.balances.read(
                [request.networkId, asset.mint, publicKey].join(BALANCE_KEY_SEPARATOR),
                read,
              );
      } catch (error) {
        throw transport(error, context);
      }
      const viable = reading.balanceAtomic >= BigInt(request.requirement.amountAtomic);
      return Object.freeze({
        requirementIndex: request.requirement.index,
        networkId: request.networkId,
        scheme: request.requirement.scheme,
        assetId: request.requirement.assetId,
        amountAtomic: request.requirement.amountAtomic,
        signerId: `solana:${publicKey}`,
        balanceAtomic: reading.balanceAtomic.toString(),
        viable,
        rejectionReasons: Object.freeze(viable ? [] : ["insufficient-balance"]),
        // The facilitator is the fee payer for the SVM exact scheme (SPEC §7.2), so the
        // buyer's expected fee in the payment asset is zero.
        estimatedFeeAtomic: "0",
        endpointId: reading.endpointId,
      });
    },

    async createAuthorization(
      request: ChainAuthorizationRequest,
    ): Promise<ChainAuthorization> {
      const { context, network, asset, signer, publicKey, plan } = await prepare(
        request,
        "sign",
      );
      let rpcUrl: string;
      try {
        ({ url: rpcUrl } = await poolFor(request.networkId, network).validatedRpcUrl(
          network.genesisHash,
          request.nowEpochMs,
        ));
      } catch (error) {
        throw transport(error, context);
      }

      const lifetimeSeconds = Math.min(
        plan.lifetimeSeconds,
        request.maxAuthorizationSeconds,
      );
      const record = { signCount: 0, expiresAtEpochMs: 0, serializedBytes: 0 };
      const clientSigner = toTransactionSigner({
        signer,
        plan: { ...plan, publicKey: plan.payer },
        presentation: {
          network: request.networkId,
          assetId: request.requirement.assetId,
          assetSymbol: asset.symbol,
          amountAtomic: request.requirement.amountAtomic,
          amountDecimal: formatMoneyDecimal(
            request.requirement.amountAtomic,
            asset.decimals,
          ),
          recipient: request.requirement.payTo,
          resourceHost: request.resourceHost,
          feePayer: plan.feePayer,
          requestHash: request.requestHash,
        },
        lifetimeSeconds,
        record,
        context,
      });

      const requirement = {
        scheme: request.requirement.scheme,
        network: request.requirement.network as `${string}:${string}`,
        asset: request.requirement.asset,
        amount: request.requirement.amountAtomic,
        payTo: request.requirement.payTo,
        maxTimeoutSeconds: lifetimeSeconds,
        extra: { ...request.requirement.extra },
      };
      let result;
      try {
        result = await new ExactSvmScheme(clientSigner, { rpcUrl }).createPaymentPayload(
          2,
          requirement,
        );
      } catch (error) {
        if (error instanceof SignerError) throw error;
        // `ExactSvmScheme` performs its **own** RPC inside `createPaymentPayload` — mint
        // metadata and a recent blockhash — so a 429 from the endpoint arrives here rather
        // than through tx402's pool. Wrapping every such failure as `SignerError` reported a
        // rate-limited endpoint as a signing fault: wrong category, and wrong `retryable`,
        // since only `TransportError` is retryable (ADR-011). It was seen once at S12 and
        // recorded as the unexplained half of O35.
        //
        // Python does not have this problem — it compiles the transaction itself (ADR-013)
        // and fetches the blockhash through `SvmRpcPool`, so its RPC failures are already
        // `TransportError`. This brings TypeScript back into line with Python rather than
        // inventing a third behaviour.
        //
        // Classification fails *safe*: anything not recognisably a transport failure stays
        // a `SignerError`, which is the conservative, non-retryable answer.
        if (isTransportFailure(error)) throw transport(error, context);
        throw new SignerError("Failed to create the Solana payment authorization", {
          context,
          details: { signerKind: "solana", causeCategory: "payload-creation-failed" },
          cause: error,
        });
      }
      if (record.signCount !== 1 || record.serializedBytes === 0) {
        throw new SignerError("Scheme did not produce exactly one Solana signature", {
          context,
          details: { signerKind: "solana", causeCategory: "unexpected-signature-count" },
        });
      }
      if (
        typeof result.payload !== "object" ||
        result.payload === null ||
        typeof (result.payload as { transaction?: unknown }).transaction !== "string"
      ) {
        throw new SignerError("Scheme returned an invalid Solana authorization payload", {
          context,
          details: { signerKind: "solana", causeCategory: "empty-payload" },
        });
      }
      return Object.freeze({
        x402Version: result.x402Version,
        payload: result.payload,
        expiresAtEpochMs: record.expiresAtEpochMs,
        signerId: `solana:${publicKey}`,
      });
    },

    resetHealth(): void {
      for (const pool of pools.values()) pool.resetHealth();
    },
  };
}
