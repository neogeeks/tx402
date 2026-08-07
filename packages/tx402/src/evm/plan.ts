/**
 * Everything the Base adapter decides before it touches the network or a key.
 *
 * Kept as a pure function on purpose. It is the part of the EVM adapter that has to behave
 * identically in Python at S9, it is what the `evm.authorization-plan` conformance vectors
 * freeze, and it is the part where a mistake is expensive: the plan is what the signer
 * adapter later enforces the EIP-712 message against.
 *
 * No RPC, no clock beyond the injected one, no signer, no randomness.
 */

import {
  InvalidPaymentRequiredError,
  UnsupportedSchemeError,
  type Tx402ErrorContext,
} from "../core/errors.js";
import type { EvmManifestAsset, EvmManifestNetwork } from "../core/manifest.js";

/** ERC-20 `balanceOf(address)` selector — the first four bytes of its keccak-256 hash.
 * A constant, because SPEC §3.2 forbids implementing keccak and a selector never changes. */
export const BALANCE_OF_SELECTOR = "0x70a08231";

/**
 * The exact scheme's only supported transfer method in v0.1.
 *
 * Upstream also implements Permit2 for tokens without EIP-3009. SPEC §7.1 scopes v0.1 to
 * "native USDC through the upstream x402 EVM implementation" and exposes no generic ERC-20
 * support, and the Permit2 path additionally needs `readContract` on the signer — a
 * capability SPEC §7.1's `EvmSigner` does not have. So a merchant asking for Permit2 is
 * declined rather than silently signed with a different primitive.
 */
export const SUPPORTED_ASSET_TRANSFER_METHOD = "eip3009";

const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/u;

/** The requirement fields the plan reads. A subset of `PolicyRequirement`. */
export interface ExactEvmRequirementInput {
  readonly index?: number;
  readonly scheme: string;
  readonly network: string;
  readonly asset: string;
  readonly amountAtomic: string;
  readonly payTo: string;
  readonly maxTimeoutSeconds: number;
  readonly extra: Readonly<Record<string, unknown>>;
}

export interface ExactEvmPlanInput {
  readonly requirement: ExactEvmRequirementInput;
  /** Canonical CAIP-2 identifier, already resolved through the manifest alias map. */
  readonly networkId: string;
  readonly network: EvmManifestNetwork;
  readonly asset: EvmManifestAsset;
  readonly payer: string;
  readonly nowEpochMs: number;
  /** SPEC §6.6's default ceiling, normally 60. */
  readonly maxAuthorizationSeconds: number;
  readonly context: Tx402ErrorContext;
}

/** A validated, bounded description of the authorization tx402 is willing to request. */
export interface ExactEvmPlan {
  readonly chainId: number;
  /** The manifest token address — never the merchant's spelling of it. */
  readonly verifyingContract: string;
  readonly domainName: string;
  readonly domainVersion: string;
  readonly payer: string;
  readonly recipient: string;
  readonly valueAtomic: string;
  /** `min(60, merchant maxTimeoutSeconds)` (SPEC §6.6). The bound that is enforced. */
  readonly lifetimeSeconds: number;
  readonly validAfterSeconds: number;
  /**
   * The window this plan describes, as of `nowEpochMs`.
   *
   * Descriptive, not enforcing. The signer adapter re-derives the same formula from a clock
   * read *after* upstream has produced the message, because a window computed here would sit
   * a whole second behind upstream's whenever the two clock reads straddle a second boundary.
   * These two fields exist so the derivation is visible, frozen by the conformance vectors,
   * and reproducible in Python at S9.
   */
  readonly notBeforeEpochSeconds: number;
  readonly notAfterEpochSeconds: number;
  /** `eth_call` data for `balanceOf(payer)`. */
  readonly balanceOfCallData: string;
}

function invalid(
  reason: string,
  schemaPath: string,
  context: Tx402ErrorContext,
): InvalidPaymentRequiredError {
  return new InvalidPaymentRequiredError(
    `Base payment requirement is unusable: ${reason}`,
    { context, details: { reason, schemaPath } },
  );
}

/** Encodes `balanceOf(owner)` call data. Frozen by the `evm.authorization-plan` vectors. */
export function encodeBalanceOfCallData(owner: string): string {
  if (!ADDRESS_PATTERN.test(owner)) {
    throw new TypeError("balanceOf owner must be a 20-byte hex address");
  }
  return `${BALANCE_OF_SELECTOR}${owner.slice(2).toLowerCase().padStart(64, "0")}`;
}

/**
 * Validates one policy-approved requirement and bounds the authorization it would produce.
 *
 * Everything checked here is checked *before* an address is resolved, a balance is read, or
 * a signer is invoked — an unusable offer costs no key access and no network round trip.
 */
export function planExactEvmAuthorization(input: ExactEvmPlanInput): ExactEvmPlan {
  const { requirement, network, asset, context } = input;

  if (requirement.scheme !== "exact") {
    throw new UnsupportedSchemeError("Base supports only the exact payment scheme", {
      context,
      details: {
        offeredSchemes: [requirement.scheme],
        offeredNetworks: [requirement.network],
        reason: "scheme-unsupported",
      },
    });
  }

  const transferMethod: unknown = requirement.extra.assetTransferMethod;
  if (transferMethod !== undefined && transferMethod !== SUPPORTED_ASSET_TRANSFER_METHOD) {
    throw new UnsupportedSchemeError(
      `Asset transfer method ${JSON.stringify(transferMethod)} is not supported in v0.1`,
      {
        context,
        details: {
          offeredSchemes: [requirement.scheme],
          offeredNetworks: [requirement.network],
          reason: "asset-transfer-method-unsupported",
        },
      },
    );
  }

  // The CAIP-2 identifier and the manifest's chain ID are two independent statements about
  // the same network. If they disagree, the manifest is the one that was signed.
  if (input.networkId !== `eip155:${network.chainId}`) {
    throw invalid("network-chain-id-mismatch", "/accepts/*/network", context);
  }
  if (requirement.network !== input.networkId) {
    throw invalid("network-not-canonical", "/accepts/*/network", context);
  }
  if (asset.address.toLowerCase() !== requirement.asset.toLowerCase()) {
    throw invalid("asset-not-manifest-asset", "/accepts/*/asset", context);
  }
  if (!ADDRESS_PATTERN.test(requirement.payTo)) {
    throw invalid("pay-to-invalid", "/accepts/*/payTo", context);
  }
  if (!ADDRESS_PATTERN.test(asset.address)) {
    throw invalid("asset-address-invalid", "/accepts/*/asset", context);
  }
  if (!ADDRESS_PATTERN.test(input.payer)) {
    throw invalid("payer-invalid", "/accepts/*/payTo", context);
  }

  // Upstream's EIP-3009 flow requires the token's EIP-712 domain name and version in
  // `extra`, and refuses to sign without them.
  const domainName = requirement.extra.name;
  const domainVersion = requirement.extra.version;
  if (
    typeof domainName !== "string" ||
    domainName.length === 0 ||
    typeof domainVersion !== "string" ||
    domainVersion.length === 0
  ) {
    throw invalid("eip712-domain-missing", "/accepts/*/extra", context);
  }
  // A version the token does not use produces a signature the token will reject on-chain.
  // Declining costs nothing; signing would burn a nonce and a reservation for nothing.
  if (asset.eip712Version !== undefined && asset.eip712Version !== domainVersion) {
    throw invalid("eip712-domain-mismatch", "/accepts/*/extra/version", context);
  }

  if (
    !Number.isInteger(requirement.maxTimeoutSeconds) ||
    requirement.maxTimeoutSeconds < 1
  ) {
    throw invalid("max-timeout-invalid", "/accepts/*/maxTimeoutSeconds", context);
  }
  if (!/^[1-9][0-9]*$/u.test(requirement.amountAtomic)) {
    throw invalid("amount-not-atomic-integer", "/accepts/*/amount", context);
  }

  const lifetimeSeconds = Math.min(
    input.maxAuthorizationSeconds,
    requirement.maxTimeoutSeconds,
  );
  const nowSeconds = Math.floor(input.nowEpochMs / 1000);

  return Object.freeze({
    chainId: network.chainId,
    verifyingContract: asset.address,
    domainName,
    domainVersion,
    payer: input.payer,
    recipient: requirement.payTo,
    valueAtomic: requirement.amountAtomic,
    lifetimeSeconds,
    validAfterSeconds: 0,
    notBeforeEpochSeconds: nowSeconds,
    notAfterEpochSeconds: nowSeconds + lifetimeSeconds,
    balanceOfCallData: encodeBalanceOfCallData(input.payer),
  });
}
