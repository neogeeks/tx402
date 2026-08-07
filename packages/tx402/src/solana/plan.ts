/** Deterministic SVM authorization plan, frozen for cross-language parity at M4. */

import { address } from "@solana/kit";

import {
  ConfigurationError,
  InvalidPaymentRequiredError,
  type Tx402ErrorContext,
} from "../core/errors.js";
import type { SvmManifestAsset, SvmManifestNetwork } from "../core/manifest.js";
import type { PolicyRequirement } from "../core/policy.js";
import { derivePaymentAtas } from "./signer.js";

export type ExactSvmRequirementInput = Pick<
  PolicyRequirement,
  | "index"
  | "scheme"
  | "network"
  | "asset"
  | "amountAtomic"
  | "payTo"
  | "maxTimeoutSeconds"
  | "extra"
>;

export interface ExactSvmPlan {
  readonly networkId: string;
  readonly genesisHash: string;
  readonly mint: string;
  readonly payer: string;
  readonly recipient: string;
  readonly feePayer: string;
  readonly sourceTokenAccount: string;
  readonly destinationTokenAccount: string;
  readonly amountAtomic: string;
  readonly decimals: number;
  readonly lifetimeSeconds: number;
  readonly recentBlockhash?: string;
  readonly lastValidBlockHeight: string;
  readonly memo?: string;
}

function invalid(
  message: string,
  reason: string,
  schemaPath: string,
  context: Tx402ErrorContext,
  cause?: unknown,
): InvalidPaymentRequiredError {
  return new InvalidPaymentRequiredError(message, {
    context,
    details: { reason, schemaPath },
    ...(cause === undefined ? {} : { cause }),
  });
}

function checkedAddress(
  value: unknown,
  reason: string,
  path: string,
  context: Tx402ErrorContext,
): string {
  if (typeof value !== "string") {
    throw invalid(
      "Solana requirement is missing an address",
      reason.replace(/-invalid$/u, "-missing"),
      path,
      context,
    );
  }
  try {
    return address(value).toString();
  } catch (error) {
    throw invalid(
      "Solana requirement contains an invalid address",
      reason,
      path,
      context,
      error,
    );
  }
}

function lastValidBlockHeight(extra: Readonly<Record<string, unknown>>): string {
  const value = extra.lastValidBlockHeight;
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value)) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return String(value);
  }
  return "0";
}

export async function planExactSvmAuthorization(input: {
  readonly requirement: ExactSvmRequirementInput;
  readonly networkId: string;
  readonly network: SvmManifestNetwork;
  readonly asset: SvmManifestAsset;
  readonly payer: string;
  readonly maxAuthorizationSeconds: number;
  readonly context: Tx402ErrorContext;
}): Promise<ExactSvmPlan> {
  const { requirement, networkId, network, asset, context } = input;
  if (asset.tokenProgram !== "spl-token") {
    throw new ConfigurationError("Solana asset is not canonical SPL Token", {
      context,
      details: { configPath: "manifest.networks", reason: "token-2022-excluded" },
    });
  }
  if (
    requirement.scheme !== "exact" ||
    requirement.network !== networkId ||
    requirement.asset !== asset.mint
  ) {
    throw invalid(
      "Solana requirement does not match the manifest exact-payment asset",
      "svm-route-mismatch",
      "/accepts",
      context,
    );
  }
  const payer = checkedAddress(input.payer, "svm-payer-invalid", "/payer", context);
  const recipient = checkedAddress(
    requirement.payTo,
    "svm-pay-to-invalid",
    "/payTo",
    context,
  );
  const feePayer = checkedAddress(
    requirement.extra.feePayer,
    "svm-feePayer-invalid",
    "/extra/feePayer",
    context,
  );
  const atas = await derivePaymentAtas({ mint: asset.mint, payer, recipient });
  const recentBlockhash = requirement.extra.recentBlockhash;
  const memo = requirement.extra.memo;
  return Object.freeze({
    networkId,
    genesisHash: network.genesisHash,
    mint: asset.mint,
    payer,
    recipient,
    feePayer,
    sourceTokenAccount: atas.source,
    destinationTokenAccount: atas.destination,
    amountAtomic: requirement.amountAtomic,
    decimals: asset.decimals,
    lifetimeSeconds: Math.min(
      60,
      input.maxAuthorizationSeconds,
      requirement.maxTimeoutSeconds,
    ),
    ...(typeof recentBlockhash === "string" ? { recentBlockhash } : {}),
    lastValidBlockHeight: lastValidBlockHeight(requirement.extra),
    ...(typeof memo === "string" ? { memo } : {}),
  });
}
