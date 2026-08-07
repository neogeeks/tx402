/** tx402 `SolanaSigner` adapted to `@solana/kit`'s `TransactionPartialSigner`. */

import {
  findAssociatedTokenPda,
  parseTransferCheckedInstruction,
  TOKEN_PROGRAM_ADDRESS,
} from "@solana-program/token";
import {
  address,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  getTransactionEncoder,
  signatureBytes,
  type Transaction,
  type TransactionPartialSigner,
} from "@solana/kit";
import { COMPUTE_BUDGET_PROGRAM_ADDRESS, MEMO_PROGRAM_ADDRESS } from "@x402/svm";

import { SignerError, type Tx402ErrorContext } from "../core/errors.js";
import type { SolanaSigner, SolanaSignerPresentation } from "../core/signers.js";

const SOLANA_WIRE_TRANSACTION_MAX_BYTES = 1232;
const HEX_NONCE_PATTERN = /^[0-9a-f]{32}$/u;
const publicKeyCache = new WeakMap<SolanaSigner, Promise<string>>();

export interface ExactSvmAuthorizationPlan {
  readonly publicKey: string;
  readonly feePayer: string;
  readonly mint: string;
  readonly sourceTokenAccount: string;
  readonly destinationTokenAccount: string;
  readonly recipient: string;
  readonly amountAtomic: string;
  readonly decimals: number;
  readonly recentBlockhash?: string;
  readonly lastValidBlockHeight: string;
  readonly memo?: string;
}

export interface SvmSigningRecord {
  signCount: number;
  expiresAtEpochMs: number;
  serializedBytes: number;
}

function failure(
  message: string,
  causeCategory: string,
  context: Tx402ErrorContext,
  cause?: unknown,
): SignerError {
  return new SignerError(message, {
    context,
    details: { signerKind: "solana", causeCategory },
    ...(cause === undefined ? {} : { cause }),
  });
}

export async function resolveSolanaPublicKey(
  signer: SolanaSigner,
  context: Tx402ErrorContext,
): Promise<string> {
  const cached = publicKeyCache.get(signer);
  if (cached !== undefined) return cached;
  const pending = (async () => {
    const value = await signer.getPublicKey();
    try {
      return address(value).toString();
    } catch (error) {
      throw failure(
        "Signer returned a malformed Solana public key",
        "address-unavailable",
        context,
        error,
      );
    }
  })();
  publicKeyCache.set(signer, pending);
  try {
    return await pending;
  } catch (error) {
    publicKeyCache.delete(signer);
    throw error instanceof SignerError
      ? error
      : failure("Signer public-key lookup failed", "address-unavailable", context, error);
  }
}

function hasInstructionShape(value: unknown): value is {
  programAddress: ReturnType<typeof address>;
  accounts: readonly unknown[];
  data: Uint8Array;
} {
  return (
    typeof value === "object" &&
    value !== null &&
    "programAddress" in value &&
    "accounts" in value &&
    Array.isArray(value.accounts) &&
    "data" in value &&
    value.data instanceof Uint8Array
  );
}

/** Validates the complete unsigned authorization at the last pre-sign boundary. */
function validateTransaction(
  transaction: Transaction,
  plan: ExactSvmAuthorizationPlan,
  context: Tx402ErrorContext,
): { transactionBytes: Uint8Array } {
  let transactionBytes: Uint8Array;
  try {
    transactionBytes = new Uint8Array(getTransactionEncoder().encode(transaction));
  } catch (error) {
    throw failure(
      "Solana transaction could not be serialized",
      "transaction-invalid",
      context,
      error,
    );
  }
  if (transactionBytes.byteLength > SOLANA_WIRE_TRANSACTION_MAX_BYTES) {
    throw failure(
      "Solana transaction exceeds the serialized size limit",
      "transaction-too-large",
      context,
    );
  }

  let decompiled;
  try {
    const compiled = getCompiledTransactionMessageDecoder().decode(
      transaction.messageBytes,
    );
    if (
      plan.recentBlockhash !== undefined &&
      compiled.lifetimeToken !== plan.recentBlockhash
    ) {
      throw failure(
        "Solana transaction blockhash does not match the approved requirement",
        "plan-mismatch",
        context,
      );
    }
    decompiled = decompileTransactionMessage(compiled);
  } catch (error) {
    if (error instanceof SignerError) throw error;
    throw failure(
      "Solana transaction message could not be decoded",
      "transaction-invalid",
      context,
      error,
    );
  }

  if (decompiled.feePayer.address.toString() !== plan.feePayer) {
    throw failure(
      "Solana fee payer does not match the challenge",
      "plan-mismatch",
      context,
    );
  }
  const instructions = decompiled.instructions;
  if (instructions.length !== 4) {
    throw failure(
      "Solana authorization has an unexpected instruction count",
      "account-constraints",
      context,
    );
  }
  const [computeLimit, computePrice, transfer, memo] = instructions;
  if (
    computeLimit?.programAddress.toString() !== COMPUTE_BUDGET_PROGRAM_ADDRESS ||
    computePrice?.programAddress.toString() !== COMPUTE_BUDGET_PROGRAM_ADDRESS ||
    memo?.programAddress.toString() !== MEMO_PROGRAM_ADDRESS ||
    transfer?.programAddress.toString() !== TOKEN_PROGRAM_ADDRESS.toString()
  ) {
    throw failure(
      "Solana authorization contains an unsupported program",
      "account-constraints",
      context,
    );
  }
  if (!hasInstructionShape(transfer)) {
    throw failure("SPL transfer instruction is malformed", "transaction-invalid", context);
  }

  let parsed;
  try {
    parsed = parseTransferCheckedInstruction(transfer);
  } catch (error) {
    throw failure(
      "SPL transfer instruction could not be decoded",
      "transaction-invalid",
      context,
      error,
    );
  }
  const actual = {
    source: parsed.accounts.source.address.toString(),
    mint: parsed.accounts.mint.address.toString(),
    destination: parsed.accounts.destination.address.toString(),
    authority: parsed.accounts.authority.address.toString(),
  };
  if (
    actual.source !== plan.sourceTokenAccount ||
    actual.mint !== plan.mint ||
    actual.destination !== plan.destinationTokenAccount ||
    actual.authority !== plan.publicKey ||
    parsed.data.amount.toString() !== plan.amountAtomic ||
    parsed.data.decimals !== plan.decimals
  ) {
    throw failure(
      "SPL transfer accounts or amount do not match the approved route",
      "plan-mismatch",
      context,
    );
  }

  const memoBytes = memo?.data;
  if (!(memoBytes instanceof Uint8Array)) {
    throw failure("Solana memo instruction is malformed", "transaction-invalid", context);
  }
  const memoText = new TextDecoder().decode(memoBytes);
  if (
    (plan.memo !== undefined && memoText !== plan.memo) ||
    (plan.memo === undefined && !HEX_NONCE_PATTERN.test(memoText))
  ) {
    throw failure(
      "Solana transaction memo does not match the plan",
      "plan-mismatch",
      context,
    );
  }
  return { transactionBytes };
}

export function toTransactionSigner(input: {
  readonly signer: SolanaSigner;
  readonly plan: ExactSvmAuthorizationPlan;
  readonly presentation: Omit<
    SolanaSignerPresentation,
    "sourceTokenAccount" | "destinationTokenAccount" | "lastValidBlockHeight"
  >;
  readonly lifetimeSeconds: number;
  readonly record: SvmSigningRecord;
  readonly context: Tx402ErrorContext;
}): TransactionPartialSigner {
  const { signer, plan, presentation, lifetimeSeconds, record, context } = input;
  return {
    address: address(plan.publicKey),
    async signTransactions(transactions) {
      if (
        record.signCount > 0 ||
        transactions.length !== 1 ||
        transactions[0] === undefined
      ) {
        throw failure(
          "Scheme requested an unexpected number of Solana signatures",
          "duplicate-signature-request",
          context,
        );
      }
      const transaction = transactions[0];
      const validated = validateTransaction(transaction, plan, context);

      // Read the clock only after the transaction exists. This mirrors the S5 clock-boundary
      // fix: never compute a bound before the value it will constrain has been produced.
      record.expiresAtEpochMs = Date.now() + lifetimeSeconds * 1000;
      record.serializedBytes = validated.transactionBytes.byteLength;
      let rawSignature: Uint8Array;
      try {
        rawSignature = await signer.signTransaction({
          messageBytes: new Uint8Array(transaction.messageBytes),
          transactionBytes: validated.transactionBytes,
          presentation: Object.freeze({
            ...presentation,
            sourceTokenAccount: plan.sourceTokenAccount,
            destinationTokenAccount: plan.destinationTokenAccount,
            lastValidBlockHeight: plan.lastValidBlockHeight,
          }),
        });
      } catch (error) {
        throw error instanceof SignerError
          ? error
          : failure(
              "Solana signer rejected the transaction",
              "signing-failed",
              context,
              error,
            );
      }
      if (!(rawSignature instanceof Uint8Array) || rawSignature.byteLength !== 64) {
        throw failure(
          "Solana signer returned a malformed signature",
          "signature-malformed",
          context,
        );
      }
      record.signCount += 1;
      return [{ [plan.publicKey]: signatureBytes(rawSignature) }];
    },
  };
}

/** Derives the canonical SPL associated token accounts used by the upstream scheme. */
export async function derivePaymentAtas(input: {
  readonly mint: string;
  readonly payer: string;
  readonly recipient: string;
}): Promise<{ readonly source: string; readonly destination: string }> {
  const mint = address(input.mint);
  const [source] = await findAssociatedTokenPda({
    mint,
    owner: address(input.payer),
    tokenProgram: TOKEN_PROGRAM_ADDRESS,
  });
  const [destination] = await findAssociatedTokenPda({
    mint,
    owner: address(input.recipient),
    tokenProgram: TOKEN_PROGRAM_ADDRESS,
  });
  return { source: source.toString(), destination: destination.toString() };
}
