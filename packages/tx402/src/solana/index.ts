/**
 * SVM chain adapter — Solana.
 *
 * Optional subpath export (`tx402/solana`). Kept out of the core import path so that
 * `@solana/kit` and `@x402/svm` are only paid for by callers who import them.
 *
 * M4 exposes the `SolanaSigner` interface from SPEC §7.2, adapts it to
 * `@solana/kit`'s `TransactionSigner`, and resolves the
 * `solana:mainnet` alias to its canonical genesis-hash CAIP-2 identifier
 * (ADR-010 decisions 4 and 5).
 */

export { createSvmChainAdapter, type SvmChainAdapterOptions } from "./adapter.js";
export { SvmRpcError, SvmRpcPool, type SvmRpcPoolOptions } from "./rpc.js";
export {
  planExactSvmAuthorization,
  type ExactSvmPlan,
  type ExactSvmRequirementInput,
} from "./plan.js";
export {
  derivePaymentAtas,
  resolveSolanaPublicKey,
  toTransactionSigner,
  type ExactSvmAuthorizationPlan,
  type SvmSigningRecord,
} from "./signer.js";
export type {
  SolanaSigner,
  SolanaSignerPresentation,
  SolanaSignRequest,
} from "../core/signers.js";
