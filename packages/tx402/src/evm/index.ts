/**
 * EVM chain adapter — Base.
 *
 * Optional subpath export (`tx402/evm`). Kept out of the core import path so that `viem` and
 * `@x402/evm` are only paid for by callers who import them (ADR-008, ADR-009). The core
 * client reaches this module through a lazy `import()` (see `core/chain.ts`), so importing
 * it directly is only necessary to construct a signer or to inspect a plan.
 *
 * Production network `eip155:8453`; test network `eip155:84532`, both from the signed
 * release manifest. v0.1 pays native USDC through upstream's exact scheme and exposes no
 * generic ERC-20 support (SPEC §7.1).
 *
 * @example
 * ```ts
 * import { createTx402Client } from "tx402";
 * import { privateKeyToEvmSigner } from "tx402/signers";
 *
 * const client = createTx402Client({
 *   signers: { evm: privateKeyToEvmSigner(process.env.DEV_KEY as `0x${string}`) },
 *   policy: { maxPerRequest: "0.50 USDC", allowedNetworks: ["eip155:8453"] },
 * });
 * ```
 */

export { createEvmChainAdapter } from "./adapter.js";
export type { EvmChainAdapterOptions } from "./adapter.js";

export {
  planExactEvmAuthorization,
  encodeBalanceOfCallData,
  BALANCE_OF_SELECTOR,
  SUPPORTED_ASSET_TRANSFER_METHOD,
} from "./plan.js";
export type { ExactEvmPlan, ExactEvmPlanInput, ExactEvmRequirementInput } from "./plan.js";

export { EvmRpcPool, EvmRpcError } from "./rpc.js";
export type { EvmBalanceReading, EvmRpcFailure, EvmRpcPoolOptions } from "./rpc.js";

export { resolveEvmAddress, toClientEvmSigner } from "./signer.js";
export type { EvmAuthorizationPlan, EvmSigningRecord } from "./signer.js";

/**
 * The signer contract itself lives on the core path — `Tx402ClientConfig.signers` has to
 * name it — and is re-exported here so that `tx402/evm` is a complete import site.
 */
export { isEvmSigner } from "../core/signers.js";
export type {
  EvmSigner,
  EvmSignerPresentation,
  EvmTypedDataDomain,
  EvmTypedDataField,
  EvmTypedDataRequest,
} from "../core/signers.js";
