/**
 * Type declarations for the deterministic EVM JSON-RPC stub.
 *
 * Hand-written rather than emitted: the implementation is plain JavaScript so it can be
 * spawned without a build step, while every TypeScript test that talks to it is typechecked
 * under `strict`.
 */

/** How the stub behaves. See `index.js` for what each mode is testing. */
export type StubMode =
  "ok" | "wrong-chain" | "hang" | "rpc-error" | "http-error" | "garbage";

export interface EvmRpcStubOptions {
  chainId?: number;
  wrongChainId?: number;
  /** Owner address (any case) to atomic-unit balance string. */
  balances?: Record<string, string>;
  defaultBalance?: string;
  /** When set, calls to any other contract are refused. */
  token?: string;
  mode?: StubMode;
  port?: number;
}

export interface EvmRpcStub {
  readonly url: string;
  readonly port: number;
  readonly chainId: number;
  /** Every JSON-RPC call received, in order. */
  readonly calls: { method: string; params: unknown[] }[];
  readonly mode: StubMode;
  setMode(next: StubMode): void;
  setBalance(owner: string, atomic: string): void;
  reset(): void;
  close(): Promise<void>;
}

export declare function createEvmRpcStub(options?: EvmRpcStubOptions): Promise<EvmRpcStub>;
