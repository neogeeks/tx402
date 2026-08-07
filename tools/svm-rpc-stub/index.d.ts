export type SvmRpcStubMode =
  "ok" | "wrong-cluster" | "hang" | "rpc-error" | "http-error" | "garbage";

export interface StubTokenAccount {
  owner: string;
  mint: string;
  amount: string;
  decimals?: number;
}

export interface SvmRpcStubOptions {
  genesisHash?: string;
  wrongGenesisHash?: string;
  mint: string;
  decimals?: number;
  tokenAccounts?: Record<string, StubTokenAccount>;
  mode?: SvmRpcStubMode;
  port?: number;
}

export interface SvmRpcStub {
  readonly url: string;
  readonly port: number;
  readonly genesisHash: string;
  readonly calls: Array<{ method: string; params: unknown[] }>;
  readonly mode: SvmRpcStubMode;
  setMode(mode: SvmRpcStubMode): void;
  setTokenAccount(address: string, account: StubTokenAccount): void;
  reset(): void;
  close(): Promise<void>;
}

export function createSvmRpcStub(options: SvmRpcStubOptions): Promise<SvmRpcStub>;
