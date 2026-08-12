/**
 * Type declarations for the deterministic, offline x402 facilitator stub.
 *
 * Hand-written rather than emitted: the implementation is plain JavaScript so it can be
 * spawned without a build step, while every TypeScript consumer that talks to it is
 * typechecked under `strict`.
 */

/** How the stub settles. See `index.js` for what each mode proves. */
export type FacilitatorMode = "settle" | "decline" | "invalid";

export interface MockFacilitatorOptions {
  mode?: FacilitatorMode;
  /** Advertised in `/supported.kinds[].extra.feePayer` for the SVM path. */
  feePayer?: string;
  /** The settlement hash reported on a successful settle; default synthetic. */
  transaction?: string;
  port?: number;
}

export interface MockFacilitator {
  readonly url: string;
  readonly port: number;
  readonly feePayer: string;
  /** Every `/verify` and `/settle` received, in order. */
  readonly calls: { path: string; body: unknown }[];
  readonly mode: FacilitatorMode;
  setMode(next: FacilitatorMode): void;
  reset(): void;
  close(): Promise<void>;
}

export declare function createMockFacilitator(
  options?: MockFacilitatorOptions,
): Promise<MockFacilitator>;
