/** Minimal Solana JSON-RPC pool for cluster identity and canonical SPL ATA balances. */

import { findAssociatedTokenPda, TOKEN_PROGRAM_ADDRESS } from "@solana-program/token";
import { address } from "@solana/kit";

import { MAX_PROVIDERS_PER_NETWORK } from "../core/chain.js";
import { HealthIndex } from "../core/health.js";

export type SvmRpcFailure =
  | "circuit-open"
  | "genesis-hash-mismatch"
  | "genesis-hash-unreadable"
  | "account-unreadable"
  | "transport"
  | "timeout"
  | "protocol";

export class SvmRpcError extends Error {
  constructor(
    readonly failure: SvmRpcFailure,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "SvmRpcError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

interface Endpoint {
  readonly url: string;
  readonly label: string;
  /** `<caip2>|<host>` — this endpoint's key in the shared health index. */
  readonly healthId: string;
}

export interface SvmRpcPoolOptions {
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof globalThis.fetch;
  readonly maxProviders?: number;
  /**
   * The client's shared health index (SPEC §6.5, O22). The Solana pool carried its own
   * 30-second circuit at M4; it now reports into the same index as the EVM pool so one
   * provider cannot be simultaneously open here and closed there.
   */
  readonly health?: HealthIndex;
  readonly networkId?: string;
}

export interface SvmBalanceReading {
  readonly balanceAtomic: bigint;
  readonly tokenAccount: string;
  readonly endpoint: string;
  /** Exact endpoint URL. Sensitive only inside the adapter; never placed in diagnostics. */
  readonly rpcUrl: string;
  /** Health-index key of the endpoint that answered, for route scoring. */
  readonly endpointId: string;
}

interface JsonRpcEnvelope {
  readonly result?: unknown;
  readonly error?: unknown;
}

const UINT_PATTERN = /^(?:0|[1-9][0-9]*)$/u;

function safeLabel(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "invalid-rpc-url";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Races the RPC in tx402's own control flow. The abort signal is only socket cleanup; it is
 * not trusted to enforce the deadline (S5's Request/WeakRef failure).
 */
async function raceRpcDeadline<T>(
  work: Promise<T>,
  controller: AbortController,
  timeoutMs: number,
): Promise<T> {
  let rejectDeadline!: (reason: Error) => void;
  const expired = new Promise<never>((_resolve, reject) => {
    rejectDeadline = reject;
  });
  expired.catch(() => undefined);
  const timer = setTimeout(() => {
    const error = new Error(`Solana RPC deadline of ${timeoutMs} ms exceeded`);
    error.name = "TimeoutError";
    controller.abort(error);
    rejectDeadline(error);
  }, timeoutMs);
  timer.unref();
  try {
    return await Promise.race([work, expired]);
  } finally {
    clearTimeout(timer);
  }
}

export class SvmRpcPool {
  readonly #endpoints: Endpoint[];
  readonly #timeoutMs: number;
  readonly #fetch: typeof globalThis.fetch;
  readonly #health: HealthIndex;
  #requestId = 0;

  constructor(rpcUrls: readonly string[], options: SvmRpcPoolOptions = {}) {
    const networkId = options.networkId ?? "solana";
    this.#endpoints = rpcUrls
      .slice(0, options.maxProviders ?? MAX_PROVIDERS_PER_NETWORK)
      .map((url) => {
        const label = safeLabel(url);
        return { url, label, healthId: HealthIndex.endpointId(networkId, label) };
      });
    this.#timeoutMs = options.timeoutMs ?? 600;
    this.#fetch = options.fetchImpl ?? globalThis.fetch;
    this.#health = options.health ?? new HealthIndex();
  }

  resetHealth(): void {
    for (const endpoint of this.#endpoints) this.#health.forget(endpoint.healthId);
  }

  async readBalance(input: {
    readonly genesisHash: string;
    readonly mint: string;
    readonly owner: string;
    readonly decimals: number;
    readonly nowEpochMs: number;
  }): Promise<SvmBalanceReading> {
    const [tokenAccount] = await findAssociatedTokenPda({
      mint: address(input.mint),
      owner: address(input.owner),
      tokenProgram: TOKEN_PROGRAM_ADDRESS,
    });
    const attempted = new Set<string>();
    let last = new SvmRpcError("transport", "No Solana RPC returned an ATA balance");
    while (attempted.size < this.#endpoints.length) {
      const { endpoint, startedAt } = await this.#withValidatedEndpoint(
        input.genesisHash,
        input.nowEpochMs,
        attempted,
      );
      try {
        const result = await this.#call(endpoint, "getAccountInfo", [
          tokenAccount,
          { encoding: "jsonParsed", commitment: "confirmed" },
        ]);
        const balanceAtomic = parseTokenAccount(
          result,
          input.owner,
          input.mint,
          input.decimals,
        );
        this.#health.recordSuccess(
          endpoint.healthId,
          performance.now() - startedAt,
          input.nowEpochMs,
        );
        return {
          balanceAtomic,
          tokenAccount: tokenAccount.toString(),
          endpoint: endpoint.label,
          rpcUrl: endpoint.url,
          endpointId: endpoint.healthId,
        };
      } catch (error) {
        this.#health.recordFailure(endpoint.healthId, input.nowEpochMs);
        last =
          error instanceof SvmRpcError
            ? error
            : new SvmRpcError("account-unreadable", "SPL token account is unreadable", {
                cause: error,
              });
      }
    }
    throw last;
  }

  /** Selects an endpoint only after it proves its genesis hash immediately before signing. */
  async validatedRpcUrl(
    genesisHash: string,
    nowEpochMs: number,
  ): Promise<{
    readonly url: string;
    readonly endpoint: string;
    readonly endpointId: string;
  }> {
    const { endpoint, startedAt } = await this.#withValidatedEndpoint(
      genesisHash,
      nowEpochMs,
    );
    this.#health.recordSuccess(
      endpoint.healthId,
      performance.now() - startedAt,
      nowEpochMs,
    );
    return { url: endpoint.url, endpoint: endpoint.label, endpointId: endpoint.healthId };
  }

  /**
   * Finds an endpoint that has just proved its cluster, leaving its health observation open.
   *
   * The caller records the outcome, because the useful latency figure spans the whole use —
   * genesis proof plus whatever it was proved for — and an endpoint that answers
   * `getGenesisHash` quickly and then stalls on the account read has not been healthy.
   */
  async #withValidatedEndpoint(
    expectedGenesisHash: string,
    nowEpochMs: number,
    attempted: Set<string> = new Set(),
  ): Promise<{ endpoint: Endpoint; startedAt: number }> {
    if (this.#endpoints.length === 0) {
      throw new SvmRpcError("transport", "No RPC endpoint is configured for this cluster");
    }
    const available = this.#endpoints.filter((endpoint) => !attempted.has(endpoint.url));
    const usable = available.filter(
      (endpoint) => this.#health.state(endpoint.healthId, nowEpochMs) !== "open",
    );
    // SPEC §6.5: an open endpoint is a last resort, permitted only when all of them are.
    const lastResort = usable.length === 0;
    const order = lastResort ? available : usable;
    let last = new SvmRpcError("circuit-open", "Every Solana RPC endpoint is open");
    for (const endpoint of order) {
      attempted.add(endpoint.url);
      if (!lastResort && this.#health.admit(endpoint.healthId, nowEpochMs) === "open") {
        last = new SvmRpcError("circuit-open", "Solana RPC endpoint circuit is open");
        continue;
      }
      const startedAt = performance.now();
      try {
        const observed = await this.#call(endpoint, "getGenesisHash", []);
        if (typeof observed !== "string" || observed.length === 0) {
          throw new SvmRpcError(
            "genesis-hash-unreadable",
            "RPC returned a malformed genesis hash",
          );
        }
        if (observed !== expectedGenesisHash) {
          // SPEC §7.2's counterpart to the EVM chain-ID rule: the wrong cluster is not a
          // reliability signal to average, it is grounds to stop using this endpoint now.
          this.#health.open(endpoint.healthId, nowEpochMs);
          last = new SvmRpcError(
            "genesis-hash-mismatch",
            "RPC serves a different Solana cluster",
          );
          continue;
        }
        return { endpoint, startedAt };
      } catch (error) {
        this.#health.recordFailure(endpoint.healthId, nowEpochMs);
        last =
          error instanceof SvmRpcError
            ? error
            : new SvmRpcError("transport", "Solana RPC call failed", { cause: error });
      }
    }
    throw last;
  }

  async #call(endpoint: Endpoint, method: string, params: unknown[]): Promise<unknown> {
    this.#requestId += 1;
    const controller = new AbortController();
    let response: Response;
    try {
      response = await raceRpcDeadline(
        this.#fetch(endpoint.url, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: this.#requestId,
            method,
            params,
          }),
          signal: controller.signal,
        }),
        controller,
        this.#timeoutMs,
      );
    } catch (error) {
      const timedOut = error instanceof Error && error.name === "TimeoutError";
      throw new SvmRpcError(timedOut ? "timeout" : "transport", `${method} failed`, {
        cause: error,
      });
    }
    if (!response.ok) {
      throw new SvmRpcError("transport", `${method} returned HTTP ${response.status}`);
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch (error) {
      throw new SvmRpcError("protocol", `${method} returned non-JSON`, { cause: error });
    }
    if (!isRecord(body)) {
      throw new SvmRpcError("protocol", `${method} returned a non-object envelope`);
    }
    const envelope = body as JsonRpcEnvelope;
    if (envelope.error !== undefined || !("result" in envelope)) {
      throw new SvmRpcError("protocol", `${method} returned a JSON-RPC error`);
    }
    return envelope.result;
  }
}

function parseTokenAccount(
  result: unknown,
  expectedOwner: string,
  expectedMint: string,
  expectedDecimals: number,
): bigint {
  if (!isRecord(result) || !("value" in result)) {
    throw new SvmRpcError("account-unreadable", "getAccountInfo returned no value member");
  }
  if (result.value === null) return 0n;
  const value = result.value;
  if (!isRecord(value) || value.owner !== TOKEN_PROGRAM_ADDRESS.toString()) {
    throw new SvmRpcError("account-unreadable", "ATA is not owned by SPL Token");
  }
  const data = value.data;
  const parsed = isRecord(data) ? data.parsed : undefined;
  const info = isRecord(parsed) ? parsed.info : undefined;
  const tokenAmount = isRecord(info) ? info.tokenAmount : undefined;
  if (
    !isRecord(info) ||
    info.owner !== expectedOwner ||
    info.mint !== expectedMint ||
    !isRecord(tokenAmount) ||
    tokenAmount.decimals !== expectedDecimals ||
    typeof tokenAmount.amount !== "string" ||
    !UINT_PATTERN.test(tokenAmount.amount)
  ) {
    throw new SvmRpcError("account-unreadable", "ATA contents do not match the route");
  }
  return BigInt(tokenAmount.amount);
}
