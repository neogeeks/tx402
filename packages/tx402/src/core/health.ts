/**
 * The unified endpoint health index and circuit breaker (SPEC §6.5, §6.4 step 17).
 *
 * **There is exactly one of these per client, and it is the only circuit in the SDK.** M3 and
 * M4 each shipped a small per-endpoint circuit inside their RPC pool because SPEC §7.1's
 * chain-ID rule and §7.2's genesis rule are security boundaries that could not wait for M5.
 * Those pools now hold no state of their own: they ask this index whether an endpoint may be
 * used and report what happened. Two circuits that disagree about the same endpoint is a bug
 * that reads as a flake, so the fix is structural — the state exists once.
 *
 * Everything here is **locally observed**. SEC-010 forbids trusting a remote party's claim
 * about its own health, so nothing an RPC or a merchant says about itself reaches this file;
 * only what tx402 measured itself does.
 *
 * ## Two ways a circuit opens, and why
 *
 * SPEC §6.5's thresholds — five consecutive failures, or half of at least ten samples — are
 * about an endpoint that is *unreliable*. SPEC §7.1 and §7.2 describe something else: an
 * endpoint that answered for the wrong chain. That is not a reliability signal to average
 * into a window, it is a MUST to stop using that endpoint now, so {@link HealthIndex.open}
 * exists alongside the thresholds and is called only for chain-identity failures.
 *
 * ## Determinism
 *
 * Route ordering reads {@link HealthIndex.score}, and SPEC §6.4 step 19 requires identical
 * ordering for identical inputs *and health state*. Scores are therefore rounded to four
 * decimal places with an explicit half-up rule rather than left as raw doubles: the Python
 * implementation at S10 must produce the same number, and `Math.round` and Python's `round`
 * disagree at a half. `floor(x * 10000 + 0.5) / 10000` agrees in both.
 */

/** SPEC §6.5. Applied to both latency and success rate. */
export const HEALTH_EWMA_ALPHA = 0.2;

/** SPEC §6.5: failures are counted over the last 20 observations. */
export const HEALTH_FAILURE_WINDOW = 20;

/** SPEC §6.5: five consecutive failures open the circuit. */
export const HEALTH_CONSECUTIVE_FAILURES_TO_OPEN = 5;

/** SPEC §6.5: or half the observations, once there are at least ten of them. */
export const HEALTH_MIN_SAMPLES_FOR_RATE = 10;
export const HEALTH_FAILURE_RATE_TO_OPEN = 0.5;

/** SPEC §6.5: an open circuit stays open for 30 s, then admits one probe. */
export const HEALTH_OPEN_MS = 30_000;

/** SPEC §6.5: health for an endpoint nothing has used for 30 minutes is dropped. */
export const HEALTH_IDLE_RETENTION_MS = 30 * 60_000;

/** SPEC §6.5: at most 128 endpoints are indexed, evicted least-recently-used first. */
export const HEALTH_MAX_ENDPOINTS = 128;

/** SPEC §6.4 step 17: an endpoint with no observations scores 0.80. */
export const HEALTH_NEW_ENDPOINT_SCORE = 0.8;

/**
 * Latency at which the full latency penalty applies.
 *
 * Deliberately the same 600 ms as the per-provider balance budget in SPEC §6.4 step 15: an
 * endpoint that consistently spends its whole budget has earned the maximum penalty, and one
 * that answers instantly earns none. Tying it to a figure SPEC already states avoids
 * inventing a constant that later has to be justified.
 */
export const HEALTH_LATENCY_REFERENCE_MS = 600;

/** The most a slow-but-working endpoint can lose from its score. */
export const HEALTH_LATENCY_PENALTY_MAX = 0.2;

/** Multipliers applied to a score by circuit state, so an open endpoint sorts far down. */
const CIRCUIT_MULTIPLIER = { closed: 1, "half-open": 0.5, open: 0.1 } as const;

export type CircuitState = "closed" | "open" | "half-open";

/**
 * Whether an endpoint may be used right now.
 *
 * `half-open` is an *admission*: the caller has been handed the single probe SPEC §6.5
 * allows, and must report the outcome so the probe is released.
 */
export type CircuitAdmission = "closed" | "half-open" | "open";

export interface EndpointHealth {
  readonly endpointId: string;
  readonly circuitState: CircuitState;
  readonly healthScore: number;
  /** EWMA latency in ms, or `undefined` when the endpoint has never answered. */
  readonly observedLatencyMs: number | undefined;
  readonly consecutiveFailures: number;
  readonly sampleCount: number;
}

interface Entry {
  /** Last 20 outcomes, oldest first. `true` is a success. */
  outcomes: boolean[];
  consecutiveFailures: number;
  latencyEwmaMs: number | undefined;
  successEwma: number;
  /** 0 when the circuit is closed. */
  openedAtEpochMs: number;
  probeInFlight: boolean;
  lastUsedEpochMs: number;
}

function round4(value: number): number {
  // Explicit half-up. See the determinism note above.
  return Math.floor(value * 10_000 + 0.5) / 10_000;
}

/**
 * Per-endpoint circuit state and health scoring, shared by every RPC pool in one client.
 *
 * Endpoint identifiers are `<caip2>|<host>` — a host, never a full URL, because an RPC URL's
 * path or query may carry a provider API key (SEC-003). Namespacing by network keeps a
 * provider that serves several chains from pooling one chain's outage into another's score.
 */
export class HealthIndex {
  /** Insertion order is recency order: reads and writes move an entry to the back. */
  readonly #entries = new Map<string, Entry>();
  readonly #maxEndpoints: number;

  constructor(options: { readonly maxEndpoints?: number } = {}) {
    this.#maxEndpoints = options.maxEndpoints ?? HEALTH_MAX_ENDPOINTS;
  }

  /** Composes the indexing key. Callers pass a host, never a URL with credentials in it. */
  static endpointId(networkId: string, host: string): string {
    return `${networkId}|${host}`;
  }

  get size(): number {
    return this.#entries.size;
  }

  /** Clears every observation. Never touches the spend ledger (SPEC §4.1). */
  reset(): void {
    this.#entries.clear();
  }

  /** Drops one endpoint's history, used when a pool is reset in isolation. */
  forget(endpointId: string): void {
    this.#entries.delete(endpointId);
  }

  /**
   * The circuit state without claiming the half-open probe.
   *
   * Use this for ordering and diagnostics; use {@link admit} to decide whether to send.
   */
  state(endpointId: string, nowEpochMs: number): CircuitState {
    const entry = this.#entries.get(endpointId);
    if (entry === undefined || entry.openedAtEpochMs === 0) return "closed";
    return nowEpochMs - entry.openedAtEpochMs < HEALTH_OPEN_MS ? "open" : "half-open";
  }

  /**
   * Asks for permission to use an endpoint, claiming the probe when one is available.
   *
   * Returns `open` when the endpoint must not be used — either the 30 s window is still
   * running, or the one half-open probe SPEC §6.5 allows is already in flight. A caller that
   * receives `closed` or `half-open` MUST report the outcome through {@link recordSuccess} or
   * {@link recordFailure}, or the probe is never released.
   */
  admit(endpointId: string, nowEpochMs: number): CircuitAdmission {
    const state = this.state(endpointId, nowEpochMs);
    if (state === "closed") return "closed";
    const entry = this.#entries.get(endpointId);
    if (entry === undefined) return "closed";
    if (state === "open" || entry.probeInFlight) return "open";
    entry.probeInFlight = true;
    this.#touch(endpointId, entry, nowEpochMs);
    return "half-open";
  }

  /**
   * Records a completed, successful use.
   *
   * A success on the far side of an open window is the one probe SPEC §6.5 needs to close the
   * circuit, and closing it discards the failure history that opened it — otherwise a
   * recovered endpoint would re-open on its next single failure.
   */
  recordSuccess(endpointId: string, latencyMs: number, nowEpochMs: number): void {
    const entry = this.#ensure(endpointId, nowEpochMs);
    const wasOpen = entry.openedAtEpochMs !== 0;
    entry.probeInFlight = false;
    if (wasOpen) {
      entry.openedAtEpochMs = 0;
      entry.outcomes = [];
    }
    entry.consecutiveFailures = 0;
    this.#observe(entry, true);
    const latency = Math.max(0, latencyMs);
    entry.latencyEwmaMs =
      entry.latencyEwmaMs === undefined
        ? latency
        : HEALTH_EWMA_ALPHA * latency + (1 - HEALTH_EWMA_ALPHA) * entry.latencyEwmaMs;
  }

  /**
   * Records a completed, failed use, opening the circuit if SPEC §6.5's thresholds are met.
   *
   * A failed half-open probe re-opens immediately: the endpoint had its one chance.
   */
  recordFailure(endpointId: string, nowEpochMs: number): void {
    const entry = this.#ensure(endpointId, nowEpochMs);
    const wasProbing = entry.probeInFlight;
    entry.probeInFlight = false;
    entry.consecutiveFailures += 1;
    this.#observe(entry, false);
    if (wasProbing || this.#shouldOpen(entry)) entry.openedAtEpochMs = nowEpochMs;
  }

  /**
   * Opens a circuit immediately, regardless of the failure window.
   *
   * Reserved for the chain-identity rules — SPEC §7.1's `eth_chainId` mismatch and §7.2's
   * genesis-hash mismatch. Those are not reliability observations to be averaged; they say
   * the endpoint is serving another chain, and both clauses require moving to the next RPC
   * rather than waiting for a threshold.
   */
  open(endpointId: string, nowEpochMs: number): void {
    const entry = this.#ensure(endpointId, nowEpochMs);
    entry.probeInFlight = false;
    entry.consecutiveFailures += 1;
    this.#observe(entry, false);
    entry.openedAtEpochMs = nowEpochMs;
  }

  /**
   * The SPEC §6.4 step 17 health score in [0, 1].
   *
   * `EWMA success − latency penalty`, scaled by circuit state. An endpoint with no history
   * scores exactly {@link HEALTH_NEW_ENDPOINT_SCORE}, which is what step 17 requires, and it
   * reaches that value by seeding the success EWMA rather than by a special case — so one
   * success moves a new endpoint up and one failure moves it down, symmetrically.
   */
  score(endpointId: string, nowEpochMs: number): number {
    const entry = this.#entries.get(endpointId);
    if (entry === undefined) return HEALTH_NEW_ENDPOINT_SCORE;
    const penalty = Math.min(
      HEALTH_LATENCY_PENALTY_MAX,
      ((entry.latencyEwmaMs ?? 0) / HEALTH_LATENCY_REFERENCE_MS) *
        HEALTH_LATENCY_PENALTY_MAX,
    );
    const scaled =
      (entry.successEwma - penalty) *
      CIRCUIT_MULTIPLIER[this.state(endpointId, nowEpochMs)];
    return round4(Math.min(1, Math.max(0, scaled)));
  }

  /** Everything ordering and diagnostics need about one endpoint, in one read. */
  inspect(endpointId: string, nowEpochMs: number): EndpointHealth {
    const entry = this.#entries.get(endpointId);
    return Object.freeze({
      endpointId,
      circuitState: this.state(endpointId, nowEpochMs),
      healthScore: this.score(endpointId, nowEpochMs),
      observedLatencyMs: entry?.latencyEwmaMs,
      consecutiveFailures: entry?.consecutiveFailures ?? 0,
      sampleCount: entry?.outcomes.length ?? 0,
    });
  }

  #shouldOpen(entry: Entry): boolean {
    if (entry.consecutiveFailures >= HEALTH_CONSECUTIVE_FAILURES_TO_OPEN) return true;
    const samples = entry.outcomes.length;
    if (samples < HEALTH_MIN_SAMPLES_FOR_RATE) return false;
    const failures = entry.outcomes.reduce((count, ok) => (ok ? count : count + 1), 0);
    return failures / samples >= HEALTH_FAILURE_RATE_TO_OPEN;
  }

  #observe(entry: Entry, ok: boolean): void {
    entry.outcomes.push(ok);
    if (entry.outcomes.length > HEALTH_FAILURE_WINDOW) entry.outcomes.shift();
    entry.successEwma =
      HEALTH_EWMA_ALPHA * (ok ? 1 : 0) + (1 - HEALTH_EWMA_ALPHA) * entry.successEwma;
  }

  #ensure(endpointId: string, nowEpochMs: number): Entry {
    const existing = this.#entries.get(endpointId);
    if (existing !== undefined) {
      this.#touch(endpointId, existing, nowEpochMs);
      return existing;
    }
    const entry: Entry = {
      outcomes: [],
      consecutiveFailures: 0,
      latencyEwmaMs: undefined,
      successEwma: HEALTH_NEW_ENDPOINT_SCORE,
      openedAtEpochMs: 0,
      probeInFlight: false,
      lastUsedEpochMs: nowEpochMs,
    };
    this.#entries.set(endpointId, entry);
    this.#evict(nowEpochMs);
    return entry;
  }

  /** Moves an entry to the back of the recency order and refreshes its idle clock. */
  #touch(endpointId: string, entry: Entry, nowEpochMs: number): void {
    entry.lastUsedEpochMs = nowEpochMs;
    this.#entries.delete(endpointId);
    this.#entries.set(endpointId, entry);
  }

  /**
   * Applies the 30-minute idle retention and the 128-entry LRU cap.
   *
   * Both walk from the front, which is the least recently used end, so this is bounded work
   * on a Map that is itself bounded — the memory-stability gate in SPEC §12.3 is met by
   * construction rather than by a periodic sweep.
   */
  #evict(nowEpochMs: number): void {
    for (const [endpointId, entry] of this.#entries) {
      if (nowEpochMs - entry.lastUsedEpochMs < HEALTH_IDLE_RETENTION_MS) break;
      this.#entries.delete(endpointId);
    }
    while (this.#entries.size > this.#maxEndpoints) {
      const oldest = this.#entries.keys().next();
      if (oldest.done === true) break;
      this.#entries.delete(oldest.value);
    }
  }
}
