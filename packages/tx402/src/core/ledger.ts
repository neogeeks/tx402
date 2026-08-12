/** Atomic rolling spend reservations (SPEC §5.3, §3, ADR-007, ADR-025/026/027/028, SEC-002). */

import { randomBytes } from "node:crypto";

import {
  BudgetExceededError,
  ConfigurationError,
  RecipientUnpinnedError,
  SpendScopeFrozenError,
} from "./errors.js";

export const RESERVATION_TTL_MS = 120_000;
export const ROLLING_WINDOW_MS = 3_600_000;

/**
 * The reservation lifecycle (SPEC §3.1). `exposed` (ADR-026, D-A2) is the durable
 * pre-transmission fence: a reservation that has been marked exposed no longer expires and
 * keeps consuming budget until an operator resolves it to `committed` or `released`.
 */
export type SpendReservationState =
  "reserved" | "committed" | "released" | "expired" | "exposed";

export interface SpendReservation {
  readonly reservationId: string;
  readonly policyScope: string;
  readonly requestFingerprint: string;
  readonly assetId: string;
  readonly amountAtomic: string;
  readonly createdAtEpochMs: number;
  readonly expiresAtEpochMs: number;
  readonly state: SpendReservationState;
}

export interface SpendEntry {
  readonly settlementId?: string;
  readonly reservationId: string;
  readonly requestFingerprint: string;
  readonly assetId: string;
  readonly amountAtomic: string;
  readonly committedAtEpochMs: number;
}

export interface SpendTotals {
  readonly committedAtomic: string;
  readonly reservedAtomic: string;
}

export interface BudgetState extends SpendTotals {
  readonly storeKind: string;
  readonly entries: readonly SpendEntry[];
  readonly reservations: readonly SpendReservation[];
  /**
   * The ledger these totals describe — the normalized merchant host (ADR-018).
   *
   * Absent only on the empty snapshot a client returns before it has paid anything. A
   * snapshot that reports figures always says which scope and asset they are for; the
   * a review found unlabelled zeros that belonged to no ledger at all.
   */
  readonly policyScope?: string;
  readonly assetId?: string;
  /** Sum of exposed (maybe-settled) reservations for this scope+asset (SPEC §7, ADR-026). */
  readonly exposedAtomic?: string;
  /** Lifetime committed for this scope+asset — survives the rolling window (ADR-025). */
  readonly cumulativeCommittedAtomic?: string;
  /** `cumulativeCommitted + exposedTotal + reservedOnly`, every amount in exactly one term. */
  readonly cumulativeConsumedAtomic?: string;
  /** Administered per-hour cap, when one is set in the store (ADR-025 §4.3). */
  readonly perHourLimitAtomic?: string;
  /** Administered cumulative cap, when one is set in the store (ADR-025 §4.3). */
  readonly cumulativeLimitAtomic?: string;
  /** Computed when a per-hour limit is known: `max(0, limit − rolling consumed)`. */
  readonly availablePerHourAtomic?: string;
  /** Computed when a cumulative limit is known: `max(0, limit − cumulativeConsumed)`. */
  readonly availableCumulativeAtomic?: string;
  /** True when `policyScope` OR the global `"*"` scope is frozen (ADR-027). */
  readonly frozen?: boolean;
}

export interface ReserveSpendInput {
  readonly reservationId?: string;
  readonly requestId: string;
  readonly policyScope: string;
  readonly requestFingerprint: string;
  readonly assetId: string;
  readonly amountAtomic: string;
  readonly maxPerHourAtomic: string;
  /** NEW (D-A1, ADR-025). Absent ⇒ no cumulative cap from the caller. */
  readonly maxTotalAtomic?: string;
  /**
   * NEW (ADR-028). The recipient the client is about to pay, asserted atomically inside
   * `reserve` against the store's authoritative recipient set (SPEC §6.2). Sent for BOTH
   * allowlist and TOFU modes. Recipient enforcement is authoritative in reserve.
   */
  readonly recipientNetwork?: string;
  readonly recipientCanonical?: string;
  /**
   * NEW (ADR-028). The caller's configured recipient-enforcement disposition; governs only
   * the no-record branch (SPEC §3.4 step 3). ABSENT is treated as `"off"`.
   */
  readonly recipientEnforcement?: "off" | "allowlist" | "tofu";
  /**
   * For a {@link MemorySpendStore} the caller's clock is authoritative (one process, one
   * clock). For a DURABLE store this is advisory only — the backend clock windows the
   * rolling hour so fleet clock skew cannot double-spend the cap (SPEC §3.4a, ADR-030).
   */
  readonly nowEpochMs: number;
}

/**
 * `reserve` returns a RESULT, not the bare reservation, so `recipientPinEstablished` is
 * response-only and never persisted — an idempotent ID-reuse replay returns `false` and does
 * not re-emit `recipient.pinned` (SPEC §3.2, ADR-028).
 */
export interface ReserveSpendResult {
  readonly reservation: SpendReservation;
  readonly recipientPinEstablished: boolean;
}

export interface CommitSpendInput {
  readonly reservationId: string;
  /** The ref fields (SPEC §3.1): the full `{policyScope, assetId, reservationId}` triple IS
   *  the reservation identity, because a sharded store routes by scope+asset. */
  readonly policyScope: string;
  readonly assetId: string;
  readonly committedAtEpochMs: number;
  readonly settlementId?: string;
}

export interface SpendQuery {
  readonly policyScope: string;
  readonly assetId: string;
  readonly nowEpochMs: number;
}

/**
 * A durable locator (SPEC §3.1, resolves P0-1). A bare reservation UUID cannot address a
 * record in a store sharded by scope+asset (Redis hash tag) or by scope (DO). Every
 * lifecycle op therefore takes a ref, not an id. `reserve` returns a {@link ReserveSpendResult}
 * whose `.reservation` is a superset of `ReservationRef`, so the client already holds one; an
 * operator obtains refs from `listExposed`/`getBudgetState`.
 */
export interface ReservationRef {
  readonly reservationId: string;
  readonly policyScope: string;
  readonly assetId: string;
}

/** Caps only (SPEC §3.1, ADR-025). Recipient policy has its own admin setters and is NOT here. */
export interface BudgetLimits {
  readonly maxPerHourAtomic?: string;
  readonly maxTotalAtomic?: string;
}

/** Declared store capabilities (SPEC §3.1, ADR-027). `atomicGlobalFreeze` gates the `"*"` freeze. */
export interface StoreCapabilities {
  readonly atomicGlobalFreeze: boolean;
}

/**
 * The pluggable spend ledger — the DATA plane (SPEC §3.1, §4.3, §5.3). Implement this to
 * share one budget across processes; the built-in {@link MemorySpendStore} is process-local.
 *
 * This is what `createTx402Client` accepts and what the agent process needs. The admin-plane
 * operations (freeze, administered limits, pin rotation, exposed reconciliation) live on the
 * separate {@link SpendStoreAdmin} interface with SEPARATE credentials and are never handed
 * to the agent path (ADR-029).
 *
 * The contract an adapter must honour, stated once so the Python `SpendStore` protocol and
 * this interface say the same thing (ADR-018):
 *
 *  - **`policyScope` is the normalized merchant host.** It is opaque to the store — the
 *    store must only ever compare it for equality, never parse it — but it is the key that
 *    makes two processes calling one merchant share one cap, so a store must not
 *    substitute its own.
 *  - **The full `{policyScope, assetId, reservationId}` triple IS the reservation identity.**
 *    A sharded store cannot detect a *wrong* scope — it routes to that scope's shard and
 *    finds nothing — so a ref whose triple names no record is a single typed
 *    `reservation-not-found` outcome, identical across every adapter (SPEC §3.1).
 *  - **`reserve` is atomic.** The cap comparison and the insert are one operation, or a
 *    concurrent pair of callers can both pass a cap only one of them fits under.
 *  - **`reserve` rejects an over-cap request with `BudgetExceededError`.** Any other
 *    exception is read as an outage: the client converts it to a retryable
 *    `TransportError`, because nothing has been signed yet.
 *  - **`commit`, `release` and `expose` are idempotent** for a reservation already in that
 *    terminal state; a replay returns the record and touches no counter.
 *  - **`resolveExposed` is NOT idempotent on replay** (U17). It transitions an `exposed`
 *    reservation exactly once; a second call — the reservation already committed/released —
 *    REFUSES with `ConfigurationError (reason: "reservation-already-terminal")`, so a retried
 *    reconciliation script must catch that refusal (SPEC §7, exposed-reconciliation runbook).
 *  - **A `commit` failure is money-relevant.** It happens after settlement, so the client
 *    converts it to `ResourceDeliveryError` with `paid: true` and does *not* release.
 *  - **`getBudgetState` is diagnostics** and may throw; the client swallows the failure
 *    rather than failing a paid request over a snapshot.
 */
export interface SpendStore {
  readonly kind: string;
  /** Declared capabilities. `atomicGlobalFreeze` gates the `"*"` freeze (SPEC §5.2). */
  readonly capabilities: StoreCapabilities;
  /** The cap comparison and reservation insert MUST be one atomic operation. */
  reserve(input: ReserveSpendInput): Promise<ReserveSpendResult>;
  commit(input: CommitSpendInput): Promise<SpendEntry>;
  release(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation>;
  /**
   * The durable PRE-transmission fence (SPEC §7, ADR-026). Records exposure BEFORE the
   * signature is transmitted; the reservation becomes non-expiring. Returns the fenced
   * reservation. The client wires the fence.
   */
  expose(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation>;
  getBudgetState(query: SpendQuery): Promise<BudgetState>;
  /**
   * Exposed (unresolved) reservations for a scope+asset, so an operator can reconcile without
   * already knowing reservation ids. Returns refs (as full reservations).
   */
  listExposed(query: SpendQuery): Promise<readonly SpendReservation[]>;
  /** Read-only. `reserve` performs its own atomic freeze check; this is for diagnostics/CLI. */
  isFrozen(scope: string): Promise<boolean>;
}

/**
 * Optional TOFU/allowlist capability (data-plane, SPEC §3.1, ADR-028). Enforcement is
 * authoritative INSIDE `reserve` (SPEC §3.4, resolves P0-6); these read/enumerate for the
 * pre-filter and the CLI. There is no standalone set-if-absent op on the request path — the
 * claim happens atomically within `reserve`.
 */
export interface RecipientPinStore {
  getRecipientPins(scope: string, network: string): Promise<readonly string[]>;
  /**
   * Inspectable recipient-policy state for a scope, so a `mode:"tofu"` client can fail closed
   * when the operator has not actually provisioned TOFU (SPEC §3.1, resolves the round-6
   * silent-disable P0).
   */
  getRecipientPolicy(
    scope: string,
  ): Promise<{ tofuEnabled: boolean; recipientAssertionRequired: boolean }>;
}

/**
 * The admin plane (SPEC §3.1, ADR-029). Operator only, SEPARATE credentials, NEVER handed to
 * the agent path. The reference {@link MemorySpendStore} implements this on the same object —
 * in-process it has no credential separation, which is acceptable and documented as
 * test-only; production separation requires a durable store with ACLs (SPEC §12).
 */
export interface SpendStoreAdmin {
  freeze(scope: string, nowEpochMs: number): Promise<void>;
  unfreeze(scope: string, nowEpochMs: number): Promise<void>;
  setRecipientPins(
    scope: string,
    network: string,
    recipients: readonly string[],
    nowEpochMs: number,
  ): Promise<void>;
  setBudgetLimits(
    scope: string,
    assetId: string,
    limits: BudgetLimits,
    nowEpochMs: number,
  ): Promise<void>;
  getBudgetLimits(scope: string, assetId: string): Promise<BudgetLimits>;
  /**
   * When set, `reserve` rejects a reservation that omits the recipient fields (SPEC §3.4 step
   * 3), so within the trusted-client scope a worker cannot silently skip recipient
   * enforcement for the scope. Behaviour is enforced in reserve.
   */
  setRecipientAssertionRequired(
    scope: string,
    required: boolean,
    nowEpochMs: number,
  ): Promise<void>;
  /**
   * Enable/disable TOFU first-use claim for a scope. `setRecipientPins` writes
   * source="admin-allowlist", a TOFU claim (only when enabled) writes source="tofu".
   */
  setTofuEnabled(scope: string, enabled: boolean, nowEpochMs: number): Promise<void>;
  /** Reconcile an exposed reservation once the operator has checked the chain (SPEC §7). */
  resolveExposed(
    ref: ReservationRef,
    outcome: "committed" | "released",
    nowEpochMs: number,
  ): Promise<void>;
  resetCumulative(scope: string, assetId: string, nowEpochMs: number): Promise<void>;
}

function uuidV7(nowEpochMs: number): string {
  const bytes = randomBytes(16);
  let timestamp = BigInt(Math.trunc(nowEpochMs));
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x70;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function atomic(value: string, field: string, positive = false): bigint {
  const pattern = positive ? /^[1-9][0-9]*$/u : /^(0|[1-9][0-9]*)$/u;
  if (!pattern.test(value))
    throw new TypeError(`${field} must be an atomic integer string`);
  return BigInt(value);
}

function frozenReservation(value: SpendReservation): SpendReservation {
  return Object.freeze({ ...value });
}

function frozenEntry(value: SpendEntry): SpendEntry {
  return Object.freeze({ ...value });
}

// A NUL is illegal in a normalized host and never appears in an asset id or UUID, so it is a
// safe, unambiguous separator for the composite reservation key and the scope+asset key.
const SEP = "\u0000";

// The asset segment is canonicalized (SPEC §6.4, `canonicalizeAsset`) so a reservation/limit keyed
// under a checksummed asset and one under its lowercase form address the SAME ledger (U16).
function refKey(policyScope: string, assetId: string, reservationId: string): string {
  return `${policyScope}${SEP}${canonicalizeAsset(assetId)}${SEP}${reservationId}`;
}

function scopeAssetKey(policyScope: string, assetId: string): string {
  return `${policyScope}${SEP}${canonicalizeAsset(assetId)}`;
}

function pinKey(scope: string, network: string): string {
  return `${scope}${SEP}${network}`;
}

/**
 * The typed envelope for a ref that names no record (SPEC §3.1/§3.4). Every adapter returns
 * this same outcome because the map is keyed by the composite triple, not the bare UUID.
 */
function reservationNotFound(ref: ReservationRef): ConfigurationError {
  return new ConfigurationError("The reservation ref names no record", {
    context: {
      requestId: "spend-store",
      phase: "policy",
      reservationId: ref.reservationId,
    },
    details: { configPath: "reservationRef", reason: "reservation-not-found" },
  });
}

/** A typed lifecycle-transition refusal (SPEC §3.4 error table). All are `ConfigurationError`. */
function lifecycleError(reason: string, ref: ReservationRef): ConfigurationError {
  return new ConfigurationError(`The reservation lifecycle transition is not permitted`, {
    context: {
      requestId: "spend-store",
      phase: "policy",
      reservationId: ref.reservationId,
    },
    details: { configPath: "reservation.lifecycle", reason },
  });
}

function maxBig(value: bigint): string {
  return (value > 0n ? value : 0n).toString();
}

/**
 * Canonicalize a recipient address for pin comparison (SPEC §6.4). eip155 → lowercase hex (the
 * `sameAddress` rule; no EIP-55 checksum re-derivation). Every other family (solana) → verbatim,
 * since base58 is injective and case-sensitive. Core-path: no chain libraries. Idempotent, so a
 * store may canonicalize a value the client already canonicalized without changing it.
 */
export function canonicalizeRecipient(network: string, value: string): string {
  return network.startsWith("eip155:") ? value.toLowerCase() : value;
}

/**
 * Canonicalize a CAIP-19 `assetId` for ledger keying (SPEC §4.2 "per normalized host + asset",
 * §6.4 canonicalization). eip155 assets → lowercase (the `erc20:0x…` contract address is hex and
 * the `eip155:<chain>` prefix is numeric, so lowercasing the whole id is equivalent to the §6.4
 * `sameAddress` rule; no EIP-55 checksum is derived or required). Every other family (solana,
 * whose `token:<mint>` is case-sensitive base58) → verbatim. Core-path: no chain libraries.
 * Idempotent, so a store may canonicalize a value already canonical without changing it.
 *
 * This mirrors {@link canonicalizeRecipient} and closes the recipient-vs-asset asymmetry (U16):
 * an administered cap set under one casing (e.g. the manifest's checksummed asset vs a lowercase
 * copy in a runbook) binds a reserve keyed under the other. The frozen SPEC §12.2 key *template*
 * (`<asset>`) is unchanged — only the value that fills it is normalized before keying.
 */
export function canonicalizeAsset(assetId: string): string {
  return assetId.startsWith("eip155:") ? assetId.toLowerCase() : assetId;
}

/**
 * A `RecipientUnpinnedError` with the SPEC §6.5/§8 conditional details (RP-8): `merchantScope`
 * and `reason` are ALWAYS present; `network`, `presentedRecipient`, and `expectedRecipients` are
 * supplied together only for `not-allowlisted`/`pin-mismatch` (a mismatch against a known set)
 * and are ABSENT for `assertion-required`.
 */
function recipientUnpinned(
  input: ReserveSpendInput,
  reason: "not-allowlisted" | "pin-mismatch" | "assertion-required",
  extra?: {
    readonly network: string;
    readonly presentedRecipient: string;
    readonly expectedRecipients: readonly string[];
  },
): RecipientUnpinnedError {
  return new RecipientUnpinnedError("The recipient is not pinned for this scope", {
    context: { requestId: input.requestId, phase: "policy", assetId: input.assetId },
    details: { merchantScope: input.policyScope, reason, ...(extra ?? {}) },
  });
}

/**
 * A caller cap that EXCEEDS the store-administered cap for a dimension (SPEC §3.4 step 4, D-A3).
 * Configuration, not a budget decision: a drifted or hostile worker cannot widen the operator's
 * ceiling by presenting a looser number. Raised BEFORE the budget arithmetic of steps 5/6, so
 * the lowered-cap precedence never collides — an over-cap *number* is config, an over-cap
 * *position* is `BudgetExceededError` (§4.3, ADR-025 §3).
 */
function capExceedsAdministered(configPath: string): ConfigurationError {
  return new ConfigurationError("Caller cap exceeds the store-administered cap", {
    context: { requestId: "spend-store", phase: "policy" },
    details: { configPath, reason: "cap-exceeds-administered" },
  });
}

/**
 * The effective cap for one dimension: `min(caller, administered)` when both exist, else
 * whichever is present (SPEC §3.4 step 4). A caller cap GREATER than an administered one is
 * rejected; a stricter (smaller) caller cap is honoured via the `min`. Administered caps are
 * non-negative (a `0` cap admits nothing); caller caps are validated positive by the caller.
 */
function resolveEffectiveCap(
  caller: bigint | undefined,
  administeredAtomic: string | undefined,
  configPath: string,
): bigint | undefined {
  if (administeredAtomic === undefined) return caller;
  const administered = atomic(administeredAtomic, "administeredCap");
  if (caller === undefined) return administered;
  if (caller > administered) throw capExceedsAdministered(configPath);
  return caller; // caller ≤ administered, so the min is the caller
}

/**
 * Process-local store implementing BOTH the data plane and the admin plane on one object
 * (SPEC §3.5). Each method mutates synchronously before its Promise resolves, so the cap
 * comparison and insert stay one event-loop turn.
 *
 * Accounting model (SPEC §3.4/§3.4a):
 *  - `#cumulative` and `#exposedTotal` are lifetime per-(scope,asset) accumulators. The
 *    committed lifetime figure cannot be derived by scanning, because committed entries are
 *    pruned once they fall out of the rolling window; the exposed lifetime figure is a
 *    parallel accumulator mirroring the durable stores (Redis/DO), where a scan is not cheap.
 *  - Rolling-hour figures (`committedAtomic`, `reservedAtomic`, and the windowed exposed term
 *    the per-hour cap uses) are derived from the persisted records.
 *  - This store uses the caller's `nowEpochMs`: one process, one clock, no skew (ADR-030).
 */
export class MemorySpendStore implements SpendStore, RecipientPinStore, SpendStoreAdmin {
  readonly kind = "memory";
  // Single process: the global `"*"` freeze is atomic with respect to every reserve (ADR-027).
  readonly capabilities: StoreCapabilities = Object.freeze({ atomicGlobalFreeze: true });
  readonly #reservations = new Map<string, SpendReservation>();
  readonly #entries = new Map<string, SpendEntry>();
  readonly #cumulative = new Map<string, bigint>();
  readonly #exposedTotal = new Map<string, bigint>();
  readonly #frozen = new Set<string>();
  readonly #limits = new Map<string, BudgetLimits>();
  readonly #pins = new Map<
    string,
    { readonly recipients: readonly string[]; readonly source: "admin-allowlist" | "tofu" }
  >();
  readonly #recipientPolicy = new Map<
    string,
    { tofuEnabled: boolean; recipientAssertionRequired: boolean }
  >();

  #maintain(nowEpochMs: number): void {
    const cutoff = nowEpochMs - ROLLING_WINDOW_MS;
    for (const [id, reservation] of this.#reservations) {
      let current = reservation;
      if (current.state === "reserved" && current.expiresAtEpochMs <= nowEpochMs) {
        current = frozenReservation({ ...current, state: "expired" });
        this.#reservations.set(id, current);
      }
      // An exposed record never expires and is never pruned until an operator resolves it
      // (ADR-026): it is maybe-settled money that keeps consuming the cumulative cap.
      if (current.state === "exposed") continue;
      const committedEntry = this.#entries.get(id);
      if (
        current.createdAtEpochMs < cutoff &&
        current.state !== "reserved" &&
        (current.state !== "committed" ||
          committedEntry === undefined ||
          committedEntry.committedAtEpochMs < cutoff)
      ) {
        this.#reservations.delete(id);
      }
    }
    for (const [id, entry] of this.#entries) {
      if (entry.committedAtEpochMs < cutoff) this.#entries.delete(id);
    }
  }

  #matching(query: SpendQuery): {
    entries: SpendEntry[];
    reservations: SpendReservation[];
    committed: bigint;
    reserved: bigint;
    exposedRolling: bigint;
  } {
    this.#maintain(query.nowEpochMs);
    const cutoff = query.nowEpochMs - ROLLING_WINDOW_MS;
    const queryAsset = canonicalizeAsset(query.assetId);
    const reservations = [...this.#reservations.values()].filter(
      (reservation) =>
        reservation.policyScope === query.policyScope &&
        canonicalizeAsset(reservation.assetId) === queryAsset,
    );
    const entries: SpendEntry[] = [];
    for (const reservation of reservations) {
      if (reservation.state !== "committed") continue;
      const entry = this.#entries.get(
        refKey(query.policyScope, query.assetId, reservation.reservationId),
      );
      if (
        entry !== undefined &&
        entry.committedAtEpochMs >= cutoff &&
        entry.committedAtEpochMs <= query.nowEpochMs
      ) {
        entries.push(entry);
      }
    }
    const committed = entries.reduce(
      (sum, entry) => sum + atomic(entry.amountAtomic, "amountAtomic", true),
      0n,
    );
    const reserved = reservations.reduce(
      (sum, reservation) =>
        reservation.state === "reserved" &&
        reservation.createdAtEpochMs >= cutoff &&
        reservation.createdAtEpochMs <= query.nowEpochMs &&
        reservation.expiresAtEpochMs > query.nowEpochMs
          ? sum + atomic(reservation.amountAtomic, "amountAtomic", true)
          : sum,
      0n,
    );
    // Exposed reservations count toward the per-hour cap only while they are inside the
    // rolling window; they count toward the cumulative cap forever (via #exposedTotal).
    const exposedRolling = reservations.reduce(
      (sum, reservation) =>
        reservation.state === "exposed" &&
        reservation.createdAtEpochMs >= cutoff &&
        reservation.createdAtEpochMs <= query.nowEpochMs
          ? sum + atomic(reservation.amountAtomic, "amountAtomic", true)
          : sum,
      0n,
    );
    return { entries, reservations, committed, reserved, exposedRolling };
  }

  // No await by design: cap comparison and insert must remain one event-loop turn.
  // eslint-disable-next-line @typescript-eslint/require-await
  async reserve(input: ReserveSpendInput): Promise<ReserveSpendResult> {
    const amount = atomic(input.amountAtomic, "amountAtomic", true);
    const cap = atomic(input.maxPerHourAtomic, "maxPerHourAtomic", true);
    const existingId = input.reservationId;
    if (existingId !== undefined) {
      const existing = this.#reservations.get(
        refKey(input.policyScope, input.assetId, existingId),
      );
      if (existing !== undefined) {
        if (
          existing.requestFingerprint !== input.requestFingerprint ||
          existing.amountAtomic !== input.amountAtomic
        ) {
          throw new Error("Reservation ID was reused with different spend data");
        }
        // No pin is claimed on a replay — the flag is response-only (ADR-028, SPEC §3.4 step 1).
        return Object.freeze({ reservation: existing, recipientPinEstablished: false });
      }
    }
    // Freeze (SPEC §3.4 step 2, D-B1): deny if this scope OR the global "*" scope is frozen.
    // In this single-process store the check and the insert are one event-loop turn, so the
    // freeze is atomic with respect to every reserve — `atomicGlobalFreeze` is true (ADR-027).
    // A stop-future-authorization control, never a rollback: an existing reservation (including
    // an `exposed` one) keeps counting across a freeze, and unfreeze preserves it (KS-7, §5.4).
    if (this.#frozen.has(input.policyScope) || this.#frozen.has("*")) {
      const frozenScope = this.#frozen.has(input.policyScope) ? input.policyScope : "*";
      throw new SpendScopeFrozenError("Spending is frozen for this scope", {
        context: {
          requestId: input.requestId,
          phase: "policy",
          amountAtomic: input.amountAtomic,
          assetId: input.assetId,
        },
        details: { scope: input.policyScope, frozenScope },
      });
    }
    // Recipient assertion (SPEC §3.4 step 3, ADR-028), driven by the STORE's administered source,
    // never the caller's mode — so a compromised caller cannot relax a mismatch or an
    // assertion-required. `recipientEnforcement` governs ONLY the no-record disposition, and its
    // absence is "off". A store READ failure here would be infrastructure unavailability (a
    // generic error reserveOrFail maps to a retryable TransportError, SS-11) — never a
    // RecipientUnpinnedError; the in-memory store cannot fail this read.
    const recipientNetwork = input.recipientNetwork;
    // Treat an empty `recipientCanonical` as NOT presented (guard on `undefined` OR ""), so the
    // assertion-required gate below fails closed — matching the durable Redis (`recipientCanonical
    // ~= ''`) and DO (truthiness) stores. Without the "" case the reference/default store would be
    // the permissive one on a safety gate (O56); an empty recipient also matches no real allowlist.
    const presentedRecipient =
      input.recipientCanonical === undefined ||
      input.recipientCanonical === "" ||
      recipientNetwork === undefined
        ? undefined
        : canonicalizeRecipient(recipientNetwork, input.recipientCanonical);
    const recipientPolicy = this.#recipientPolicy.get(input.policyScope);
    let recipientPinEstablished = false;
    if (
      recipientPolicy?.recipientAssertionRequired === true &&
      (presentedRecipient === undefined || recipientNetwork === undefined)
    ) {
      throw recipientUnpinned(input, "assertion-required");
    }
    if (presentedRecipient !== undefined && recipientNetwork !== undefined) {
      const record = this.#pins.get(pinKey(input.policyScope, recipientNetwork));
      if (record !== undefined) {
        const expectedRecipients = record.recipients.map((value) =>
          canonicalizeRecipient(recipientNetwork, value),
        );
        if (!expectedRecipients.includes(presentedRecipient)) {
          throw recipientUnpinned(
            input,
            record.source === "admin-allowlist" ? "not-allowlisted" : "pin-mismatch",
            { network: recipientNetwork, presentedRecipient, expectedRecipients },
          );
        }
      } else if ((input.recipientEnforcement ?? "off") === "tofu") {
        // No record, and the caller enforces TOFU: claim-if-absent IN THIS ATOM (reading
        // `tofuEnabled` inside the atom closes the round-6 TOCTOU). Only "tofu" ever claims;
        // "allowlist" here is advisory (allowlist wins, TOFU fills gaps) and "off" admits.
        if (recipientPolicy?.tofuEnabled !== true) {
          throw new ConfigurationError("Recipient TOFU is not provisioned for this scope", {
            context: {
              requestId: input.requestId,
              phase: "policy",
              assetId: input.assetId,
            },
            details: {
              configPath: "recipientPolicy",
              reason: "recipient-tofu-not-provisioned",
            },
          });
        }
        this.#pins.set(pinKey(input.policyScope, recipientNetwork), {
          recipients: Object.freeze([presentedRecipient]),
          source: "tofu",
        });
        recipientPinEstablished = true;
      }
    }
    // Step 4 (D-A3, §4.3): resolve each dimension against any administered cap. `min` honours a
    // stricter caller cap; a caller cap that exceeds the administered one is rejected as
    // configuration, before any budget arithmetic (so the lowered-cap precedence never collides).
    const saKey = scopeAssetKey(input.policyScope, input.assetId);
    const administered = this.#limits.get(saKey);
    const effectiveMaxPerHour = resolveEffectiveCap(
      cap,
      administered?.maxPerHourAtomic,
      "policy.maxPerHour",
    ) as bigint; // caller maxPerHour is always present, so the effective cap is always defined
    const effectiveMaxTotal = resolveEffectiveCap(
      input.maxTotalAtomic === undefined
        ? undefined
        : atomic(input.maxTotalAtomic, "maxTotalAtomic", true),
      administered?.maxTotalAtomic,
      "policy.maxTotal",
    );
    const current = this.#matching(input);
    // Step 5 — per-hour cap over the rolling window; the three terms are disjoint (§3.4 step 5).
    if (
      current.committed + current.reserved + current.exposedRolling + amount >
      effectiveMaxPerHour
    ) {
      throw new BudgetExceededError("Hourly spend limit would be exceeded", {
        context: {
          requestId: input.requestId,
          phase: "policy",
          amountAtomic: input.amountAtomic,
          assetId: input.assetId,
        },
        details: {
          requestedAtomic: input.amountAtomic,
          capAtomic: effectiveMaxPerHour.toString(),
          committedAtomic: current.committed.toString(),
          reservedAtomic: (current.reserved + current.exposedRolling).toString(),
          capKind: "per-hour",
        },
      });
    }
    // Step 6 — cumulative cap, only when one is in effect. `reservedOnly` is state==="reserved"
    // reservations only; exposed is counted exactly once through `exposedTotal` (§3.4 step 6,
    // resolves P1-5, the prior double-count). This is the same lifetime sum getBudgetState
    // reports as `cumulativeConsumedAtomic`.
    if (effectiveMaxTotal !== undefined) {
      const cumulativeCommitted = this.#cumulative.get(saKey) ?? 0n;
      const exposedTotal = this.#exposedTotal.get(saKey) ?? 0n;
      const reservedOnly = current.reserved;
      if (cumulativeCommitted + exposedTotal + reservedOnly + amount > effectiveMaxTotal) {
        throw new BudgetExceededError("Cumulative spend limit would be exceeded", {
          context: {
            requestId: input.requestId,
            phase: "policy",
            amountAtomic: input.amountAtomic,
            assetId: input.assetId,
          },
          details: {
            requestedAtomic: input.amountAtomic,
            capAtomic: effectiveMaxTotal.toString(),
            committedAtomic: cumulativeCommitted.toString(),
            reservedAtomic: (exposedTotal + reservedOnly).toString(),
            capKind: "cumulative",
          },
        });
      }
    }
    const reservation = frozenReservation({
      reservationId: input.reservationId ?? uuidV7(input.nowEpochMs),
      policyScope: input.policyScope,
      requestFingerprint: input.requestFingerprint,
      // Stored canonical (SPEC §6.4, U16) so every adapter round-trips one form; the client threads
      // this back for commit/release/expose and the key derivation canonicalizes again (idempotent).
      assetId: canonicalizeAsset(input.assetId),
      amountAtomic: input.amountAtomic,
      createdAtEpochMs: input.nowEpochMs,
      expiresAtEpochMs: input.nowEpochMs + RESERVATION_TTL_MS,
      state: "reserved",
    });
    this.#reservations.set(
      refKey(reservation.policyScope, reservation.assetId, reservation.reservationId),
      reservation,
    );
    // `recipientPinEstablished` is response-only and never persisted (ADR-028): a later id-reuse
    // replay returns the record above with the flag false and re-emits no `recipient.pinned`.
    return Object.freeze({ reservation, recipientPinEstablished });
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async commit(input: CommitSpendInput): Promise<SpendEntry> {
    const key = refKey(input.policyScope, input.assetId, input.reservationId);
    const existing = this.#entries.get(key);
    if (existing !== undefined) return existing;
    this.#maintain(input.committedAtEpochMs);
    const reservation = this.#reservations.get(key);
    if (reservation === undefined)
      throw reservationNotFound({
        reservationId: input.reservationId,
        policyScope: input.policyScope,
        assetId: input.assetId,
      });
    if (reservation.state === "released")
      throw lifecycleError("released-cannot-commit", reservation);
    // The pre-transmission fence means a legitimate payment is `exposed` before it settles;
    // an `expired` reservation can never legitimately commit, and permitting it would breach
    // the cumulative cap (SPEC §3.4, a named 0.2.0 break — shipped v0.1 permitted it).
    if (reservation.state === "expired")
      throw lifecycleError("expired-cannot-commit", reservation);
    const amount = atomic(reservation.amountAtomic, "amountAtomic", true);
    const saKey = scopeAssetKey(input.policyScope, input.assetId);
    const entry = frozenEntry({
      reservationId: reservation.reservationId,
      requestFingerprint: reservation.requestFingerprint,
      assetId: reservation.assetId,
      amountAtomic: reservation.amountAtomic,
      committedAtEpochMs: input.committedAtEpochMs,
      // An empty settlementId is "no settlement id" — omit it, matching Redis/DO so every adapter
      // round-trips an empty id as absent, not `""` (O27).
      ...(input.settlementId ? { settlementId: input.settlementId } : {}),
    });
    this.#entries.set(key, entry);
    this.#reservations.set(key, frozenReservation({ ...reservation, state: "committed" }));
    this.#cumulative.set(saKey, (this.#cumulative.get(saKey) ?? 0n) + amount);
    if (reservation.state === "exposed") {
      this.#exposedTotal.set(saKey, (this.#exposedTotal.get(saKey) ?? 0n) - amount);
    }
    return entry;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async release(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation> {
    this.#maintain(nowEpochMs);
    const key = refKey(ref.policyScope, ref.assetId, ref.reservationId);
    const reservation = this.#reservations.get(key);
    if (reservation === undefined) throw reservationNotFound(ref);
    if (reservation.state === "reserved") {
      const released = frozenReservation({ ...reservation, state: "released" });
      this.#reservations.set(key, released);
      return released;
    }
    if (reservation.state === "exposed") {
      const released = frozenReservation({ ...reservation, state: "released" });
      this.#reservations.set(key, released);
      const saKey = scopeAssetKey(ref.policyScope, ref.assetId);
      this.#exposedTotal.set(
        saKey,
        (this.#exposedTotal.get(saKey) ?? 0n) -
          atomic(reservation.amountAtomic, "amountAtomic", true),
      );
      return released;
    }
    // committed / released / expired: replay → return the record unchanged (matches shipped).
    return reservation;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async expose(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation> {
    this.#maintain(nowEpochMs);
    const key = refKey(ref.policyScope, ref.assetId, ref.reservationId);
    const reservation = this.#reservations.get(key);
    if (reservation === undefined) throw reservationNotFound(ref);
    if (reservation.state === "exposed") return reservation; // replay, no counter change
    if (reservation.state !== "reserved")
      throw lifecycleError("reservation-already-terminal", reservation);
    // Clear expiry by moving to `exposed`: #maintain never expires or prunes an exposed record.
    const exposed = frozenReservation({ ...reservation, state: "exposed" });
    this.#reservations.set(key, exposed);
    const saKey = scopeAssetKey(ref.policyScope, ref.assetId);
    this.#exposedTotal.set(
      saKey,
      (this.#exposedTotal.get(saKey) ?? 0n) +
        atomic(reservation.amountAtomic, "amountAtomic", true),
    );
    return exposed;
  }

  async resolveExposed(
    ref: ReservationRef,
    outcome: "committed" | "released",
    nowEpochMs: number,
  ): Promise<void> {
    this.#maintain(nowEpochMs);
    const key = refKey(ref.policyScope, ref.assetId, ref.reservationId);
    const reservation = this.#reservations.get(key);
    if (reservation === undefined) throw reservationNotFound(ref);
    if (reservation.state === "reserved")
      throw lifecycleError("reservation-not-exposed", reservation);
    if (reservation.state !== "exposed")
      throw lifecycleError("reservation-already-terminal", reservation);
    // resolveExposed(committed|released) is exactly commit(exposed)/release(exposed) via admin.
    if (outcome === "committed") {
      await this.commit({
        reservationId: ref.reservationId,
        policyScope: ref.policyScope,
        assetId: ref.assetId,
        committedAtEpochMs: nowEpochMs,
      });
    } else {
      await this.release(ref, nowEpochMs);
    }
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async listExposed(query: SpendQuery): Promise<readonly SpendReservation[]> {
    this.#maintain(query.nowEpochMs);
    const queryAsset = canonicalizeAsset(query.assetId);
    return Object.freeze(
      [...this.#reservations.values()]
        .filter(
          (reservation) =>
            reservation.policyScope === query.policyScope &&
            canonicalizeAsset(reservation.assetId) === queryAsset &&
            reservation.state === "exposed",
        )
        .map(frozenReservation),
    );
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async isFrozen(scope: string): Promise<boolean> {
    return this.#frozen.has(scope) || this.#frozen.has("*");
  }

  peekBudgetState(query: SpendQuery): BudgetState {
    const current = this.#matching(query);
    const saKey = scopeAssetKey(query.policyScope, query.assetId);
    const cumulativeCommitted = this.#cumulative.get(saKey) ?? 0n;
    const exposedTotal = this.#exposedTotal.get(saKey) ?? 0n;
    const cumulativeConsumed = cumulativeCommitted + exposedTotal + current.reserved;
    const limits = this.#limits.get(saKey);
    const frozen = this.#frozen.has(query.policyScope) || this.#frozen.has("*");
    const rollingConsumed = current.committed + current.reserved + current.exposedRolling;
    return Object.freeze({
      storeKind: this.kind,
      policyScope: query.policyScope,
      assetId: canonicalizeAsset(query.assetId),
      committedAtomic: current.committed.toString(),
      reservedAtomic: current.reserved.toString(),
      exposedAtomic: exposedTotal.toString(),
      cumulativeCommittedAtomic: cumulativeCommitted.toString(),
      cumulativeConsumedAtomic: cumulativeConsumed.toString(),
      frozen,
      ...(limits?.maxPerHourAtomic === undefined
        ? {}
        : {
            perHourLimitAtomic: limits.maxPerHourAtomic,
            availablePerHourAtomic: maxBig(
              atomic(limits.maxPerHourAtomic, "maxPerHourAtomic") - rollingConsumed,
            ),
          }),
      ...(limits?.maxTotalAtomic === undefined
        ? {}
        : {
            cumulativeLimitAtomic: limits.maxTotalAtomic,
            availableCumulativeAtomic: maxBig(
              atomic(limits.maxTotalAtomic, "maxTotalAtomic") - cumulativeConsumed,
            ),
          }),
      entries: Object.freeze(current.entries.map(frozenEntry)),
      reservations: Object.freeze(current.reservations.map(frozenReservation)),
    });
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async getBudgetState(query: SpendQuery): Promise<BudgetState> {
    return this.peekBudgetState(query);
  }

  // ── Admin plane (SPEC §3.1). In-process, no credential separation (test-only, SPEC §3.5). ──

  // eslint-disable-next-line @typescript-eslint/require-await
  async freeze(scope: string, _nowEpochMs?: number): Promise<void> {
    // atomicGlobalFreeze is true, so "*" is a permitted scope here (ADR-027).
    this.#frozen.add(scope);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async unfreeze(scope: string, _nowEpochMs?: number): Promise<void> {
    this.#frozen.delete(scope);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async setRecipientPins(
    scope: string,
    network: string,
    recipients: readonly string[],
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#pins.set(pinKey(scope, network), {
      recipients: Object.freeze([...recipients]),
      source: "admin-allowlist",
    });
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async getRecipientPins(scope: string, network: string): Promise<readonly string[]> {
    return this.#pins.get(pinKey(scope, network))?.recipients ?? Object.freeze([]);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async getRecipientPolicy(
    scope: string,
  ): Promise<{ tofuEnabled: boolean; recipientAssertionRequired: boolean }> {
    const policy = this.#recipientPolicy.get(scope);
    return {
      tofuEnabled: policy?.tofuEnabled ?? false,
      recipientAssertionRequired: policy?.recipientAssertionRequired ?? false,
    };
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async setBudgetLimits(
    scope: string,
    assetId: string,
    limits: BudgetLimits,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#limits.set(
      scopeAssetKey(scope, assetId),
      Object.freeze({
        ...(limits.maxPerHourAtomic === undefined
          ? {}
          : { maxPerHourAtomic: limits.maxPerHourAtomic }),
        ...(limits.maxTotalAtomic === undefined
          ? {}
          : { maxTotalAtomic: limits.maxTotalAtomic }),
      }),
    );
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async getBudgetLimits(scope: string, assetId: string): Promise<BudgetLimits> {
    return this.#limits.get(scopeAssetKey(scope, assetId)) ?? Object.freeze({});
  }

  #policyFor(scope: string): { tofuEnabled: boolean; recipientAssertionRequired: boolean } {
    let policy = this.#recipientPolicy.get(scope);
    if (policy === undefined) {
      policy = { tofuEnabled: false, recipientAssertionRequired: false };
      this.#recipientPolicy.set(scope, policy);
    }
    return policy;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async setRecipientAssertionRequired(
    scope: string,
    required: boolean,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#policyFor(scope).recipientAssertionRequired = required;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async setTofuEnabled(
    scope: string,
    enabled: boolean,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#policyFor(scope).tofuEnabled = enabled;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async resetCumulative(
    scope: string,
    assetId: string,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#cumulative.delete(scopeAssetKey(scope, assetId));
  }
}
