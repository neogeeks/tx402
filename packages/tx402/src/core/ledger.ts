/** Atomic rolling spend reservations (SPEC §5.3, ADR-007, SEC-002). */

import { randomBytes } from "node:crypto";

import { BudgetExceededError } from "./errors.js";

export const RESERVATION_TTL_MS = 120_000;
export const ROLLING_WINDOW_MS = 3_600_000;

export type SpendReservationState = "reserved" | "committed" | "released" | "expired";

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
   * audit's O45 found unlabelled zeros that belonged to no ledger at all.
   */
  readonly policyScope?: string;
  readonly assetId?: string;
}

export interface ReserveSpendInput {
  readonly reservationId?: string;
  readonly requestId: string;
  readonly policyScope: string;
  readonly requestFingerprint: string;
  readonly assetId: string;
  readonly amountAtomic: string;
  readonly maxPerHourAtomic: string;
  readonly nowEpochMs: number;
}

export interface CommitSpendInput {
  readonly reservationId: string;
  readonly committedAtEpochMs: number;
  readonly settlementId?: string;
}

export interface SpendQuery {
  readonly policyScope: string;
  readonly assetId: string;
  readonly nowEpochMs: number;
}

/**
 * The pluggable spend ledger (SPEC §4.3, §5.3). Implement this to share one budget across
 * processes; the built-in {@link MemorySpendStore} is process-local.
 *
 * The contract an adapter must honour, stated once so the Python `SpendStore` protocol and
 * this interface say the same thing (ADR-018):
 *
 *  - **`policyScope` is the normalized merchant host.** It is opaque to the store — the
 *    store must only ever compare it for equality, never parse it — but it is the key that
 *    makes two processes calling one merchant share one cap, so a store must not
 *    substitute its own.
 *  - **`reserve` is atomic.** The cap comparison and the insert are one operation, or a
 *    concurrent pair of callers can both pass a cap only one of them fits under.
 *  - **`reserve` rejects an over-cap request with `BudgetExceededError`.** Any other
 *    exception is read as an outage: the client converts it to a retryable
 *    `TransportError`, because nothing has been signed yet.
 *  - **`commit` and `release` are idempotent** for a reservation already in that state.
 *  - **A `commit` failure is money-relevant.** It happens after settlement, so the client
 *    converts it to `ResourceDeliveryError` with `paid: true` and does *not* release. Fail
 *    loudly rather than returning a fabricated entry.
 *  - **`getBudgetState` is diagnostics** and may throw; the client swallows the failure
 *    rather than failing a paid request over a snapshot.
 */
export interface SpendStore {
  readonly kind: string;
  /** The cap comparison and reservation insert MUST be one atomic operation. */
  reserve(input: ReserveSpendInput): Promise<SpendReservation>;
  commit(input: CommitSpendInput): Promise<SpendEntry>;
  release(reservationId: string, nowEpochMs: number): Promise<SpendReservation>;
  getBudgetState(query: SpendQuery): Promise<BudgetState>;
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

/** Process-local store. Each method mutates synchronously before its Promise resolves. */
export class MemorySpendStore implements SpendStore {
  readonly kind = "memory";
  readonly #reservations = new Map<string, SpendReservation>();
  readonly #entries = new Map<string, SpendEntry>();

  #maintain(nowEpochMs: number): void {
    const cutoff = nowEpochMs - ROLLING_WINDOW_MS;
    for (const [id, reservation] of this.#reservations) {
      let current = reservation;
      if (current.state === "reserved" && current.expiresAtEpochMs <= nowEpochMs) {
        current = frozenReservation({ ...current, state: "expired" });
        this.#reservations.set(id, current);
      }
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
  } {
    this.#maintain(query.nowEpochMs);
    const cutoff = query.nowEpochMs - ROLLING_WINDOW_MS;
    const entries = [...this.#entries.values()].filter(
      (entry) =>
        entry.assetId === query.assetId &&
        entry.committedAtEpochMs >= cutoff &&
        entry.committedAtEpochMs <= query.nowEpochMs &&
        this.#reservations.get(entry.reservationId)?.policyScope === query.policyScope,
    );
    const reservations = [...this.#reservations.values()].filter(
      (reservation) =>
        reservation.policyScope === query.policyScope &&
        reservation.assetId === query.assetId,
    );
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
    return { entries, reservations, committed, reserved };
  }

  // No await by design: cap comparison and insert must remain one event-loop turn.
  // eslint-disable-next-line @typescript-eslint/require-await
  async reserve(input: ReserveSpendInput): Promise<SpendReservation> {
    const amount = atomic(input.amountAtomic, "amountAtomic", true);
    const cap = atomic(input.maxPerHourAtomic, "maxPerHourAtomic", true);
    const existingId = input.reservationId;
    if (existingId !== undefined) {
      const existing = this.#reservations.get(existingId);
      if (existing !== undefined) {
        if (
          existing.policyScope !== input.policyScope ||
          existing.requestFingerprint !== input.requestFingerprint ||
          existing.assetId !== input.assetId ||
          existing.amountAtomic !== input.amountAtomic
        ) {
          throw new Error("Reservation ID was reused with different spend data");
        }
        return existing;
      }
    }
    const current = this.#matching(input);
    if (current.committed + current.reserved + amount > cap) {
      throw new BudgetExceededError("Hourly spend limit would be exceeded", {
        context: {
          requestId: input.requestId,
          phase: "policy",
          amountAtomic: input.amountAtomic,
          assetId: input.assetId,
        },
        details: {
          requestedAtomic: input.amountAtomic,
          capAtomic: input.maxPerHourAtomic,
          committedAtomic: current.committed.toString(),
          reservedAtomic: current.reserved.toString(),
          capKind: "per-hour",
        },
      });
    }
    const reservation = frozenReservation({
      reservationId: input.reservationId ?? uuidV7(input.nowEpochMs),
      policyScope: input.policyScope,
      requestFingerprint: input.requestFingerprint,
      assetId: input.assetId,
      amountAtomic: input.amountAtomic,
      createdAtEpochMs: input.nowEpochMs,
      expiresAtEpochMs: input.nowEpochMs + RESERVATION_TTL_MS,
      state: "reserved",
    });
    this.#reservations.set(reservation.reservationId, reservation);
    return reservation;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async commit(input: CommitSpendInput): Promise<SpendEntry> {
    const existing = this.#entries.get(input.reservationId);
    if (existing !== undefined) return existing;
    this.#maintain(input.committedAtEpochMs);
    const reservation = this.#reservations.get(input.reservationId);
    if (reservation === undefined) throw new Error("Unknown spend reservation");
    if (reservation.state === "released")
      throw new Error("Released reservation cannot commit");
    const entry = frozenEntry({
      reservationId: reservation.reservationId,
      requestFingerprint: reservation.requestFingerprint,
      assetId: reservation.assetId,
      amountAtomic: reservation.amountAtomic,
      committedAtEpochMs: input.committedAtEpochMs,
      ...(input.settlementId === undefined ? {} : { settlementId: input.settlementId }),
    });
    this.#entries.set(input.reservationId, entry);
    this.#reservations.set(
      input.reservationId,
      frozenReservation({ ...reservation, state: "committed" }),
    );
    return entry;
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async release(reservationId: string, nowEpochMs: number): Promise<SpendReservation> {
    this.#maintain(nowEpochMs);
    const reservation = this.#reservations.get(reservationId);
    if (reservation === undefined) throw new Error("Unknown spend reservation");
    if (reservation.state !== "reserved") return reservation;
    const released = frozenReservation({ ...reservation, state: "released" });
    this.#reservations.set(reservationId, released);
    return released;
  }

  peekBudgetState(query: SpendQuery): BudgetState {
    const current = this.#matching(query);
    return Object.freeze({
      storeKind: this.kind,
      policyScope: query.policyScope,
      assetId: query.assetId,
      committedAtomic: current.committed.toString(),
      reservedAtomic: current.reserved.toString(),
      entries: Object.freeze(current.entries.map(frozenEntry)),
      reservations: Object.freeze(current.reservations.map(frozenReservation)),
    });
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async getBudgetState(query: SpendQuery): Promise<BudgetState> {
    return this.peekBudgetState(query);
  }
}
