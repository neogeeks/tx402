/**
 * The wire shapes exchanged between {@link Tx402SpendStoreDO} and the
 * {@link durableObjectSpendStore} adapter (SPEC §12.3/§12.4). Pure data types with NO
 * `cloudflare:workers` dependency, so the adapter — which never touches the Workers runtime —
 * and the DO — which runs inside it — share one protocol without dragging the Workers globals
 * into the adapter's compilation.
 *
 * Every transition returns a DISCRIMINATED ENVELOPE rather than throwing across the RPC
 * boundary. Cloudflare's RPC serializes a thrown error as a plain `Error` and loses its class,
 * so a typed refusal (`BudgetExceededError`, `SpendScopeFrozenError`, …) would arrive at the
 * client stripped of its taxonomy. Instead the DO returns `{ ok: false, kind, … }` and the
 * adapter reconstructs the exact typed error client-side — the same design the Redis adapter
 * uses with its `cjson` replies, so a DO-backed store is byte-identical to a Redis-backed one
 * and passes the same `checkSpendStore`/`checkDurableSpendStore` suites.
 */

import type { BudgetLimits, SpendReservationState } from "../core/ledger.js";

/** A reservation row as the DO returns it (amounts are decimal strings; times are epoch-ms). */
export interface RawReservation {
  reservationId: string;
  policyScope: string;
  requestFingerprint: string;
  assetId: string;
  amountAtomic: string;
  createdAtEpochMs: number;
  expiresAtEpochMs: number;
  state: SpendReservationState;
}

/** A committed entry as the DO returns it. */
export interface RawEntry {
  reservationId: string;
  requestFingerprint: string;
  assetId: string;
  amountAtomic: string;
  committedAtEpochMs: number;
  settlementId?: string;
}

/** The full `getBudgetState` snapshot the DO computes (SPEC §3.2). */
export interface RawSnapshot {
  committedAtomic: string;
  reservedAtomic: string;
  exposedAtomic: string;
  cumulativeCommittedAtomic: string;
  cumulativeConsumedAtomic: string;
  frozen: boolean;
  perHourLimitAtomic?: string;
  availablePerHourAtomic?: string;
  cumulativeLimitAtomic?: string;
  availableCumulativeAtomic?: string;
  entries: RawEntry[];
  reservations: RawReservation[];
}

/**
 * A refusal the adapter maps to the exact typed error (SPEC §3.4/§5/§6). The discriminant
 * `kind` and its payload mirror the Redis adapter's `Refusal` so the two adapters share one
 * mapping shape.
 */
export type Refusal =
  | { ok: false; kind: "idreuse" }
  | { ok: false; kind: "frozen"; frozenScope: string }
  | {
      ok: false;
      kind: "recipient";
      reason: string;
      network?: string;
      presentedRecipient?: string;
      expectedRecipients?: string[];
    }
  | {
      ok: false;
      kind: "budget";
      capKind: string;
      requestedAtomic: string;
      capAtomic: string;
      committedAtomic: string;
      reservedAtomic: string;
    }
  | { ok: false; kind: "config"; configPath: string; reason: string };

export type ReserveEnvelope =
  { ok: true; reservation: RawReservation; recipientPinEstablished: boolean } | Refusal;
export type CommitEnvelope = { ok: true; entry: RawEntry } | Refusal;
export type ReservationEnvelope = { ok: true; reservation: RawReservation } | Refusal;
export type VoidEnvelope = { ok: true } | Refusal;
export type LimitsEnvelope = { ok: true; limits: BudgetLimits } | Refusal;

/**
 * The RPC surface the {@link Tx402SpendStoreDO} exposes, as the adapter sees it through a
 * `DurableObjectStub`. Every method is asynchronous over the wire even though the DO body runs
 * synchronously (RPC wraps the return in a Promise). Structurally compatible with
 * `DurableObjectStub<Tx402SpendStoreDO>`, so the harness can hand the adapter a real stub
 * without the adapter importing any Workers type.
 *
 * The admin methods take an `adminToken` the DO verifies INSIDE itself against its Worker-env
 * secret (SPEC §12.3): a separate TypeScript method set is not a security boundary on DO,
 * where any binding-holder can call every RPC method, so the token — not the type — is the
 * boundary. `atomicGlobalFreeze` is the caller's declared topology capability (operator
 * configuration, not a data-plane input); the DO refuses `freeze("*")` when it is false.
 */
export interface Tx402SpendStoreDOStub {
  reserve(input: ReserveInput): Promise<ReserveEnvelope>;
  commit(input: CommitInput): Promise<CommitEnvelope>;
  release(ref: RefInput, nowEpochMs: number): Promise<ReservationEnvelope>;
  expose(ref: RefInput, nowEpochMs: number): Promise<ReservationEnvelope>;
  getBudgetState(query: QueryInput): Promise<RawSnapshot>;
  listExposed(query: QueryInput): Promise<RawReservation[]>;
  isFrozen(scope: string): Promise<boolean>;
  getRecipientPins(scope: string, network: string): Promise<string[]>;
  getRecipientPolicy(
    scope: string,
  ): Promise<{ tofuEnabled: boolean; recipientAssertionRequired: boolean }>;

  freeze(
    scope: string,
    adminToken: string,
    atomicGlobalFreeze: boolean,
  ): Promise<VoidEnvelope>;
  unfreeze(scope: string, adminToken: string): Promise<VoidEnvelope>;
  setRecipientPins(
    scope: string,
    network: string,
    recipients: string[],
    adminToken: string,
  ): Promise<VoidEnvelope>;
  setBudgetLimits(
    scope: string,
    assetId: string,
    limits: BudgetLimits,
    adminToken: string,
  ): Promise<VoidEnvelope>;
  getBudgetLimits(
    scope: string,
    assetId: string,
    adminToken: string,
  ): Promise<LimitsEnvelope>;
  setRecipientAssertionRequired(
    scope: string,
    required: boolean,
    adminToken: string,
  ): Promise<VoidEnvelope>;
  setTofuEnabled(
    scope: string,
    enabled: boolean,
    adminToken: string,
  ): Promise<VoidEnvelope>;
  resolveExposed(
    ref: RefInput,
    outcome: "committed" | "released",
    nowEpochMs: number,
    adminToken: string,
  ): Promise<VoidEnvelope>;
  resetCumulative(
    scope: string,
    assetId: string,
    adminToken: string,
  ): Promise<VoidEnvelope>;

  /** TEST-ONLY (SPEC §3.4a). Honoured only when the DO's env enables the test clock. */
  setBackendClock(nowEpochMs: number): Promise<void>;
  /** TEST-ONLY. Wipes the DO's tables. Honoured only when the DO's env enables test mode. */
  reset(): Promise<void>;
  /** TEST-ONLY. Evicts the DO instance so durability across a restart can be checked (§12.4). */
  __evict(): Promise<void>;
}

/**
 * The reserve arguments the DO receives. A structural subset of `ReserveSpendInput` (SPEC
 * §3.1) — repeated here so the protocol module has no dependency on the ledger's readonly
 * interface, and so the RPC payload's shape is documented in one place.
 */
export interface ReserveInput {
  reservationId?: string;
  requestId: string;
  policyScope: string;
  requestFingerprint: string;
  assetId: string;
  amountAtomic: string;
  maxPerHourAtomic: string;
  maxTotalAtomic?: string;
  recipientNetwork?: string;
  recipientCanonical?: string;
  recipientEnforcement?: "off" | "allowlist" | "tofu";
  nowEpochMs: number;
}

export interface CommitInput {
  reservationId: string;
  policyScope: string;
  assetId: string;
  committedAtEpochMs: number;
  settlementId?: string;
}

export interface RefInput {
  reservationId: string;
  policyScope: string;
  assetId: string;
}

export interface QueryInput {
  policyScope: string;
  assetId: string;
  nowEpochMs: number;
}
