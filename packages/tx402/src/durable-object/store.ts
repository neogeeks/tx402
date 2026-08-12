/**
 * `DurableObjectSpendStore` — the data-plane + admin {@link SpendStore} adapter over a
 * {@link Tx402SpendStoreDO}. It holds a `locate(scope)` function that returns
 * the scope's DO stub and turns every RPC envelope into the exact typed result or error, so a
 * DO-backed store is byte-identical to a Redis-backed one and to `MemorySpendStore` — it passes
 * the same `checkSpendStore`/`checkDurableSpendStore` suites.
 *
 * **Two topologies, both just a `locate` + a capability flag:**
 *  - **id-per-scope (default):** `locate` routes each scope to its own DO (`ns.idFromName(scope)`).
 *    Per-scope reserve/commit/expose/freeze is atomic; global `"*"` freeze is NOT
 *    (`atomicGlobalFreeze: false`), so `freeze("*")` fails closed `global-freeze-unsupported`.
 *  - **single-coordinator (opt-in):** `locate` routes every scope to one coordinator DO, so a
 *    `"*"` freeze shares the reservation's coordination domain (`atomicGlobalFreeze: true`).
 *
 * **Fail-closed overload.** A `reserve` whose DO cannot be reached raises a retryable
 * `TransportError` — never a signature. The adapter cannot tell an overloaded shard from an
 * unreachable one, and nothing has been signed at reserve time, so it treats any RPC failure as
 * infrastructure unavailability (the client retries or fails without paying), never a policy
 * decision.
 *
 * **No admin token on the data plane.** {@link durableObjectSpendStore} builds a
 * store with no `adminToken`, so every admin mutation is refused inside the DO with
 * `admin-credential-required` — plane separation holds without TypeScript standing in for a
 * security boundary. The gateway (§12.5) is how a non-Worker caller reaches an admin DO.
 */

import {
  BudgetExceededError,
  ConfigurationError,
  RecipientUnpinnedError,
  SpendScopeFrozenError,
  TransportError,
} from "../core/errors.js";
import type {
  BudgetLimits,
  BudgetState,
  CommitSpendInput,
  RecipientPinStore,
  ReservationRef,
  ReserveSpendInput,
  ReserveSpendResult,
  SpendEntry,
  SpendQuery,
  SpendReservation,
  SpendStore,
  SpendStoreAdmin,
  StoreCapabilities,
} from "../core/ledger.js";
import type {
  LimitsEnvelope,
  RawEntry,
  RawReservation,
  RawSnapshot,
  Refusal,
  ReservationEnvelope,
  ReserveEnvelope,
  Tx402SpendStoreDOStub,
  VoidEnvelope,
} from "./protocol.js";

/** Resolves a scope to its Durable Object stub (SPEC §12.3 topology). */
export type DurableObjectLocator = (scope: string) => Tx402SpendStoreDOStub;

export interface DurableObjectSpendStoreOptions {
  /**
   * Routes a scope to its DO stub. id-per-scope: `(scope) => ns.get(ns.idFromName(scope))`;
   * single-coordinator: `() => ns.get(ns.idFromName("<coordinator>"))`.
   */
  readonly locate: DurableObjectLocator;
  /**
   * Whether `freeze("*")` is atomic with a reservation. `true` only under the
   * single-coordinator topology (all reserves share one DO); `false` id-per-scope, where each
   * scope is a private object and no `"*"` object can atomically span them. Default `false`.
   */
  readonly atomicGlobalFreeze?: boolean;
  /**
   * The admin token the DO verifies against its `TX402_DO_ADMIN_SECRET`. Present
   * only on the operator/gateway store; the data-plane adapter carries none, so every admin
   * mutation is refused `admin-credential-required`.
   */
  readonly adminToken?: string;
}

// SPEC §6.4/U16: canonicalize the CAIP-19 asset (eip155 → lowercase; every other family verbatim).
// Reimplemented locally — byte-identical to `canonicalizeAsset` in `core/ledger.ts` — so this client
// adapter does not value-import that module (the DO itself keys on the canonical asset regardless;
// this only keeps the echoed BudgetState.assetId consistent with the canonical reservations it wraps).
function canonAsset(assetId: string): string {
  return assetId.startsWith("eip155:") ? assetId.toLowerCase() : assetId;
}

function toReservation(raw: RawReservation): SpendReservation {
  return Object.freeze({
    reservationId: raw.reservationId,
    policyScope: raw.policyScope,
    requestFingerprint: raw.requestFingerprint,
    assetId: raw.assetId,
    amountAtomic: raw.amountAtomic,
    createdAtEpochMs: raw.createdAtEpochMs,
    expiresAtEpochMs: raw.expiresAtEpochMs,
    state: raw.state,
  });
}

function toEntry(raw: RawEntry): SpendEntry {
  return Object.freeze({
    reservationId: raw.reservationId,
    requestFingerprint: raw.requestFingerprint,
    assetId: raw.assetId,
    amountAtomic: raw.amountAtomic,
    committedAtEpochMs: raw.committedAtEpochMs,
    ...(raw.settlementId === undefined ? {} : { settlementId: raw.settlementId }),
  });
}

/** The reference DO {@link SpendStore} — data plane, admin plane, and recipient reads. */
export class DurableObjectSpendStore
  implements SpendStore, RecipientPinStore, SpendStoreAdmin
{
  readonly kind = "durable-object";
  readonly capabilities: StoreCapabilities;
  readonly #locate: DurableObjectLocator;
  readonly #adminToken: string;

  constructor(options: DurableObjectSpendStoreOptions) {
    this.#locate = options.locate;
    this.#adminToken = options.adminToken ?? "";
    this.capabilities = Object.freeze({
      atomicGlobalFreeze: options.atomicGlobalFreeze ?? false,
    });
  }

  #stub(scope: string): Tx402SpendStoreDOStub {
    return this.#locate(scope);
  }

  #mapRefusal(
    res: Refusal,
    ctx: {
      requestId?: string;
      policyScope: string;
      assetId?: string;
      amountAtomic?: string;
      reservationId?: string;
    },
  ): Error {
    const requestId = ctx.requestId ?? "spend-store";
    const context = {
      requestId,
      phase: "policy" as const,
      ...(ctx.assetId === undefined ? {} : { assetId: ctx.assetId }),
      ...(ctx.amountAtomic === undefined ? {} : { amountAtomic: ctx.amountAtomic }),
      ...(ctx.reservationId === undefined ? {} : { reservationId: ctx.reservationId }),
    };
    switch (res.kind) {
      case "idreuse":
        return new Error("Reservation ID was reused with different spend data");
      case "frozen":
        return new SpendScopeFrozenError("Spending is frozen for this scope", {
          context,
          details: { scope: ctx.policyScope, frozenScope: res.frozenScope },
        });
      case "recipient": {
        const details: Record<string, unknown> = {
          merchantScope: ctx.policyScope,
          reason: res.reason,
        };
        if (res.reason === "not-allowlisted" || res.reason === "pin-mismatch") {
          details.network = res.network;
          details.presentedRecipient = res.presentedRecipient;
          details.expectedRecipients = res.expectedRecipients;
        }
        return new RecipientUnpinnedError("The recipient is not pinned for this scope", {
          context,
          details,
        });
      }
      case "budget":
        return new BudgetExceededError(
          res.capKind === "cumulative"
            ? "Cumulative spend limit would be exceeded"
            : "Hourly spend limit would be exceeded",
          {
            context,
            details: {
              requestedAtomic: res.requestedAtomic,
              capAtomic: res.capAtomic,
              committedAtomic: res.committedAtomic,
              reservedAtomic: res.reservedAtomic,
              capKind: res.capKind,
            },
          },
        );
      case "config":
        return new ConfigurationError(
          res.reason === "reservation-not-found"
            ? "The reservation ref names no record"
            : res.reason === "admin-credential-required"
              ? "An admin credential is required for this operation"
              : res.reason === "global-freeze-unsupported"
                ? "Atomic global freeze is not supported by this topology"
                : res.reason === "recipient-tofu-not-provisioned"
                  ? "Recipient TOFU is not provisioned for this scope"
                  : res.reason === "cap-exceeds-administered"
                    ? "Caller cap exceeds the store-administered cap"
                    : "The reservation lifecycle transition is not permitted",
          { context, details: { configPath: res.configPath, reason: res.reason } },
        );
    }
  }

  /** A reserve whose DO is unreachable/overloaded is fail-closed: retryable, never a signature. */
  #transportError(cause: unknown): TransportError {
    return new TransportError("The spend store Durable Object is unreachable", {
      context: { requestId: "spend-store", phase: "policy" },
      details: { causeCategory: "durable-object-unreachable" },
      cause,
    });
  }

  // ── data plane ──────────────────────────────────────────────────────────────────────────────

  async reserve(input: ReserveSpendInput): Promise<ReserveSpendResult> {
    let res: ReserveEnvelope;
    try {
      res = await this.#stub(input.policyScope).reserve({ ...input });
    } catch (error) {
      // Overload / unreachable DO → fail-closed. Nothing has been signed, so this is retryable
      // infrastructure unavailability, not a budget decision.
      throw this.#transportError(error);
    }
    if (res.ok) {
      return Object.freeze({
        reservation: toReservation(res.reservation),
        recipientPinEstablished: res.recipientPinEstablished,
      });
    }
    throw this.#mapRefusal(res, {
      requestId: input.requestId,
      policyScope: input.policyScope,
      assetId: input.assetId,
      amountAtomic: input.amountAtomic,
    });
  }

  async commit(input: CommitSpendInput): Promise<SpendEntry> {
    const res = await this.#stub(input.policyScope).commit({ ...input });
    if (res.ok) return toEntry(res.entry);
    throw this.#mapRefusal(res, {
      policyScope: input.policyScope,
      assetId: input.assetId,
      reservationId: input.reservationId,
    });
  }

  async release(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation> {
    const res = await this.#stub(ref.policyScope).release({ ...ref }, nowEpochMs);
    return this.#reservationOr(res, ref);
  }

  async expose(ref: ReservationRef, nowEpochMs: number): Promise<SpendReservation> {
    const res = await this.#stub(ref.policyScope).expose({ ...ref }, nowEpochMs);
    return this.#reservationOr(res, ref);
  }

  #reservationOr(res: ReservationEnvelope, ref: ReservationRef): SpendReservation {
    if (res.ok) return toReservation(res.reservation);
    throw this.#mapRefusal(res, {
      policyScope: ref.policyScope,
      assetId: ref.assetId,
      reservationId: ref.reservationId,
    });
  }

  async getBudgetState(query: SpendQuery): Promise<BudgetState> {
    let s: RawSnapshot;
    try {
      s = await this.#stub(query.policyScope).getBudgetState({ ...query });
    } catch (error) {
      // A read against an unreachable/overloaded DO is a retryable outage, typed exactly as a
      // reserve is — never an untyped Cloudflare RPC error leaking to the caller/CLI.
      throw this.#transportError(error);
    }
    return Object.freeze({
      storeKind: this.kind,
      policyScope: query.policyScope,
      assetId: canonAsset(query.assetId),
      committedAtomic: s.committedAtomic,
      reservedAtomic: s.reservedAtomic,
      exposedAtomic: s.exposedAtomic,
      cumulativeCommittedAtomic: s.cumulativeCommittedAtomic,
      cumulativeConsumedAtomic: s.cumulativeConsumedAtomic,
      frozen: s.frozen,
      ...(s.perHourLimitAtomic === undefined
        ? {}
        : {
            perHourLimitAtomic: s.perHourLimitAtomic,
            availablePerHourAtomic: s.availablePerHourAtomic,
          }),
      ...(s.cumulativeLimitAtomic === undefined
        ? {}
        : {
            cumulativeLimitAtomic: s.cumulativeLimitAtomic,
            availableCumulativeAtomic: s.availableCumulativeAtomic,
          }),
      entries: Object.freeze(s.entries.map(toEntry)),
      reservations: Object.freeze(s.reservations.map(toReservation)),
    });
  }

  async listExposed(query: SpendQuery): Promise<readonly SpendReservation[]> {
    let raw: Awaited<ReturnType<Tx402SpendStoreDOStub["listExposed"]>>;
    try {
      raw = await this.#stub(query.policyScope).listExposed({ ...query });
    } catch (error) {
      throw this.#transportError(error); // outage → typed retryable TransportError
    }
    return Object.freeze(raw.map(toReservation));
  }

  async isFrozen(scope: string): Promise<boolean> {
    try {
      return await this.#stub(scope).isFrozen(scope);
    } catch (error) {
      throw this.#transportError(error); // outage → typed retryable TransportError
    }
  }

  // ── recipient reads (data plane, SPEC §3.1) ────────────────────────────────────────────────

  async getRecipientPins(scope: string, network: string): Promise<readonly string[]> {
    try {
      return Object.freeze(await this.#stub(scope).getRecipientPins(scope, network));
    } catch (error) {
      throw this.#transportError(error); // outage → typed retryable TransportError
    }
  }

  async getRecipientPolicy(
    scope: string,
  ): Promise<{ tofuEnabled: boolean; recipientAssertionRequired: boolean }> {
    try {
      return await this.#stub(scope).getRecipientPolicy(scope);
    } catch (error) {
      throw this.#transportError(error); // outage → typed retryable TransportError
    }
  }

  // ── admin plane. The DO verifies the token; a data credential is refused. ──

  // Each admin method accepts an OPTIONAL trailing `_nowEpochMs` — the DO reads its own backend
  // clock inside the atom (`Date.now()`, §3.4a), so the value is accepted-and-ignored. It is
  // declared (like MemorySpendStore's `_nowEpochMs?`) so the concrete store matches the
  // `SpendStoreAdmin` interface arity and every operator doc example that passes `Date.now()`
  // type-checks against it.

  async freeze(scope: string, _nowEpochMs?: number): Promise<void> {
    this.#voidOr(
      await this.#stub(scope).freeze(
        scope,
        this.#adminToken,
        this.capabilities.atomicGlobalFreeze,
      ),
      scope,
    );
  }

  async unfreeze(scope: string, _nowEpochMs?: number): Promise<void> {
    this.#voidOr(await this.#stub(scope).unfreeze(scope, this.#adminToken), scope);
  }

  async setRecipientPins(
    scope: string,
    network: string,
    recipients: readonly string[],
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#voidOr(
      await this.#stub(scope).setRecipientPins(
        scope,
        network,
        [...recipients],
        this.#adminToken,
      ),
      scope,
    );
  }

  async setBudgetLimits(
    scope: string,
    assetId: string,
    limits: BudgetLimits,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#voidOr(
      await this.#stub(scope).setBudgetLimits(
        scope,
        assetId,
        { ...limits },
        this.#adminToken,
      ),
      scope,
    );
  }

  async getBudgetLimits(scope: string, assetId: string): Promise<BudgetLimits> {
    let res: LimitsEnvelope;
    try {
      res = await this.#stub(scope).getBudgetLimits(scope, assetId, this.#adminToken);
    } catch (error) {
      throw this.#transportError(error); // outage → typed retryable TransportError
    }
    if (res.ok) return Object.freeze({ ...res.limits });
    throw this.#mapRefusal(res, { policyScope: scope, assetId });
  }

  async setRecipientAssertionRequired(
    scope: string,
    required: boolean,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#voidOr(
      await this.#stub(scope).setRecipientAssertionRequired(
        scope,
        required,
        this.#adminToken,
      ),
      scope,
    );
  }

  async setTofuEnabled(
    scope: string,
    enabled: boolean,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#voidOr(
      await this.#stub(scope).setTofuEnabled(scope, enabled, this.#adminToken),
      scope,
    );
  }

  async resolveExposed(
    ref: ReservationRef,
    outcome: "committed" | "released",
    nowEpochMs: number,
  ): Promise<void> {
    this.#voidOr(
      await this.#stub(ref.policyScope).resolveExposed(
        { ...ref },
        outcome,
        nowEpochMs,
        this.#adminToken,
      ),
      ref.policyScope,
      ref.assetId,
      ref.reservationId,
    );
  }

  async resetCumulative(
    scope: string,
    assetId: string,
    _nowEpochMs?: number,
  ): Promise<void> {
    this.#voidOr(
      await this.#stub(scope).resetCumulative(scope, assetId, this.#adminToken),
      scope,
    );
  }

  #voidOr(
    res: VoidEnvelope,
    policyScope: string,
    assetId?: string,
    reservationId?: string,
  ): void {
    if (res.ok) return;
    throw this.#mapRefusal(res, {
      policyScope,
      ...(assetId === undefined ? {} : { assetId }),
      ...(reservationId === undefined ? {} : { reservationId }),
    });
  }
}

/**
 * The DATA-plane {@link SpendStore} adapter. Carries no admin token, so every admin
 * mutation is refused `admin-credential-required` — the data/admin boundary is real. A non-Worker
 * caller (CLI, Python) reaches an admin DO through the gateway (§12.5), which holds the token.
 */
export function durableObjectSpendStore(
  options: Omit<DurableObjectSpendStoreOptions, "adminToken">,
): SpendStore & RecipientPinStore {
  return new DurableObjectSpendStore(options);
}
