/**
 * `Tx402SpendStoreDO` — the reference durable {@link import("../core/ledger.js").SpendStore}
 * over a SQLite-backed Cloudflare Durable Object (SPEC §12.3/§12.4, ADR-025..030).
 *
 * **Why the whole reserve is one `storage.transactionSync` with no `await` inside (SPEC §12.3).**
 * A Durable Object processes one event at a time, but an `await` inside a handler yields the
 * isolate and lets another request interleave — so a read-decide-write critical section split by
 * an `await` is NOT atomic. The reserve transition (freeze check, recipient assert/claim, `min`
 * cap resolution, big-integer windowed sums, insert) therefore runs end-to-end inside a single
 * synchronous `storage.transactionSync` closure: `ctx.storage.sql.exec(...)` is synchronous, and
 * there is no `await` between the read and the write, so a concurrent reserve cannot slip between
 * the cap check and the insert. The transaction also rolls back on a thrown error, so a partial
 * write never escapes; a *refusal* is RETURNED (not thrown), matching the Redis atom, so a
 * side-effect that legitimately precedes the refusal — a TOFU claim ahead of a cap rejection —
 * persists exactly as it does on Redis and in `MemorySpendStore`.
 *
 * **Amounts are TEXT, never a JS `number` (SPEC §12.3/§12.2).** A single money input is up to 78
 * atomic digits and the lifetime accumulators grow past that, so every amount is a decimal string
 * and every sum/compare goes through JS `BigInt` (arbitrary width). Only epoch-ms timestamps are
 * numbers (INTEGER columns), all < 2^53.
 *
 * **Backend-authoritative time (SPEC §3.4a).** Windowing and the `createdAt`/`committedAt`/
 * `expiresAt` stamps use the DO's own clock read INSIDE the atom (`Date.now()`), never the
 * caller's `nowEpochMs`, so fleet clock skew cannot double-spend the shared cap. A TEST-ONLY,
 * env-gated injectable backend clock (`TX402_DO_TEST_MODE`) lets the conformance harness pin exact
 * `expiresAt`, then advance by 120 s and by 1 h without waiting; production leaves it disabled, so
 * the setter is inert and the atom always reads `Date.now()`.
 *
 * **The data/admin boundary is a token verified INSIDE the DO, not TypeScript method separation
 * (SPEC §12.3).** Cloudflare exposes every public RPC method to any Worker holding the binding, so
 * separate method sets are not a security boundary. Each admin RPC takes an `adminToken` argument
 * verified against the Worker-env secret `TX402_DO_ADMIN_SECRET` — never set by an RPC first-write,
 * so there is no unauthenticated bootstrap to race. The `durableObjectSpendStore` data-plane
 * adapter carries no admin token, so plane separation holds.
 */

import { DurableObject } from "cloudflare:workers";

import { RESERVATION_TTL_MS, ROLLING_WINDOW_MS } from "../core/ledger.js";
import type { BudgetLimits } from "../core/ledger.js";
import type {
  CommitEnvelope,
  CommitInput,
  LimitsEnvelope,
  RawEntry,
  RawReservation,
  RawSnapshot,
  Refusal,
  ReservationEnvelope,
  ReserveEnvelope,
  ReserveInput,
  RefInput,
  QueryInput,
  VoidEnvelope,
} from "./protocol.js";

/** The Worker environment `Tx402SpendStoreDO` reads (SPEC §12.3). */
export interface Tx402DurableObjectEnv {
  /**
   * The admin-plane secret. Present only in the ADMIN/gateway Worker's env, never the data
   * Worker's, so a compromised data Worker holds the binding but cannot forge an admin call.
   * A deployment Wrangler secret — never set by an RPC call (SPEC §12.3).
   */
  readonly TX402_DO_ADMIN_SECRET?: string;
  /**
   * TEST-ONLY. `"1"` enables the injectable backend clock and the `reset` hook so the
   * conformance harness can drive exact-expiry / +120 s / +1 h transitions and clear state.
   * Absent in production, where the DO always windows on `Date.now()` and the setters are inert.
   */
  readonly TX402_DO_TEST_MODE?: string;
}

type Row = Record<string, string | number | null>;

// ── decimal big-integer helpers (amounts exceed 2^53; JS BigInt is arbitrary-width) ──────────

function big(value: string): bigint {
  // Decimal atomic strings only; a malformed value throws, which the adapter reads as an outage
  // (a retryable TransportError) rather than a policy decision — nothing has been signed.
  return BigInt(value);
}

function availStr(capAtomic: string, consumed: bigint): string {
  const cap = big(capAtomic);
  return cap < consumed ? "0" : (cap - consumed).toString();
}

/**
 * Canonicalize a recipient for pin comparison (SPEC §6.4): eip155 → lowercase hex; every other
 * family verbatim (base58 is injective, case-sensitive). Reimplemented locally — byte-identical to
 * `canonicalizeRecipient` in `core/ledger.ts` — so the DO stays free of that module's `node:crypto`
 * import on the Workers hot path.
 */
function canon(network: string, value: string): string {
  if (value === "") return value;
  return network.startsWith("eip155:") ? value.toLowerCase() : value;
}

/**
 * Canonicalize a CAIP-19 `assetId` for ledger keying (SPEC §6.4, U16): eip155 → lowercase (the
 * `erc20:0x…` address is hex and the `eip155:<chain>` prefix numeric, so lowercasing the whole id
 * matches the §6.4 `sameAddress` rule); every other family (solana `token:<mint>`, case-sensitive
 * base58) verbatim. Reimplemented locally — byte-identical to `canonicalizeAsset` in
 * `core/ledger.ts` — so the DO stays free of that module's `node:crypto` import. An administered
 * cap set under one casing binds a reserve keyed under the other; the frozen §12.2 `asset` column
 * layout is unchanged (only the value stored/compared is normalized).
 */
function canonAsset(assetId: string): string {
  return assetId.startsWith("eip155:") ? assetId.toLowerCase() : assetId;
}

/** UUIDv7 from the backend clock + Workers `crypto.getRandomValues` (no `node:crypto`). */
function uuidV7(nowEpochMs: number): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let timestamp = BigInt(Math.trunc(nowEpochMs));
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x70;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Constant-time string compare, so admin-token verification leaks neither content nor length by
 * timing: the length difference is folded into the accumulator and the loop runs `max(len)` rather
 * than early-returning on a length mismatch — the identical length-independent form the gateway's
 * `bearerTokenScope` compare uses (O62). Behaviour is unchanged (a wrong token of any length is
 * denied, the correct token accepted); only the length-timing path is removed.
 */
function timingSafeEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const max = Math.max(a.length, b.length);
  for (let index = 0; index < max; index += 1) {
    diff |= (a.charCodeAt(index) || 0) ^ (b.charCodeAt(index) || 0);
  }
  return diff === 0;
}

const CLOCK_KEY = "__test-clock__";

function refusal(configPath: string, reason: string): Refusal {
  return { ok: false, kind: "config", configPath, reason };
}

const ADMIN_DENIED = refusal("credential", "admin-credential-required");

export class Tx402SpendStoreDO extends DurableObject<Tx402DurableObjectEnv> {
  readonly #testMode: boolean;

  constructor(ctx: DurableObjectState, env: Tx402DurableObjectEnv) {
    super(ctx, env);
    this.#testMode = env.TX402_DO_TEST_MODE === "1";
    // Schema creation is synchronous (SQLite-backed storage), idempotent, and cheap.
    const sql = this.ctx.storage.sql;
    sql.exec(
      `CREATE TABLE IF NOT EXISTS reservations (
         scope TEXT NOT NULL, asset TEXT NOT NULL, id TEXT NOT NULL,
         fingerprint TEXT NOT NULL, amount TEXT NOT NULL,
         created INTEGER NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL,
         PRIMARY KEY (scope, asset, id))`,
    );
    sql.exec(
      `CREATE TABLE IF NOT EXISTS committed (
         scope TEXT NOT NULL, asset TEXT NOT NULL, id TEXT NOT NULL,
         fingerprint TEXT NOT NULL, amount TEXT NOT NULL,
         committed INTEGER NOT NULL, settlement TEXT,
         PRIMARY KEY (scope, asset, id))`,
    );
    sql.exec(
      `CREATE TABLE IF NOT EXISTS counters (
         scope TEXT NOT NULL, asset TEXT NOT NULL,
         total TEXT NOT NULL DEFAULT '0', exposed TEXT NOT NULL DEFAULT '0',
         PRIMARY KEY (scope, asset))`,
    );
    sql.exec(
      `CREATE TABLE IF NOT EXISTS limits (
         scope TEXT NOT NULL, asset TEXT NOT NULL,
         max_per_hour TEXT, max_total TEXT,
         PRIMARY KEY (scope, asset))`,
    );
    sql.exec(`CREATE TABLE IF NOT EXISTS frozen (scope TEXT PRIMARY KEY)`);
    sql.exec(
      `CREATE TABLE IF NOT EXISTS pins (
         scope TEXT NOT NULL, network TEXT NOT NULL,
         recipients TEXT NOT NULL, source TEXT NOT NULL,
         PRIMARY KEY (scope, network))`,
    );
    sql.exec(
      `CREATE TABLE IF NOT EXISTS recipient_policy (
         scope TEXT PRIMARY KEY,
         tofu_enabled INTEGER NOT NULL DEFAULT 0,
         assertion_required INTEGER NOT NULL DEFAULT 0)`,
    );
    sql.exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  }

  // ── storage helpers ─────────────────────────────────────────────────────────────────────────

  #rows(query: string, ...bindings: (string | number | null)[]): Row[] {
    return this.ctx.storage.sql.exec<Row>(query, ...bindings).toArray();
  }
  #one(query: string, ...bindings: (string | number | null)[]): Row | undefined {
    return this.#rows(query, ...bindings)[0];
  }
  #run(query: string, ...bindings: (string | number | null)[]): void {
    this.ctx.storage.sql.exec(query, ...bindings);
  }

  /**
   * The `now` the atom windows on (SPEC §3.4a). Production (`TX402_DO_TEST_MODE` off) returns the
   * DO's own `Date.now()`. Test mode returns the pinned shared clock if set — so a skewed caller
   * clock cannot double-spend — else the caller's clock, so the single-plane `checkSpendStore`
   * (which never pins) still runs. Read INSIDE the atom, so it is backend-authoritative.
   */
  #now(callerNow: number): number {
    if (!this.#testMode) return Date.now();
    const pinned = this.#one("SELECT value FROM meta WHERE key = ?", CLOCK_KEY);
    return pinned ? Number(pinned.value) : callerNow;
  }

  #counter(scope: string, asset: string, column: "total" | "exposed"): string {
    const row = this.#one(
      `SELECT ${column} AS v FROM counters WHERE scope = ? AND asset = ?`,
      scope,
      asset,
    );
    return row ? String(row.v) : "0";
  }
  #setCounter(
    scope: string,
    asset: string,
    column: "total" | "exposed",
    value: string,
  ): void {
    this.#run(
      `INSERT INTO counters (scope, asset, ${column}) VALUES (?, ?, ?)
       ON CONFLICT(scope, asset) DO UPDATE SET ${column} = excluded.${column}`,
      scope,
      asset,
      value,
    );
  }

  #reservationRow(scope: string, asset: string, id: string): Row | undefined {
    return this.#one(
      "SELECT * FROM reservations WHERE scope = ? AND asset = ? AND id = ?",
      scope,
      asset,
      id,
    );
  }

  #verifyAdmin(adminToken: string): boolean {
    const secret = this.env.TX402_DO_ADMIN_SECRET;
    if (secret === undefined || secret === "") return false;
    return timingSafeEqual(adminToken, secret);
  }

  // ── data plane ──────────────────────────────────────────────────────────────────────────────

  reserve(input: ReserveInput): ReserveEnvelope {
    return this.ctx.storage.transactionSync(() => this.#reserveAtom(input));
  }

  #reserveAtom(input: ReserveInput): ReserveEnvelope {
    const { policyScope: scope } = input;
    const asset = canonAsset(input.assetId); // SPEC §6.4/U16: key on the canonical asset
    const id = input.reservationId ?? uuidV7(this.#now(input.nowEpochMs));
    const now = this.#now(input.nowEpochMs);

    // step 1 — reservation-id reuse (first): an identical replay returns the existing record.
    const existing = this.#reservationRow(scope, asset, id);
    if (existing !== undefined) {
      if (
        existing.fingerprint !== input.requestFingerprint ||
        existing.amount !== input.amountAtomic
      ) {
        return { ok: false, kind: "idreuse" };
      }
      return {
        ok: true,
        reservation: toReservation(existing),
        recipientPinEstablished: false,
      };
    }

    // step 2 — freeze (D-B1): this scope OR the global "*" scope. Both are LOCAL reads on this DO
    // (no foreign-slot problem as on Redis Cluster); "*" is present only under the single-
    // coordinator topology, where freeze("*") is honoured — in id-per-scope it is never set.
    if (this.#one("SELECT 1 FROM frozen WHERE scope = ?", scope) !== undefined) {
      return { ok: false, kind: "frozen", frozenScope: scope };
    }
    if (this.#one("SELECT 1 FROM frozen WHERE scope = ?", "*") !== undefined) {
      return { ok: false, kind: "frozen", frozenScope: "*" };
    }

    // step 3 — recipient assertion, driven by the STORE's administered source (SPEC §3.4 step 3).
    const presented =
      input.recipientCanonical && input.recipientNetwork
        ? canon(input.recipientNetwork, input.recipientCanonical)
        : undefined;
    const policy = this.#one(
      "SELECT tofu_enabled, assertion_required FROM recipient_policy WHERE scope = ?",
      scope,
    );
    let recipientPinEstablished = false;
    if (policy?.assertion_required === 1 && presented === undefined) {
      return { ok: false, kind: "recipient", reason: "assertion-required" };
    }
    if (presented !== undefined && input.recipientNetwork !== undefined) {
      const network = input.recipientNetwork;
      const pin = this.#one(
        "SELECT recipients, source FROM pins WHERE scope = ? AND network = ?",
        scope,
        network,
      );
      if (pin !== undefined) {
        const expected = String(pin.recipients)
          .split("\n")
          .map((value) => canon(network, value));
        if (!expected.includes(presented)) {
          return {
            ok: false,
            kind: "recipient",
            reason: pin.source === "admin-allowlist" ? "not-allowlisted" : "pin-mismatch",
            network,
            presentedRecipient: presented,
            expectedRecipients: expected,
          };
        }
      } else if (input.recipientEnforcement === "tofu") {
        // No record + TOFU: claim-if-absent IN THIS ATOM, reading tofuEnabled inside (closes the
        // TOCTOU). Only "tofu" ever claims; "allowlist"/"off"/absent with no record admit advisory.
        if (policy?.tofu_enabled !== 1) {
          return refusal("recipientPolicy", "recipient-tofu-not-provisioned");
        }
        this.#run(
          `INSERT INTO pins (scope, network, recipients, source) VALUES (?, ?, ?, 'tofu')
           ON CONFLICT(scope, network) DO UPDATE SET recipients = excluded.recipients, source = 'tofu'`,
          scope,
          network,
          presented,
        );
        recipientPinEstablished = true;
      }
    }

    // step 4 — resolve caps against any administered limit (min; a caller cap ABOVE it is rejected).
    const limits = this.#one(
      "SELECT max_per_hour, max_total FROM limits WHERE scope = ? AND asset = ?",
      scope,
      asset,
    );
    const adminPerHour =
      limits?.max_per_hour == null ? undefined : String(limits.max_per_hour);
    const adminTotal = limits?.max_total == null ? undefined : String(limits.max_total);
    if (adminPerHour !== undefined && big(input.maxPerHourAtomic) > big(adminPerHour)) {
      return refusal("policy.maxPerHour", "cap-exceeds-administered");
    }
    const effPerHour = input.maxPerHourAtomic;
    let effTotal: string | undefined;
    if (input.maxTotalAtomic !== undefined && input.maxTotalAtomic !== "") {
      if (adminTotal !== undefined && big(input.maxTotalAtomic) > big(adminTotal)) {
        return refusal("policy.maxTotal", "cap-exceeds-administered");
      }
      effTotal = input.maxTotalAtomic;
    } else if (adminTotal !== undefined) {
      effTotal = adminTotal;
    }

    // windowed sums (also lazily expires reserved records whose TTL passed).
    const cutoff = now - ROLLING_WINDOW_MS;
    let committed = 0n;
    for (const row of this.#rows(
      "SELECT amount FROM committed WHERE scope = ? AND asset = ? AND committed >= ? AND committed <= ?",
      scope,
      asset,
      cutoff,
      now,
    )) {
      committed += big(String(row.amount));
    }
    let reserved = 0n;
    let exposedRolling = 0n;
    for (const row of this.#rows(
      "SELECT id, amount, expires, state FROM reservations WHERE scope = ? AND asset = ? AND created >= ? AND created <= ?",
      scope,
      asset,
      cutoff,
      now,
    )) {
      if (row.state === "reserved") {
        if (Number(row.expires) <= now) {
          this.#run(
            "UPDATE reservations SET state = 'expired' WHERE scope = ? AND asset = ? AND id = ?",
            scope,
            asset,
            String(row.id),
          );
        } else {
          reserved += big(String(row.amount));
        }
      } else if (row.state === "exposed") {
        exposedRolling += big(String(row.amount));
      }
    }

    // step 5 — per-hour cap over the rolling window; the three terms are disjoint.
    const amount = big(input.amountAtomic);
    if (committed + reserved + exposedRolling + amount > big(effPerHour)) {
      return {
        ok: false,
        kind: "budget",
        capKind: "per-hour",
        requestedAtomic: input.amountAtomic,
        capAtomic: effPerHour,
        committedAtomic: committed.toString(),
        reservedAtomic: (reserved + exposedRolling).toString(),
      };
    }

    // step 6 — cumulative cap, only when one is in effect. Exposed is counted once, via the counter.
    if (effTotal !== undefined) {
      const cumCommitted = this.#counter(scope, asset, "total");
      const exposedTotal = this.#counter(scope, asset, "exposed");
      const sum = big(cumCommitted) + big(exposedTotal) + reserved + amount;
      if (sum > big(effTotal)) {
        return {
          ok: false,
          kind: "budget",
          capKind: "cumulative",
          requestedAtomic: input.amountAtomic,
          capAtomic: effTotal,
          committedAtomic: cumCommitted,
          reservedAtomic: (big(exposedTotal) + reserved).toString(),
        };
      }
    }

    // step 7 — insert.
    const expiresAt = now + RESERVATION_TTL_MS;
    this.#run(
      `INSERT INTO reservations (scope, asset, id, fingerprint, amount, created, expires, state)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved')`,
      scope,
      asset,
      id,
      input.requestFingerprint,
      input.amountAtomic,
      now,
      expiresAt,
    );
    return {
      ok: true,
      reservation: {
        reservationId: id,
        policyScope: scope,
        requestFingerprint: input.requestFingerprint,
        assetId: asset,
        amountAtomic: input.amountAtomic,
        createdAtEpochMs: now,
        expiresAtEpochMs: expiresAt,
        state: "reserved",
      },
      recipientPinEstablished,
    };
  }

  commit(input: CommitInput): CommitEnvelope {
    return this.ctx.storage.transactionSync(() => this.#commitAtom(input));
  }

  #commitAtom(input: CommitInput): CommitEnvelope {
    const { policyScope: scope, reservationId: id } = input;
    const asset = canonAsset(input.assetId); // SPEC §6.4/U16: key on the canonical asset
    const now = this.#now(input.committedAtEpochMs);
    const committedRow = this.#one(
      "SELECT * FROM committed WHERE scope = ? AND asset = ? AND id = ?",
      scope,
      asset,
      id,
    );
    if (committedRow !== undefined) return { ok: true, entry: toEntry(committedRow) }; // replay

    const rk = this.#reservationRow(scope, asset, id);
    if (rk === undefined) return refusal("reservationRef", "reservation-not-found");
    let state = String(rk.state);
    if (state === "reserved" && Number(rk.expires) <= now) {
      this.#run(
        "UPDATE reservations SET state = 'expired' WHERE scope = ? AND asset = ? AND id = ?",
        scope,
        asset,
        id,
      );
      state = "expired";
    }
    if (state === "released")
      return refusal("reservation.lifecycle", "released-cannot-commit");
    if (state === "expired")
      return refusal("reservation.lifecycle", "expired-cannot-commit");

    const amount = String(rk.amount);
    const fingerprint = String(rk.fingerprint);
    // An empty settlementId means "no settlement id" — store NULL, matching Redis (whose Lua drops
    // an empty value) so every adapter round-trips an empty id as absent, not `""` (O27).
    const settlement = input.settlementId ? input.settlementId : null;
    this.#run(
      `INSERT INTO committed (scope, asset, id, fingerprint, amount, committed, settlement)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      scope,
      asset,
      id,
      fingerprint,
      amount,
      now,
      settlement,
    );
    this.#run(
      "UPDATE reservations SET state = 'committed' WHERE scope = ? AND asset = ? AND id = ?",
      scope,
      asset,
      id,
    );
    this.#setCounter(
      scope,
      asset,
      "total",
      (big(this.#counter(scope, asset, "total")) + big(amount)).toString(),
    );
    if (state === "exposed") {
      this.#setCounter(
        scope,
        asset,
        "exposed",
        (big(this.#counter(scope, asset, "exposed")) - big(amount)).toString(),
      );
    }
    return {
      ok: true,
      entry: {
        reservationId: id,
        requestFingerprint: fingerprint,
        assetId: asset,
        amountAtomic: amount,
        committedAtEpochMs: now,
        ...(input.settlementId ? { settlementId: input.settlementId } : {}),
      },
    };
  }

  release(ref: RefInput, nowEpochMs: number): ReservationEnvelope {
    return this.ctx.storage.transactionSync(() => this.#releaseAtom(ref, nowEpochMs));
  }

  #releaseAtom(ref: RefInput, nowEpochMs: number): ReservationEnvelope {
    const { policyScope: scope, reservationId: id } = ref;
    const asset = canonAsset(ref.assetId); // SPEC §6.4/U16: key on the canonical asset
    const now = this.#now(nowEpochMs);
    const rk = this.#reservationRow(scope, asset, id);
    if (rk === undefined) return refusal("reservationRef", "reservation-not-found");
    let state = String(rk.state);
    if (state === "reserved" && Number(rk.expires) <= now) {
      this.#run(
        "UPDATE reservations SET state = 'expired' WHERE scope = ? AND asset = ? AND id = ?",
        scope,
        asset,
        id,
      );
      state = "expired";
    }
    if (state === "reserved") {
      this.#run(
        "UPDATE reservations SET state = 'released' WHERE scope = ? AND asset = ? AND id = ?",
        scope,
        asset,
        id,
      );
    } else if (state === "exposed") {
      this.#run(
        "UPDATE reservations SET state = 'released' WHERE scope = ? AND asset = ? AND id = ?",
        scope,
        asset,
        id,
      );
      this.#setCounter(
        scope,
        asset,
        "exposed",
        (big(this.#counter(scope, asset, "exposed")) - big(String(rk.amount))).toString(),
      );
    }
    // committed / released / expired: replay → return the record unchanged.
    return {
      ok: true,
      reservation: toReservation(this.#reservationRow(scope, asset, id)!),
    };
  }

  expose(ref: RefInput, nowEpochMs: number): ReservationEnvelope {
    return this.ctx.storage.transactionSync(() => this.#exposeAtom(ref, nowEpochMs));
  }

  #exposeAtom(ref: RefInput, nowEpochMs: number): ReservationEnvelope {
    const { policyScope: scope, reservationId: id } = ref;
    const asset = canonAsset(ref.assetId); // SPEC §6.4/U16: key on the canonical asset
    const now = this.#now(nowEpochMs);
    const rk = this.#reservationRow(scope, asset, id);
    if (rk === undefined) return refusal("reservationRef", "reservation-not-found");
    let state = String(rk.state);
    if (state === "reserved" && Number(rk.expires) <= now) {
      this.#run(
        "UPDATE reservations SET state = 'expired' WHERE scope = ? AND asset = ? AND id = ?",
        scope,
        asset,
        id,
      );
      state = "expired";
    }
    if (state === "exposed") return { ok: true, reservation: toReservation(rk) }; // replay
    if (state !== "reserved")
      return refusal("reservation.lifecycle", "reservation-already-terminal");
    this.#run(
      "UPDATE reservations SET state = 'exposed' WHERE scope = ? AND asset = ? AND id = ?",
      scope,
      asset,
      id,
    );
    this.#setCounter(
      scope,
      asset,
      "exposed",
      (big(this.#counter(scope, asset, "exposed")) + big(String(rk.amount))).toString(),
    );
    return {
      ok: true,
      reservation: toReservation(this.#reservationRow(scope, asset, id)!),
    };
  }

  getBudgetState(query: QueryInput): RawSnapshot {
    return this.ctx.storage.transactionSync(() => this.#snapshotAtom(query));
  }

  #snapshotAtom(query: QueryInput): RawSnapshot {
    const { policyScope: scope } = query;
    const asset = canonAsset(query.assetId); // SPEC §6.4/U16: key on the canonical asset
    const now = this.#now(query.nowEpochMs);
    const cutoff = now - ROLLING_WINDOW_MS;

    // GC committed entries + their reservation once the commit falls out of the window.
    for (const row of this.#rows(
      "SELECT id FROM committed WHERE scope = ? AND asset = ? AND committed < ?",
      scope,
      asset,
      cutoff,
    )) {
      const id = String(row.id);
      this.#run(
        "DELETE FROM committed WHERE scope = ? AND asset = ? AND id = ?",
        scope,
        asset,
        id,
      );
      this.#run(
        "DELETE FROM reservations WHERE scope = ? AND asset = ? AND id = ?",
        scope,
        asset,
        id,
      );
    }

    let committed = 0n;
    const entries: RawEntry[] = [];
    for (const row of this.#rows(
      "SELECT * FROM committed WHERE scope = ? AND asset = ? AND committed >= ? AND committed <= ? ORDER BY committed",
      scope,
      asset,
      cutoff,
      now,
    )) {
      committed += big(String(row.amount));
      entries.push(toEntry(row));
    }

    let reserved = 0n;
    let exposedRolling = 0n;
    const reservations: RawReservation[] = [];
    for (const row of this.#rows(
      "SELECT * FROM reservations WHERE scope = ? AND asset = ? ORDER BY created",
      scope,
      asset,
    )) {
      let state = String(row.state);
      if (state === "reserved" && Number(row.expires) <= now) {
        this.#run(
          "UPDATE reservations SET state = 'expired' WHERE scope = ? AND asset = ? AND id = ?",
          scope,
          asset,
          String(row.id),
        );
        state = "expired";
        row.state = "expired";
      }
      const created = Number(row.created);
      // GC an out-of-window terminal reservation (never an exposed or committed one).
      if (
        state !== "exposed" &&
        state !== "committed" &&
        state !== "reserved" &&
        created < cutoff
      ) {
        this.#run(
          "DELETE FROM reservations WHERE scope = ? AND asset = ? AND id = ?",
          scope,
          asset,
          String(row.id),
        );
        continue;
      }
      reservations.push(toReservation(row));
      if (created >= cutoff && created <= now) {
        if (state === "reserved") reserved += big(String(row.amount));
        else if (state === "exposed") exposedRolling += big(String(row.amount));
      }
    }

    const cumCommitted = this.#counter(scope, asset, "total");
    const exposedTotal = this.#counter(scope, asset, "exposed");
    const cumConsumed = (big(cumCommitted) + big(exposedTotal) + reserved).toString();
    const rollingConsumed = committed + reserved + exposedRolling;
    const frozen =
      this.#one("SELECT 1 FROM frozen WHERE scope = ? OR scope = ?", scope, "*") !==
      undefined;

    const limits = this.#one(
      "SELECT max_per_hour, max_total FROM limits WHERE scope = ? AND asset = ?",
      scope,
      asset,
    );
    const perHour = limits?.max_per_hour == null ? undefined : String(limits.max_per_hour);
    const total = limits?.max_total == null ? undefined : String(limits.max_total);

    return {
      committedAtomic: committed.toString(),
      reservedAtomic: reserved.toString(),
      exposedAtomic: exposedTotal,
      cumulativeCommittedAtomic: cumCommitted,
      cumulativeConsumedAtomic: cumConsumed,
      frozen,
      entries,
      reservations,
      ...(perHour === undefined
        ? {}
        : {
            perHourLimitAtomic: perHour,
            availablePerHourAtomic: availStr(perHour, rollingConsumed),
          }),
      ...(total === undefined
        ? {}
        : {
            cumulativeLimitAtomic: total,
            availableCumulativeAtomic: availStr(total, big(cumConsumed)),
          }),
    };
  }

  listExposed(query: QueryInput): RawReservation[] {
    return this.#rows(
      "SELECT * FROM reservations WHERE scope = ? AND asset = ? AND state = 'exposed' ORDER BY created",
      query.policyScope,
      canonAsset(query.assetId), // SPEC §6.4/U16
    ).map(toReservation);
  }

  isFrozen(scope: string): boolean {
    return (
      this.#one("SELECT 1 FROM frozen WHERE scope = ? OR scope = ?", scope, "*") !==
      undefined
    );
  }

  getRecipientPins(scope: string, network: string): string[] {
    const row = this.#one(
      "SELECT recipients FROM pins WHERE scope = ? AND network = ?",
      scope,
      network,
    );
    // Guard on empty CONTENT, not just row existence: an administered empty set stores `""`, and
    // `"".split("\n")` is `[""]`, not `[]` — so an empty allowlist must read back `[]` to match
    // Memory/Redis (O27).
    const recipients = row ? String(row.recipients) : "";
    return recipients === "" ? [] : recipients.split("\n");
  }

  getRecipientPolicy(scope: string): {
    tofuEnabled: boolean;
    recipientAssertionRequired: boolean;
  } {
    const row = this.#one(
      "SELECT tofu_enabled, assertion_required FROM recipient_policy WHERE scope = ?",
      scope,
    );
    return {
      tofuEnabled: row?.tofu_enabled === 1,
      recipientAssertionRequired: row?.assertion_required === 1,
    };
  }

  // ── admin plane (token-verified INSIDE the DO — SPEC §12.3). ────────────────────────────────

  freeze(scope: string, adminToken: string, atomicGlobalFreeze: boolean): VoidEnvelope {
    if (!this.#verifyAdmin(adminToken)) return ADMIN_DENIED;
    if (scope === "*" && !atomicGlobalFreeze) {
      return refusal("freeze.global", "global-freeze-unsupported");
    }
    this.#run("INSERT OR IGNORE INTO frozen (scope) VALUES (?)", scope);
    return { ok: true };
  }

  unfreeze(scope: string, adminToken: string): VoidEnvelope {
    if (!this.#verifyAdmin(adminToken)) return ADMIN_DENIED;
    this.#run("DELETE FROM frozen WHERE scope = ?", scope);
    return { ok: true };
  }

  setRecipientPins(
    scope: string,
    network: string,
    recipients: string[],
    adminToken: string,
  ): VoidEnvelope {
    if (!this.#verifyAdmin(adminToken)) return ADMIN_DENIED;
    this.#run(
      `INSERT INTO pins (scope, network, recipients, source) VALUES (?, ?, ?, 'admin-allowlist')
       ON CONFLICT(scope, network) DO UPDATE SET recipients = excluded.recipients, source = 'admin-allowlist'`,
      scope,
      network,
      recipients.join("\n"),
    );
    return { ok: true };
  }

  setBudgetLimits(
    scope: string,
    asset: string,
    limits: BudgetLimits,
    adminToken: string,
  ): VoidEnvelope {
    if (!this.#verifyAdmin(adminToken)) return ADMIN_DENIED;
    asset = canonAsset(asset); // SPEC §6.4/U16: store the cap under the canonical asset
    // DELETE + conditional INSERT in ONE transaction (like every other DO transition), so a crash
    // between the two can never persist the delete and lose the cap, and no partial write escapes
    // (O26). `transactionSync` rolls back on a thrown error. Replace semantics — an absent field is
    // removed — match MemorySpendStore/Redis.
    this.ctx.storage.transactionSync(() => {
      this.#run("DELETE FROM limits WHERE scope = ? AND asset = ?", scope, asset);
      if (limits.maxPerHourAtomic !== undefined || limits.maxTotalAtomic !== undefined) {
        this.#run(
          "INSERT INTO limits (scope, asset, max_per_hour, max_total) VALUES (?, ?, ?, ?)",
          scope,
          asset,
          limits.maxPerHourAtomic ?? null,
          limits.maxTotalAtomic ?? null,
        );
      }
    });
    return { ok: true };
  }

  getBudgetLimits(scope: string, asset: string, adminToken: string): LimitsEnvelope {
    if (!this.#verifyAdmin(adminToken)) return ADMIN_DENIED;
    asset = canonAsset(asset); // SPEC §6.4/U16
    const row = this.#one(
      "SELECT max_per_hour, max_total FROM limits WHERE scope = ? AND asset = ?",
      scope,
      asset,
    );
    return {
      ok: true,
      limits: {
        ...(row?.max_per_hour == null
          ? {}
          : { maxPerHourAtomic: String(row.max_per_hour) }),
        ...(row?.max_total == null ? {} : { maxTotalAtomic: String(row.max_total) }),
      },
    };
  }

  setRecipientAssertionRequired(
    scope: string,
    required: boolean,
    adminToken: string,
  ): VoidEnvelope {
    if (!this.#verifyAdmin(adminToken)) return ADMIN_DENIED;
    this.#run(
      `INSERT INTO recipient_policy (scope, assertion_required) VALUES (?, ?)
       ON CONFLICT(scope) DO UPDATE SET assertion_required = excluded.assertion_required`,
      scope,
      required ? 1 : 0,
    );
    return { ok: true };
  }

  setTofuEnabled(scope: string, enabled: boolean, adminToken: string): VoidEnvelope {
    if (!this.#verifyAdmin(adminToken)) return ADMIN_DENIED;
    this.#run(
      `INSERT INTO recipient_policy (scope, tofu_enabled) VALUES (?, ?)
       ON CONFLICT(scope) DO UPDATE SET tofu_enabled = excluded.tofu_enabled`,
      scope,
      enabled ? 1 : 0,
    );
    return { ok: true };
  }

  resolveExposed(
    ref: RefInput,
    outcome: "committed" | "released",
    nowEpochMs: number,
    adminToken: string,
  ): VoidEnvelope {
    if (!this.#verifyAdmin(adminToken)) return ADMIN_DENIED;
    return this.ctx.storage.transactionSync(() =>
      this.#resolveExposedAtom(ref, outcome, nowEpochMs),
    );
  }

  #resolveExposedAtom(
    ref: RefInput,
    outcome: "committed" | "released",
    nowEpochMs: number,
  ): VoidEnvelope {
    const { policyScope: scope, reservationId: id } = ref;
    const asset = canonAsset(ref.assetId); // SPEC §6.4/U16: key on the canonical asset
    const now = this.#now(nowEpochMs);
    const rk = this.#reservationRow(scope, asset, id);
    if (rk === undefined) return refusal("reservationRef", "reservation-not-found");
    const state = String(rk.state);
    if (state === "reserved")
      return refusal("reservation.lifecycle", "reservation-not-exposed");
    if (state !== "exposed")
      return refusal("reservation.lifecycle", "reservation-already-terminal");
    const amount = String(rk.amount);
    if (outcome === "committed") {
      this.#run(
        `INSERT INTO committed (scope, asset, id, fingerprint, amount, committed, settlement)
         VALUES (?, ?, ?, ?, ?, ?, NULL)`,
        scope,
        asset,
        id,
        String(rk.fingerprint),
        amount,
        now,
      );
      this.#run(
        "UPDATE reservations SET state = 'committed' WHERE scope = ? AND asset = ? AND id = ?",
        scope,
        asset,
        id,
      );
      this.#setCounter(
        scope,
        asset,
        "total",
        (big(this.#counter(scope, asset, "total")) + big(amount)).toString(),
      );
      this.#setCounter(
        scope,
        asset,
        "exposed",
        (big(this.#counter(scope, asset, "exposed")) - big(amount)).toString(),
      );
    } else {
      this.#run(
        "UPDATE reservations SET state = 'released' WHERE scope = ? AND asset = ? AND id = ?",
        scope,
        asset,
        id,
      );
      this.#setCounter(
        scope,
        asset,
        "exposed",
        (big(this.#counter(scope, asset, "exposed")) - big(amount)).toString(),
      );
    }
    return { ok: true };
  }

  resetCumulative(scope: string, asset: string, adminToken: string): VoidEnvelope {
    if (!this.#verifyAdmin(adminToken)) return ADMIN_DENIED;
    asset = canonAsset(asset); // SPEC §6.4/U16
    this.#setCounter(scope, asset, "total", "0");
    return { ok: true };
  }

  // ── TEST-ONLY (env-gated; SPEC §3.4a/§3.6). Inert in production. ─────────────────────────────

  setBackendClock(nowEpochMs: number): void {
    if (!this.#testMode) return;
    this.#run(
      `INSERT INTO meta (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      CLOCK_KEY,
      String(nowEpochMs),
    );
  }

  /**
   * TEST-ONLY. Aborts this DO instance (`ctx.abort`), discarding all in-memory state and forcing
   * the runtime to reconstruct it on the next call — the local analog of the Redis AOF restart
   * (`_check_restart`, SPEC §12.4). The SQLite storage is durable and survives, so the revived
   * instance reads the same reservations and counters. The call itself is torn down by the abort,
   * so the harness ignores its rejection.
   */
  __evict(): void {
    if (!this.#testMode) return;
    this.ctx.abort("tx402-test-eviction");
  }

  reset(): void {
    if (!this.#testMode) return;
    for (const table of [
      "reservations",
      "committed",
      "counters",
      "limits",
      "frozen",
      "pins",
      "recipient_policy",
      "meta",
    ]) {
      this.#run(`DELETE FROM ${table}`);
    }
  }
}

function toReservation(row: Row): RawReservation {
  return {
    reservationId: String(row.id),
    policyScope: String(row.scope),
    requestFingerprint: String(row.fingerprint),
    assetId: String(row.asset),
    amountAtomic: String(row.amount),
    createdAtEpochMs: Number(row.created),
    expiresAtEpochMs: Number(row.expires),
    state: String(row.state) as RawReservation["state"],
  };
}

function toEntry(row: Row): RawEntry {
  return {
    reservationId: String(row.id),
    requestFingerprint: String(row.fingerprint),
    assetId: String(row.asset),
    amountAtomic: String(row.amount),
    committedAtEpochMs: Number(row.committed),
    ...(row.settlement == null ? {} : { settlementId: String(row.settlement) }),
  };
}
