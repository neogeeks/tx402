"""The reference durable Redis :class:`~tx402.ledger.SpendStore` (SPEC §12.2, ADR-025..030).

``RedisSpendStore`` (sync, over ``redis.Redis``) and ``AsyncRedisSpendStore`` (async, over
``redis.asyncio.Redis``) run the byte-identical Lua atoms in :mod:`tx402.stores._lua` — the
same scripts the TypeScript ``tx402/redis`` adapter uses (verified by matching EVAL shas),
so both SDKs share one backend semantics, not merely an interface. Both are held to the
SPEC §3 contract by ``tx402.spend_store_contract`` running against a live Redis.

Design (mirrors ``packages/tx402/src/redis/store.ts``):

- **One server-side atom per transition** via ``EVAL`` (``EVALSHA`` with an ``EVAL``
  fallback on ``NOSCRIPT``), never a client read-decide-write and never ``FUNCTION LOAD`` —
  managed Redis (Upstash) support for Redis Functions is spotty (O14).
- **Backend-authoritative time (§3.4a).** The atom windows on ``redis.call('TIME')``; the
  caller's ``now_epoch_ms`` never windows anything. A TEST-ONLY injectable clock
  (``test_clock``) lets the suite pin and advance time; production never enables it.
- **Unbounded-width arithmetic (§12.2).** Amounts are decimal strings put through Lua
  big-integer helpers; only epoch-ms timestamps are Lua numbers.
- **``{ns:scope}`` single slot** so a scope's whole atom is one Cluster slot (§12.2).
- **Data/admin plane split (ADR-029).** A data-plane store (``admin=False``, the default)
  refuses every admin mutation with ``admin-credential-required`` (enforced in the adapter;
  a raw Redis ACL user hardens it.)
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Literal, cast

import redis
import redis.asyncio
from redis.exceptions import NoScriptError

from tx402.errors import (
    BudgetExceededError,
    ConfigurationError,
    RecipientUnpinnedError,
    SpendScopeFrozenError,
    TransportError,
    Tx402ErrorContext,
    is_tx402_error,
)
from tx402.ledger import (
    RESERVATION_TTL_MS,
    ROLLING_WINDOW_MS,
    BudgetLimits,
    BudgetState,
    ReservationRef,
    ReserveSpendResult,
    SpendEntry,
    SpendReservation,
    StoreCapabilities,
    canonicalize_asset,
)
from tx402.stores import _lua

__all__ = ["AsyncRedisSpendStore", "RedisSpendStore"]

_SHA = {
    "reserve": hashlib.sha1(_lua.RESERVE.encode()).hexdigest(),
    "commit": hashlib.sha1(_lua.COMMIT.encode()).hexdigest(),
    "release": hashlib.sha1(_lua.RELEASE.encode()).hexdigest(),
    "expose": hashlib.sha1(_lua.EXPOSE.encode()).hexdigest(),
    "resolve_exposed": hashlib.sha1(_lua.RESOLVE_EXPOSED.encode()).hexdigest(),
    "snapshot": hashlib.sha1(_lua.SNAPSHOT.encode()).hexdigest(),
    "list_exposed": hashlib.sha1(_lua.LIST_EXPOSED.encode()).hexdigest(),
    "set_limits": hashlib.sha1(_lua.SET_LIMITS.encode()).hexdigest(),
}


def _text(value: object) -> str | None:
    """Decode a Redis string reply, whatever the client's ``decode_responses`` setting."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, str):
        return value
    return str(value)


def _script_reply(value: object) -> str:
    """A Lua ``EVAL`` reply is always the ``cjson`` string; narrow it away from ``Any``."""
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, str):
        return value
    raise TypeError(f"unexpected Redis EVAL reply type: {type(value)!r}")


def _as_list(value: Any) -> list[Any]:
    # cjson encodes an empty array as ``{}`` (a JSON object); coerce it back to a list.
    return value if isinstance(value, list) else []


def _reservation_from(d: dict[str, Any]) -> SpendReservation:
    return SpendReservation(
        reservation_id=d["reservationId"],
        policy_scope=d["policyScope"],
        request_fingerprint=d["requestFingerprint"],
        asset_id=d["assetId"],
        amount_atomic=d["amountAtomic"],
        created_at_epoch_ms=int(d["createdAtEpochMs"]),
        expires_at_epoch_ms=int(d["expiresAtEpochMs"]),
        state=d["state"],
    )


def _entry_from(d: dict[str, Any]) -> SpendEntry:
    return SpendEntry(
        reservation_id=d["reservationId"],
        request_fingerprint=d["requestFingerprint"],
        asset_id=d["assetId"],
        amount_atomic=d["amountAtomic"],
        committed_at_epoch_ms=int(d["committedAtEpochMs"]),
        settlement_id=d.get("settlementId"),
    )


def _reserve_argv(
    ns: str,
    *,
    policy_scope: str,
    asset_id: str,
    reservation_id: str,
    request_fingerprint: str,
    amount_atomic: str,
    max_per_hour_atomic: str,
    max_total_atomic: str | None,
    recipient_network: str | None,
    recipient_canonical: str | None,
    recipient_enforcement: str | None,
    now: str,
    check_global_frozen: str,
) -> list[str]:
    return [
        ns,
        policy_scope,
        canonicalize_asset(asset_id),  # SPEC §6.4/U16: the atom keys on the canonical asset
        reservation_id,
        request_fingerprint,
        amount_atomic,
        max_per_hour_atomic,
        max_total_atomic or "",
        recipient_network or "",
        recipient_canonical or "",
        recipient_enforcement or "",
        now,
        str(RESERVATION_TTL_MS),
        str(ROLLING_WINDOW_MS),
        check_global_frozen,
    ]


def _map_refusal(
    res: dict[str, Any],
    *,
    request_id: str,
    policy_scope: str,
    asset_id: str | None,
    amount_atomic: str | None = None,
    reservation_id: str | None = None,
) -> Exception:
    """Turn a cjson refusal into the exact typed error (TS-adapter parity, SPEC §8)."""
    kind = res["kind"]
    if kind == "idreuse":
        return ValueError("Reservation ID was reused with different spend data")
    if kind == "frozen":
        return SpendScopeFrozenError(
            "Spending is frozen for this scope",
            context=Tx402ErrorContext(
                request_id=request_id,
                phase="policy",
                amount_atomic=amount_atomic,
                asset_id=asset_id,
            ),
            details={"scope": policy_scope, "frozenScope": res["frozenScope"]},
        )
    if kind == "recipient":
        details: dict[str, Any] = {"merchantScope": policy_scope, "reason": res["reason"]}
        if res["reason"] in ("not-allowlisted", "pin-mismatch"):
            details["network"] = res["network"]
            details["presentedRecipient"] = res["presentedRecipient"]
            details["expectedRecipients"] = res["expectedRecipients"]
        return RecipientUnpinnedError(
            "The recipient is not pinned for this scope",
            context=Tx402ErrorContext(
                request_id=request_id, phase="policy", asset_id=asset_id
            ),
            details=details,
        )
    if kind == "budget":
        message = (
            "Cumulative spend limit would be exceeded"
            if res["capKind"] == "cumulative"
            else "Hourly spend limit would be exceeded"
        )
        return BudgetExceededError(
            message,
            context=Tx402ErrorContext(
                request_id=request_id,
                phase="policy",
                amount_atomic=amount_atomic,
                asset_id=asset_id,
            ),
            details={
                "requestedAtomic": res["requestedAtomic"],
                "capAtomic": res["capAtomic"],
                "committedAtomic": res["committedAtomic"],
                "reservedAtomic": res["reservedAtomic"],
                "capKind": res["capKind"],
            },
        )
    # kind == "config"
    reason = res["reason"]
    message = (
        "The reservation ref names no record"
        if reason == "reservation-not-found"
        else "The reservation lifecycle transition is not permitted"
    )
    return ConfigurationError(
        message,
        context=Tx402ErrorContext(
            request_id=request_id, phase="policy", reservation_id=reservation_id
        ),
        details={"configPath": res["configPath"], "reason": reason},
    )


def _admin_required() -> ConfigurationError:
    return ConfigurationError(
        "An admin credential is required for this operation",
        context=Tx402ErrorContext(request_id="spend-store", phase="policy"),
        details={"configPath": "credential", "reason": "admin-credential-required"},
    )


def _persistence_warning(appendonly: str | None) -> str | None:
    """The §12.2 warning for a CONFIG ``appendonly`` value, or ``None`` when AOF is on."""
    if appendonly == "yes":
        return None
    return (
        f"tx402: Redis persistence is disabled (appendonly={appendonly or 'unknown'}). "
        "This store is NOT restart-durable — a crash or restart loses every reservation "
        "and counter. Enable AOF (appendonly yes, appendfsync everysec or stricter) for a "
        "durable shared spend store (SPEC §12.2)."
    )


def _global_freeze_unsupported() -> ConfigurationError:
    return ConfigurationError(
        "Atomic global freeze is not supported by this topology",
        context=Tx402ErrorContext(request_id="spend-store", phase="policy"),
        details={"configPath": "freeze.global", "reason": "global-freeze-unsupported"},
    )


#: The reserved suffix of the per-asset index/counter keys (SPEC §12.2):
#: ``{...}:res:<asset>:idx`` / ``{...}:cmt:<asset>:idx`` (``_lua`` ``resIdx``/``cmtIdx``).
_RESERVED_KEY_SUFFIXES: frozenset[str] = frozenset({"idx", "total", "exposed", "limits"})


def _reservation_id_aliases_key(reservation_id: str) -> bool:
    """True when ``reservation_id`` aliases a reserved index/counter/limits key (O48/O54).

    ``resKey(asset, id) = ...:res:<asset>:<id>`` while
    ``resIdx(asset) = ...:res:<asset>:idx``, so ``id == "idx"`` maps a reservation HASH onto
    the index ZSET key; likewise ``resKey(A, "total") = ...:res:A:total`` equals
    ``totalKey("res:A")``, so an ``id`` equal to a counter/limits suffix bricks a
    ``res:``/``cmt:``-prefixed pseudo-asset ledger (O54). And because the key builders join
    components with ``:``, an ``id`` containing ``:`` re-parses to a different
    ``(asset, id)`` pair whose final segment can be a reserved suffix
    (``asset="A", id="B:idx"`` == ``resIdx("A:B")``). Every such collision corrupts the
    ``(scope, asset)`` ledger with ``WRONGTYPE`` (or, for ``limits``, overwrites the caps).
    Store-generated UUIDv7 ids and realistic CAIP-19 asset ids never match.
    ``MemorySpendStore`` and the DO store are immune; this is the Redis-only guard.
    """
    return reservation_id in _RESERVED_KEY_SUFFIXES or ":" in reservation_id


def _assert_reservation_id_safe(
    reservation_id: str, *, request_id: str = "spend-store", asset_id: str | None = None
) -> None:
    """Fail closed with a typed :class:`ConfigurationError` before any Redis write (O48).

    Does not change the frozen SPEC §12.2 key layout: it refuses the pathological caller
    input that would alias a reserved key. Store-generated UUIDv7 ids never match.
    """
    if not _reservation_id_aliases_key(reservation_id):
        return
    raise ConfigurationError(
        'reservationId may not be "idx"/"total"/"exposed"/"limits" or contain ":" - it '
        "would alias a reserved index/counter key in the Redis keyspace (SPEC §12.2).",
        context=Tx402ErrorContext(request_id=request_id, phase="policy", asset_id=asset_id),
        details={"configPath": "reservationId", "reason": "reservation-id-aliases-index"},
    )


def _is_store_unreachable(error: BaseException) -> bool:
    """True when ``error`` is a store-*unreachable* failure, not a server reply (U9).

    A ``ResponseError`` (``WRONGTYPE``, a Lua ``error()``, ``NOSCRIPT``) means the server
    was reached and answered, never a transport outage. A connection refused / timeout /
    closed socket is the store being unreachable, the same failure ``reserve`` already
    surfaces as a typed retryable ``TransportError``.
    """
    if isinstance(error, redis.exceptions.ResponseError):
        return False
    return isinstance(
        error,
        (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, OSError),
    )


def _store_unavailable_transport(kind: str) -> TransportError:
    return TransportError(
        "The spend store is unreachable",
        context=Tx402ErrorContext(request_id="spend-store", phase="policy"),
        # Coarse category only (SEC-003) — never the DSN or the redis-py internal message.
        details={"causeCategory": "spend-store-unavailable", "storeKind": kind},
    )


@contextmanager
def _reclassify_unreachable(kind: str) -> Iterator[None]:
    """Reclassify a store-unreachable failure in the block as a typed ``TransportError``.

    Works for both the sync and async stores: an awaited coroutine that fails raises at
    the ``await`` site inside this block, so a plain (sync) context manager catches it
    (U9). A typed tx402 error or a server reply error passes through unchanged.
    """
    try:
        yield
    except Exception as error:
        if not is_tx402_error(error) and _is_store_unreachable(error):
            raise _store_unavailable_transport(kind) from None
        raise


class _Keys:
    """The ``{ns:scope}`` key builders, shared by the sync and async stores."""

    def __init__(self, ns: str) -> None:
        self._ns = ns

    def route(self, scope: str) -> list[str]:
        # A representative key so Cluster routes the atom to the scope's single slot.
        return ["{" + self._ns + ":" + scope + "}"]

    def clock(self) -> str:
        return f"{self._ns}:__test-clock__"

    def global_frozen(self) -> str:
        return "{" + self._ns + "}:global-frozen"

    def scope(self, scope: str, suffix: str) -> str:
        return "{" + self._ns + ":" + scope + "}:" + suffix

    def patterns(self) -> tuple[str, str]:
        return ("{" + self._ns + "*", f"{self._ns}:*")


class RedisSpendStore:
    """The reference synchronous Redis store (``redis.Redis``); see the module docstring."""

    kind = "redis"

    def __init__(
        self,
        client: redis.Redis,
        *,
        namespace: str = "tx402",
        admin: bool = False,
        atomic_global_freeze: bool = True,
        test_clock: bool = False,
    ) -> None:
        self._client = client
        self._ns = namespace
        self._admin = admin
        self._test_clock = test_clock
        self._keys = _Keys(namespace)
        self.capabilities = StoreCapabilities(atomic_global_freeze=atomic_global_freeze)

    # ── plumbing ──────────────────────────────────────────────────────────────────────────

    def _now(self, caller_now: int) -> str:
        if not self._test_clock:
            return ""
        pinned = _text(self._client.get(self._keys.clock()))
        return pinned if pinned is not None else str(caller_now)

    def _check_global_frozen(self) -> str:
        # "1" lets the atom consult the foreign-slot {ns}:global-frozen key; "" (Cluster,
        # atomic_global_freeze=False) skips it so the atom stays single-slot (§5.2/§12.2).
        return "1" if self.capabilities.atomic_global_freeze else ""

    def _run(self, script: str, sha: str, keys: list[str], args: list[str]) -> str:
        try:
            reply = self._client.evalsha(sha, len(keys), *keys, *args)
        except NoScriptError:
            # Script not cached on this server yet — load it via EVAL (which caches it).
            reply = self._client.eval(script, len(keys), *keys, *args)
        return _script_reply(reply)

    def _require_admin(self) -> None:
        if not self._admin:
            raise _admin_required()

    # ── data plane ────────────────────────────────────────────────────────────────────────

    def reserve(
        self,
        *,
        reservation_id: str,
        request_id: str,
        policy_scope: str,
        request_fingerprint: str,
        asset_id: str,
        amount_atomic: str,
        max_per_hour_atomic: str,
        max_total_atomic: str | None = None,
        recipient_network: str | None = None,
        recipient_canonical: str | None = None,
        recipient_enforcement: str | None = None,
        now_epoch_ms: int,
    ) -> ReserveSpendResult:
        _assert_reservation_id_safe(
            reservation_id, request_id=request_id, asset_id=asset_id
        )
        raw = self._run(
            _lua.RESERVE,
            _SHA["reserve"],
            self._keys.route(policy_scope),
            _reserve_argv(
                self._ns,
                policy_scope=policy_scope,
                asset_id=asset_id,
                reservation_id=reservation_id,
                request_fingerprint=request_fingerprint,
                amount_atomic=amount_atomic,
                max_per_hour_atomic=max_per_hour_atomic,
                max_total_atomic=max_total_atomic,
                recipient_network=recipient_network,
                recipient_canonical=recipient_canonical,
                recipient_enforcement=recipient_enforcement,
                now=self._now(now_epoch_ms),
                check_global_frozen=self._check_global_frozen(),
            ),
        )
        res = json.loads(raw)
        if res["ok"]:
            return ReserveSpendResult(
                _reservation_from(res["reservation"]),
                recipient_pin_established=res["recipientPinEstablished"],
            )
        raise _map_refusal(
            res,
            request_id=request_id,
            policy_scope=policy_scope,
            asset_id=asset_id,
            amount_atomic=amount_atomic,
        )

    def commit(
        self,
        *,
        ref: ReservationRef,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        _assert_reservation_id_safe(ref.reservation_id, asset_id=ref.asset_id)
        raw = self._run(
            _lua.COMMIT,
            _SHA["commit"],
            self._keys.route(ref.policy_scope),
            [
                self._ns,
                ref.policy_scope,
                canonicalize_asset(ref.asset_id),  # SPEC §6.4/U16
                ref.reservation_id,
                self._now(committed_at_epoch_ms),
                settlement_id or "",
            ],
        )
        res = json.loads(raw)
        if res["ok"]:
            return _entry_from(res["entry"])
        raise _map_refusal(
            res,
            request_id="spend-store",
            policy_scope=ref.policy_scope,
            asset_id=ref.asset_id,
            reservation_id=ref.reservation_id,
        )

    def release(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return self._reservation_op(_lua.RELEASE, _SHA["release"], ref, now_epoch_ms)

    def expose(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return self._reservation_op(_lua.EXPOSE, _SHA["expose"], ref, now_epoch_ms)

    def _reservation_op(
        self, script: str, sha: str, ref: ReservationRef, now_epoch_ms: int
    ) -> SpendReservation:
        _assert_reservation_id_safe(ref.reservation_id, asset_id=ref.asset_id)
        raw = self._run(
            script,
            sha,
            self._keys.route(ref.policy_scope),
            [
                self._ns,
                ref.policy_scope,
                canonicalize_asset(ref.asset_id),  # SPEC §6.4/U16
                ref.reservation_id,
                self._now(now_epoch_ms),
            ],
        )
        res = json.loads(raw)
        if res["ok"]:
            return _reservation_from(res["reservation"])
        raise _map_refusal(
            res,
            request_id="spend-store",
            policy_scope=ref.policy_scope,
            asset_id=ref.asset_id,
            reservation_id=ref.reservation_id,
        )

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        with _reclassify_unreachable(self.kind):
            raw = self._run(
                _lua.SNAPSHOT,
                _SHA["snapshot"],
                self._keys.route(policy_scope),
                [
                    self._ns,
                    policy_scope,
                    asset_id,
                    self._now(now_epoch_ms),
                    str(ROLLING_WINDOW_MS),
                    self._check_global_frozen(),
                ],
            )
        return _snapshot_from(json.loads(raw), policy_scope, asset_id)

    def list_exposed(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> tuple[SpendReservation, ...]:
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        with _reclassify_unreachable(self.kind):
            raw = self._run(
                _lua.LIST_EXPOSED,
                _SHA["list_exposed"],
                self._keys.route(policy_scope),
                [self._ns, policy_scope, asset_id],
            )
        return tuple(_reservation_from(r) for r in _as_list(json.loads(raw)))

    def is_frozen(self, *, scope: str) -> bool:
        with _reclassify_unreachable(self.kind):
            # The global-freeze key is a foreign slot; a store that cannot set it (Cluster,
            # atomic_global_freeze=False) never reads it — stays single-key-routable.
            if (
                self.capabilities.atomic_global_freeze
                and self._client.get(self._keys.global_frozen()) is not None
            ):
                return True
            return self._client.get(self._keys.scope(scope, "frozen")) is not None

    def warn_if_persistence_disabled(self) -> str | None:
        """The warning to surface when Redis is NOT restart-durable, else ``None`` (§12.2).

        Restart durability requires AOF (``appendonly yes``, ``appendfsync everysec`` or
        stricter); without it a crash or restart loses every reservation and counter. This
        does not emit anything itself — a caller logs the returned message. Returns ``None``
        when AOF is on, or when ``CONFIG GET`` is unavailable (a managed Redis may restrict
        it), where durability cannot be asserted here and the runbook is authoritative.
        """
        try:
            cfg = cast("dict[Any, Any]", self._client.config_get("appendonly"))
        except Exception:
            return None
        appendonly = _text(cfg.get("appendonly")) or _text(cfg.get(b"appendonly"))
        return _persistence_warning(appendonly)

    # ── recipient reads (data plane) ──────────────────────────────────────────────────────

    def get_recipient_pins(self, scope: str, network: str) -> tuple[str, ...]:
        # A store outage here is a typed retryable TransportError, exactly as
        # get_budget_state already is (O53) — never a raw redis-py ConnectionError (which
        # embeds host:port) leaking to the CLI `pins` verb, which must exit 7, not 2. The
        # S14f U9 fix missed this sibling read.
        with _reclassify_unreachable(self.kind):
            hash_ = self._client.hgetall(self._keys.scope(scope, f"pins:{network}"))
        joined = _text(hash_.get(b"recipients") or hash_.get("recipients"))
        return tuple(joined.split("\n")) if joined else ()

    def get_recipient_policy(self, scope: str) -> dict[str, bool]:
        with _reclassify_unreachable(self.kind):
            tofu = self._client.get(self._keys.scope(scope, "tofu-enabled"))
            required = self._client.get(self._keys.scope(scope, "recipient-required"))
        return {
            "tofu_enabled": tofu is not None,
            "recipient_assertion_required": required is not None,
        }

    # ── admin plane (every mutation refuses a data credential) ────────────────────────────

    def freeze(self, scope: str, now_epoch_ms: int) -> None:
        self._require_admin()
        if scope == "*":
            if not self.capabilities.atomic_global_freeze:
                raise _global_freeze_unsupported()
            self._client.set(self._keys.global_frozen(), "1")
            return
        self._client.set(self._keys.scope(scope, "frozen"), "1")

    def unfreeze(self, scope: str, now_epoch_ms: int) -> None:
        self._require_admin()
        key = (
            self._keys.global_frozen()
            if scope == "*"
            else self._keys.scope(scope, "frozen")
        )
        self._client.delete(key)

    def set_recipient_pins(
        self, scope: str, network: str, recipients: tuple[str, ...], now_epoch_ms: int
    ) -> None:
        self._require_admin()
        self._client.hset(
            self._keys.scope(scope, f"pins:{network}"),
            mapping={"recipients": "\n".join(recipients), "source": "admin-allowlist"},
        )

    def set_budget_limits(
        self, scope: str, asset_id: str, limits: BudgetLimits, now_epoch_ms: int
    ) -> None:
        self._require_admin()
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        # ONE atom (DEL + conditional HSET), not a client-side DEL-then-HSET: a reserve
        # racing it sees the whole old or whole new cap, never a torn value, and a
        # failure never deletes the cap (O26). Replace: an absent field is removed.
        self._run(
            _lua.SET_LIMITS,
            _SHA["set_limits"],
            self._keys.route(scope),
            [
                self._ns,
                scope,
                asset_id,
                limits.max_per_hour_atomic or "",
                limits.max_total_atomic or "",
            ],
        )

    def get_budget_limits(self, scope: str, asset_id: str) -> BudgetLimits:
        # get_budget_limits is an admin-plane read (SPEC §3.1, part of SpendStoreAdmin): the
        # DO gates it and the gateway 403s a data token, so the raw Redis store requires an
        # admin credential too (O55). No disclosure changes — the administered caps stay
        # data-readable via get_budget_state. A store outage is a TransportError (O53).
        self._require_admin()
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        with _reclassify_unreachable(self.kind):
            raw = self._client.hgetall(self._keys.scope(scope, f"{asset_id}:limits"))
        hash_ = {_text(k): _text(v) for k, v in raw.items()}
        return BudgetLimits(
            max_per_hour_atomic=hash_.get("maxPerHourAtomic"),
            max_total_atomic=hash_.get("maxTotalAtomic"),
        )

    def set_recipient_assertion_required(
        self, scope: str, required: bool, now_epoch_ms: int
    ) -> None:
        self._require_admin()
        key = self._keys.scope(scope, "recipient-required")
        self._client.set(key, "1") if required else self._client.delete(key)

    def set_tofu_enabled(self, scope: str, enabled: bool, now_epoch_ms: int) -> None:
        self._require_admin()
        key = self._keys.scope(scope, "tofu-enabled")
        self._client.set(key, "1") if enabled else self._client.delete(key)

    def resolve_exposed(
        self,
        ref: ReservationRef,
        outcome: Literal["committed", "released"],
        now_epoch_ms: int,
    ) -> None:
        self._require_admin()
        _assert_reservation_id_safe(ref.reservation_id, asset_id=ref.asset_id)
        raw = self._run(
            _lua.RESOLVE_EXPOSED,
            _SHA["resolve_exposed"],
            self._keys.route(ref.policy_scope),
            [
                self._ns,
                ref.policy_scope,
                canonicalize_asset(ref.asset_id),  # SPEC §6.4/U16
                ref.reservation_id,
                outcome,
                self._now(now_epoch_ms),
            ],
        )
        res = json.loads(raw)
        if not res["ok"]:
            raise _map_refusal(
                res,
                request_id="spend-store",
                policy_scope=ref.policy_scope,
                asset_id=ref.asset_id,
                reservation_id=ref.reservation_id,
            )

    def reset_cumulative(self, scope: str, asset_id: str, now_epoch_ms: int) -> None:
        self._require_admin()
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        self._client.delete(self._keys.scope(scope, f"{asset_id}:total"))

    # ── test-only harness helpers (SPEC §3.4a/§3.6) ───────────────────────────────────────

    def set_backend_clock(self, now_epoch_ms: int) -> None:
        self._client.set(self._keys.clock(), str(now_epoch_ms))

    def reset(self) -> None:
        found: set[Any] = set()
        for pattern in self._keys.patterns():
            found.update(self._client.keys(pattern))
        if found:
            self._client.delete(*found)


def _snapshot_from(s: dict[str, Any], policy_scope: str, asset_id: str) -> BudgetState:
    return BudgetState(
        store_kind="redis",
        committed_atomic=s["committedAtomic"],
        reserved_atomic=s["reservedAtomic"],
        entries=tuple(_entry_from(e) for e in _as_list(s["entries"])),
        reservations=tuple(_reservation_from(r) for r in _as_list(s["reservations"])),
        policy_scope=policy_scope,
        asset_id=asset_id,
        exposed_atomic=s["exposedAtomic"],
        cumulative_committed_atomic=s["cumulativeCommittedAtomic"],
        cumulative_consumed_atomic=s["cumulativeConsumedAtomic"],
        per_hour_limit_atomic=s.get("perHourLimitAtomic"),
        cumulative_limit_atomic=s.get("cumulativeLimitAtomic"),
        available_per_hour_atomic=s.get("availablePerHourAtomic"),
        available_cumulative_atomic=s.get("availableCumulativeAtomic"),
        frozen=s["frozen"],
    )


class AsyncRedisSpendStore:
    """The reference async Redis store (``redis.asyncio.Redis``); see the module docstring.

    Identical contract to :class:`RedisSpendStore`, every method ``async def`` so
    :class:`~tx402.client.AsyncTx402Client` awaits it directly rather than offloading a sync
    via ``asyncio.to_thread`` (SPEC §3.3, ADR-031).
    """

    kind = "redis"

    def __init__(
        self,
        client: redis.asyncio.Redis,
        *,
        namespace: str = "tx402",
        admin: bool = False,
        atomic_global_freeze: bool = True,
        test_clock: bool = False,
    ) -> None:
        self._client = client
        self._ns = namespace
        self._admin = admin
        self._test_clock = test_clock
        self._keys = _Keys(namespace)
        self.capabilities = StoreCapabilities(atomic_global_freeze=atomic_global_freeze)

    async def _now(self, caller_now: int) -> str:
        if not self._test_clock:
            return ""
        pinned = _text(await self._client.get(self._keys.clock()))
        return pinned if pinned is not None else str(caller_now)

    def _check_global_frozen(self) -> str:
        # "1" lets the atom consult the foreign-slot {ns}:global-frozen key; "" (Cluster,
        # atomic_global_freeze=False) skips it so the atom stays single-slot (§5.2/§12.2).
        return "1" if self.capabilities.atomic_global_freeze else ""

    async def _run(self, script: str, sha: str, keys: list[str], args: list[str]) -> str:
        try:
            reply = await self._client.evalsha(sha, len(keys), *keys, *args)
        except NoScriptError:
            # Script not cached on this server yet — load it via EVAL (which caches it).
            reply = await self._client.eval(script, len(keys), *keys, *args)
        return _script_reply(reply)

    def _require_admin(self) -> None:
        if not self._admin:
            raise _admin_required()

    async def reserve(
        self,
        *,
        reservation_id: str,
        request_id: str,
        policy_scope: str,
        request_fingerprint: str,
        asset_id: str,
        amount_atomic: str,
        max_per_hour_atomic: str,
        max_total_atomic: str | None = None,
        recipient_network: str | None = None,
        recipient_canonical: str | None = None,
        recipient_enforcement: str | None = None,
        now_epoch_ms: int,
    ) -> ReserveSpendResult:
        _assert_reservation_id_safe(
            reservation_id, request_id=request_id, asset_id=asset_id
        )
        raw = await self._run(
            _lua.RESERVE,
            _SHA["reserve"],
            self._keys.route(policy_scope),
            _reserve_argv(
                self._ns,
                policy_scope=policy_scope,
                asset_id=asset_id,
                reservation_id=reservation_id,
                request_fingerprint=request_fingerprint,
                amount_atomic=amount_atomic,
                max_per_hour_atomic=max_per_hour_atomic,
                max_total_atomic=max_total_atomic,
                recipient_network=recipient_network,
                recipient_canonical=recipient_canonical,
                recipient_enforcement=recipient_enforcement,
                now=await self._now(now_epoch_ms),
                check_global_frozen=self._check_global_frozen(),
            ),
        )
        res = json.loads(raw)
        if res["ok"]:
            return ReserveSpendResult(
                _reservation_from(res["reservation"]),
                recipient_pin_established=res["recipientPinEstablished"],
            )
        raise _map_refusal(
            res,
            request_id=request_id,
            policy_scope=policy_scope,
            asset_id=asset_id,
            amount_atomic=amount_atomic,
        )

    async def commit(
        self,
        *,
        ref: ReservationRef,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        _assert_reservation_id_safe(ref.reservation_id, asset_id=ref.asset_id)
        raw = await self._run(
            _lua.COMMIT,
            _SHA["commit"],
            self._keys.route(ref.policy_scope),
            [
                self._ns,
                ref.policy_scope,
                canonicalize_asset(ref.asset_id),  # SPEC §6.4/U16
                ref.reservation_id,
                await self._now(committed_at_epoch_ms),
                settlement_id or "",
            ],
        )
        res = json.loads(raw)
        if res["ok"]:
            return _entry_from(res["entry"])
        raise _map_refusal(
            res,
            request_id="spend-store",
            policy_scope=ref.policy_scope,
            asset_id=ref.asset_id,
            reservation_id=ref.reservation_id,
        )

    async def release(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return await self._reservation_op(_lua.RELEASE, _SHA["release"], ref, now_epoch_ms)

    async def expose(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return await self._reservation_op(_lua.EXPOSE, _SHA["expose"], ref, now_epoch_ms)

    async def _reservation_op(
        self, script: str, sha: str, ref: ReservationRef, now_epoch_ms: int
    ) -> SpendReservation:
        _assert_reservation_id_safe(ref.reservation_id, asset_id=ref.asset_id)
        raw = await self._run(
            script,
            sha,
            self._keys.route(ref.policy_scope),
            [
                self._ns,
                ref.policy_scope,
                canonicalize_asset(ref.asset_id),  # SPEC §6.4/U16
                ref.reservation_id,
                await self._now(now_epoch_ms),
            ],
        )
        res = json.loads(raw)
        if res["ok"]:
            return _reservation_from(res["reservation"])
        raise _map_refusal(
            res,
            request_id="spend-store",
            policy_scope=ref.policy_scope,
            asset_id=ref.asset_id,
            reservation_id=ref.reservation_id,
        )

    async def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        with _reclassify_unreachable(self.kind):
            raw = await self._run(
                _lua.SNAPSHOT,
                _SHA["snapshot"],
                self._keys.route(policy_scope),
                [
                    self._ns,
                    policy_scope,
                    asset_id,
                    await self._now(now_epoch_ms),
                    str(ROLLING_WINDOW_MS),
                    self._check_global_frozen(),
                ],
            )
        return _snapshot_from(json.loads(raw), policy_scope, asset_id)

    async def list_exposed(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> tuple[SpendReservation, ...]:
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        with _reclassify_unreachable(self.kind):
            raw = await self._run(
                _lua.LIST_EXPOSED,
                _SHA["list_exposed"],
                self._keys.route(policy_scope),
                [self._ns, policy_scope, asset_id],
            )
        return tuple(_reservation_from(r) for r in _as_list(json.loads(raw)))

    async def is_frozen(self, *, scope: str) -> bool:
        with _reclassify_unreachable(self.kind):
            # The global-freeze key is a foreign slot; a store that cannot set it (Cluster,
            # atomic_global_freeze=False) never reads it — stays single-key-routable.
            if (
                self.capabilities.atomic_global_freeze
                and await self._client.get(self._keys.global_frozen()) is not None
            ):
                return True
            return await self._client.get(self._keys.scope(scope, "frozen")) is not None

    async def warn_if_persistence_disabled(self) -> str | None:
        """The warning to surface when Redis is NOT restart-durable, else ``None`` (§12.2).

        See :meth:`RedisSpendStore.warn_if_persistence_disabled`.
        """
        try:
            cfg = cast("dict[Any, Any]", await self._client.config_get("appendonly"))
        except Exception:
            return None
        appendonly = _text(cfg.get("appendonly")) or _text(cfg.get(b"appendonly"))
        return _persistence_warning(appendonly)

    async def get_recipient_pins(self, scope: str, network: str) -> tuple[str, ...]:
        # A store outage is a typed retryable TransportError (O53); _reclassify_unreachable
        # is a sync CM that catches the failure raised at the await site inside the block.
        with _reclassify_unreachable(self.kind):
            hash_ = await self._client.hgetall(self._keys.scope(scope, f"pins:{network}"))
        joined = _text(hash_.get(b"recipients") or hash_.get("recipients"))
        return tuple(joined.split("\n")) if joined else ()

    async def get_recipient_policy(self, scope: str) -> dict[str, bool]:
        with _reclassify_unreachable(self.kind):
            tofu = await self._client.get(self._keys.scope(scope, "tofu-enabled"))
            required = await self._client.get(self._keys.scope(scope, "recipient-required"))
        return {
            "tofu_enabled": tofu is not None,
            "recipient_assertion_required": required is not None,
        }

    async def freeze(self, scope: str, now_epoch_ms: int) -> None:
        self._require_admin()
        if scope == "*":
            if not self.capabilities.atomic_global_freeze:
                raise _global_freeze_unsupported()
            await self._client.set(self._keys.global_frozen(), "1")
            return
        await self._client.set(self._keys.scope(scope, "frozen"), "1")

    async def unfreeze(self, scope: str, now_epoch_ms: int) -> None:
        self._require_admin()
        key = (
            self._keys.global_frozen()
            if scope == "*"
            else self._keys.scope(scope, "frozen")
        )
        await self._client.delete(key)

    async def set_recipient_pins(
        self, scope: str, network: str, recipients: tuple[str, ...], now_epoch_ms: int
    ) -> None:
        self._require_admin()
        await self._client.hset(
            self._keys.scope(scope, f"pins:{network}"),
            mapping={"recipients": "\n".join(recipients), "source": "admin-allowlist"},
        )

    async def set_budget_limits(
        self, scope: str, asset_id: str, limits: BudgetLimits, now_epoch_ms: int
    ) -> None:
        self._require_admin()
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        # ONE atom (DEL + conditional HSET), like the sync path — never torn (O26).
        await self._run(
            _lua.SET_LIMITS,
            _SHA["set_limits"],
            self._keys.route(scope),
            [
                self._ns,
                scope,
                asset_id,
                limits.max_per_hour_atomic or "",
                limits.max_total_atomic or "",
            ],
        )

    async def get_budget_limits(self, scope: str, asset_id: str) -> BudgetLimits:
        # Admin-plane read; requires an admin credential (O55). Outage -> transport (O53).
        self._require_admin()
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        with _reclassify_unreachable(self.kind):
            raw = await self._client.hgetall(self._keys.scope(scope, f"{asset_id}:limits"))
        hash_ = {_text(k): _text(v) for k, v in raw.items()}
        return BudgetLimits(
            max_per_hour_atomic=hash_.get("maxPerHourAtomic"),
            max_total_atomic=hash_.get("maxTotalAtomic"),
        )

    async def set_recipient_assertion_required(
        self, scope: str, required: bool, now_epoch_ms: int
    ) -> None:
        self._require_admin()
        key = self._keys.scope(scope, "recipient-required")
        if required:
            await self._client.set(key, "1")
        else:
            await self._client.delete(key)

    async def set_tofu_enabled(self, scope: str, enabled: bool, now_epoch_ms: int) -> None:
        self._require_admin()
        key = self._keys.scope(scope, "tofu-enabled")
        if enabled:
            await self._client.set(key, "1")
        else:
            await self._client.delete(key)

    async def resolve_exposed(
        self,
        ref: ReservationRef,
        outcome: Literal["committed", "released"],
        now_epoch_ms: int,
    ) -> None:
        self._require_admin()
        _assert_reservation_id_safe(ref.reservation_id, asset_id=ref.asset_id)
        raw = await self._run(
            _lua.RESOLVE_EXPOSED,
            _SHA["resolve_exposed"],
            self._keys.route(ref.policy_scope),
            [
                self._ns,
                ref.policy_scope,
                canonicalize_asset(ref.asset_id),  # SPEC §6.4/U16
                ref.reservation_id,
                outcome,
                await self._now(now_epoch_ms),
            ],
        )
        res = json.loads(raw)
        if not res["ok"]:
            raise _map_refusal(
                res,
                request_id="spend-store",
                policy_scope=ref.policy_scope,
                asset_id=ref.asset_id,
                reservation_id=ref.reservation_id,
            )

    async def reset_cumulative(self, scope: str, asset_id: str, now_epoch_ms: int) -> None:
        self._require_admin()
        asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
        await self._client.delete(self._keys.scope(scope, f"{asset_id}:total"))

    async def set_backend_clock(self, now_epoch_ms: int) -> None:
        await self._client.set(self._keys.clock(), str(now_epoch_ms))

    async def reset(self) -> None:
        found: set[Any] = set()
        for pattern in self._keys.patterns():
            found.update(await self._client.keys(pattern))
        if found:
            await self._client.delete(*found)
