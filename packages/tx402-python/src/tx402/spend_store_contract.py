"""A runnable conformance suite for third-party :class:`~tx402.ledger.SpendStore` adapters.

Shipped in the wheel rather than kept in ``tests/`` on purpose. An adapter author — someone
putting the fleet's budget in Redis or Postgres so that twenty agent processes share one
hourly cap — is not a contributor to this repository and cannot import its test tree.

Usage::

    from tx402.spend_store_contract import check_spend_store

    def test_my_store_is_a_spend_store() -> None:
        check_spend_store(lambda: RedisSpendStore(url="redis://localhost/15"))

``check_spend_store`` raises :class:`SpendStoreContractError` on the first violation, with a
message naming the rule that was broken. It is deliberately dependency-free and framework-
free: it is a function, not a pytest fixture, so it runs under any runner or none.

It is also **invocable** — ``python -m tx402.spend_store_contract`` runs the whole suite
against the built-in :class:`~tx402.ledger.MemorySpendStore` and exits non-zero on the first
violation (resolves O9: the module used to define the suite but run nothing).

**What it does and does not prove.** The single-plane :func:`check_spend_store`
exercises the rules checkable from outside in one process against a data-plane store:
the rolling window, idempotency, the typed over-cap refusal, scope/asset isolation, the
exposure lifecycle, and — with real threads — that reserve is atomic. It cannot prove
atomicity across *machines*, the operator/agent credential split, restart durability, or
backend-authoritative time; those need a durable backend and both security planes, which is
what :func:`check_durable_spend_store` is for (run against the Redis and DO adapters).
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Final

from tx402.errors import (
    BudgetExceededError,
    ConfigurationError,
    RecipientUnpinnedError,
    SpendScopeFrozenError,
)
from tx402.ledger import (
    RESERVATION_TTL_MS,
    ROLLING_WINDOW_MS,
    MemorySpendStore,
    ReservationRef,
    assert_spend_store,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to a type checker
    from tx402.ledger import (
        BudgetLimits,
        ReserveSpendResult,
        SpendReservation,
        SpendStore,
        SpendStoreAdmin,
    )

__all__ = [
    "SpendStoreContractError",
    "check_durable_spend_store",
    "check_spend_store",
    "main",
]

#: A fixed instant, so every check is deterministic and never reads a real clock.
_NOW: Final = 1_800_000_000_000
_ASSET: Final = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
#: The EIP-55 CHECKSUMMED form of the SAME erc20 contract as ``_ASSET`` — the casing the
#: signed manifest carries. The store keys both on the canonical asset.
_ASSET_CHECKSUMMED: Final = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
_OTHER_ASSET: Final = "solana:mainnet/spl:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_SCOPE: Final = "merchant.example"
_OTHER_SCOPE: Final = "other.example"
_CANON_SCOPE: Final = "canon.example"
_FINGERPRINT: Final = "sha256:" + "0" * 64


class SpendStoreContractError(AssertionError):
    """A spend store violated the contract. The message names the rule."""


def _require(condition: bool, rule: str) -> None:
    if not condition:
        raise SpendStoreContractError(rule)


def _ref(reservation: SpendReservation) -> ReservationRef:
    """The durable locator for a reservation: its full scope+asset+id triple."""
    return ReservationRef(
        reservation.reservation_id, reservation.policy_scope, reservation.asset_id
    )


def _reserve(
    store: SpendStore,
    *,
    reservation_id: str,
    amount: str,
    cap: str = "1000000",
    scope: str = _SCOPE,
    asset: str = _ASSET,
    now: int = _NOW,
) -> SpendReservation:
    result = store.reserve(
        reservation_id=reservation_id,
        request_id="contract-" + reservation_id,
        policy_scope=scope,
        request_fingerprint=_FINGERPRINT,
        asset_id=asset,
        amount_atomic=amount,
        max_per_hour_atomic=cap,
        now_epoch_ms=now,
    )
    return result.reservation


def _totals(
    store: SpendStore,
    *,
    scope: str = _SCOPE,
    asset: str = _ASSET,
    now: int = _NOW,
) -> tuple[int, int]:
    state = store.get_budget_state(policy_scope=scope, asset_id=asset, now_epoch_ms=now)
    return int(state.committed_atomic), int(state.reserved_atomic)


def _check_shape(make_store: Callable[[], SpendStore]) -> None:
    store = make_store()
    assert_spend_store(store)
    _require(
        isinstance(getattr(store, "kind", None), str) and bool(store.kind),
        "kind must be a non-empty string identifying the store in diagnostics",
    )
    capabilities = getattr(store, "capabilities", None)
    _require(
        isinstance(getattr(capabilities, "atomic_global_freeze", None), bool),
        "capabilities.atomic_global_freeze must be a boolean (SPEC §3.1)",
    )


def _check_reserve_and_totals(make_store: Callable[[], SpendStore]) -> None:
    store = make_store()
    committed, reserved = _totals(store)
    _require(
        (committed, reserved) == (0, 0),
        "a fresh scope/asset pair must report committed 0 and reserved 0",
    )

    result = store.reserve(
        reservation_id="r1",
        request_id="contract-r1",
        policy_scope=_SCOPE,
        request_fingerprint=_FINGERPRINT,
        asset_id=_ASSET,
        amount_atomic="1500",
        max_per_hour_atomic="1000000",
        now_epoch_ms=_NOW,
    )
    _require(
        getattr(result, "recipient_pin_established", None) is False,
        "reserve must return a ReserveSpendResult with recipient_pin_established False by "
        "default (SPEC §3.2)",
    )
    reservation = result.reservation
    _require(
        getattr(reservation, "state", None) == "reserved",
        "reserve must return a reservation in state 'reserved'",
    )
    _require(
        getattr(reservation, "amount_atomic", None) == "1500",
        "reserve must echo amount_atomic back unchanged, as an atomic string",
    )
    _require(
        getattr(reservation, "expires_at_epoch_ms", 0) == _NOW + RESERVATION_TTL_MS,
        f"a reservation must expire {RESERVATION_TTL_MS} ms after it was created",
    )
    _require(
        _totals(store) == (0, 1500),
        "an open reservation must count toward reserved, not committed",
    )


def _check_scope_and_asset_isolation(make_store: Callable[[], SpendStore]) -> None:
    store = make_store()
    _reserve(store, reservation_id="s1", amount="700")
    _require(
        _totals(store, scope=_OTHER_SCOPE) == (0, 0),
        "reservations must not leak between policy scopes — a scope is a separate ledger",
    )
    _require(
        _totals(store, asset=_OTHER_ASSET) == (0, 0),
        "reservations must not leak between assets — atomic units are asset-specific",
    )


def _check_commit_and_release(make_store: Callable[[], SpendStore]) -> None:
    store = make_store()
    reserved = _reserve(store, reservation_id="c1", amount="900")
    entry = store.commit(
        ref=_ref(reserved), committed_at_epoch_ms=_NOW + 10, settlement_id="0xabc"
    )
    _require(
        getattr(entry, "amount_atomic", None) == "900",
        "commit must record the reserved amount unchanged",
    )
    _require(
        getattr(entry, "settlement_id", None) == "0xabc",
        "commit must retain the settlement id it was given",
    )
    _require(
        _totals(store, now=_NOW + 10) == (900, 0),
        "a committed reservation moves from reserved to committed, not both",
    )
    again = store.commit(ref=_ref(reserved), committed_at_epoch_ms=_NOW + 20)
    _require(
        getattr(again, "committed_at_epoch_ms", None)
        == getattr(entry, "committed_at_epoch_ms", None),
        "commit must be idempotent: a second call returns the first entry unchanged",
    )

    # O27: an empty settlement_id means "no settlement id" — every adapter must
    # ABSENT (None), not "" (Memory/DO kept ""; Redis dropped it — a cross-adapter split).
    empty_store = make_store()
    empty_reserved = _reserve(empty_store, reservation_id="c-empty", amount="100")
    empty_entry = empty_store.commit(
        ref=_ref(empty_reserved), committed_at_epoch_ms=_NOW + 10, settlement_id=""
    )
    _require(
        getattr(empty_entry, "settlement_id", None) is None,
        'commit with an empty settlement_id must round-trip as absent, never ""',
    )
    empty_replay = empty_store.commit(
        ref=_ref(empty_reserved), committed_at_epoch_ms=_NOW + 20
    )
    _require(
        getattr(empty_replay, "settlement_id", None) is None,
        "the stored entry read back on a replay must show an empty settlement_id absent",
    )

    store = make_store()
    reserved = _reserve(store, reservation_id="c2", amount="900")
    released = store.release(ref=_ref(reserved), now_epoch_ms=_NOW + 5)
    _require(
        getattr(released, "state", None) == "released",
        "release must return the reservation in state 'released'",
    )
    _require(
        _totals(store, now=_NOW + 5) == (0, 0),
        "a released reservation must stop counting toward the cap immediately",
    )
    store.release(ref=_ref(reserved), now_epoch_ms=_NOW + 6)

    raised = False
    try:
        store.commit(ref=_ref(reserved), committed_at_epoch_ms=_NOW + 7)
    except Exception:
        raised = True
    _require(raised, "commit on a released reservation must raise, never silently succeed")


def _check_idempotent_reserve(make_store: Callable[[], SpendStore]) -> None:
    store = make_store()
    first = _reserve(store, reservation_id="i1", amount="400")
    second = _reserve(store, reservation_id="i1", amount="400")
    _require(
        getattr(first, "reservation_id", None) == getattr(second, "reservation_id", None),
        "a repeated reservation_id with identical data must return the same reservation",
    )
    _require(
        _totals(store) == (0, 400),
        "a repeated reservation_id must not double-count against the cap",
    )

    raised = False
    try:
        _reserve(store, reservation_id="i1", amount="401")
    except Exception:
        raised = True
    _require(
        raised,
        "a reservation_id reused with different spend data must raise, not overwrite",
    )


def _check_cap_refusal(make_store: Callable[[], SpendStore]) -> None:
    store = make_store()
    _reserve(store, reservation_id="b1", amount="800", cap="1000")
    try:
        _reserve(store, reservation_id="b2", amount="300", cap="1000")
    except BudgetExceededError as error:
        for key in (
            "requestedAtomic",
            "capAtomic",
            "committedAtomic",
            "reservedAtomic",
            "capKind",
        ):
            _require(
                key in error.details,
                f"BudgetExceededError must carry details[{key!r}] (SPEC §8)",
            )
    except Exception as error:
        raise SpendStoreContractError(
            "an over-cap reserve must raise BudgetExceededError, not "
            f"{type(error).__name__}; any other exception is read as a store outage"
        ) from error
    else:
        raise SpendStoreContractError(
            "an over-cap reserve must be refused: 800 + 300 exceeds a cap of 1000"
        )
    _require(
        _totals(store) == (0, 800),
        "a refused reserve must leave the ledger exactly as it was",
    )


def _check_rolling_window(make_store: Callable[[], SpendStore]) -> None:
    # Two stores, not one. A query is allowed to prune what has fallen out of the window,
    # so asking about a *later* instant first and an earlier one second would test the
    # store's pruning rather than its window — and would fail a correct implementation.
    inside = make_store()
    reserved = _reserve(inside, reservation_id="w1", amount="500")
    inside.commit(ref=_ref(reserved), committed_at_epoch_ms=_NOW)
    _require(
        _totals(inside, now=_NOW + ROLLING_WINDOW_MS - 1) == (500, 0),
        "a commit must still count one millisecond before the window closes",
    )

    outside = make_store()
    reserved = _reserve(outside, reservation_id="w1", amount="500")
    outside.commit(ref=_ref(reserved), committed_at_epoch_ms=_NOW)
    _require(
        _totals(outside, now=_NOW + ROLLING_WINDOW_MS + 1) == (0, 0),
        f"a commit must leave the rolling window {ROLLING_WINDOW_MS} ms after it happened",
    )


def _check_expiry(make_store: Callable[[], SpendStore]) -> None:
    store = make_store()
    _reserve(store, reservation_id="e1", amount="600")
    expired = _NOW + RESERVATION_TTL_MS + 1
    _require(
        _totals(store, now=expired) == (0, 0),
        "an expired reservation must stop counting toward the cap (SPEC §5.3)",
    )


def _check_exposure_lifecycle(make_store: Callable[[], SpendStore]) -> None:
    """expose fences a reservation open; commit/release move it out of exposed (§3.4)."""
    store = make_store()
    reserved = _reserve(store, reservation_id="x1", amount="400")
    exposed = store.expose(ref=_ref(reserved), now_epoch_ms=_NOW + 5)
    _require(
        getattr(exposed, "state", None) == "exposed",
        "expose must move a reserved reservation to state 'exposed'",
    )
    state = store.get_budget_state(
        policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW + 5
    )
    _require(
        state.exposed_atomic == "400" and state.reserved_atomic == "0",
        "an exposed reservation must count as exposed, not reserved (SPEC §7)",
    )
    _require(
        state.cumulative_consumed_atomic == "400",
        "exposed spend must fold into cumulative_consumed (SPEC §3.4)",
    )
    # Exposed does not expire: still counted a full window later.
    later = store.get_budget_state(
        policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW + ROLLING_WINDOW_MS + 1
    )
    _require(
        later.exposed_atomic == "400",
        "an exposed reservation must not expire; it stays counted until resolved (ADR-026)",
    )
    listed = store.list_exposed(
        policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW + ROLLING_WINDOW_MS + 1
    )
    _require(
        tuple(r.reservation_id for r in listed) == ("x1",),
        "list_exposed must enumerate the unresolved exposed reservation",
    )
    store.commit(ref=_ref(reserved), committed_at_epoch_ms=_NOW + 20)
    resolved_state = store.get_budget_state(
        policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW + 20
    )
    _require(
        resolved_state.exposed_atomic == "0"
        and resolved_state.cumulative_committed_atomic == "400",
        "commit on an exposed reservation must move it from exposed to committed",
    )


def _check_atomicity(make_store: Callable[[], SpendStore]) -> None:
    """Twenty threads, five units of headroom, one unit each. Exactly five may win.

    This is the check worth the extra machinery. A store that reads the total, decides, and
    then inserts — the obvious implementation — passes every other check in this module and
    fails only here, under contention, which is precisely where money is lost.
    """
    store = make_store()
    attempts = 20
    cap = "5"

    def attempt(index: int) -> bool:
        try:
            _reserve(store, reservation_id=f"a{index}", amount="1", cap=cap)
        except BudgetExceededError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=attempts) as pool:
        admitted = sum(pool.map(attempt, range(attempts)))

    _require(
        admitted == 5,
        f"reserve must be atomic: 20 concurrent one-unit reservations under a cap of 5 "
        f"admitted {admitted}, not 5",
    )
    _require(
        _totals(store) == (0, 5),
        "after a contended run the ledger must total exactly the cap, never more",
    )


def _check_reservation_id_aliasing(make_store: Callable[[], SpendStore]) -> None:
    """O48/O54: a reservation_id that aliases a reserved key must not brick the ledger.

    The pathological ids are the reserved final-segment suffixes — the index ZSET (``idx``)
    AND the per-asset counter/limits keys (``total``/``exposed``/``limits``, O54) — and any
    id carrying the ``:`` key separator (which re-parses to a different ``(asset, id)``
    pair). A store that flattens its keys into one namespace (Redis) refuses each with a
    typed ``ConfigurationError``; a store immune by construction (Memory's NUL-joined map
    keys, the DO's parameterized SQLite column) simply records it. What NO store may do is
    throw an untyped error, or leave the ledger unreadable afterwards (the Redis WRONGTYPE
    brick). Each id runs in its own scope so the readability assertion is unambiguous.
    """
    for reservation_id in ("idx", "total", "exposed", "limits", "a:idx"):
        store = make_store()
        scope = f"alias.{reservation_id.replace(':', '_')}.example"
        accepted = False
        try:
            _reserve(store, reservation_id=reservation_id, amount="1", scope=scope)
            accepted = True
        except ConfigurationError as error:
            _require(
                error.details.get("reason") == "reservation-id-aliases-index",
                f"a reservation_id ({reservation_id}) that aliases a reserved "
                "index/counter key must be refused as a typed ConfigurationError "
                "(reason reservation-id-aliases-index)",
            )
        # The (scope, asset) ledger must stay readable either way — no WRONGTYPE brick.
        state = store.get_budget_state(
            policy_scope=scope, asset_id=_ASSET, now_epoch_ms=_NOW
        )
        _require(
            int(state.reserved_atomic) == (1 if accepted else 0),
            f"getBudgetState must still return after reservation_id "
            f"'{reservation_id}' (no brick)",
        )


def _check_asset_canonicalization(make_store: Callable[[], SpendStore]) -> None:
    # U16: the (scope, asset) ledger keys on the CANONICAL asset (eip155 lowercased).
    # A reserve under the checksummed manifest asset and a read/second-reserve under its
    # lowercase form must address the SAME ledger. ``_ASSET`` is already lowercase;
    # ``_ASSET_CHECKSUMMED`` is the manifest's EIP-55 form. Data-plane, every store runs it.
    store = make_store()
    _reserve(
        store,
        reservation_id="u16-canon-1",
        amount="700",
        cap="1000",
        asset=_ASSET_CHECKSUMMED,
    )
    _require(
        _totals(store, asset=_ASSET) == (0, 700),
        "a reserve under the checksummed asset must be visible under its lowercase form "
        "(the ledger keys on the canonical asset, U16)",
    )
    try:
        _reserve(
            store, reservation_id="u16-canon-2", amount="400", cap="1000", asset=_ASSET
        )
    except BudgetExceededError:
        pass
    except Exception as error:
        raise SpendStoreContractError(
            "a reserve under the lowercase asset shares the checksummed ledger's cap, so "
            f"it must be refused BudgetExceededError, not {type(error).__name__} (U16)"
        ) from error
    else:
        raise SpendStoreContractError(
            "a reserve under the lowercase asset shares the checksummed ledger's per-hour "
            "cap, so 700 + 400 > 1000 is refused (U16 canonicalization)"
        )


_CHECKS: Final = (
    _check_shape,
    _check_reserve_and_totals,
    _check_asset_canonicalization,
    _check_scope_and_asset_isolation,
    _check_commit_and_release,
    _check_idempotent_reserve,
    _check_cap_refusal,
    _check_rolling_window,
    _check_expiry,
    _check_exposure_lifecycle,
    _check_atomicity,
    _check_reservation_id_aliasing,
)


def check_spend_store(make_store: Callable[[], SpendStore]) -> None:
    """Runs every single-plane contract check against stores produced by ``make_store``.

    ``make_store`` is a factory rather than an instance because several checks need a store
    with no history; a factory that hands back the same populated object will fail them.
    Each call should produce an empty, independent ledger.

    Raises :class:`SpendStoreContractError` on the first violation.
    """
    for check in _CHECKS:
        check(make_store)


# ── The durable harness ────────────────────────────────────────────────────
#
# A networked store cannot be checked through ``check_spend_store`` alone: that factory
# back independent empty stores, so it cannot express a shared backend, a restart, the
# operator/agent credential split, or backend time. ``check_durable_spend_store`` takes
# takes BOTH security planes over one shared, resettable namespace plus a settable backend
# clock. The full check set (freeze, cumulative, pins, administered limits, true-parallel
# atomicity) is added for the Redis and DO adapters; the API and
# the two checks that only the harness can express — plane separation and clock skew.

ConnectData = Callable[[], "SpendStore"]
ConnectAdmin = Callable[[], "SpendStoreAdmin"]
SetBackendClock = Callable[[int], None]
Reset = Callable[[], None]
RestartFn = Callable[[], None]

_AdminCall = Callable[["SpendStoreAdmin"], None]
_ADMIN_METHOD_CALLS: Final[tuple[tuple[str, _AdminCall], ...]] = (
    ("freeze", lambda admin: admin.freeze(_SCOPE, _NOW)),
    ("unfreeze", lambda admin: admin.unfreeze(_SCOPE, _NOW)),
    (
        "set_recipient_pins",
        lambda admin: admin.set_recipient_pins(_SCOPE, "eip155:8453", ("0x0",), _NOW),
    ),
    (
        "set_budget_limits",
        lambda admin: admin.set_budget_limits(_SCOPE, _ASSET, _no_limits(), _NOW),
    ),
    (
        "set_recipient_assertion_required",
        lambda admin: admin.set_recipient_assertion_required(_SCOPE, True, _NOW),
    ),
    ("set_tofu_enabled", lambda admin: admin.set_tofu_enabled(_SCOPE, True, _NOW)),
    (
        "reset_cumulative",
        lambda admin: admin.reset_cumulative(_SCOPE, _ASSET, _NOW),
    ),
)


def _no_limits() -> BudgetLimits:  # pragma: no cover
    from tx402.ledger import BudgetLimits as _BudgetLimits

    return _BudgetLimits()


def _limits(  # pragma: no cover
    *, max_per_hour: str | None = None, max_total: str | None = None
) -> BudgetLimits:
    from tx402.ledger import BudgetLimits as _BudgetLimits

    return _BudgetLimits(max_per_hour_atomic=max_per_hour, max_total_atomic=max_total)


def _reserve_with_recipient(  # pragma: no cover
    store: SpendStore,
    *,
    reservation_id: str,
    recipient: str,
    network: str,
    scope: str = _SCOPE,
    enforcement: str = "tofu",
    now: int = _NOW,
) -> ReserveSpendResult:
    return store.reserve(
        reservation_id=reservation_id,
        request_id="contract-" + reservation_id,
        policy_scope=scope,
        request_fingerprint=_FINGERPRINT,
        asset_id=_ASSET,
        amount_atomic="1",
        max_per_hour_atomic="1000000",
        recipient_network=network,
        recipient_canonical=recipient,
        recipient_enforcement=enforcement,
        now_epoch_ms=now,
    )


def _check_plane_separation(  # pragma: no cover
    connect_admin_with_data_credential: ConnectAdmin,
) -> None:
    """Every admin method invoked with a DATA credential is denied.

    The harness binds the admin method surface to the data credential; each mutation must be
    refused with ``admin-credential-required`` so a compromised agent path cannot freeze a
    scope, widen a cap, or rewrite a pin.
    """
    admin = connect_admin_with_data_credential()
    for name, call in _ADMIN_METHOD_CALLS:
        try:
            call(admin)
        except ConfigurationError as error:
            _require(
                error.details.get("reason") == "admin-credential-required",
                f"{name} with a data credential must be denied with reason "
                f"'admin-credential-required', got {error.details.get('reason')!r}",
            )
        except Exception as error:
            raise SpendStoreContractError(
                f"{name} with a data credential must raise a typed "
                f"admin-credential-required ConfigurationError, not {type(error).__name__}"
            ) from error
        else:
            raise SpendStoreContractError(
                f"{name} must be denied when invoked with a data credential (ADR-029)"
            )


def _check_skew(  # pragma: no cover
    connect_data: ConnectData,
    set_backend_clock: SetBackendClock,
) -> None:
    """Backend time windows the cap, so fleet skew cannot double-spend it.

    Two independent connections: A reserves the whole cap with a *future*-skewed clock,
    then B reserves with an *earlier* caller clock. A durable store windows on its own,
    so it still counts A's reservation and caps B — the round-7 skew breach this closes.
    """
    set_backend_clock(_NOW)
    a = connect_data()
    b = connect_data()
    a.reserve(
        reservation_id="skew-a",
        request_id="skew-a",
        policy_scope=_SCOPE,
        request_fingerprint=_FINGERPRINT,
        asset_id=_ASSET,
        amount_atomic="5",
        max_per_hour_atomic="5",
        now_epoch_ms=_NOW + 20_000,  # A's caller clock runs fast; the backend clock wins.
    )
    refused = False
    try:
        b.reserve(
            reservation_id="skew-b",
            request_id="skew-b",
            policy_scope=_SCOPE,
            request_fingerprint=_FINGERPRINT,
            asset_id=_ASSET,
            amount_atomic="1",
            max_per_hour_atomic="5",
            now_epoch_ms=_NOW,  # B's caller clock is earlier; it must not exclude A.
        )
    except BudgetExceededError:
        refused = True
    _require(
        refused,
        "a durable store must window on its own clock: B must not exceed a cap A already "
        "filled just because B's caller clock is earlier (SPEC §3.4a)",
    )


def _check_locator(connect_data: ConnectData) -> None:  # pragma: no cover
    """A ref resolves across connections (SPEC §12.4 ``_check_locator``).

    A reservation opened on one data connection is committed / released / exposed from a
    *different* one, by its ref alone — the cross-machine addressing a bare reservation UUID
    cannot express in a sharded store (P0-1).
    """
    a = connect_data()
    b = connect_data()
    to_commit = _reserve(a, reservation_id="loc-commit", amount="10")
    entry = b.commit(
        ref=_ref(to_commit), committed_at_epoch_ms=_NOW + 1, settlement_id="0xloc"
    )
    _require(
        entry.amount_atomic == "10",
        "commit on connection B must resolve a reservation opened on connection A "
        "(SPEC §12.4)",
    )
    to_release = _reserve(a, reservation_id="loc-release", amount="10")
    released = b.release(ref=_ref(to_release), now_epoch_ms=_NOW + 2)
    _require(
        released.state == "released",
        "release on connection B must resolve a reservation opened on connection A",
    )
    to_expose = _reserve(a, reservation_id="loc-expose", amount="10")
    exposed = b.expose(ref=_ref(to_expose), now_epoch_ms=_NOW + 3)
    _require(
        exposed.state == "exposed",
        "expose on connection B must fence a reservation opened on connection A",
    )


def _check_cumulative_cap(  # pragma: no cover
    connect_data: ConnectData, set_backend_clock: SetBackendClock
) -> None:
    """The cumulative cap binds first and survives the rolling boundary.

    A lifetime ceiling still refuses after the per-hour figure has aged out of the window.
    """
    set_backend_clock(_NOW)
    store = connect_data()
    first = store.reserve(
        reservation_id="cum-1",
        request_id="cum-1",
        policy_scope=_SCOPE,
        request_fingerprint=_FINGERPRINT,
        asset_id=_ASSET,
        amount_atomic="6",
        max_per_hour_atomic="1000",
        max_total_atomic="10",
        now_epoch_ms=_NOW,
    )
    store.commit(ref=_ref(first.reservation), committed_at_epoch_ms=_NOW)
    cap_kind: object = None
    try:
        store.reserve(
            reservation_id="cum-2",
            request_id="cum-2",
            policy_scope=_SCOPE,
            request_fingerprint=_FINGERPRINT,
            asset_id=_ASSET,
            amount_atomic="5",
            max_per_hour_atomic="1000",
            max_total_atomic="10",
            now_epoch_ms=_NOW,
        )
    except BudgetExceededError as error:
        cap_kind = error.details.get("capKind")
    _require(
        cap_kind == "cumulative",
        "the cumulative cap must bind (capKind 'cumulative') where the per-hour cap has "
        "room (SPEC §4)",
    )
    # Advance a full rolling window: the per-hour figure resets, the lifetime one does not.
    set_backend_clock(_NOW + ROLLING_WINDOW_MS + 1)
    still_refused = False
    try:
        store.reserve(
            reservation_id="cum-3",
            request_id="cum-3",
            policy_scope=_SCOPE,
            request_fingerprint=_FINGERPRINT,
            asset_id=_ASSET,
            amount_atomic="5",
            max_per_hour_atomic="1000",
            max_total_atomic="10",
            now_epoch_ms=_NOW + ROLLING_WINDOW_MS + 1,
        )
    except BudgetExceededError:
        still_refused = True
    _require(
        still_refused,
        "cumulative spend is lifetime: it must still bind after the rolling hour resets "
        "the per-hour figure (SPEC §4.2)",
    )


def _check_exposure(  # pragma: no cover
    connect_data: ConnectData,
    connect_admin: ConnectAdmin,
    set_backend_clock: SetBackendClock,
) -> None:
    """Exposure is durable and never escapes (SPEC §3.6 ``_check_exposure``, §7).

    An exposed reservation keeps counting past the 120 s TTL and the rolling hour,
    ``list_exposed`` enumerates it across connections, and the admin ``resolve_exposed``
    reconciles it (and refuses a second, terminal call).
    """
    set_backend_clock(_NOW)
    data = connect_data()
    admin = connect_admin()
    opened = _reserve(data, reservation_id="exp-1", amount="400")
    exposed = data.expose(ref=_ref(opened), now_epoch_ms=_NOW + 5)
    _require(exposed.state == "exposed", "expose must fence a reserved reservation")
    set_backend_clock(_NOW + ROLLING_WINDOW_MS + 1)
    later = data.get_budget_state(
        policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW + ROLLING_WINDOW_MS + 1
    )
    _require(
        later.exposed_atomic == "400" and later.cumulative_consumed_atomic == "400",
        "an exposed reservation must not expire — it keeps counting past 120 s and the "
        "rolling hour (ADR-026)",
    )
    listed = data.list_exposed(
        policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW + ROLLING_WINDOW_MS + 1
    )
    _require(
        tuple(r.reservation_id for r in listed) == (opened.reservation_id,),
        "list_exposed must enumerate the unresolved exposed reservation across connections",
    )
    admin.resolve_exposed(_ref(opened), "committed", _NOW + ROLLING_WINDOW_MS + 2)
    resolved = data.get_budget_state(
        policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW + ROLLING_WINDOW_MS + 2
    )
    _require(
        resolved.exposed_atomic == "0" and resolved.cumulative_committed_atomic == "400",
        "resolve_exposed(committed) must move exposed spend into cumulative committed "
        "(SPEC §7)",
    )
    terminal = False
    try:
        admin.resolve_exposed(_ref(opened), "committed", _NOW + ROLLING_WINDOW_MS + 3)
    except ConfigurationError as error:
        terminal = error.details.get("reason") == "reservation-already-terminal"
    _require(
        terminal,
        "resolve_exposed on an already-resolved reservation must refuse as "
        "reservation-already-terminal",
    )


def _check_atomicity_parallel(  # pragma: no cover
    connect_data: ConnectData, set_backend_clock: SetBackendClock
) -> None:
    """``reserve`` is atomic under TRUE parallelism over independent connections (§3.6).

    Exactly the cap is admitted of a burst that far exceeds it, and the ledger totals
    exactly the cap — never more, however the reads and writes interleave across machines.
    """
    set_backend_clock(_NOW)
    attempts = 20

    def attempt(index: int) -> bool:
        try:
            connect_data().reserve(
                reservation_id=f"par-{index}",
                request_id=f"par-{index}",
                policy_scope=_SCOPE,
                request_fingerprint=_FINGERPRINT,
                asset_id=_ASSET,
                amount_atomic="1",
                max_per_hour_atomic="5",
                now_epoch_ms=_NOW,
            )
        except BudgetExceededError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=attempts) as pool:
        admitted = sum(pool.map(attempt, range(attempts)))
    _require(
        admitted == 5,
        f"reserve must be atomic across independent connections: 20 concurrent one-unit "
        f"reserves under a cap of 5 admitted {admitted}, not 5 (SPEC §3.6)",
    )
    _require(
        _totals(connect_data()) == (0, 5),
        "after a contended parallel run the shared ledger must total exactly the cap, "
        "never more",
    )


def _check_freeze(  # pragma: no cover
    connect_data: ConnectData,
    connect_admin: ConnectAdmin,
    set_backend_clock: SetBackendClock,
) -> None:
    """Freeze is admin-plane and atomic with reserve (SPEC §3.6 ``_check_freeze``, §5).

    Freezing a scope makes every reserve on it raise ``SpendScopeFrozenError``; committed
    spend survives the freeze; unfreeze restores it. The global-``"*"`` arm is parameterized
    by ``capabilities.atomic_global_freeze`` exactly as §5.2: a capable store asserts
    ``"*"`` blocks a distinct scope; an incapable one asserts ``freeze("*")`` fails closed
    with ``global-freeze-unsupported``.
    """
    set_backend_clock(_NOW)
    data = connect_data()
    admin = connect_admin()

    pre = _reserve(data, reservation_id="fz-pre", amount="100")
    data.commit(ref=_ref(pre), committed_at_epoch_ms=_NOW)

    admin.freeze(_SCOPE, _NOW)
    _require(
        data.is_frozen(scope=_SCOPE), "is_frozen must report a scope the admin just froze"
    )

    try:
        _reserve(data, reservation_id="fz-1", amount="1")
    except SpendScopeFrozenError as error:
        _require(
            error.details.get("frozenScope") == _SCOPE
            and error.details.get("scope") == _SCOPE,
            "a per-scope freeze must carry details.frozenScope and details.scope = the "
            "scope (§5.3)",
        )
    except Exception as error:
        raise SpendStoreContractError(
            "reserve on a frozen scope must raise SpendScopeFrozenError, not "
            f"{type(error).__name__}"
        ) from error
    else:
        raise SpendStoreContractError("reserve on a frozen scope must be refused")

    preserved = data.get_budget_state(
        policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW
    )
    _require(
        preserved.committed_atomic == "100" and preserved.frozen is True,
        "a freeze must preserve committed accounting and report frozen (KS-7, §5.4)",
    )

    admin.unfreeze(_SCOPE, _NOW)
    _require(not data.is_frozen(scope=_SCOPE), "unfreeze must clear the scope's freeze")
    readmitted = _reserve(data, reservation_id="fz-2", amount="1")
    _require(readmitted.state == "reserved", "unfreeze must restore reserves on the scope")

    if data.capabilities.atomic_global_freeze:
        admin.freeze("*", _NOW)
        try:
            _reserve(data, reservation_id="fz-g", amount="1", scope=_OTHER_SCOPE)
        except SpendScopeFrozenError as error:
            _require(
                error.details.get("frozenScope") == "*",
                'a global freeze must report frozenScope "*" (SPEC §5.2)',
            )
        except Exception as error:
            raise SpendStoreContractError(
                'an atomic_global_freeze store must let freeze("*") block a distinct scope '
                f"with SpendScopeFrozenError, not {type(error).__name__}"
            ) from error
        else:
            raise SpendStoreContractError(
                'freeze("*") must block a distinct scope on a capable store'
            )
        admin.unfreeze("*", _NOW)
        after_global = _reserve(
            data, reservation_id="fz-g2", amount="1", scope=_OTHER_SCOPE
        )
        _require(
            after_global.state == "reserved",
            "unfreeze(*) must restore reserves fleet-wide",
        )
    else:
        try:
            admin.freeze("*", _NOW)
        except ConfigurationError as error:
            _require(
                error.details.get("reason") == "global-freeze-unsupported"
                and error.details.get("configPath") == "freeze.global",
                'freeze("*") on an incapable store must fail closed as '
                "global-freeze-unsupported (§5.2)",
            )
        except Exception as error:
            raise SpendStoreContractError(
                'a store without atomic_global_freeze must refuse freeze("*") with a typed '
                f"ConfigurationError, not {type(error).__name__}"
            ) from error
        else:
            raise SpendStoreContractError(
                'freeze("*") must be refused on an incapable store'
            )


def _check_pins(  # pragma: no cover
    connect_data: ConnectData,
    connect_admin: ConnectAdmin,
    set_backend_clock: SetBackendClock,
) -> None:
    """Recipient pinning under contention (SPEC §3.6 ``_check_pins``, §6.2, §12.4).

    A concurrent in-reserve TOFU claim converges to exactly one pin (one worker reports
    establishing it, and it is authoritative afterward); a recipient rotation racing a burst
    of reserves never tears — a reader sees the whole old pin or the whole new one, never a
    transient empty/partial record.
    """
    network = "eip155:8453"
    r1 = "0x" + "1" * 40
    r2 = "0x" + "2" * 40

    # ── A: a concurrent in-reserve TOFU claim converges to exactly one pin. ──
    set_backend_clock(_NOW)
    connect_admin().set_tofu_enabled(_SCOPE, True, _NOW)

    def claim(index: int) -> ReserveSpendResult:
        return _reserve_with_recipient(
            connect_data(),
            reservation_id=f"pin-{index}",
            recipient=r1,
            network=network,
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(claim, range(12)))
    established = sum(1 for r in results if r.recipient_pin_established)
    _require(
        established == 1,
        f"a contended TOFU claim must converge to one pin: {established} workers reported "
        "establishing it, not 1 (SPEC §6.2)",
    )

    try:
        _reserve_with_recipient(
            connect_data(), reservation_id="pin-r2", recipient=r2, network=network
        )
    except RecipientUnpinnedError as error:
        _require(
            error.details.get("reason") == "pin-mismatch",
            "a recipient not matching the converged TOFU pin must be reason 'pin-mismatch' "
            "(§6.5)",
        )
    except Exception as error:
        raise SpendStoreContractError(
            "after a TOFU claim a different recipient must raise RecipientUnpinnedError, "
            f"not {type(error).__name__}"
        ) from error
    else:
        raise SpendStoreContractError(
            "a different recipient after a TOFU claim must be refused"
        )

    # ── B: a rotation racing reserves never tears (atomic pin write). On a DISTINCT scope
    # (fresh, tofu OFF) an admin allowlist [r1] is rotated to [r2] while a burst of reserves
    # present r2 under enforcement "tofu". With an atomic write each reserve sees the whole
    # old pin (not-allowlisted) or the whole new one (admit) — never a transient no-record,
    # which under tofu-not-provisioned would surface as a ConfigurationError. ──
    connect_admin().set_recipient_pins(_OTHER_SCOPE, network, (r1,), _NOW)

    def rotate() -> None:
        connect_admin().set_recipient_pins(_OTHER_SCOPE, network, (r2,), _NOW)

    def racer(index: int) -> None:
        try:
            _reserve_with_recipient(
                connect_data(),
                reservation_id=f"rot-{index}",
                recipient=r2,
                network=network,
                scope=_OTHER_SCOPE,
            )
        except RecipientUnpinnedError as error:
            if error.details.get("reason") != "not-allowlisted":
                raise SpendStoreContractError(
                    "a reserve racing a rotation must be admitted or not-allowlisted, not "
                    f"reason {error.details.get('reason')!r} (§12.4)"
                ) from error
        except ConfigurationError as error:
            raise SpendStoreContractError(
                "a reserve racing a pin rotation saw a torn (no-record) read — the pin "
                f"write must be atomic (§12.4): {error.details.get('reason')!r}"
            ) from error

    with ThreadPoolExecutor(max_workers=13) as pool:
        futures = [pool.submit(rotate)]
        futures += [pool.submit(racer, index) for index in range(12)]
        for future in futures:
            future.result()  # re-raise any SpendStoreContractError from a worker

    settled = _reserve_with_recipient(
        connect_data(),
        reservation_id="rot-final",
        recipient=r2,
        network=network,
        scope=_OTHER_SCOPE,
    )
    _require(
        settled.recipient_pin_established is False,
        "a rotated admin allowlist must admit the new recipient without a TOFU claim",
    )

    # C: an administered EMPTY recipient set must read back as () on EVERY adapter;
    # the DO stored "" and returned ("",), diverging from Memory/Redis which returned ().
    empty_network = "eip155:1"
    connect_admin().set_recipient_pins(_OTHER_SCOPE, empty_network, (), _NOW)
    # Every durable store here is also a RecipientPinStore (Memory/Redis/DO).
    empty_pins = connect_data().get_recipient_pins(_OTHER_SCOPE, empty_network)  # type: ignore[attr-defined]
    _require(
        len(empty_pins) == 0,
        f"an administered empty recipient set must read back as (), not "
        f'("",) (got {empty_pins!r}, O27)',
    )


def _check_administered_limits(  # pragma: no cover
    connect_data: ConnectData,
    connect_admin: ConnectAdmin,
    set_backend_clock: SetBackendClock,
) -> None:
    """Store-administered caps and their precedence.

    A caller cap ABOVE the administered one is rejected per dimension
    (``cap-exceeds-administered``); a stricter caller cap is honoured via ``min``. Lowering
    an administered cap below current consumption does not unspend — it clamps availability
    to 0 and refuses new reserves whose caller cap is now within the lowered limit.
    """
    set_backend_clock(_NOW)
    data = connect_data()
    admin = connect_admin()

    # U16: a cap administered under the LOWERCASE asset must bind a reserve under the
    # CHECKSUMMED form of the SAME contract — both key on the canonical (lowercased) asset.
    # This is the exact drifted-worker scenario the runbook teaches. Runs first in a
    # dedicated scope so it cannot perturb the assertions below.
    admin.set_budget_limits(_CANON_SCOPE, _ASSET, _limits(max_per_hour="100"), _NOW)
    try:
        data.reserve(
            reservation_id="u16-canon",
            request_id="u16-canon",
            policy_scope=_CANON_SCOPE,
            request_fingerprint=_FINGERPRINT,
            asset_id=_ASSET_CHECKSUMMED,  # checksummed form of the administered asset
            amount_atomic="1",
            max_per_hour_atomic="200",  # caller cap ABOVE the administered 100
            now_epoch_ms=_NOW,
        )
    except ConfigurationError as error:
        _require(
            error.details.get("reason") == "cap-exceeds-administered",
            "an administered cap under the LOWERCASE asset must bind a reserve under the "
            "CHECKSUMMED asset (U16 canonicalization)",
        )
    except Exception as error:
        raise SpendStoreContractError(
            "an administered cap under the lowercase asset must bind a checksummed reserve "
            f"(U16), not raise {type(error).__name__}"
        ) from error
    else:
        raise SpendStoreContractError(
            "an administered cap under the lowercase asset must bind a reserve under the "
            "checksummed asset (U16 canonicalization) — the over-cap reserve was ADMITTED"
        )

    admin.set_budget_limits(
        _SCOPE, _ASSET, _limits(max_per_hour="100", max_total="100"), _NOW
    )

    for dimension, config_path in (
        ("per_hour", "policy.maxPerHour"),
        ("total", "policy.maxTotal"),
    ):
        try:
            data.reserve(
                reservation_id=f"adm-hi-{dimension}",
                request_id=f"adm-hi-{dimension}",
                policy_scope=_SCOPE,
                request_fingerprint=_FINGERPRINT,
                asset_id=_ASSET,
                amount_atomic="1",
                max_per_hour_atomic="200" if dimension == "per_hour" else "50",
                max_total_atomic="200" if dimension == "total" else "50",
                now_epoch_ms=_NOW,
            )
        except ConfigurationError as error:
            _require(
                error.details.get("reason") == "cap-exceeds-administered"
                and error.details.get("configPath") == config_path,
                "a caller cap above the administered one must be cap-exceeds-administered "
                f"at {config_path} (§4.3)",
            )
        except Exception as error:
            raise SpendStoreContractError(
                f"a caller {dimension} cap above the administered one must raise "
                f"ConfigurationError, not {type(error).__name__}"
            ) from error
        else:
            raise SpendStoreContractError(
                f"a caller {dimension} cap above the administered one must be refused"
            )

    admitted = data.reserve(
        reservation_id="adm-ok",
        request_id="adm-ok",
        policy_scope=_SCOPE,
        request_fingerprint=_FINGERPRINT,
        asset_id=_ASSET,
        amount_atomic="10",
        max_per_hour_atomic="50",
        max_total_atomic="50",
        now_epoch_ms=_NOW,
    )
    data.commit(ref=_ref(admitted.reservation), committed_at_epoch_ms=_NOW)

    admin.set_budget_limits(_SCOPE, _ASSET, _limits(max_per_hour="5", max_total="5"), _NOW)
    clamped = data.get_budget_state(policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW)
    _require(
        clamped.available_per_hour_atomic == "0"
        and clamped.available_cumulative_atomic == "0",
        "a cap lowered below current consumption must clamp availability to 0, never "
        "negative (§4.3)",
    )
    try:
        data.reserve(
            reservation_id="adm-over",
            request_id="adm-over",
            policy_scope=_SCOPE,
            request_fingerprint=_FINGERPRINT,
            asset_id=_ASSET,
            amount_atomic="1",
            max_per_hour_atomic="5",
            max_total_atomic="5",
            now_epoch_ms=_NOW,
        )
    except BudgetExceededError:
        pass
    except Exception as error:
        raise SpendStoreContractError(
            "a reserve under a lowered administered cap must raise BudgetExceededError, "
            f"not {type(error).__name__}"
        ) from error
    else:
        raise SpendStoreContractError(
            "a reserve whose consumption exceeds the lowered administered cap must be "
            "refused (§4.3)"
        )

    # O26: set_budget_limits is ONE atom — a reserve racing it sees the whole OLD or NEW
    # cap, never a transient "no administered cap". An administered max_per_hour "5" ->
    # "6" while reserves present caller cap "1000000" (above BOTH) and amount "100":
    # every reserve MUST be refused cap-exceeds-administered; an ADMIT betrays a torn read.
    admin.set_budget_limits(_OTHER_SCOPE, _ASSET, _limits(max_per_hour="5"), _NOW)

    def _rewrite() -> None:
        connect_admin().set_budget_limits(
            _OTHER_SCOPE, _ASSET, _limits(max_per_hour="6"), _NOW
        )

    def _race(index: int) -> None:
        try:
            connect_data().reserve(
                reservation_id=f"lim-race-{index}",
                request_id=f"lim-race-{index}",
                policy_scope=_OTHER_SCOPE,
                request_fingerprint=_FINGERPRINT,
                asset_id=_ASSET,
                amount_atomic="100",
                max_per_hour_atomic="1000000",
                max_total_atomic="1000000",
                now_epoch_ms=_NOW,
            )
        except ConfigurationError as error:
            if error.details.get("reason") != "cap-exceeds-administered":
                raise SpendStoreContractError(
                    "a reserve racing set_budget_limits must be cap-exceeds-administered, "
                    f"not reason {error.details.get('reason')!r} (§4.3, O26)"
                ) from error
        else:
            raise SpendStoreContractError(
                "a reserve racing set_budget_limits was ADMITTED — it saw a torn "
                "cap' window; the replacement must be one atom (§4.3, O26)"
            )

    with ThreadPoolExecutor(max_workers=13) as pool:
        futures = [pool.submit(_rewrite)]
        futures += [pool.submit(_race, index) for index in range(12)]
        for future in futures:
            future.result()


def _check_restart(  # pragma: no cover
    connect_data: ConnectData,
    restart: RestartFn,
    set_backend_clock: SetBackendClock,
) -> None:
    """Restart durability (SPEC §3.6 ``_check_restart``, §12.4).

    A reservation and a committed entry written before a backend restart must both survive
    it, and the reservation must still be committable by its ref (Redis proves AOF
    persistence). Runs only when the harness provides a ``restart`` hook.
    """
    set_backend_clock(_NOW)
    before = connect_data()
    held = _reserve(before, reservation_id="rst-held", amount="42")
    to_commit = _reserve(before, reservation_id="rst-committed", amount="8")
    before.commit(ref=_ref(to_commit), committed_at_epoch_ms=_NOW)

    restart()

    after = connect_data()
    state = None
    for _attempt in range(20):
        try:
            state = after.get_budget_state(
                policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW
            )
            break
        except Exception:
            time.sleep(0.25)
    if state is None:
        raise SpendStoreContractError("the store was unreachable after a restart")
    _require(
        state.reserved_atomic == "42" and state.committed_atomic == "8",
        "AOF durability: a reservation and a committed entry must survive a server restart "
        "(§12.4)",
    )
    entry = after.commit(ref=_ref(held), committed_at_epoch_ms=_NOW + 1)
    _require(
        entry.amount_atomic == "42",
        "a reservation that survived a restart must remain committable by its ref (§12.4)",
    )


def check_durable_spend_store(  # pragma: no cover
    *,
    connect_data: ConnectData,
    connect_admin: ConnectAdmin,
    connect_admin_with_data_credential: ConnectAdmin,
    reset: Reset,
    set_backend_clock: SetBackendClock,
    restart: RestartFn | None = None,
) -> None:
    """Runs the durable-store checks that need both planes, a shared namespace, and a clock.

    ``connect_data`` opens a data-plane store and ``connect_admin`` an admin store over one
    shared, ``reset``-able namespace; ``connect_admin_with_data_credential`` returns the
    admin method surface bound to the *data* credential (so plane separation is reachable);
    ``set_backend_clock`` drives the store's test-only backend clock (§3.4a). Production
    builds expose no such setter.

    plane-separation and clock-skew, plus the locator, cumulative-cap,
    exposure, and true-parallel atomicity checks, and the admin-STATE governance checks
    — freeze (with the capability-parameterized global arm), pins (contended TOFU claim +
    rotation-vs-reserve), administered limits, and — when ``restart`` is provided — restart
    durability (§3.6/§12.4). A harness without ``restart`` runs every other check.
    """
    reset()
    _check_plane_separation(connect_admin_with_data_credential)
    reset()
    _check_skew(connect_data, set_backend_clock)
    reset()
    _check_locator(connect_data)
    reset()
    _check_cumulative_cap(connect_data, set_backend_clock)
    reset()
    _check_exposure(connect_data, connect_admin, set_backend_clock)
    reset()
    _check_atomicity_parallel(connect_data, set_backend_clock)
    reset()
    _check_freeze(connect_data, connect_admin, set_backend_clock)
    reset()
    _check_pins(connect_data, connect_admin, set_backend_clock)
    reset()
    _check_administered_limits(connect_data, connect_admin, set_backend_clock)
    # Restart durability runs last (it interrupts connections) and only when the harness can
    # drive a backend restart (§3.6/§12.4).
    if restart is not None:
        reset()
        _check_restart(connect_data, restart, set_backend_clock)


def main(argv: list[str] | None = None) -> int:
    """Run the single-plane suite against the built-in store.

    ``python -m tx402.spend_store_contract`` calls this; it runs every check in
    :data:`_CHECKS` against :class:`~tx402.ledger.MemorySpendStore` and exits non-zero
    first violation. The durable harness is not run here — it needs a live backend and both
    credential planes, which a self-check cannot provide.
    """
    del argv
    try:
        check_spend_store(MemorySpendStore)
    except SpendStoreContractError as error:
        print(f"FAIL  spend-store contract: {error}", file=sys.stderr)
        return 1
    print(
        f"OK    spend-store contract — {len(_CHECKS)} checks passed vs MemorySpendStore v2"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
