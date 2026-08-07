"""A runnable conformance suite for third-party :class:`~tx402.ledger.SpendStore` adapters.

Shipped in the wheel rather than kept in ``tests/`` on purpose. An adapter author — someone
putting the fleet's budget in Redis or Postgres so that twenty agent processes share one
hourly cap — is not a contributor to this repository and cannot import its test tree. Before
S15b there was nothing for them to run at all, which is the audit's O54: the product
promised a public contract and published only a concrete class.

Usage::

    from tx402.spend_store_contract import check_spend_store

    def test_my_store_is_a_spend_store() -> None:
        check_spend_store(lambda: RedisSpendStore(url="redis://localhost/15"))

``check_spend_store`` raises :class:`SpendStoreContractError` on the first violation, with a
message naming the rule that was broken. It is deliberately dependency-free and framework-
free: it is a function, not a pytest fixture, so it runs under any runner or none.

**What it does and does not prove.** It exercises the rules that can be checked from the
outside in one process: money arithmetic, the rolling window, idempotency, the typed
over-cap refusal, scope and asset isolation, and — with real threads — that the cap
comparison and insert are one atomic operation. It cannot prove atomicity across *machines*;
for a networked store that means the check passing is necessary and not sufficient, and the
adapter still owns its transaction boundary.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Final

from tx402.errors import BudgetExceededError
from tx402.ledger import RESERVATION_TTL_MS, ROLLING_WINDOW_MS, assert_spend_store

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to a type checker
    from tx402.ledger import SpendStore

__all__ = ["SpendStoreContractError", "check_spend_store"]

#: A fixed instant, so every check is deterministic and never reads a real clock.
_NOW: Final = 1_800_000_000_000
_ASSET: Final = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
_OTHER_ASSET: Final = "solana:mainnet/spl:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_SCOPE: Final = "merchant.example"
_OTHER_SCOPE: Final = "other.example"
_FINGERPRINT: Final = "sha256:" + "0" * 64


class SpendStoreContractError(AssertionError):
    """A spend store violated the contract. The message names the rule."""


def _require(condition: bool, rule: str) -> None:
    if not condition:
        raise SpendStoreContractError(rule)


def _reserve(
    store: SpendStore,
    *,
    reservation_id: str,
    amount: str,
    cap: str = "1000000",
    scope: str = _SCOPE,
    asset: str = _ASSET,
    now: int = _NOW,
) -> object:
    return store.reserve(
        reservation_id=reservation_id,
        request_id="contract-" + reservation_id,
        policy_scope=scope,
        request_fingerprint=_FINGERPRINT,
        asset_id=asset,
        amount_atomic=amount,
        max_per_hour_atomic=cap,
        now_epoch_ms=now,
    )


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


def _check_reserve_and_totals(make_store: Callable[[], SpendStore]) -> None:
    store = make_store()
    committed, reserved = _totals(store)
    _require(
        (committed, reserved) == (0, 0),
        "a fresh scope/asset pair must report committed 0 and reserved 0",
    )

    reservation = _reserve(store, reservation_id="r1", amount="1500")
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
    _reserve(store, reservation_id="c1", amount="900")
    entry = store.commit(
        reservation_id="c1", committed_at_epoch_ms=_NOW + 10, settlement_id="0xabc"
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
    again = store.commit(reservation_id="c1", committed_at_epoch_ms=_NOW + 20)
    _require(
        getattr(again, "committed_at_epoch_ms", None)
        == getattr(entry, "committed_at_epoch_ms", None),
        "commit must be idempotent: a second call returns the first entry unchanged",
    )

    store = make_store()
    _reserve(store, reservation_id="c2", amount="900")
    released = store.release(reservation_id="c2", now_epoch_ms=_NOW + 5)
    _require(
        getattr(released, "state", None) == "released",
        "release must return the reservation in state 'released'",
    )
    _require(
        _totals(store, now=_NOW + 5) == (0, 0),
        "a released reservation must stop counting toward the cap immediately",
    )
    store.release(reservation_id="c2", now_epoch_ms=_NOW + 6)

    raised = False
    try:
        store.commit(reservation_id="c2", committed_at_epoch_ms=_NOW + 7)
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
    _reserve(inside, reservation_id="w1", amount="500")
    inside.commit(reservation_id="w1", committed_at_epoch_ms=_NOW)
    _require(
        _totals(inside, now=_NOW + ROLLING_WINDOW_MS - 1) == (500, 0),
        "a commit must still count one millisecond before the window closes",
    )

    outside = make_store()
    _reserve(outside, reservation_id="w1", amount="500")
    outside.commit(reservation_id="w1", committed_at_epoch_ms=_NOW)
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


_CHECKS: Final = (
    _check_shape,
    _check_reserve_and_totals,
    _check_scope_and_asset_isolation,
    _check_commit_and_release,
    _check_idempotent_reserve,
    _check_cap_refusal,
    _check_rolling_window,
    _check_expiry,
    _check_atomicity,
)


def check_spend_store(make_store: Callable[[], SpendStore]) -> None:
    """Runs every contract check against stores produced by ``make_store``.

    ``make_store`` is a factory rather than an instance because several checks need a store
    with no history; a factory that hands back the same populated object will fail them.
    Each call should produce an empty, independent ledger.

    Raises :class:`SpendStoreContractError` on the first violation.
    """
    for check in _CHECKS:
        check(make_store)
