"""Unit tests for MemorySpendStore v2 — the SPEC §3 contract-v2 behaviour (ADR-023).

The cross-language conformance vectors (spend-ledger.behavior) and the base contract suite
cover reserve/commit/release; these run the *new* 0.2.0 surface directly: the exposure
transition matrix, the lifetime counters, capabilities, the ref-based locator, and the admin
plane the reference store implements on the same object (SPEC §3.5).
"""

from __future__ import annotations

import pytest

from tx402.errors import (
    BudgetExceededError,
    ConfigurationError,
    RecipientUnpinnedError,
)
from tx402.ledger import (
    RESERVATION_TTL_MS,
    ROLLING_WINDOW_MS,
    BudgetLimits,
    BudgetState,
    MemorySpendStore,
    ReservationRef,
    ReserveSpendResult,
)

NOW = 1_785_715_200_000
ASSET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
SCOPE = "client-1"
FINGERPRINT = "sha256:" + "1" * 64


def reservation_id(index: int) -> str:
    return f"00000000-0000-7000-8000-{index:012d}"


def ref(index: int, *, scope: str = SCOPE, asset: str = ASSET) -> ReservationRef:
    return ReservationRef(reservation_id(index), scope, asset)


def reserve(
    store: MemorySpendStore,
    index: int,
    *,
    amount: str = "2",
    cap: str = "6",
    max_total: str | None = None,
) -> ReserveSpendResult:
    return store.reserve(
        reservation_id=reservation_id(index),
        request_id=f"request-{index}",
        policy_scope=SCOPE,
        request_fingerprint=FINGERPRINT,
        asset_id=ASSET,
        amount_atomic=amount,
        max_per_hour_atomic=cap,
        max_total_atomic=max_total,
        now_epoch_ms=NOW,
    )


def snapshot(store: MemorySpendStore, now: int = NOW) -> BudgetState:
    return store.get_budget_state(policy_scope=SCOPE, asset_id=ASSET, now_epoch_ms=now)


def test_declares_atomic_global_freeze_capability() -> None:
    assert MemorySpendStore().capabilities.atomic_global_freeze is True


def test_reserve_returns_result_with_pin_flag_false() -> None:
    store = MemorySpendStore()
    result = reserve(store, 1)
    assert result.recipient_pin_established is False
    assert result.reservation.state == "reserved"
    replay = reserve(store, 1)
    assert replay.recipient_pin_established is False
    assert replay.reservation.reservation_id == reservation_id(1)


def test_reuse_with_different_data_raises() -> None:
    store = MemorySpendStore()
    reserve(store, 1, amount="2")
    with pytest.raises(ValueError, match="different spend data"):
        reserve(store, 1, amount="3")


@pytest.mark.parametrize("bad", ["-5", "0", "007", " 5 ", "5.0", ""])
def test_reserve_rejects_malformed_amount_before_insert(bad: str) -> None:
    # O58: the reference store guards amount_atomic with ^[1-9][0-9]*$ and raises TypeError
    # BEFORE any insert — matching the TS twin. A bare int() used to accept "-5"/"0"/"007",
    # and a negative even LOWERED the cap sum. Unreachable on the validated path, but the
    # reference/default store must not be the permissive one at its API boundary.
    store = MemorySpendStore()
    with pytest.raises(TypeError):
        store.reserve(
            reservation_id=reservation_id(1),
            request_id="o58",
            policy_scope=SCOPE,
            request_fingerprint=FINGERPRINT,
            asset_id=ASSET,
            amount_atomic=bad,
            max_per_hour_atomic="1000",
            now_epoch_ms=NOW,
        )
    assert snapshot(store).reserved_atomic == "0"  # the guard fired before any insert


@pytest.mark.parametrize("bad_cap", ["-5", "0", "007", "5.0", ""])
def test_reserve_rejects_malformed_per_hour_cap(bad_cap: str) -> None:
    # O58 companion: the caller per-hour cap is guarded the same way (positive atomic).
    store = MemorySpendStore()
    with pytest.raises(TypeError):
        store.reserve(
            reservation_id=reservation_id(1),
            request_id="o58-cap",
            policy_scope=SCOPE,
            request_fingerprint=FINGERPRINT,
            asset_id=ASSET,
            amount_atomic="5",
            max_per_hour_atomic=bad_cap,
            now_epoch_ms=NOW,
        )


def test_expose_keeps_counting_past_ttl_and_lists() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    exposed = store.expose(ref=ref(1), now_epoch_ms=NOW + 5)
    assert exposed.state == "exposed"

    state = snapshot(store)
    assert state.reserved_atomic == "0"
    assert state.exposed_atomic == "2"
    assert state.cumulative_consumed_atomic == "2"

    later = snapshot(store, NOW + ROLLING_WINDOW_MS + 1)
    assert later.exposed_atomic == "2"
    listed = store.list_exposed(
        policy_scope=SCOPE, asset_id=ASSET, now_epoch_ms=NOW + ROLLING_WINDOW_MS + 1
    )
    assert [r.reservation_id for r in listed] == [reservation_id(1)]


def test_expose_is_idempotent_and_matches_list_exposed() -> None:
    store = MemorySpendStore()
    reserve(store, 1, amount="2")
    reserve(store, 2, amount="3", cap="6")
    store.expose(ref=ref(1), now_epoch_ms=NOW)
    replay = store.expose(ref=ref(1), now_epoch_ms=NOW)  # no double-count
    assert replay.state == "exposed"
    store.expose(ref=ref(2), now_epoch_ms=NOW)
    state = snapshot(store)
    listed = store.list_exposed(policy_scope=SCOPE, asset_id=ASSET, now_epoch_ms=NOW)
    assert state.exposed_atomic == str(sum(int(r.amount_atomic) for r in listed)) == "5"


def test_exposed_counts_against_per_hour_cap() -> None:
    store = MemorySpendStore()
    reserve(store, 1, amount="2")
    store.expose(ref=ref(1), now_epoch_ms=NOW)
    reserve(store, 2, amount="2")
    reserve(store, 3, amount="2")  # 2 exposed + 2 + 2 = 6, at cap
    from tx402.errors import BudgetExceededError

    with pytest.raises(BudgetExceededError):
        reserve(store, 4, amount="2")


def test_commit_exposed_moves_to_cumulative_committed() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    store.expose(ref=ref(1), now_epoch_ms=NOW)
    store.commit(ref=ref(1), committed_at_epoch_ms=NOW + 10, settlement_id="s1")
    state = snapshot(store, NOW + 10)
    assert state.exposed_atomic == "0"
    assert state.cumulative_committed_atomic == "2"
    assert state.committed_atomic == "2"


def test_release_exposed_frees_budget() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    store.expose(ref=ref(1), now_epoch_ms=NOW)
    released = store.release(ref=ref(1), now_epoch_ms=NOW + 10)
    assert released.state == "released"
    assert snapshot(store, NOW + 10).exposed_atomic == "0"


def test_commit_expired_is_refused() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    snapshot(store, NOW + RESERVATION_TTL_MS)  # maintain: reservation 1 -> expired
    with pytest.raises(ConfigurationError) as excinfo:
        store.commit(ref=ref(1), committed_at_epoch_ms=NOW + RESERVATION_TTL_MS + 1)
    assert excinfo.value.details["reason"] == "expired-cannot-commit"
    assert excinfo.value.details["configPath"] == "reservation.lifecycle"


def test_resolve_exposed_committed_equals_commit_exposed() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    store.expose(ref=ref(1), now_epoch_ms=NOW)
    store.resolve_exposed(ref(1), "committed", NOW + 10)
    assert snapshot(store, NOW + 10).cumulative_committed_atomic == "2"


def test_resolve_exposed_on_reserved_is_not_exposed() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    with pytest.raises(ConfigurationError) as excinfo:
        store.resolve_exposed(ref(1), "committed", NOW)
    assert excinfo.value.details["reason"] == "reservation-not-exposed"


def test_resolve_exposed_released_and_terminal_paths() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    store.expose(ref=ref(1), now_epoch_ms=NOW)
    store.resolve_exposed(ref(1), "released", NOW + 5)  # release branch
    assert snapshot(store, NOW + 5).exposed_atomic == "0"
    with pytest.raises(ConfigurationError) as excinfo:
        store.resolve_exposed(ref(1), "committed", NOW + 6)
    assert excinfo.value.details["reason"] == "reservation-already-terminal"


def test_expose_on_committed_is_terminal() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    store.commit(ref=ref(1), committed_at_epoch_ms=NOW)
    with pytest.raises(ConfigurationError) as excinfo:
        store.expose(ref=ref(1), now_epoch_ms=NOW)
    assert excinfo.value.details["reason"] == "reservation-already-terminal"


def test_commit_released_is_released_cannot_commit() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    store.release(ref=ref(1), now_epoch_ms=NOW)
    with pytest.raises(ConfigurationError) as excinfo:
        store.commit(ref=ref(1), committed_at_epoch_ms=NOW + 10)
    assert excinfo.value.details["reason"] == "released-cannot-commit"


def test_wrong_scope_ref_is_reservation_not_found() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    wrong = ref(1, scope="someone-else")
    for op in (
        lambda: store.release(ref=wrong, now_epoch_ms=NOW),
        lambda: store.expose(ref=wrong, now_epoch_ms=NOW),
        lambda: store.resolve_exposed(wrong, "committed", NOW),
        lambda: store.commit(ref=wrong, committed_at_epoch_ms=NOW),
    ):
        with pytest.raises(ConfigurationError) as excinfo:
            op()
        assert excinfo.value.details["reason"] == "reservation-not-found"
        assert excinfo.value.details["configPath"] == "reservationRef"


def test_release_committed_returns_unchanged() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    store.commit(ref=ref(1), committed_at_epoch_ms=NOW)
    # release on a committed record is a no-op replay, not an error (per shipped).
    unchanged = store.release(ref=ref(1), now_epoch_ms=NOW + 5)
    assert unchanged.state == "committed"


def test_admin_limits_and_freeze_reporting() -> None:
    store = MemorySpendStore()
    store.set_budget_limits(
        SCOPE, ASSET, BudgetLimits(max_per_hour_atomic="100", max_total_atomic="1000"), NOW
    )
    reserve(store, 1)  # 2 reserved
    state = snapshot(store)
    assert state.per_hour_limit_atomic == "100"
    assert state.cumulative_limit_atomic == "1000"
    assert state.available_per_hour_atomic == "98"
    assert state.available_cumulative_atomic == "998"
    assert state.frozen is False
    assert store.get_budget_limits(SCOPE, ASSET).max_total_atomic == "1000"

    assert store.is_frozen(scope=SCOPE) is False
    store.freeze(SCOPE, NOW)
    assert store.is_frozen(scope=SCOPE) is True
    assert snapshot(store).frozen is True
    store.unfreeze(SCOPE, NOW)
    store.freeze("*", NOW)  # global freeze covers a distinct scope (atomic-global-freeze)
    assert store.is_frozen(scope=SCOPE) is True


def test_admin_recipient_pins_and_policy() -> None:
    store = MemorySpendStore()
    assert store.get_recipient_policy(SCOPE) == {
        "tofu_enabled": False,
        "recipient_assertion_required": False,
    }
    store.set_recipient_pins(SCOPE, "eip155:8453", ("0xabc",), NOW)
    assert store.get_recipient_pins(SCOPE, "eip155:8453") == ("0xabc",)
    assert store.get_recipient_pins(SCOPE, "solana:mainnet") == ()
    store.set_tofu_enabled(SCOPE, True, NOW)
    store.set_recipient_assertion_required(SCOPE, True, NOW)
    assert store.get_recipient_policy(SCOPE) == {
        "tofu_enabled": True,
        "recipient_assertion_required": True,
    }


def test_empty_recipient_fails_closed_when_assertion_required() -> None:
    # O56: the reference/default store must NOT be the permissive one on a safety gate. A
    # defined-but-empty recipient_canonical is NOT a presented recipient, so an
    # assertion-required scope refuses it — matching the durable Redis/DO stores.
    store = MemorySpendStore()
    store.set_recipient_assertion_required(SCOPE, True, NOW)
    with pytest.raises(RecipientUnpinnedError) as excinfo:
        store.reserve(
            reservation_id=reservation_id(1),
            request_id="request-1",
            policy_scope=SCOPE,
            request_fingerprint=FINGERPRINT,
            asset_id=ASSET,
            amount_atomic="2",
            max_per_hour_atomic="6",
            now_epoch_ms=NOW,
            recipient_network="eip155:8453",
            recipient_canonical="",
        )
    assert excinfo.value.details.get("reason") == "assertion-required"
    # And nothing was reserved (the refusal is pre-insert).
    assert snapshot(store).reserved_atomic == "0"


def test_reset_cumulative_clears_lifetime_committed() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    store.commit(ref=ref(1), committed_at_epoch_ms=NOW)
    assert snapshot(store).cumulative_committed_atomic == "2"
    store.reset_cumulative(SCOPE, ASSET, NOW)
    assert snapshot(store).cumulative_committed_atomic == "0"


def test_scope_and_asset_partition_the_ledger() -> None:
    store = MemorySpendStore()
    reserve(store, 1)
    other = store.get_budget_state(policy_scope="other", asset_id=ASSET, now_epoch_ms=NOW)
    assert other.reserved_atomic == "0"
    assert snapshot(store).reserved_atomic == "2"


# The cumulative-cap vectors drive the caller-cap path cross-language; the administered
# precedence (SPEC §4.3) is not expressible in a ledger vector (no admin verbs in the op
# set), so it is proven here against MemorySpendStore directly (ADR-023).


def test_cumulative_cap_refuses_what_per_hour_admits() -> None:
    store = MemorySpendStore()
    # Per-hour has headroom (100); the cumulative cap (10) is the binding dimension.
    reserve(store, 1, amount="6", cap="100", max_total="10")
    store.commit(ref=ref(1), committed_at_epoch_ms=NOW)
    with pytest.raises(BudgetExceededError) as excinfo:
        reserve(store, 2, amount="6", cap="100", max_total="10")
    assert excinfo.value.details["capKind"] == "cumulative"
    assert excinfo.value.details["capAtomic"] == "10"
    assert excinfo.value.details["committedAtomic"] == "6"


def test_administered_cumulative_cap_binds_without_a_caller_cap() -> None:
    store = MemorySpendStore()
    store.set_budget_limits(SCOPE, ASSET, BudgetLimits(max_total_atomic="10"), NOW)
    reserve(store, 1, amount="6", cap="100")  # no caller max_total
    store.commit(ref=ref(1), committed_at_epoch_ms=NOW)
    with pytest.raises(BudgetExceededError) as excinfo:
        reserve(store, 2, amount="6", cap="100")
    assert excinfo.value.details["capKind"] == "cumulative"
    assert excinfo.value.details["capAtomic"] == "10"


def test_caller_cumulative_cap_above_administered_is_config_error() -> None:
    store = MemorySpendStore()
    store.set_budget_limits(SCOPE, ASSET, BudgetLimits(max_total_atomic="10"), NOW)
    with pytest.raises(ConfigurationError) as excinfo:
        reserve(store, 1, amount="1", cap="100", max_total="20")
    assert excinfo.value.details["reason"] == "cap-exceeds-administered"
    assert excinfo.value.details["configPath"] == "policy.maxTotal"


def test_caller_per_hour_cap_above_administered_is_config_error() -> None:
    store = MemorySpendStore()
    store.set_budget_limits(SCOPE, ASSET, BudgetLimits(max_per_hour_atomic="5"), NOW)
    with pytest.raises(ConfigurationError) as excinfo:
        reserve(store, 1, amount="1", cap="10")
    assert excinfo.value.details["reason"] == "cap-exceeds-administered"
    assert excinfo.value.details["configPath"] == "policy.maxPerHour"


def test_stricter_caller_per_hour_cap_binds_via_min() -> None:
    store = MemorySpendStore()
    store.set_budget_limits(SCOPE, ASSET, BudgetLimits(max_per_hour_atomic="100"), NOW)
    # The caller cap (5) is below the administered one (100); min = 5, so 6 is refused.
    with pytest.raises(BudgetExceededError) as excinfo:
        reserve(store, 1, amount="6", cap="5")
    assert excinfo.value.details["capKind"] == "per-hour"
    assert excinfo.value.details["capAtomic"] == "5"


def test_lowered_cap_precedence_config_then_budget() -> None:
    store = MemorySpendStore()
    store.set_budget_limits(SCOPE, ASSET, BudgetLimits(max_total_atomic="10"), NOW)
    reserve(store, 1, amount="8", cap="100", max_total="10")
    store.commit(ref=ref(1), committed_at_epoch_ms=NOW)  # consume 8 under the original cap
    # Lower the administered cap below current consumption — permitted, no rollback (§4.3).
    store.set_budget_limits(SCOPE, ASSET, BudgetLimits(max_total_atomic="5"), NOW)
    # A worker still presenting its old, higher caller cap trips step 4 (configuration).
    with pytest.raises(ConfigurationError) as config_error:
        reserve(store, 2, amount="1", cap="100", max_total="10")
    assert config_error.value.details["reason"] == "cap-exceeds-administered"
    # A worker whose caller cap is now <= the administered cap gets a budget refusal.
    with pytest.raises(BudgetExceededError) as budget_error:
        reserve(store, 3, amount="1", cap="100", max_total="5")
    assert budget_error.value.details["capKind"] == "cumulative"
    assert budget_error.value.details["capAtomic"] == "5"


def test_no_cumulative_cap_never_binds() -> None:
    store = MemorySpendStore()
    reservation = reserve(store, 1, amount="1000000", cap="1000000").reservation
    assert reservation.state == "reserved"
