"""The one health index and its circuit (SPEC §6.5).

The two ``health.circuit`` conformance vectors already pin the thresholds and the exact
scores; these cover what a vector cannot conveniently express — the LRU bound, idle
retention, probe exclusivity, and the fact that ``reset``/``forget`` clear observations
without touching anything else.
"""

from __future__ import annotations

from tx402.health import (
    HEALTH_IDLE_RETENTION_MS,
    HEALTH_NEW_ENDPOINT_SCORE,
    HEALTH_OPEN_MS,
    HealthIndex,
)

ENDPOINT = "eip155:8453|rpc.example.com"
OTHER = "eip155:8453|backup.example.com"

#: A real wall-clock instant, matching the frozen ``health.circuit`` vectors.
#:
#: Not zero: both SDKs use ``openedAtEpochMs == 0`` as the "circuit closed" sentinel, so an
#: endpoint opened at epoch 0 would read as closed. The convention is shared, so the fix
#: is to test at a plausible time rather than give Python its own sentinel (PLAN.md O29).
BASE = 1_785_715_200_000


def open_circuit(health: HealthIndex, endpoint: str, at: int = BASE) -> None:
    """Five consecutive failures at one instant, so the window opens exactly at ``at``."""
    for _ in range(5):
        health.record_failure(endpoint, at)


class TestScoring:
    def test_an_unknown_endpoint_scores_the_spec_seed(self) -> None:
        """SPEC §6.4 step 17: new endpoints start at 0.80."""
        health = HealthIndex()
        assert health.score(ENDPOINT, BASE) == HEALTH_NEW_ENDPOINT_SCORE
        assert health.inspect(ENDPOINT, BASE).observed_latency_ms is None
        assert health.size == 0

    def test_latency_penalty_is_capped_and_relative_to_the_probe_budget(self) -> None:
        fast, slow = HealthIndex(), HealthIndex()
        fast.record_success(ENDPOINT, 0, BASE)
        slow.record_success(ENDPOINT, 10_000, BASE)
        # Both saw one success, so the success EWMA is identical (0.2 * 1 + 0.8 * 0.8) and
        # only the latency term differs — and a 10 s endpoint loses exactly the capped 0.2
        # rather than an unbounded amount.
        assert fast.score(ENDPOINT, BASE) == 0.84
        assert slow.score(ENDPOINT, BASE) == 0.64

    def test_scores_are_rounded_half_up_to_four_places(self) -> None:
        """Python's ``round`` is banker's rounding; the cross-language rule is half-up."""
        health = HealthIndex()
        for offset in range(4):
            health.record_failure(ENDPOINT, BASE + offset)
        # 0.8 * 0.8**4 = 0.32768 -> 0.3277, not 0.3276.
        assert health.score(ENDPOINT, BASE + 3) == 0.3277


class TestCircuit:
    def test_open_is_immediate_and_independent_of_the_thresholds(self) -> None:
        """SPEC §7.1/§7.2 chain identity: one wrong-chain answer is enough."""
        health = HealthIndex()
        health.open(ENDPOINT, BASE)
        assert health.state(ENDPOINT, BASE) == "open"
        assert health.inspect(ENDPOINT, BASE).consecutive_failures == 1

    def test_only_one_probe_is_handed_out_while_half_open(self) -> None:
        health = HealthIndex()
        open_circuit(health, ENDPOINT)
        half_open_at = BASE + HEALTH_OPEN_MS
        assert health.admit(ENDPOINT, half_open_at) == "half-open"
        assert health.admit(ENDPOINT, half_open_at) == "open"

    def test_a_failed_probe_reopens_without_waiting_for_a_threshold(self) -> None:
        health = HealthIndex()
        open_circuit(health, ENDPOINT)
        probe_at = BASE + HEALTH_OPEN_MS
        assert health.admit(ENDPOINT, probe_at) == "half-open"
        health.record_failure(ENDPOINT, probe_at)
        # The endpoint had its one chance; the window restarts from the probe.
        assert health.state(ENDPOINT, probe_at) == "open"
        assert health.state(ENDPOINT, probe_at + HEALTH_OPEN_MS) == "half-open"

    def test_a_successful_probe_discards_the_history_that_opened_the_circuit(self) -> None:
        """Otherwise a recovered endpoint re-opens on its very next single failure."""
        health = HealthIndex()
        open_circuit(health, ENDPOINT)
        probe_at = BASE + HEALTH_OPEN_MS
        health.record_success(ENDPOINT, 10, probe_at)
        assert health.state(ENDPOINT, probe_at) == "closed"
        assert health.inspect(ENDPOINT, probe_at).sample_count == 1
        health.record_failure(ENDPOINT, probe_at + 1)
        assert health.state(ENDPOINT, probe_at + 1) == "closed"

    def test_admitting_an_unknown_endpoint_is_closed(self) -> None:
        assert HealthIndex().admit(ENDPOINT, BASE) == "closed"


class TestRetention:
    def test_the_lru_cap_evicts_the_least_recently_used_endpoint(self) -> None:
        health = HealthIndex(max_endpoints=2)
        health.record_failure("a", BASE)
        health.record_failure("b", BASE + 1)
        health.record_failure("a", BASE + 2)  # touches "a", making "b" the oldest
        health.record_failure("c", BASE + 3)
        assert health.size == 2
        assert health.inspect("b", BASE + 3).sample_count == 0
        assert health.inspect("a", BASE + 3).sample_count == 2

    def test_idle_endpoints_are_dropped_after_the_retention_window(self) -> None:
        health = HealthIndex()
        health.record_failure(ENDPOINT, BASE)
        idle_at = BASE + HEALTH_IDLE_RETENTION_MS + 1
        health.record_failure(OTHER, idle_at)
        assert health.inspect(ENDPOINT, idle_at).sample_count == 0

    def test_reset_and_forget_clear_observations(self) -> None:
        health = HealthIndex()
        health.record_failure(ENDPOINT, BASE)
        health.record_failure(OTHER, BASE)
        health.forget(ENDPOINT)
        assert health.size == 1
        health.reset()
        assert health.size == 0
