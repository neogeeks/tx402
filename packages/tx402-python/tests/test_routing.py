"""Deterministic route planning (SPEC §6.4).

The four ``routing.candidate-order`` vectors pin the ordering key cascade itself; this
suite covers the planner around it — concurrency, balance deduplication, the retention of
non-viable candidates, and step 20's three failure cases, which must not be conflated.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import MappingProxyType
from typing import Any

import pytest

from tx402.chain import ChainRoute
from tx402.errors import (
    InsufficientLiquidityError,
    TransportError,
    Tx402ErrorContext,
    UnsupportedSchemeError,
)
from tx402.health import HealthIndex
from tx402.policy import PolicyRequirement
from tx402.routing import (
    BalanceProbeCache,
    RouteCandidate,
    RoutePlan,
    RouteProbeOutcome,
    order_route_candidates,
    plan_routes,
    plan_routes_async,
)

BASE = "eip155:8453"
SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
CONTEXT = Tx402ErrorContext(request_id="test", phase="route")


def requirement(
    index: int, network: str = BASE, amount: str = "50000"
) -> PolicyRequirement:
    return PolicyRequirement(
        MappingProxyType(
            {
                "index": index,
                "scheme": "exact",
                "network": network,
                "asset": "0xasset",
                "amountAtomic": amount,
                "payTo": "0xpayto",
                "maxTimeoutSeconds": 60,
                "extra": {},
            }
        ),
        f"{network}/erc20:0xasset",
        MappingProxyType({"symbol": "USDC", "decimals": 6}),
        "500000",
        "10000000",
    )


def route(item: PolicyRequirement, balance: str, endpoint: str | None = None) -> ChainRoute:
    offer = item.requirement
    viable = int(balance) >= int(offer["amountAtomic"])
    return ChainRoute(
        requirement_index=offer["index"],
        network_id=offer["network"],
        scheme=offer["scheme"],
        asset_id=item.asset_id,
        amount_atomic=offer["amountAtomic"],
        signer_id="evm:0xsigner",
        balance_atomic=balance,
        viable=viable,
        rejection_reasons=() if viable else ("insufficient-balance",),
        endpoint_id=endpoint,
    )


def plan(
    requirements: list[PolicyRequirement], probe: Any, prefer: list[str] | None = None
) -> RoutePlan:
    return plan_routes(
        requirements=requirements,
        prefer_networks=prefer or [],
        health=HealthIndex(),
        now_epoch_ms=1_785_715_200_000,
        context=CONTEXT,
        probe=probe,
    )


class TestConcurrencyAndDeduplication:
    def test_every_probe_is_awaited_before_anything_is_ordered(self) -> None:
        """A "first viable wins" shortcut would make selection depend on RPC latency.

        The preferred candidate is deliberately the *slowest* to answer, and it must still
        win — SPEC §6.4 step 19 makes ordering a pure function of the candidates.
        """
        items = [requirement(0), requirement(1, SOLANA)]

        def probe(
            item: PolicyRequirement, _balances: BalanceProbeCache
        ) -> RouteProbeOutcome:
            if item.requirement["network"] == SOLANA:
                time.sleep(0.05)
            return RouteProbeOutcome(kind="route", route=route(item, "5000000"))

        result = plan(items, probe, prefer=[SOLANA])
        assert result.selected.requirement_index == 1

    def test_probes_run_concurrently_rather_than_end_to_end(self) -> None:
        started = threading.Barrier(3, timeout=2)

        def probe(
            item: PolicyRequirement, _balances: BalanceProbeCache
        ) -> RouteProbeOutcome:
            # Every probe must be in flight at once or the barrier times out.
            started.wait()
            return RouteProbeOutcome(kind="route", route=route(item, "5000000"))

        result = plan([requirement(0), requirement(1), requirement(2)], probe)
        assert len(result.candidates) == 3

    def test_requirements_sharing_a_key_collapse_onto_one_read(self) -> None:
        """SPEC §6.4 step 15's deduplication, which the 150 ms decision budget needs."""
        reads = 0

        def probe(
            item: PolicyRequirement, balances: BalanceProbeCache
        ) -> RouteProbeOutcome:
            def read() -> str:
                nonlocal reads
                reads += 1
                time.sleep(0.02)
                return "5000000"

            balance = balances.read("eip155:8453|usdc|0xowner", read)
            return RouteProbeOutcome(kind="route", route=route(item, balance))

        plan([requirement(0), requirement(1), requirement(2)], probe)
        assert reads == 1

    def test_a_deduplicated_failure_is_replayed_to_every_joiner(self) -> None:
        """The cache memoizes the outcome, not just the success."""
        cache = BalanceProbeCache()

        def fail() -> str:
            raise RuntimeError("rpc down")

        for _ in range(2):
            with pytest.raises(RuntimeError, match="rpc down"):
                cache.read("key", fail)

    @pytest.mark.asyncio
    async def test_async_probes_gather_and_share_one_read(self) -> None:
        reads = 0

        async def probe(
            item: PolicyRequirement, balances: BalanceProbeCache
        ) -> RouteProbeOutcome:
            async def read() -> str:
                nonlocal reads
                reads += 1
                await asyncio.sleep(0.01)
                return "5000000"

            balance = await balances.read_async("shared", read)
            return RouteProbeOutcome(kind="route", route=route(item, balance))

        result = await plan_routes_async(
            requirements=[requirement(0), requirement(1)],
            prefer_networks=[],
            health=HealthIndex(),
            now_epoch_ms=1_785_715_200_000,
            context=CONTEXT,
            probe=probe,
        )
        assert reads == 1
        assert result.selected.requirement_index == 0


class TestStepTwenty:
    def test_nothing_attempted_is_unsupported_scheme_not_insufficient_liquidity(
        self,
    ) -> None:
        """ "No signer configured" must not be reported as a funding problem."""

        def probe(_item: PolicyRequirement, _b: BalanceProbeCache) -> RouteProbeOutcome:
            return RouteProbeOutcome(kind="rejected", reason="no-signer-configured")

        with pytest.raises(UnsupportedSchemeError) as raised:
            plan([requirement(0), requirement(1, SOLANA)], probe)
        assert raised.value.details["offeredNetworks"] == [BASE, SOLANA]

    def test_balances_read_and_none_sufficient_reports_per_network_deficits(self) -> None:
        def probe(item: PolicyRequirement, _b: BalanceProbeCache) -> RouteProbeOutcome:
            return RouteProbeOutcome(kind="route", route=route(item, "10"))

        with pytest.raises(InsufficientLiquidityError) as raised:
            plan([requirement(1, SOLANA), requirement(0)], probe)
        # Reported in the merchant's requirement order, not in rank order: the same wallet
        # against the same challenge must produce the same-looking error.
        assert [item["network"] for item in raised.value.details["deficits"]] == [
            BASE,
            SOLANA,
        ]

    def test_an_unreachable_rpc_is_reported_as_transport_not_liquidity(self) -> None:
        """Blaming the caller's funds for an unreachable RPC sends them somewhere wrong."""
        failure = TransportError(
            "rpc down",
            context=CONTEXT,
            details={"causeCategory": "timeout"},
        )

        def probe(_item: PolicyRequirement, _b: BalanceProbeCache) -> RouteProbeOutcome:
            return RouteProbeOutcome(
                kind="failed", reason="balance-unavailable", error=failure, fatal=False
            )

        with pytest.raises(TransportError):
            plan([requirement(0)], probe)

    def test_a_raising_probe_becomes_one_non_viable_candidate(self) -> None:
        def probe(item: PolicyRequirement, _b: BalanceProbeCache) -> RouteProbeOutcome:
            if item.requirement["index"] == 0:
                raise RuntimeError("boom")
            return RouteProbeOutcome(kind="route", route=route(item, "5000000"))

        result = plan([requirement(0), requirement(1, SOLANA)], probe)
        assert result.selected.requirement_index == 1
        failed = next(item for item in result.candidates if item.requirement_index == 0)
        assert failed.rejection_reasons == ("balance-unavailable",)


class TestCandidateRetention:
    def test_non_viable_candidates_are_ranked_rather_than_dropped(self) -> None:
        """Step 20's deficits and the SPEC §10 diagnostics need the full considered set."""

        def probe(item: PolicyRequirement, _b: BalanceProbeCache) -> RouteProbeOutcome:
            balance = "5000000" if item.requirement["index"] == 1 else "1"
            return RouteProbeOutcome(kind="route", route=route(item, balance))

        result = plan([requirement(0), requirement(1, SOLANA)], probe)
        assert [item.rank for item in result.candidates] == [1, 2]
        assert result.selected.requirement_index == 1
        assert result.candidates[1].viable is False

    def test_health_is_read_from_the_index_for_the_endpoint_that_answered(self) -> None:
        health = HealthIndex()
        endpoint = HealthIndex.endpoint_id(BASE, "rpc.example.com")
        health.record_success(endpoint, 60, 1_785_715_200_000)

        def probe(item: PolicyRequirement, _b: BalanceProbeCache) -> RouteProbeOutcome:
            return RouteProbeOutcome(
                kind="route", route=route(item, "5000000", endpoint=endpoint)
            )

        result = plan_routes(
            requirements=[requirement(0)],
            prefer_networks=[],
            health=health,
            now_epoch_ms=1_785_715_200_000,
            context=CONTEXT,
            probe=probe,
        )
        assert result.selected.health_score == health.score(endpoint, 1_785_715_200_000)
        assert result.selected.observed_latency_ms == 60


class TestOrderingIsAPureFunction:
    """SPEC §6.4 step 19, stated as the property it actually is (PLAN.md O34).

    Step 19 requires identical output for identical inputs *and health state*. That is a
    property of :func:`order_route_candidates` alone, so it is asserted here on fixed
    inputs rather than through a live client whose probes re-measure the wall clock on
    every pass. The mirror of these two assertions lives in
    ``packages/tx402/test/routing.test.ts``.
    """

    @staticmethod
    def candidate(index: int, network: str = BASE, **overrides: Any) -> RouteCandidate:
        fields: dict[str, Any] = {
            "requirement_index": index,
            "network": network,
            "scheme": "exact",
            "asset_id": f"{network}/erc20:0xasset",
            "amount_atomic": "50000",
            "estimated_fee_atomic": "0",
            "health_score": 0.8,
            "circuit_state": "closed",
            "viable": True,
        }
        fields.update(overrides)
        return RouteCandidate(**fields)

    def test_an_exact_tie_on_every_key_above_it_is_decided_by_requirement_index(
        self,
    ) -> None:
        """The one deterministic guarantee a caller gets when nothing else separates two
        candidates: the merchant's own ordering wins, not whichever RPC answered first."""
        ordered = order_route_candidates(
            [
                self.candidate(1, SOLANA, observed_latency_ms=41.0),
                self.candidate(0, BASE, observed_latency_ms=41.0),
            ],
            [],
        )
        assert [item.requirement_index for item in ordered] == [0, 1]

    def test_output_does_not_depend_on_the_order_the_probes_finished_in(self) -> None:
        candidates = [
            self.candidate(0, BASE, health_score=0.70, observed_latency_ms=30.0),
            self.candidate(1, SOLANA, health_score=0.90, observed_latency_ms=300.0),
            self.candidate(2, BASE, health_score=0.90, observed_latency_ms=20.0),
        ]
        forward = [c.requirement_index for c in order_route_candidates(candidates, [])]
        reverse = [
            c.requirement_index for c in order_route_candidates(candidates[::-1], [])
        ]
        assert forward == [2, 1, 0]
        assert reverse == forward
