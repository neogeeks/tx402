"""Deterministic route planning (SPEC §6.4, §5.2).

Port of ``packages/tx402/src/core/routing.ts``. The planner is reached only after the
policy engine has approved a set of requirements — SPEC §6.3 step 13 makes that ordering a
MUST, because this is the first place that talks to a network, and a balance query against
a merchant-named chain is already an observable side effect of a request policy might have
refused.

Three properties shape the code:

1. **Ordering is a pure function of the candidates.** SPEC §6.4 step 19 requires identical
   output for identical inputs and health state, so every comparison key is either carried
   on the candidate or read once from the health index before sorting.
   ``requirement_index`` is the final key and is unique per challenge, which makes the order
   a total one — the result does not depend on the sort being stable, or on which probe
   finished first.
2. **Balances are fetched concurrently, once per unique network/asset/owner.** Step 15 says
   concurrently; the deduplication is what keeps a challenge offering the same network twice
   from spending two round trips out of the 150 ms decision budget.
3. **Nothing is dropped.** A requirement with no signer, an unreadable balance, and an
   insufficient balance all become candidates carrying their ``rejection_reasons``, because
   SPEC §6.4 step 20's per-network deficits and the SPEC §10 diagnostics both need the full
   considered set rather than the survivors.
"""

from __future__ import annotations

import asyncio
import dataclasses
import threading
from collections.abc import Awaitable, Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Final, Generic, Literal, TypeVar

from tx402.chain import ChainRoute
from tx402.errors import (
    InsufficientLiquidityError,
    Tx402ErrorContext,
    UnsupportedSchemeError,
)
from tx402.health import HEALTH_NEW_ENDPOINT_SCORE, CircuitState, HealthIndex
from tx402.policy import PolicyRequirement

#: The closed set from ``core-spec/schemas/route-candidate.schema.json``.
RouteRejectionReason = Literal[
    "no-signer-configured",
    "scheme-unsupported",
    "network-not-in-manifest",
    "network-not-allowed-by-policy",
    "asset-unsupported",
    "environment-mismatch",
    "insufficient-balance",
    "balance-unavailable",
    "chain-identity-mismatch",
    "circuit-open",
]

#: Separates the parts of a balance-cache key.
#:
#: A NUL cannot appear in a CAIP-2 identifier, a token address, or an account address, so
#: joining on it makes the key unambiguous — the same reason :mod:`tx402.policy` uses it for
#: its network/asset index. It is written as the ``\\u0000`` escape rather than as a literal
#: control character: a raw NUL byte in a source file makes git classify the file as binary
#: and stop diffing it (PLAN.md open item O25).
BALANCE_KEY_SEPARATOR: Final = "\u0000"

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class RouteCandidate:
    """One scored route (SPEC §5.2). Every field here is redaction-safe."""

    requirement_index: int
    network: str
    scheme: str
    asset_id: str
    amount_atomic: str
    estimated_fee_atomic: str
    health_score: float
    circuit_state: CircuitState
    viable: bool
    rejection_reasons: tuple[str, ...] = ()
    signer_id: str | None = None
    balance_atomic: str | None = None
    observed_latency_ms: float | None = None
    rank: int = 0


class _OnceCell(Generic[T]):
    """Runs ``load`` exactly once and replays its outcome — result or exception."""

    __slots__ = ("_done", "_error", "_load", "_lock", "_value")

    def __init__(self, load: Callable[[], T]) -> None:
        self._load = load
        self._lock = threading.Lock()
        self._done = False
        self._value: T | None = None
        self._error: BaseException | None = None

    def get(self) -> T:
        with self._lock:
            if not self._done:
                try:
                    self._value = self._load()
                except BaseException as error:
                    self._error = error
                self._done = True
        if self._error is not None:
            raise self._error
        return self._value  # type: ignore[return-value]


class BalanceProbeCache:
    """Memoizes an in-flight read so requirements sharing network/asset/owner share a query.

    Keyed on the in-flight work rather than on the result, so concurrent callers join the
    same request instead of racing two. The cache lives for exactly one planning pass: a
    balance is a snapshot, and reusing it across requests would be reusing a stale one.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sync: dict[str, _OnceCell[Any]] = {}
        self._async: dict[str, asyncio.Task[Any]] = {}

    def read(self, key: str, load: Callable[[], T]) -> T:
        """Synchronous join. The first caller loads; the rest wait on the same outcome."""
        with self._lock:
            cell = self._sync.get(key)
            if cell is None:
                cell = _OnceCell(load)
                self._sync[key] = cell
        result: T = cell.get()
        return result

    async def read_async(self, key: str, load: Callable[[], Awaitable[T]]) -> T:
        """Asynchronous join, on the loop that started the planning pass.

        A ``Task`` may be awaited any number of times, so joiners simply await the one the
        first caller created.
        """
        task = self._async.get(key)
        if task is None:
            task = asyncio.ensure_future(load())
            self._async[key] = task
        result: T = await task
        return result


@dataclass(frozen=True, slots=True)
class RouteProbeOutcome:
    """What a probe can report back about one requirement.

    ``kind`` is ``"route"`` (the adapter scored the requirement against the chain),
    ``"rejected"`` (nothing was attempted — no signer, no adapter, no manifest entry), or
    ``"failed"`` (an attempt was made and failed; ``fatal`` outranks a liquidity report).
    """

    kind: Literal["route", "rejected", "failed"]
    route: ChainRoute | None = None
    reason: str | None = None
    error: BaseException | None = None
    fatal: bool = False


@dataclass(frozen=True, slots=True)
class RoutePlan:
    #: Every requirement considered, ranked. Non-viable candidates are retained.
    candidates: tuple[RouteCandidate, ...]
    selected: RouteCandidate
    selected_requirement: PolicyRequirement
    selected_route: ChainRoute


def order_route_candidates(
    candidates: Sequence[RouteCandidate],
    prefer_networks: Sequence[str],
) -> tuple[RouteCandidate, ...]:
    """Orders candidates by SPEC §6.4 step 18, with SPEC §6.5's open-circuit rule on top.

    Step 18's list is *viable, preference, fee, health, latency, index*. SPEC §6.5 adds a
    stronger statement about one of those inputs — "an open endpoint may be used only when
    every compatible endpoint is open, and it is ranked **last**" — which cannot be
    expressed as a health-score adjustment: a big enough preference bonus would outrank it.
    It is therefore its own key, immediately below viability, and above preference.

    Every key is a total or near-total order and the last is unique per challenge, so the
    result does not depend on sort stability.
    """
    preference: dict[str, int] = {}
    for network in prefer_networks:
        if network not in preference:
            preference[network] = len(preference)
    unpreferred = len(preference)

    def key(candidate: RouteCandidate) -> tuple[int, int, int, int, float, float, int]:
        return (
            0 if candidate.viable else 1,
            1 if candidate.circuit_state == "open" else 0,
            preference.get(candidate.network, unpreferred),
            int(candidate.estimated_fee_atomic),
            # Higher health sorts first, so this one key is negated. Reversing the whole
            # sort would invert every other key along with it.
            -candidate.health_score,
            # An endpoint with no observation is not slow, it is unmeasured; treating it as
            # 0 keeps this key from silently doing the work of the health score above it.
            candidate.observed_latency_ms or 0.0,
            candidate.requirement_index,
        )

    # Ranks are 1-based and dense: every considered candidate is ranked, viable or not.
    return tuple(
        dataclasses.replace(candidate, rank=index + 1)
        for index, candidate in enumerate(sorted(candidates, key=key))
    )


def _health_of(
    health: HealthIndex, endpoint_id: str | None, now_epoch_ms: int
) -> tuple[float, CircuitState, float | None]:
    if endpoint_id is None:
        return HEALTH_NEW_ENDPOINT_SCORE, "closed", None
    observed = health.inspect(endpoint_id, now_epoch_ms)
    return observed.health_score, observed.circuit_state, observed.observed_latency_ms


def _candidate_from_outcome(
    requirement: PolicyRequirement,
    outcome: RouteProbeOutcome,
    health: HealthIndex,
    now_epoch_ms: int,
) -> RouteCandidate:
    offer = requirement.requirement
    if outcome.kind == "route" and outcome.route is not None:
        route = outcome.route
        score, circuit, latency = _health_of(health, route.endpoint_id, now_epoch_ms)
        return RouteCandidate(
            requirement_index=offer["index"],
            network=offer["network"],
            scheme=offer["scheme"],
            asset_id=requirement.asset_id,
            amount_atomic=offer["amountAtomic"],
            estimated_fee_atomic=route.estimated_fee_atomic,
            health_score=score,
            circuit_state=circuit,
            observed_latency_ms=latency,
            signer_id=route.signer_id,
            balance_atomic=route.balance_atomic,
            viable=route.viable,
            rejection_reasons=() if route.viable else tuple(route.rejection_reasons),
        )
    return RouteCandidate(
        requirement_index=offer["index"],
        network=offer["network"],
        scheme=offer["scheme"],
        asset_id=requirement.asset_id,
        amount_atomic=offer["amountAtomic"],
        estimated_fee_atomic="0",
        health_score=HEALTH_NEW_ENDPOINT_SCORE,
        circuit_state="closed",
        viable=False,
        rejection_reasons=(outcome.reason or "balance-unavailable",),
    )


def _finish(
    requirements: Sequence[PolicyRequirement],
    outcomes: Sequence[RouteProbeOutcome],
    prefer_networks: Sequence[str],
    health: HealthIndex,
    now_epoch_ms: int,
    context: Tx402ErrorContext,
) -> RoutePlan:
    """Applies steps 16 through 20 once every probe has answered."""
    candidates = order_route_candidates(
        [
            _candidate_from_outcome(requirement, outcome, health, now_epoch_ms)
            for requirement, outcome in zip(requirements, outcomes, strict=True)
        ],
        prefer_networks,
    )

    selected = next((candidate for candidate in candidates if candidate.viable), None)
    if selected is not None:
        index = next(
            position
            for position, requirement in enumerate(requirements)
            if requirement.requirement["index"] == selected.requirement_index
        )
        route = outcomes[index].route
        if route is None:  # pragma: no cover - a viable candidate always carries a route
            raise RuntimeError("Selected candidate has no route")
        return RoutePlan(candidates, selected, requirements[index], route)

    # Step 20, in three cases that must not be conflated.
    if all(outcome.kind == "rejected" for outcome in outcomes):
        raise UnsupportedSchemeError(
            "No offered network has a configured signer and chain adapter",
            context=context,
            details={
                "offeredSchemes": list(
                    dict.fromkeys(item.requirement["scheme"] for item in requirements)
                ),
                "offeredNetworks": list(
                    dict.fromkeys(item.requirement["network"] for item in requirements)
                ),
            },
        )

    # Reported in the merchant's own requirement order rather than in rank order: a deficit
    # report answers "what was offered and what was short", and ranking it by measured
    # health would make the same wallet and challenge produce a different-looking error.
    deficits = [
        {
            "network": candidate.network,
            "assetId": candidate.asset_id,
            "required": candidate.amount_atomic,
            "available": candidate.balance_atomic,
        }
        for candidate in sorted(
            (item for item in candidates if item.balance_atomic is not None),
            key=lambda item: item.requirement_index,
        )
    ]

    if not deficits:
        # Every attempt failed before a balance was observed. Reporting insufficient
        # liquidity here would blame the caller's funds for what is an unreachable RPC.
        failure = next((outcome for outcome in outcomes if outcome.kind == "failed"), None)
        if failure is not None and failure.error is not None:
            raise failure.error

    raise InsufficientLiquidityError(
        "No offered route has sufficient balance",
        context=context,
        details={"deficits": deficits},
    )


def plan_routes(
    *,
    requirements: Sequence[PolicyRequirement],
    prefer_networks: Sequence[str],
    health: HealthIndex,
    now_epoch_ms: int,
    context: Tx402ErrorContext,
    probe: Callable[[PolicyRequirement, BalanceProbeCache], RouteProbeOutcome],
) -> RoutePlan:
    """Runs every probe concurrently, then applies steps 16 through 20.

    The probes are raced together rather than run in requirement order, and every one of
    them completes before anything is ordered — a "first viable candidate wins" shortcut
    would make the selection depend on which RPC answered first, which is precisely what
    step 19 forbids.
    """
    balances = BalanceProbeCache()

    def guarded(requirement: PolicyRequirement) -> RouteProbeOutcome:
        try:
            return probe(requirement, balances)
        except BaseException as error:
            return RouteProbeOutcome(
                kind="failed", reason="balance-unavailable", error=error, fatal=True
            )

    if len(requirements) == 1:
        outcomes = [guarded(requirements[0])]
    else:
        with ThreadPoolExecutor(max_workers=len(requirements)) as pool:
            outcomes = list(pool.map(guarded, requirements))
    return _finish(requirements, outcomes, prefer_networks, health, now_epoch_ms, context)


async def plan_routes_async(
    *,
    requirements: Sequence[PolicyRequirement],
    prefer_networks: Sequence[str],
    health: HealthIndex,
    now_epoch_ms: int,
    context: Tx402ErrorContext,
    probe: Callable[[PolicyRequirement, BalanceProbeCache], Awaitable[RouteProbeOutcome]],
) -> RoutePlan:
    """Asynchronous counterpart to :func:`plan_routes`, with identical ordering."""
    balances = BalanceProbeCache()

    async def guarded(requirement: PolicyRequirement) -> RouteProbeOutcome:
        try:
            return await probe(requirement, balances)
        except BaseException as error:
            return RouteProbeOutcome(
                kind="failed", reason="balance-unavailable", error=error, fatal=True
            )

    outcomes = list(
        await asyncio.gather(*(guarded(requirement) for requirement in requirements))
    )
    return _finish(requirements, outcomes, prefer_networks, health, now_epoch_ms, context)
