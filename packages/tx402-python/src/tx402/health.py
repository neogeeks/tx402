"""The unified endpoint health index and circuit breaker (SPEC §6.5, §6.4 step 17).

Port of ``packages/tx402/src/core/health.ts``. **There is exactly one of these per client,
and it is the only circuit in the SDK.** RPC pools hold endpoint lists and failure
classification; they hold no circuit state of their own. Two circuits that disagree about
the same endpoint is a bug that reads as a flake, so the state exists once.

Everything here is *locally observed*. SEC-010 forbids trusting a remote party's claim
about its own health, so nothing an RPC or a merchant says about itself reaches this file.

Two ways a circuit opens, and why
--------------------------------
SPEC §6.5's thresholds — five consecutive failures, or half of at least ten samples — are
about an endpoint that is *unreliable*. SPEC §7.1 and §7.2 describe something else: an
endpoint that answered for the wrong chain. That is not a reliability signal to average
into a window, it is a MUST to stop using that endpoint now, so :meth:`HealthIndex.open`
exists alongside the thresholds and is called only for chain-identity failures.

Determinism
-----------
Route ordering reads :meth:`HealthIndex.score`, and SPEC §6.4 step 19 requires identical
ordering for identical inputs *and health state*. Scores are rounded to four decimal places
with an explicit half-up rule rather than left as raw floats: ``Math.round`` in JavaScript
and Python's banker's-rounding ``round`` disagree at a half, and the two implementations
have to produce the same number rather than merely close ones.
``floor(x * 10000 + 0.5) / 10000`` agrees in both.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass
from typing import Final, Literal

#: SPEC §6.5. Applied to both latency and success rate.
HEALTH_EWMA_ALPHA: Final = 0.2

#: SPEC §6.5: failures are counted over the last 20 observations.
HEALTH_FAILURE_WINDOW: Final = 20

#: SPEC §6.5: five consecutive failures open the circuit.
HEALTH_CONSECUTIVE_FAILURES_TO_OPEN: Final = 5

#: SPEC §6.5: or half the observations, once there are at least ten of them.
HEALTH_MIN_SAMPLES_FOR_RATE: Final = 10
HEALTH_FAILURE_RATE_TO_OPEN: Final = 0.5

#: SPEC §6.5: an open circuit stays open for 30 s, then admits one probe.
HEALTH_OPEN_MS: Final = 30_000

#: SPEC §6.5: health for an endpoint nothing has used for 30 minutes is dropped.
HEALTH_IDLE_RETENTION_MS: Final = 30 * 60_000

#: SPEC §6.5: at most 128 endpoints are indexed, evicted least-recently-used first.
HEALTH_MAX_ENDPOINTS: Final = 128

#: SPEC §6.4 step 17: an endpoint with no observations scores 0.80.
HEALTH_NEW_ENDPOINT_SCORE: Final = 0.8

#: Latency at which the full latency penalty applies.
#:
#: Deliberately the same 600 ms as the per-provider balance budget in SPEC §6.4 step 15: an
#: endpoint that consistently spends its whole budget has earned the maximum penalty, and
#: one that answers instantly earns none. Tying it to a figure SPEC already states avoids
#: inventing a constant that later has to be justified.
HEALTH_LATENCY_REFERENCE_MS: Final = 600

#: The most a slow-but-working endpoint can lose from its score.
HEALTH_LATENCY_PENALTY_MAX: Final = 0.2

CircuitState = Literal["closed", "open", "half-open"]

#: Whether an endpoint may be used right now.
#:
#: ``half-open`` is an *admission*: the caller has been handed the single probe SPEC §6.5
#: allows, and must report the outcome so the probe is released.
CircuitAdmission = Literal["closed", "half-open", "open"]

#: Multipliers applied to a score by circuit state, so an open endpoint sorts far down.
_CIRCUIT_MULTIPLIER: Final[dict[str, float]] = {
    "closed": 1.0,
    "half-open": 0.5,
    "open": 0.1,
}


@dataclass(frozen=True, slots=True)
class EndpointHealth:
    endpoint_id: str
    circuit_state: CircuitState
    health_score: float
    #: EWMA latency in ms, or ``None`` when the endpoint has never answered.
    observed_latency_ms: float | None
    consecutive_failures: int
    sample_count: int


@dataclass(slots=True)
class _Entry:
    #: Last 20 outcomes, oldest first. ``True`` is a success.
    outcomes: list[bool]
    consecutive_failures: int
    latency_ewma_ms: float | None
    success_ewma: float
    #: 0 when the circuit is closed.
    opened_at_epoch_ms: int
    probe_in_flight: bool
    last_used_epoch_ms: int


def _round4(value: float) -> float:
    """Explicit half-up rounding. See the determinism note in the module docstring."""
    return math.floor(value * 10_000 + 0.5) / 10_000


class HealthIndex:
    """Per-endpoint circuit state and health scoring, shared by every RPC pool.

    Endpoint identifiers are ``<caip2>|<host>`` — a host, never a full URL, because an RPC
    URL's path or query may carry a provider API key (SEC-003). Namespacing by network keeps
    a provider that serves several chains from pooling one chain's outage into another's
    score.
    """

    def __init__(self, *, max_endpoints: int = HEALTH_MAX_ENDPOINTS) -> None:
        #: Insertion order is recency order: reads and writes move an entry to the back.
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._max_endpoints = max_endpoints

    @staticmethod
    def endpoint_id(network_id: str, host: str) -> str:
        """Composes the indexing key. Callers pass a host, never a URL with credentials."""
        return f"{network_id}|{host}"

    @property
    def size(self) -> int:
        return len(self._entries)

    def reset(self) -> None:
        """Clears every observation. Never touches the spend ledger (SPEC §4.1)."""
        self._entries.clear()

    def forget(self, endpoint_id: str) -> None:
        """Drops one endpoint's history, used when a pool is reset in isolation."""
        self._entries.pop(endpoint_id, None)

    def state(self, endpoint_id: str, now_epoch_ms: int) -> CircuitState:
        """The circuit state without claiming the half-open probe.

        Use this for ordering and diagnostics; use :meth:`admit` to decide whether to send.
        """
        entry = self._entries.get(endpoint_id)
        if entry is None or entry.opened_at_epoch_ms == 0:
            return "closed"
        return (
            "open"
            if now_epoch_ms - entry.opened_at_epoch_ms < HEALTH_OPEN_MS
            else "half-open"
        )

    def admit(self, endpoint_id: str, now_epoch_ms: int) -> CircuitAdmission:
        """Asks for permission to use an endpoint, claiming the probe when one is free.

        Returns ``"open"`` when the endpoint must not be used — either the 30 s window is
        still running, or the one half-open probe SPEC §6.5 allows is already in flight. A
        caller that receives ``"closed"`` or ``"half-open"`` MUST report the outcome through
        :meth:`record_success` or :meth:`record_failure`, or the probe is never released.
        """
        state = self.state(endpoint_id, now_epoch_ms)
        if state == "closed":
            return "closed"
        entry = self._entries.get(endpoint_id)
        if entry is None:
            return "closed"
        if state == "open" or entry.probe_in_flight:
            return "open"
        entry.probe_in_flight = True
        self._touch(endpoint_id, entry, now_epoch_ms)
        return "half-open"

    def record_success(
        self, endpoint_id: str, latency_ms: float, now_epoch_ms: int
    ) -> None:
        """Records a completed, successful use.

        A success on the far side of an open window is the one probe SPEC §6.5 needs to
        close the circuit, and closing it discards the failure history that opened it —
        otherwise a recovered endpoint would re-open on its next single failure.
        """
        entry = self._ensure(endpoint_id, now_epoch_ms)
        was_open = entry.opened_at_epoch_ms != 0
        entry.probe_in_flight = False
        if was_open:
            entry.opened_at_epoch_ms = 0
            entry.outcomes = []
        entry.consecutive_failures = 0
        self._observe(entry, True)
        latency = max(0.0, float(latency_ms))
        entry.latency_ewma_ms = (
            latency
            if entry.latency_ewma_ms is None
            else HEALTH_EWMA_ALPHA * latency
            + (1 - HEALTH_EWMA_ALPHA) * entry.latency_ewma_ms
        )

    def record_failure(self, endpoint_id: str, now_epoch_ms: int) -> None:
        """Records a completed, failed use, opening the circuit at SPEC §6.5's thresholds.

        A failed half-open probe re-opens immediately: the endpoint had its one chance.
        """
        entry = self._ensure(endpoint_id, now_epoch_ms)
        was_probing = entry.probe_in_flight
        entry.probe_in_flight = False
        entry.consecutive_failures += 1
        self._observe(entry, False)
        if was_probing or self._should_open(entry):
            entry.opened_at_epoch_ms = now_epoch_ms

    def open(self, endpoint_id: str, now_epoch_ms: int) -> None:
        """Opens a circuit immediately, regardless of the failure window.

        Reserved for the chain-identity rules — SPEC §7.1's ``eth_chainId`` mismatch and
        §7.2's genesis-hash mismatch. Those are not reliability observations to be averaged;
        they say the endpoint is serving another chain, and both clauses require moving to
        the next RPC rather than waiting for a threshold.
        """
        entry = self._ensure(endpoint_id, now_epoch_ms)
        entry.probe_in_flight = False
        entry.consecutive_failures += 1
        self._observe(entry, False)
        entry.opened_at_epoch_ms = now_epoch_ms

    def score(self, endpoint_id: str, now_epoch_ms: int) -> float:
        """The SPEC §6.4 step 17 health score in ``[0, 1]``.

        ``EWMA success minus latency penalty``, scaled by circuit state. An endpoint with no
        history scores exactly :data:`HEALTH_NEW_ENDPOINT_SCORE`, which is what step 17
        requires, and it reaches that value by seeding the success EWMA rather than by a
        special case — so one success moves a new endpoint up and one failure moves it down,
        symmetrically.
        """
        entry = self._entries.get(endpoint_id)
        if entry is None:
            return HEALTH_NEW_ENDPOINT_SCORE
        penalty = min(
            HEALTH_LATENCY_PENALTY_MAX,
            ((entry.latency_ewma_ms or 0.0) / HEALTH_LATENCY_REFERENCE_MS)
            * HEALTH_LATENCY_PENALTY_MAX,
        )
        scaled = (entry.success_ewma - penalty) * _CIRCUIT_MULTIPLIER[
            self.state(endpoint_id, now_epoch_ms)
        ]
        return _round4(min(1.0, max(0.0, scaled)))

    def inspect(self, endpoint_id: str, now_epoch_ms: int) -> EndpointHealth:
        """Everything ordering and diagnostics need about one endpoint, in one read."""
        entry = self._entries.get(endpoint_id)
        return EndpointHealth(
            endpoint_id=endpoint_id,
            circuit_state=self.state(endpoint_id, now_epoch_ms),
            health_score=self.score(endpoint_id, now_epoch_ms),
            observed_latency_ms=None if entry is None else entry.latency_ewma_ms,
            consecutive_failures=0 if entry is None else entry.consecutive_failures,
            sample_count=0 if entry is None else len(entry.outcomes),
        )

    def _should_open(self, entry: _Entry) -> bool:
        if entry.consecutive_failures >= HEALTH_CONSECUTIVE_FAILURES_TO_OPEN:
            return True
        samples = len(entry.outcomes)
        if samples < HEALTH_MIN_SAMPLES_FOR_RATE:
            return False
        failures = sum(1 for ok in entry.outcomes if not ok)
        return failures / samples >= HEALTH_FAILURE_RATE_TO_OPEN

    @staticmethod
    def _observe(entry: _Entry, ok: bool) -> None:
        entry.outcomes.append(ok)
        if len(entry.outcomes) > HEALTH_FAILURE_WINDOW:
            entry.outcomes.pop(0)
        entry.success_ewma = (
            HEALTH_EWMA_ALPHA * (1.0 if ok else 0.0)
            + (1 - HEALTH_EWMA_ALPHA) * entry.success_ewma
        )

    def _ensure(self, endpoint_id: str, now_epoch_ms: int) -> _Entry:
        existing = self._entries.get(endpoint_id)
        if existing is not None:
            self._touch(endpoint_id, existing, now_epoch_ms)
            return existing
        entry = _Entry(
            outcomes=[],
            consecutive_failures=0,
            latency_ewma_ms=None,
            success_ewma=HEALTH_NEW_ENDPOINT_SCORE,
            opened_at_epoch_ms=0,
            probe_in_flight=False,
            last_used_epoch_ms=now_epoch_ms,
        )
        self._entries[endpoint_id] = entry
        self._evict(now_epoch_ms)
        return entry

    def _touch(self, endpoint_id: str, entry: _Entry, now_epoch_ms: int) -> None:
        """Moves an entry to the back of the recency order and refreshes its idle clock."""
        entry.last_used_epoch_ms = now_epoch_ms
        self._entries.move_to_end(endpoint_id)

    def _evict(self, now_epoch_ms: int) -> None:
        """Applies the 30-minute idle retention and the 128-entry LRU cap.

        Both walk from the front, which is the least recently used end, so this is bounded
        work on a mapping that is itself bounded — the memory-stability gate in SPEC §12.3
        is met by construction rather than by a periodic sweep.
        """
        for endpoint_id, entry in list(self._entries.items()):
            if now_epoch_ms - entry.last_used_epoch_ms < HEALTH_IDLE_RETENTION_MS:
                break
            del self._entries[endpoint_id]
        while len(self._entries) > self._max_endpoints:
            self._entries.popitem(last=False)
