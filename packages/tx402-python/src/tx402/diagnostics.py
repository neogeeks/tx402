"""Structured, redaction-safe diagnostics (SPEC §10).

Mirrors the ``Tx402Logger`` surface in ``packages/tx402/src/core/client.ts``. Per ADR-005
TypeScript is the reference, so the event names and every field name here are copied from
it rather than re-derived — a caller who ships one log pipeline for both SDKs must be able
to parse either stream with the same code.

**Redaction is by construction, not by filtering.** There is deliberately no scrubber that
inspects outgoing events for things that look secret. A denylist is the wrong shape for
SEC-003: it fails open, so the day a new field carries key material the logger emits it and
the test suite stays green. Instead the call sites assemble each event from a fixed set of
public identifiers, counts, hashes, and atomic amounts, and nothing else is ever in scope
to leak. ``test_diagnostics.py`` seeds a real secret into every input the request path
touches and asserts it appears in no event — which tests the property that matters rather
than the presence of a filter.

The module is named ``diagnostics`` rather than ``logging`` on purpose: a package-local
``tx402/logging.py`` is a well-known way to shadow the standard library for anything that
later does a non-absolute import, and the failure appears far from the cause.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from types import MappingProxyType
from typing import Final, Literal, Protocol, runtime_checkable

#: The four levels SPEC §10 requires. Ordered least to most severe.
LogLevel = Literal["debug", "info", "warn", "error"]

#: Every event name the request path emits, in roughly the order a successful paid call
#: produces them. Exported so a caller can exhaustively switch without string literals, and
#: so the parity test can assert the two SDKs emit the same set.
EVENT_NAMES: Final[tuple[str, ...]] = (
    "request.started",
    "payment.required",
    "policy.checked",
    "route.planned",
    "budget.reserved",
    "sign.started",
    "sign.completed",
    "request.retried",
    "payment.completed",
    "request.failed",
)


@runtime_checkable
class Tx402Logger(Protocol):
    """Sink for structured diagnostics.

    Each method takes one immutable mapping. Implementations must not mutate it and must
    not assume any particular key is present: SPEC §10 fixes a *minimum* field set per
    event, and later versions may add fields.
    """

    def debug(self, event: Mapping[str, object]) -> None: ...

    def info(self, event: Mapping[str, object]) -> None: ...

    def warn(self, event: Mapping[str, object]) -> None: ...

    def error(self, event: Mapping[str, object]) -> None: ...


class NoopLogger:
    """The default sink. Discards everything.

    SPEC §10 forbids console output from library code, so the default cannot be "print" —
    a library that logs to stderr by default corrupts the stdout/stderr contract the CLI
    depends on (SPEC §11).
    """

    __slots__ = ()

    def debug(self, event: Mapping[str, object]) -> None:
        """Discard."""

    def info(self, event: Mapping[str, object]) -> None:
        """Discard."""

    def warn(self, event: Mapping[str, object]) -> None:
        """Discard."""

    def error(self, event: Mapping[str, object]) -> None:
        """Discard."""


#: Shared immutable default, so constructing a client allocates nothing for diagnostics.
NOOP_LOGGER: Final[Tx402Logger] = NoopLogger()


def emit(logger: Tx402Logger, level: LogLevel, event: Mapping[str, object]) -> None:
    """Deliver one event, absorbing any failure in the caller's logger.

    Application diagnostics must never turn a successful HTTP operation into a failed one.
    A logger that raises — a full disk, a closed socket, a serialiser that chokes on a
    large integer — would otherwise fail a payment that already settled, which is the worst
    possible outcome for an observability feature.

    ``BaseException`` is deliberately *not* caught: ``KeyboardInterrupt`` and
    ``SystemExit`` are not logger failures and must keep propagating.
    """
    with suppress(Exception):
        getattr(logger, level)(MappingProxyType(dict(event)))


def settlement_id_hash(settlement_id: str) -> str:
    """Hash a merchant settlement identifier for logging.

    The raw identifier is a merchant-side correlation handle. It is hashed rather than
    logged so a diagnostic stream cannot be joined against a merchant's ledger by anyone
    who merely reads logs, while still letting the *operator* confirm two records refer to
    the same settlement. Same construction as the TypeScript reference, so the two SDKs
    produce identical hashes for the same input.
    """
    return f"sha256:{hashlib.sha256(settlement_id.encode('utf-8')).hexdigest()}"


#: Monotonic millisecond source for durations. SPEC §10 requires a monotonic clock, because
#: a wall clock can step backwards over an NTP correction and yield a negative duration.
Monotonic = Callable[[], float]


def monotonic_ms() -> float:
    """Default monotonic source, in milliseconds."""
    return time.monotonic() * 1000.0


def elapsed_ms(monotonic: Monotonic, started_at: float) -> float:
    """Milliseconds since ``started_at``, floored at zero.

    The floor mirrors the TypeScript reference's ``Math.max(0, ...)``. It is not defensive
    padding: an injected test clock is free to return anything, and a negative duration in
    a log stream is far more confusing than a zero.
    """
    return max(0.0, monotonic() - started_at)
