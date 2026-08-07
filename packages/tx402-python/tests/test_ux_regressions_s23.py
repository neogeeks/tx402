"""Regressions for the third fresh-eyes UX pass (§11.3), open item O84.

Run against ``03f368f`` first and observed to fail there. A regression that passes before
the fix is not evidence.

O84 is one finding with two halves that are **not** the same defect and are not fixed the
same way — the reasoning is ADR-021. This module covers the half that was closed in code:
``timeouts.initialRequestMs`` is a SPEC §4.3 configuration field, and §4.3 is a
language-neutral normative table, so a Python client that offers no spelling for it is a
conformance gap rather than a documentation one. The documentation page opened by asserting
that "every field in it is implemented", which was false for Python and is true again now.

The other half — TypeScript's ``getBudgetState()``/``queryBudgetState()`` split — is
required of TypeScript by SPEC §4.1 and of Python by nothing (§4.2's export table does not
name a budget accessor), so it is documented per language rather than mirrored into an API
no specification asks for. Its regression is a documentation assertion and lives with the
TypeScript suite, which is where the pages are swept.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
import pytest

import tx402
from tx402 import AsyncTx402Client, Tx402Client
from tx402.errors import ConfigurationError, TransportError


def test_timeouts_are_exported_under_a_name_python_can_import() -> None:
    """``from tx402 import Timeouts`` raised ``ImportError`` while the page documented it.

    Python's spelling is flat and per-field rather than a nested object, which is idiomatic
    and is also precisely why silently documenting only the nested TypeScript form left a
    reader constructing something that does not exist. The contract asserted here is that
    both fields are reachable, not that the shape matches TypeScript's.
    """
    for name in ("initial_request_timeout_ms", "payment_retry_timeout_ms"):
        assert name in Tx402Client.__init__.__annotations__, name
        assert name in AsyncTx402Client.__init__.__annotations__, name


def test_initial_request_timeout_defaults_to_the_callers_own() -> None:
    """SPEC §4.3: "SDK does not silently shorten caller timeout."

    Absent by default in both languages. The default is the *behaviour* Python already had;
    what it lacked was any way to ask for a deadline.
    """
    with Tx402Client() as client:
        assert client._transport._core.initial_request_timeout_ms is None


def test_initial_request_timeout_is_validated_at_construction() -> None:
    """A mistake is an error, not a setting that quietly never applies.

    The *rule* mirrors TypeScript exactly — a positive integer or nothing, reported with
    ``reason: "expected-positive-integer"``. The ``configPath`` deliberately does not: this
    assertion originally pinned ``timeouts.initialRequestMs``, and that spelling was
    reversed by the ADR-021 amendment because it named a path Python does not accept. The
    full argument, and the regression holding the rule generally, are in the S25 module.
    """
    for bad in (0, -1, 1.5, "1000"):
        with pytest.raises(ConfigurationError) as caught:
            Tx402Client(initial_request_timeout_ms=bad)  # type: ignore[arg-type]
        assert caught.value.details["configPath"] == "initial_request_timeout_ms"
        assert caught.value.details["reason"] == "expected-positive-integer"


def test_initial_request_timeout_bounds_the_unpaid_request() -> None:
    """The deadline has to actually fire, or it is documentation rather than a feature.

    A merchant that never answers the *initial* request is the case this covers: before
    this, the only bound was whatever httpx timeout the caller had configured, and the
    documented field offered no way to add one.
    """
    started = threading.Event()

    def never_answers(_request: httpx.Request) -> httpx.Response:
        started.set()
        time.sleep(30)  # pragma: no cover - the deadline is expected to win
        raise AssertionError("the deadline should have fired")

    transport = httpx.MockTransport(never_answers)
    began = time.monotonic()
    with (
        Tx402Client(
            transport=transport,
            initial_request_timeout_ms=250,
            allow_insecure_localhost=True,
        ) as client,
        pytest.raises(TransportError) as caught,
    ):
        client.get("http://127.0.0.1:1/resource")

    assert started.is_set()
    # Bounded by the SDK's deadline, not by the 30-second sleep.
    assert time.monotonic() - began < 10
    # Reported as the unpaid phase, which is the whole reason a deadline is safe here:
    # nothing has been signed, so an expiry is a plain transport failure rather than the
    # ambiguity a paid-retry timeout produces.
    assert caught.value.context.phase == "initial"


@pytest.mark.asyncio
async def test_initial_request_timeout_bounds_the_async_unpaid_request() -> None:
    """Parity between the two Python clients — an absent one is its own kind of surprise."""
    import asyncio

    async def never_answers(_request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(30)  # pragma: no cover - the deadline is expected to win
        raise AssertionError("the deadline should have fired")

    transport = httpx.MockTransport(never_answers)
    began = time.monotonic()
    async with AsyncTx402Client(
        transport=transport,
        initial_request_timeout_ms=250,
        allow_insecure_localhost=True,
    ) as client:
        with pytest.raises(TransportError):
            await client.get("http://127.0.0.1:1/resource")

    assert time.monotonic() - began < 10


def test_python_still_offers_exactly_one_budget_accessor() -> None:
    """The deliberate non-change, pinned so it stays deliberate (ADR-021).

    Python's ``get_budget_state`` is the *store query*: it takes a scope and an asset and
    reads the ledger. TypeScript additionally offers a synchronous snapshot of the most
    recent paid request, which SPEC §4.1 requires of it and §4.2 requires of nothing. The
    documentation now says which language has which, rather than showing a Python block
    under a sentence describing two TypeScript calls.
    """
    assert not hasattr(Tx402Client, "query_budget_state")
    assert "Timeouts" not in dir(tx402)

    annotations: dict[str, Any] = Tx402Client.get_budget_state.__annotations__
    assert "policy_scope" in annotations
    assert "asset_id" in annotations
