"""Deadlines tx402 enforces in its own control flow.

A deadline may not be entrusted to cancellation propagation. The TypeScript SDK learned
this the hard way at S5 — a composed ``AbortSignal`` was collected before it could fire, and
a rebuilt ``Request`` silently broke the follow chain — and the same class of failure exists
in Python: a transport wrapper that swallows :class:`asyncio.CancelledError`, or a
synchronous client with no cancellation mechanism at all, leaves a hanging merchant hanging
the caller.

So both helpers here *race* the work rather than cancel it. Cancellation is still requested
where the runtime offers it, because it is what tears the socket down, but the timeout is
enforced by tx402 returning control to its caller — which nothing downstream can prevent.

This matters beyond a flaky test: a paid retry to a merchant that accepts the connection and
never answers must raise ``AmbiguousPaymentError``, which is the one outcome SPEC §6.7 most
needs reported. Silence exactly where money may already have moved is the worst failure this
SDK can produce.
"""

from __future__ import annotations

import asyncio
import queue
import threading
from collections.abc import Awaitable, Callable
from contextlib import suppress
from typing import TypeVar

T = TypeVar("T")


def with_deadline(call: Callable[[], T], timeout_ms: int) -> T:
    """Race a synchronous operation on a daemon thread; the SDK owns the deadline.

    The worker thread is deliberately *not* joined on timeout. A synchronous HTTP client
    offers no way to interrupt a blocking socket read, so waiting for it would reproduce
    the hang this exists to prevent. The thread is a daemon and its result is discarded.
    """
    result: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result.put((True, call()))
        except BaseException as error:
            result.put((False, error))

    threading.Thread(target=run, daemon=True).start()
    try:
        succeeded, value = result.get(timeout=timeout_ms / 1_000)
    except queue.Empty as error:
        raise TimeoutError("tx402 operation deadline elapsed") from error
    if succeeded:
        return value  # type: ignore[return-value]
    raise value  # type: ignore[misc]


async def with_deadline_async(awaitable: Awaitable[T], timeout_ms: int) -> T:
    """Race an async operation without relying on its cancellation propagation.

    Cancellation is *requested* on expiry, and a done-callback consumes whatever the task
    eventually produces so a late failure is not reported as "exception never retrieved".
    The timeout itself is enforced by returning here, not by the cancellation landing.
    """
    operation = asyncio.ensure_future(awaitable)
    done, _pending = await asyncio.wait({operation}, timeout=timeout_ms / 1_000)
    if operation not in done:
        operation.cancel()

        def consume_result(completed: asyncio.Future[T]) -> None:
            with suppress(BaseException):
                completed.result()

        operation.add_done_callback(consume_result)
        raise TimeoutError("tx402 operation deadline elapsed")
    return operation.result()
