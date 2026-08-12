"""The async client must not block the event loop on a synchronous store.

`AsyncTx402Client` reuses a synchronous core; a network-backed store called on the loop
would stall every other coroutine on the loop. 0.2.0's decision is that a sync
`SpendStore` is offloaded to a worker thread via `asyncio.to_thread`, so the loop stays
responsive. This is the conformance test the S2 exit criteria names: under an artificially
slow store, a concurrent task keeps making progress.
"""

from __future__ import annotations

import asyncio
import time

from tx402.client import AsyncTx402Client
from tx402.ledger import BudgetState, MemorySpendStore

ASSET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
NOW = 1_785_715_200_000
_STORE_DELAY_S = 0.2
_TICK_S = 0.01


class _SlowSyncStore(MemorySpendStore):
    """A sync store whose budget read blocks the way a network round-trip would."""

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        time.sleep(_STORE_DELAY_S)
        return super().get_budget_state(
            policy_scope=policy_scope, asset_id=asset_id, now_epoch_ms=now_epoch_ms
        )


async def test_async_get_budget_state_does_not_block_the_loop() -> None:
    client = AsyncTx402Client(spend_store=_SlowSyncStore())
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(_TICK_S)
            ticks += 1

    task = asyncio.create_task(ticker())
    try:
        await asyncio.sleep(0)  # let the ticker start
        state = await client.get_budget_state(
            policy_scope="merchant.example", asset_id=ASSET, now_epoch_ms=NOW
        )
    finally:
        task.cancel()
        await client.aclose()

    # The read blocked for ~200 ms; a responsive loop ticks ~20 times in that window. If the
    # sync store had been called on the loop thread, the ticker would not have advanced.
    assert ticks >= 5, f"event loop stalled during the store read (only {ticks} ticks)"
    assert state.committed_atomic == "0"


async def test_async_get_budget_state_is_a_coroutine_named_break() -> None:
    # The 0.1 sync accessor became `async def`: calling it without await
    # returns a coroutine, and only awaiting it produces the snapshot.
    client = AsyncTx402Client(spend_store=MemorySpendStore())
    try:
        pending = client.get_budget_state(
            policy_scope="merchant.example", asset_id=ASSET, now_epoch_ms=NOW
        )
        assert asyncio.iscoroutine(pending)
        state = await pending
        assert state.reserved_atomic == "0"
    finally:
        await client.aclose()
