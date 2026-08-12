"""O53 (S14g) / U12 (S14h): a store OUTAGE on the READ path must raise a typed, retryable
TransportError.

A read against a Redis that is DOWN must surface the same typed TransportError (code
TX402_TRANSPORT) that a reserve against that dead store already does, never an untyped
redis.exceptions.ConnectionError (which even embeds the store host:port). This points a
store at a dead port (no live Redis needed, so it always runs) and asserts the
classification for the sync and async stores. U9 covered get_budget_state / list_exposed /
is_frozen; S14i (O53) adds the three sibling reads the S14f fix left unwrapped:
get_recipient_pins, get_recipient_policy, get_budget_limits, and checks O55 (admin gate).
"""

from __future__ import annotations

import asyncio

import pytest
import redis
import redis.asyncio
from redis.asyncio.retry import Retry as AsyncRetry
from redis.backoff import NoBackoff
from redis.retry import Retry

from tx402.errors import ConfigurationError, TransportError, is_tx402_error
from tx402.stores.redis import AsyncRedisSpendStore, RedisSpendStore

_NOW = 1_800_000_000_000
_SCOPE = "outage.example"
_NETWORK = "eip155:8453"
_ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
_PORT = 6399  # nothing listens here


def _assert_typed_transport(error: BaseException) -> None:
    assert isinstance(error, TransportError), (
        f"expected TransportError, got {type(error)!r}"
    )
    assert is_tx402_error(error)
    assert error.code == "TX402_TRANSPORT"
    assert error.retryable is True
    assert error.details.get("causeCategory") == "spend-store-unavailable"
    # Redaction (SEC-003): the coarse category, never the DSN or the redis internal message.
    message = str(error)
    assert "6399" not in message
    assert "Connection refused" not in message


def _sync_client() -> redis.Redis:
    # Fail fast: no reconnection retries, short connect timeout.
    return redis.Redis(
        host="127.0.0.1",
        port=_PORT,
        socket_connect_timeout=0.3,
        retry=Retry(NoBackoff(), 0),
    )


def _sync_store() -> RedisSpendStore:
    return RedisSpendStore(_sync_client())


def _sync_admin_store() -> RedisSpendStore:
    # get_budget_limits is admin-gated (O55), so its outage test needs an admin store.
    return RedisSpendStore(_sync_client(), admin=True)


def test_get_budget_state_outage_is_typed_transport() -> None:
    store = _sync_store()
    try:
        store.get_budget_state(policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW)
        raise AssertionError("expected the dead store to raise")
    except TransportError as error:
        _assert_typed_transport(error)


def test_list_exposed_outage_is_typed_transport() -> None:
    store = _sync_store()
    try:
        store.list_exposed(policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW)
        raise AssertionError("expected the dead store to raise")
    except TransportError as error:
        _assert_typed_transport(error)


def test_is_frozen_outage_is_typed_transport() -> None:
    store = _sync_store()
    try:
        store.is_frozen(scope=_SCOPE)
        raise AssertionError("expected the dead store to raise")
    except TransportError as error:
        _assert_typed_transport(error)


# ── O53: the three sibling reads the S14f U9 fix left unwrapped ──────────────────


def test_get_recipient_pins_outage_is_typed_transport() -> None:
    store = _sync_store()
    try:
        store.get_recipient_pins(_SCOPE, _NETWORK)
        raise AssertionError("expected the dead store to raise")
    except TransportError as error:
        _assert_typed_transport(error)


def test_get_recipient_policy_outage_is_typed_transport() -> None:
    store = _sync_store()
    try:
        store.get_recipient_policy(_SCOPE)
        raise AssertionError("expected the dead store to raise")
    except TransportError as error:
        _assert_typed_transport(error)


def test_get_budget_limits_outage_is_typed_transport() -> None:
    store = _sync_admin_store()  # get_budget_limits is admin-gated (O55)
    try:
        store.get_budget_limits(_SCOPE, _ASSET)
        raise AssertionError("expected the dead store to raise")
    except TransportError as error:
        _assert_typed_transport(error)


def test_get_budget_limits_on_a_data_store_requires_admin() -> None:
    # O55: _require_admin fires before any Redis command, so this needs no live server and
    # never reaches the (dead) connection -- a typed ConfigurationError, not a transport
    # outage. Matches the DO (_verify_admin) and the gateway (403s a data token).
    store = _sync_store()  # admin=False
    with pytest.raises(ConfigurationError) as excinfo:
        store.get_budget_limits(_SCOPE, _ASSET)
    assert excinfo.value.details.get("reason") == "admin-credential-required"


def _async_client() -> redis.asyncio.Redis:
    return redis.asyncio.Redis(
        host="127.0.0.1",
        port=_PORT,
        socket_connect_timeout=0.3,
        retry=AsyncRetry(NoBackoff(), 0),
    )


def test_async_get_budget_state_outage_is_typed_transport() -> None:
    async def run() -> None:
        client = _async_client()
        store = AsyncRedisSpendStore(client)
        try:
            await store.get_budget_state(
                policy_scope=_SCOPE, asset_id=_ASSET, now_epoch_ms=_NOW
            )
            raise AssertionError("expected the dead store to raise")
        except TransportError as error:
            _assert_typed_transport(error)
        finally:
            await client.aclose()

    asyncio.run(run())


def test_async_get_recipient_pins_outage_is_typed_transport() -> None:
    async def run() -> None:
        client = _async_client()
        store = AsyncRedisSpendStore(client)
        try:
            await store.get_recipient_pins(_SCOPE, _NETWORK)
            raise AssertionError("expected the dead store to raise")
        except TransportError as error:
            _assert_typed_transport(error)
        finally:
            await client.aclose()

    asyncio.run(run())


def test_async_get_recipient_policy_outage_is_typed_transport() -> None:
    async def run() -> None:
        client = _async_client()
        store = AsyncRedisSpendStore(client)
        try:
            await store.get_recipient_policy(_SCOPE)
            raise AssertionError("expected the dead store to raise")
        except TransportError as error:
            _assert_typed_transport(error)
        finally:
            await client.aclose()

    asyncio.run(run())


def test_async_get_budget_limits_outage_is_typed_transport() -> None:
    async def run() -> None:
        client = _async_client()
        store = AsyncRedisSpendStore(client, admin=True)  # admin-gated (O55)
        try:
            await store.get_budget_limits(_SCOPE, _ASSET)
            raise AssertionError("expected the dead store to raise")
        except TransportError as error:
            _assert_typed_transport(error)
        finally:
            await client.aclose()

    asyncio.run(run())
