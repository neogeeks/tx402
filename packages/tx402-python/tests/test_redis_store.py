"""``RedisSpendStore`` / ``AsyncRedisSpendStore`` against a LIVE Redis (SPEC §12.2/§12.4).

Skipped unless ``TX402_TEST_REDIS_URL`` is set (mirrors ``tools/durable-check`` and the TS
``redis-store`` suite), so a no-Redis checkout still passes; the ``durable-store`` CI job
and the local instance set it.

Both advertised Python arms run the whole contract:

- **sync** — ``RedisSpendStore`` over ``redis.Redis`` directly.
- **async** — ``AsyncRedisSpendStore`` over ``redis.asyncio.Redis``, awaited on a persistent
  background loop and presented to the sync contract runner through :class:`_AsyncBridge`.
  Every call is a real ``await`` of the async store; ``run_coroutine_threadsafe`` lets the
  ThreadPoolExecutor-based atomicity check drive true concurrency onto the one loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Coroutine, Iterator
from typing import Any, TypeVar, cast

import pytest
import redis
import redis.asyncio
from redis.asyncio.cluster import RedisCluster as AsyncRedisCluster
from redis.cluster import ClusterNode, RedisCluster

from tx402.errors import ConfigurationError
from tx402.ledger import (
    BudgetLimits,
    BudgetState,
    ReservationRef,
    ReserveSpendResult,
    SpendEntry,
    SpendReservation,
    StoreCapabilities,
)
from tx402.spend_store_contract import check_durable_spend_store, check_spend_store
from tx402.stores.redis import AsyncRedisSpendStore, RedisSpendStore

_URL = os.environ.get("TX402_TEST_REDIS_URL")
_SHARED_NS = "tx402-durable-py"
_CLUSTER = [
    seed.strip()
    for seed in (os.environ.get("TX402_TEST_REDIS_CLUSTER") or "").split(",")
    if seed.strip()
]
_RESTART_ENABLED = os.environ.get("TX402_TEST_REDIS_RESTART") == "1"

_ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
_FINGERPRINT = "sha256:" + "0" * 64
_NOW = 1_800_000_000_000

pytestmark = pytest.mark.skipif(_URL is None, reason="TX402_TEST_REDIS_URL is not set")

_T = TypeVar("_T")


def _cmd(client: redis.Redis, *args: str) -> Any:
    """Run a raw command (redis-py's ``execute_command`` is untyped)."""
    return client.execute_command(*args)  # type: ignore[no-untyped-call]


class _AsyncBridge:
    """Present an ``AsyncRedisSpendStore`` as a sync ``SpendStore`` + ``SpendStoreAdmin``.

    Each method blocks on the coroutine's result via ``run_coroutine_threadsafe`` against a
    persistent background loop, so the async store's real ``await`` paths run under the sync
    contract runner — including from the atomicity check's worker threads.
    """

    kind = "redis"

    def __init__(
        self, loop: asyncio.AbstractEventLoop, store: AsyncRedisSpendStore
    ) -> None:
        self._loop = loop
        self._store = store
        self.capabilities: StoreCapabilities = store.capabilities

    def _call(self, coro: Coroutine[Any, Any, _T]) -> _T:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def reserve(
        self,
        *,
        reservation_id: str,
        request_id: str,
        policy_scope: str,
        request_fingerprint: str,
        asset_id: str,
        amount_atomic: str,
        max_per_hour_atomic: str,
        max_total_atomic: str | None = None,
        recipient_network: str | None = None,
        recipient_canonical: str | None = None,
        recipient_enforcement: str | None = None,
        now_epoch_ms: int,
    ) -> ReserveSpendResult:
        return self._call(
            self._store.reserve(
                reservation_id=reservation_id,
                request_id=request_id,
                policy_scope=policy_scope,
                request_fingerprint=request_fingerprint,
                asset_id=asset_id,
                amount_atomic=amount_atomic,
                max_per_hour_atomic=max_per_hour_atomic,
                max_total_atomic=max_total_atomic,
                recipient_network=recipient_network,
                recipient_canonical=recipient_canonical,
                recipient_enforcement=recipient_enforcement,
                now_epoch_ms=now_epoch_ms,
            )
        )

    def commit(
        self,
        *,
        ref: ReservationRef,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        return self._call(
            self._store.commit(
                ref=ref,
                committed_at_epoch_ms=committed_at_epoch_ms,
                settlement_id=settlement_id,
            )
        )

    def release(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return self._call(self._store.release(ref=ref, now_epoch_ms=now_epoch_ms))

    def expose(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return self._call(self._store.expose(ref=ref, now_epoch_ms=now_epoch_ms))

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        return self._call(
            self._store.get_budget_state(
                policy_scope=policy_scope, asset_id=asset_id, now_epoch_ms=now_epoch_ms
            )
        )

    def list_exposed(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> tuple[SpendReservation, ...]:
        return self._call(
            self._store.list_exposed(
                policy_scope=policy_scope, asset_id=asset_id, now_epoch_ms=now_epoch_ms
            )
        )

    def is_frozen(self, *, scope: str) -> bool:
        return self._call(self._store.is_frozen(scope=scope))

    def get_recipient_pins(self, scope: str, network: str) -> tuple[str, ...]:
        return self._call(self._store.get_recipient_pins(scope, network))

    def warn_if_persistence_disabled(self) -> str | None:
        return self._call(self._store.warn_if_persistence_disabled())

    def freeze(self, scope: str, now_epoch_ms: int) -> None:
        self._call(self._store.freeze(scope, now_epoch_ms))

    def unfreeze(self, scope: str, now_epoch_ms: int) -> None:
        self._call(self._store.unfreeze(scope, now_epoch_ms))

    def set_recipient_pins(
        self, scope: str, network: str, recipients: tuple[str, ...], now_epoch_ms: int
    ) -> None:
        self._call(self._store.set_recipient_pins(scope, network, recipients, now_epoch_ms))

    def set_budget_limits(
        self, scope: str, asset_id: str, limits: BudgetLimits, now_epoch_ms: int
    ) -> None:
        self._call(self._store.set_budget_limits(scope, asset_id, limits, now_epoch_ms))

    def get_budget_limits(self, scope: str, asset_id: str) -> BudgetLimits:
        return self._call(self._store.get_budget_limits(scope, asset_id))

    def set_recipient_assertion_required(
        self, scope: str, required: bool, now_epoch_ms: int
    ) -> None:
        self._call(
            self._store.set_recipient_assertion_required(scope, required, now_epoch_ms)
        )

    def set_tofu_enabled(self, scope: str, enabled: bool, now_epoch_ms: int) -> None:
        self._call(self._store.set_tofu_enabled(scope, enabled, now_epoch_ms))

    def resolve_exposed(self, ref: ReservationRef, outcome: Any, now_epoch_ms: int) -> None:
        self._call(self._store.resolve_exposed(ref, outcome, now_epoch_ms))

    def reset_cumulative(self, scope: str, asset_id: str, now_epoch_ms: int) -> None:
        self._call(self._store.reset_cumulative(scope, asset_id, now_epoch_ms))

    def set_backend_clock(self, now_epoch_ms: int) -> None:
        self._call(self._store.set_backend_clock(now_epoch_ms))

    def reset(self) -> None:
        self._call(self._store.reset())


@pytest.fixture
def sync_client() -> Iterator[redis.Redis]:
    assert _URL is not None
    client = redis.Redis.from_url(_URL, decode_responses=True)
    RedisSpendStore(client, namespace=_SHARED_NS).reset()
    # Pre-clean the single-plane contract namespaces so a re-run against a persistent DB is
    # clean (each factory reuses `contract-sync-<n>`, and the pinned clock keeps its
    # records from expiring). CI's DB is already fresh, so this is a no-op there.
    for index in range(1, 17):
        RedisSpendStore(client, namespace=f"contract-sync-{index}").reset()
    yield client
    client.close()


@pytest.fixture
def async_env() -> Iterator[tuple[asyncio.AbstractEventLoop, Callable[..., _AsyncBridge]]]:
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    assert _URL is not None
    client = redis.asyncio.Redis.from_url(_URL, decode_responses=True)

    def make(**kwargs: Any) -> _AsyncBridge:
        return _AsyncBridge(loop, AsyncRedisSpendStore(client, **kwargs))

    # Clean shared namespace (and the reused single-plane namespaces) before the arms run.
    async def _clean() -> None:
        await AsyncRedisSpendStore(client, namespace=_SHARED_NS).reset()
        for index in range(1, 17):
            await AsyncRedisSpendStore(client, namespace=f"contract-async-{index}").reset()

    asyncio.run_coroutine_threadsafe(_clean(), loop).result()
    try:
        yield loop, make
    finally:
        asyncio.run_coroutine_threadsafe(client.aclose(), loop).result()
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5)
        loop.close()


def test_sync_single_plane_contract(sync_client: redis.Redis) -> None:
    counter = {"n": 0}

    def make() -> RedisSpendStore:
        counter["n"] += 1
        return RedisSpendStore(
            sync_client, namespace=f"contract-sync-{counter['n']}", test_clock=True
        )

    check_spend_store(make)


def test_sync_durable_harness(sync_client: redis.Redis) -> None:
    def control(admin: bool) -> RedisSpendStore:
        return RedisSpendStore(
            sync_client, namespace=_SHARED_NS, admin=admin, test_clock=True
        )

    check_durable_spend_store(
        connect_data=lambda: control(False),
        connect_admin=lambda: control(True),
        connect_admin_with_data_credential=lambda: control(False),
        reset=lambda: control(False).reset(),
        set_backend_clock=lambda ms: control(False).set_backend_clock(ms),
    )


def test_async_single_plane_contract(
    async_env: tuple[asyncio.AbstractEventLoop, Callable[..., _AsyncBridge]],
) -> None:
    _loop, make = async_env
    counter = {"n": 0}

    def factory() -> _AsyncBridge:
        counter["n"] += 1
        return make(namespace=f"contract-async-{counter['n']}", test_clock=True)

    check_spend_store(factory)


def test_async_durable_harness(
    async_env: tuple[asyncio.AbstractEventLoop, Callable[..., _AsyncBridge]],
) -> None:
    _loop, make = async_env

    def control(admin: bool) -> _AsyncBridge:
        return make(namespace=_SHARED_NS, admin=admin, test_clock=True)

    check_durable_spend_store(
        connect_data=lambda: control(False),
        connect_admin=lambda: control(True),
        connect_admin_with_data_credential=lambda: control(False),
        reset=lambda: control(False).reset(),
        set_backend_clock=lambda ms: control(False).set_backend_clock(ms),
    )


# ── persistence-disabled warning (SPEC §12.2) ────────────────────────────


def test_persistence_warning_sync(sync_client: redis.Redis) -> None:
    store = RedisSpendStore(sync_client, namespace="tx402-persist-py")
    assert store.warn_if_persistence_disabled() is None
    sync_client.config_set("appendonly", "no")
    try:
        warning = store.warn_if_persistence_disabled()
        assert warning is not None
        assert "persistence is disabled" in warning
        sync_client.config_set("appendonly", "yes")
        assert store.warn_if_persistence_disabled() is None
    finally:
        sync_client.config_set("appendonly", "yes")


def test_persistence_warning_async(
    async_env: tuple[asyncio.AbstractEventLoop, Callable[..., _AsyncBridge]],
    sync_client: redis.Redis,
) -> None:
    _loop, make = async_env
    bridge = make(namespace="tx402-persist-apy")
    assert bridge.warn_if_persistence_disabled() is None
    sync_client.config_set("appendonly", "no")
    try:
        warning = bridge.warn_if_persistence_disabled()
        assert warning is not None
        assert "persistence is disabled" in warning
    finally:
        sync_client.config_set("appendonly", "yes")


# ── raw Redis ACL data/admin-state separation (SPEC §9.1/§12.2) ───────────
#
# See the TypeScript twin for the full rationale. EVAL/EVALSHA (not FUNCTION — O14) means
# the data user needs +eval; admin-STATE integrity is a KEY-PATTERN ACL that holds even
# under +eval because each redis.call inside a script is ACL-checked. The pins key is the
# one honest gap (data-writable via the in-reserve TOFU claim); the durable boundary is the
# gateway (§9.1, S9). Patterns use the CONCRETE scope (a `{ns:*}` wildcard-inside-braces
# mis-matches on some Redis builds); ACL DRYRUN verifies the split.


def test_acl_data_admin_separation(sync_client: redis.Redis) -> None:
    assert _URL is not None
    ns = "tx402-acl-py"
    scope = "merchant.example"
    tag = "{" + ns + ":" + scope + "}"
    root = sync_client
    for user in ("tx402datapy", "tx402adminpy"):
        with contextlib.suppress(redis.exceptions.RedisError):
            _cmd(root, "ACL", "DELUSER", user)
    _cmd(
        root,
        "ACL",
        "SETUSER",
        "tx402datapy",
        "on",
        ">datapass",
        "+@read",
        "+@write",
        "-@dangerous",
        "+eval",
        "+evalsha",
        "+time",
        "+select",
        f"%RW~{tag}",
        f"%RW~{tag}:res:*",
        f"%RW~{tag}:cmt:*",
        f"%RW~{tag}:*:total",
        f"%RW~{tag}:*:exposed",
        f"%RW~{tag}:pins:*",
        f"%R~{tag}:frozen",
        f"%R~{tag}:*:limits",
        f"%R~{tag}:tofu-enabled",
        f"%R~{tag}:recipient-required",
        "%R~{" + ns + "}:global-frozen",
    )
    _cmd(root, "ACL", "SETUSER", "tx402adminpy", "on", ">adminpass", "+@all", "~*", "&*")
    for key in root.keys("{" + ns + "*"):
        root.delete(key)

    def dry(*command: str) -> str:
        return str(_cmd(root, "ACL", "DRYRUN", "tx402datapy", *command))

    # Denied: a data user cannot write the admin-state keys.
    assert dry("SET", f"{tag}:frozen", "1") != "OK"
    assert dry("HSET", f"{tag}:{_ASSET}:limits", "maxPerHourAtomic", "1") != "OK"
    assert dry("SET", f"{tag}:tofu-enabled", "1") != "OK"
    assert dry("SET", f"{tag}:recipient-required", "1") != "OK"
    # Allowed: reads of them, writes of the data keys, and the honest pins-write gap.
    assert dry("GET", f"{tag}:frozen") == "OK"
    assert dry("HSET", f"{tag}:res:{_ASSET}:id", "state", "reserved") == "OK"
    assert dry("HSET", f"{tag}:pins:eip155:8453", "recipients", "0x0") == "OK"

    data_client = redis.Redis.from_url(
        _URL, username="tx402datapy", password="datapass", decode_responses=True
    )
    admin_client = redis.Redis.from_url(
        _URL, username="tx402adminpy", password="adminpass", decode_responses=True
    )
    try:
        data = RedisSpendStore(data_client, namespace=ns, admin=False)
        admin = RedisSpendStore(admin_client, namespace=ns, admin=True)
        # The full EVAL data path works under the restricted credential.
        reserved = data.reserve(
            reservation_id="acl-1",
            request_id="acl-1",
            policy_scope=scope,
            request_fingerprint=_FINGERPRINT,
            asset_id=_ASSET,
            amount_atomic="7",
            max_per_hour_atomic="100",
            now_epoch_ms=_NOW,
        )
        assert reserved.reservation.state == "reserved"
        entry = data.commit(
            ref=ReservationRef("acl-1", scope, _ASSET), committed_at_epoch_ms=_NOW
        )
        assert entry.amount_atomic == "7"
        # +eval can't write admin state for the data user (the inner call is ACL-checked).
        # Assert the property: rejected + key stays absent, not the exact error wording.
        crafted_rejected = False
        try:
            data_client.eval("return redis.call('SET', KEYS[1], '1')", 1, f"{tag}:frozen")
        except redis.exceptions.RedisError:
            crafted_rejected = True
        assert crafted_rejected
        assert root.exists(f"{tag}:frozen") == 0
        # The app-level split still holds: the data store refuses admin ops before Redis.
        with pytest.raises(ConfigurationError) as excinfo:
            data.freeze(scope, _NOW)
        assert excinfo.value.details.get("reason") == "admin-credential-required"
        # The admin credential performs admin ops.
        admin.freeze(scope, _NOW)
        assert data.is_frozen(scope=scope) is True
        admin.unfreeze(scope, _NOW)
    finally:
        data_client.close()
        admin_client.close()
        for user in ("tx402datapy", "tx402adminpy"):
            with contextlib.suppress(redis.exceptions.RedisError):
                _cmd(root, "ACL", "DELUSER", user)
        for key in root.keys("{" + ns + "*"):
            root.delete(key)


# ── Redis Cluster, atomicGlobalFreeze:false (SPEC §5.2/§12.2) ─────────────


@pytest.mark.skipif(not _CLUSTER, reason="TX402_TEST_REDIS_CLUSTER is not set")
def test_sync_cluster_durable_harness() -> None:
    host, port = _CLUSTER[0].split(":")
    node = ClusterNode(host, int(port))  # type: ignore[no-untyped-call]
    cluster = RedisCluster(startup_nodes=[node], decode_responses=True)
    # The adapter is duck-typed on the Redis command surface; RedisCluster satisfies it.
    client = cast("redis.Redis", cluster)
    ns = "tx402-cluster-py"

    def store(admin: bool) -> RedisSpendStore:
        return RedisSpendStore(
            client, namespace=ns, admin=admin, atomic_global_freeze=False, test_clock=True
        )

    def flush() -> None:
        cluster.flushall(target_nodes=RedisCluster.PRIMARIES)

    try:
        # The whole durable harness single-slot; the incapable global-freeze arm runs here.
        check_durable_spend_store(
            connect_data=lambda: store(False),
            connect_admin=lambda: store(True),
            connect_admin_with_data_credential=lambda: store(False),
            reset=flush,
            set_backend_clock=lambda ms: store(False).set_backend_clock(ms),
        )
    finally:
        cluster.close()


@pytest.mark.skipif(not _CLUSTER, reason="TX402_TEST_REDIS_CLUSTER is not set")
def test_async_cluster_focused() -> None:
    """Async store on a Cluster: single-slot reserve/commit + false-cap freeze."""
    host, port = _CLUSTER[0].split(":")
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()

    def call(coro: Coroutine[Any, Any, _T]) -> _T:
        return asyncio.run_coroutine_threadsafe(coro, loop).result()

    cluster = AsyncRedisCluster(host=host, port=int(port), decode_responses=True)
    # The adapter is duck-typed on the async Redis surface; RedisCluster satisfies it.
    client = cast("redis.asyncio.Redis", cluster)
    ns = "tx402-cluster-apy"
    data = AsyncRedisSpendStore(
        client, namespace=ns, admin=False, atomic_global_freeze=False, test_clock=True
    )
    admin = AsyncRedisSpendStore(
        client, namespace=ns, admin=True, atomic_global_freeze=False, test_clock=True
    )
    try:
        call(
            cast(
                "Coroutine[Any, Any, Any]",
                cluster.flushall(target_nodes=AsyncRedisCluster.PRIMARIES),
            )
        )
        call(admin.set_backend_clock(_NOW))
        reserved = call(
            data.reserve(
                reservation_id="ac-1",
                request_id="ac-1",
                policy_scope="merchant.example",
                request_fingerprint=_FINGERPRINT,
                asset_id=_ASSET,
                amount_atomic="5",
                max_per_hour_atomic="100",
                now_epoch_ms=_NOW,
            )
        )
        assert reserved.reservation.state == "reserved"
        entry = call(
            data.commit(
                ref=ReservationRef("ac-1", "merchant.example", _ASSET),
                committed_at_epoch_ms=_NOW,
            )
        )
        assert entry.amount_atomic == "5"
        state = call(
            data.get_budget_state(
                policy_scope="merchant.example", asset_id=_ASSET, now_epoch_ms=_NOW
            )
        )
        assert state.committed_atomic == "5"
        with pytest.raises(ConfigurationError) as excinfo:
            call(admin.freeze("*", _NOW))
        assert excinfo.value.details.get("reason") == "global-freeze-unsupported"
    finally:
        call(cluster.aclose())
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5)
        loop.close()


# ── AOF restart durability (SPEC §12.4) ───────────────────────────────────

_RESTART_PORT = 6398


def _raw_ping(port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as conn:
            conn.sendall(b"PING\r\n")
            return conn.recv(64).startswith(b"+PONG")
    except OSError:
        return False


def _wait_for(predicate: Callable[[], bool], tries: int = 60) -> bool:
    for _attempt in range(tries):
        if predicate():
            return True
        time.sleep(0.25)
    return False


class _DedicatedRedis:
    def __init__(self, port: int) -> None:
        self.port = port
        self._dir = tempfile.mkdtemp(prefix="tx402-restart-py-")

    def _launch(self) -> None:
        subprocess.run(
            [
                "redis-server",
                "--port",
                str(self.port),
                "--dir",
                self._dir,
                "--appendonly",
                "yes",
                "--save",
                "",
                "--daemonize",
                "yes",
                "--pidfile",
                os.path.join(self._dir, "redis.pid"),
            ],
            check=False,
        )

    def start(self) -> bool:
        self._launch()
        return _wait_for(lambda: _raw_ping(self.port))

    def restart(self) -> None:
        subprocess.run(
            ["redis-cli", "-p", str(self.port), "shutdown", "nosave"], check=False
        )
        _wait_for(lambda: not _raw_ping(self.port))
        self._launch()
        _wait_for(lambda: _raw_ping(self.port))

    def stop(self) -> None:
        subprocess.run(
            ["redis-cli", "-p", str(self.port), "shutdown", "nosave"], check=False
        )
        _wait_for(lambda: not _raw_ping(self.port))
        shutil.rmtree(self._dir, ignore_errors=True)


@pytest.mark.skipif(
    not _RESTART_ENABLED or shutil.which("redis-server") is None,
    reason="TX402_TEST_REDIS_RESTART!=1 or redis-server unavailable",
)
def test_sync_restart_durability() -> None:
    server = _DedicatedRedis(_RESTART_PORT)
    assert server.start(), "dedicated Redis did not come up for the restart arm"
    ns = "tx402-restart-py"
    client = redis.Redis(host="127.0.0.1", port=_RESTART_PORT, decode_responses=True)
    try:
        RedisSpendStore(client, namespace=ns).reset()

        def store(admin: bool) -> RedisSpendStore:
            return RedisSpendStore(client, namespace=ns, admin=admin, test_clock=True)

        check_durable_spend_store(
            connect_data=lambda: store(False),
            connect_admin=lambda: store(True),
            connect_admin_with_data_credential=lambda: store(False),
            reset=lambda: store(False).reset(),
            set_backend_clock=lambda ms: store(False).set_backend_clock(ms),
            restart=server.restart,
        )
    finally:
        client.close()
        server.stop()


# ── O26: set_budget_limits atomicity — a failed replacement must not lose the prior cap ──
class _FailLimitsWrite:
    """Wraps a redis client so the next limits WRITE fails. The atom runs as one ``evalsha``
    (``eval`` on NOSCRIPT); the pre-fix code ran ``delete`` then ``hset``. Failing
    ``evalsha``/``eval``/``hset`` fails the write either way — but only the atom keeps the
    cap intact; ``delete``-then-``hset`` already deleted it before ``hset`` raised (O26)."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def evalsha(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("injected: limits write failed")

    def eval(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("injected: limits write failed")

    def hset(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("injected: limits write failed")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def test_o26_set_budget_limits_failure_preserves_prior_cap() -> None:
    assert _URL is not None
    client = redis.Redis.from_url(_URL)
    ns = "tx402-o26-py"
    scope = "o26.example"
    asset = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    now = 1_800_000_000_000
    try:
        admin = RedisSpendStore(client, namespace=ns, admin=True)
        admin.set_budget_limits(scope, asset, BudgetLimits(max_per_hour_atomic="100"), now)
        assert admin.get_budget_limits(scope, asset).max_per_hour_atomic == "100"

        failing = RedisSpendStore(
            cast(redis.Redis, _FailLimitsWrite(client)), namespace=ns, admin=True
        )
        with pytest.raises(RuntimeError):
            failing.set_budget_limits(
                scope, asset, BudgetLimits(max_per_hour_atomic="50"), now
            )

        # The prior cap survived — the replacement is one atom (§4.3, O26).
        assert admin.get_budget_limits(scope, asset).max_per_hour_atomic == "100"
    finally:
        client.close()
