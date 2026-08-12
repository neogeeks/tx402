"""``check_durable_spend_store`` BEHIND the reference gateway, from Python.

The whole durable harness runs over the two reference gateways, driven by the Python
``HttpGatewaySpendStore`` / ``AsyncHttpGatewaySpendStore`` — proving a gateway-backed store
is byte-identical to a direct one from Python, over BOTH backends:

  - **Node gateway → Redis** (``TX402_TEST_REDIS_URL``): a Node process
    (``serve-redis.mjs``) fronts ``RedisSpendStore``; ``atomicGlobalFreeze`` is ``True``
    (single instance) → the capable arm.
  - **Worker gateway → Durable Object** (miniflare, no Cloudflare account): a local Workers
    runtime (``serve-do.mjs``) fronts ``Tx402SpendStoreDO`` over HTTP; both topologies run →
    the incapable (id-per-scope) and capable (single-coordinator) arms.

``reset``/``setBackendClock`` are test-only and out-of-band: the Redis arm drives them via a
Python ``RedisSpendStore`` on the same namespace; the DO arm via the launcher's ``/test/*``
endpoints (the DO stubs are unreachable from Python). Neither is in the §12.5 wire set.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from tx402.ledger import BudgetLimits, ReservationRef, StoreCapabilities
from tx402.spend_store_contract import check_durable_spend_store
from tx402.stores.gateway import (
    AsyncHttpGatewaySpendStore,
    HttpGatewaySpendStore,
    http_gateway_spend_store,
)

_TS_DIR = Path(__file__).parents[2] / "tx402"
_DIST_READY = (_TS_DIR / "dist/gateway/index.js").is_file()
_MINIFLARE_READY = (_TS_DIR / "node_modules/miniflare/package.json").is_file()
_NODE = shutil.which("node")

# These arms spawn a Node reference gateway (and, for the DO arm, a local Workers runtime
# via miniflare — which needs Node 22 + a built workerd), so they are opt-in via
# TX402_TEST_GATEWAY=1: they run only in the properly-provisioned gateway CI job, never in a
# job that merely has node + miniflare on a different Node (like TX402_TEST_REDIS_RESTART).
_GATEWAY_ENABLED = os.environ.get("TX402_TEST_GATEWAY") == "1"

# Open a fresh connection per request (no keep-alive reuse). The miniflare-served DO gateway
# closes idle keep-alive connections in a way that surfaced as an intermittent CI connection
# reset when httpx reused one; a fresh connection is deterministic. The harness fires many
# small requests, so the extra handshakes cost little.
_NO_KEEPALIVE = httpx.Limits(max_keepalive_connections=0)

_URL = os.environ.get("TX402_TEST_REDIS_URL")
DATA_TOKEN = "data-token-abc"
ADMIN_TOKEN = "admin-token-xyz"


def _read_handshake(proc: subprocess.Popen[str], timeout: float = 40.0) -> str:
    """Read the one ``{"url": ...}`` line the launcher prints once it is listening."""
    holder: dict[str, str] = {}

    def reader() -> None:
        assert proc.stdout is not None
        line = proc.stdout.readline()
        if line:
            holder["line"] = line

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout)
    if "line" not in holder:
        raise RuntimeError("gateway launcher did not report a URL in time")
    return str(json.loads(holder["line"])["url"])


@contextmanager
def _spawn_gateway(script: str, env: dict[str, str]) -> Iterator[str]:
    proc = subprocess.Popen(
        [str(_NODE), script],
        cwd=_TS_DIR,
        env={**os.environ, **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        yield _read_handshake(proc)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── Node gateway → Redis (the capable, single-instance arm) ──


@pytest.mark.skipif(
    not _GATEWAY_ENABLED or _URL is None or _NODE is None or not _DIST_READY,
    reason="needs TX402_TEST_GATEWAY=1, TX402_TEST_REDIS_URL, node, and a built dist",
)
def test_redis_behind_gateway_sync() -> None:
    import redis

    from tx402.stores.redis import RedisSpendStore

    assert _URL is not None  # guarded by skipif; narrows for the type checker
    namespace = "tx402-gw-py-redis"
    control_client = redis.Redis.from_url(_URL, decode_responses=True)
    control = RedisSpendStore(
        control_client, namespace=namespace, admin=True, test_clock=True
    )
    env = {
        "TX402_TEST_REDIS_URL": str(_URL),
        "TX402_GATEWAY_NS": namespace,
        "TX402_GATEWAY_DATA_TOKEN": DATA_TOKEN,
        "TX402_GATEWAY_ADMIN_TOKEN": ADMIN_TOKEN,
    }
    with _spawn_gateway("test/gateway/serve-redis.mjs", env) as url:
        http = httpx.Client(timeout=30.0, limits=_NO_KEEPALIVE)
        try:
            caps = http_gateway_spend_store(
                base_url=url, token=DATA_TOKEN, client=http
            ).capabilities
            assert caps.atomic_global_freeze is True

            def client(token: str) -> HttpGatewaySpendStore:
                return HttpGatewaySpendStore(
                    base_url=url, token=token, capabilities=caps, client=http
                )

            check_durable_spend_store(
                connect_data=lambda: client(DATA_TOKEN),
                connect_admin=lambda: client(ADMIN_TOKEN),
                connect_admin_with_data_credential=lambda: client(DATA_TOKEN),
                reset=control.reset,
                set_backend_clock=control.set_backend_clock,
            )
        finally:
            http.close()
            control_client.close()


class _AsyncGatewayBridge:
    """Present ``AsyncHttpGatewaySpendStore`` as a sync store on a persistent loop (like the
    redis async arm), so the sync ``check_durable_spend_store`` drives the async client."""

    kind = "gateway"

    def __init__(
        self, loop: asyncio.AbstractEventLoop, store: AsyncHttpGatewaySpendStore
    ) -> None:
        self._loop = loop
        self._store = store
        self.capabilities = store.capabilities

    def _call(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def reserve(self, **kwargs: Any) -> Any:
        return self._call(self._store.reserve(**kwargs))

    def commit(self, **kwargs: Any) -> Any:
        return self._call(self._store.commit(**kwargs))

    def release(self, *, ref: ReservationRef, now_epoch_ms: int) -> Any:
        return self._call(self._store.release(ref=ref, now_epoch_ms=now_epoch_ms))

    def expose(self, *, ref: ReservationRef, now_epoch_ms: int) -> Any:
        return self._call(self._store.expose(ref=ref, now_epoch_ms=now_epoch_ms))

    def get_budget_state(self, **kwargs: Any) -> Any:
        return self._call(self._store.get_budget_state(**kwargs))

    def list_exposed(self, **kwargs: Any) -> Any:
        return self._call(self._store.list_exposed(**kwargs))

    def is_frozen(self, *, scope: str) -> Any:
        return self._call(self._store.is_frozen(scope=scope))

    def get_recipient_pins(self, scope: str, network: str) -> Any:
        return self._call(self._store.get_recipient_pins(scope, network))

    def get_recipient_policy(self, scope: str) -> Any:
        return self._call(self._store.get_recipient_policy(scope))

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

    def get_budget_limits(self, scope: str, asset_id: str) -> Any:
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


@pytest.mark.skipif(
    not _GATEWAY_ENABLED or _URL is None or _NODE is None or not _DIST_READY,
    reason="needs TX402_TEST_GATEWAY=1, TX402_TEST_REDIS_URL, node, and a built dist",
)
def test_redis_behind_gateway_async() -> None:
    import redis

    from tx402.stores.redis import RedisSpendStore

    assert _URL is not None  # guarded by skipif; narrows for the type checker
    namespace = "tx402-gw-py-redis-async"
    control_client = redis.Redis.from_url(_URL, decode_responses=True)
    control = RedisSpendStore(
        control_client, namespace=namespace, admin=True, test_clock=True
    )
    env = {
        "TX402_TEST_REDIS_URL": str(_URL),
        "TX402_GATEWAY_NS": namespace,
        "TX402_GATEWAY_DATA_TOKEN": DATA_TOKEN,
        "TX402_GATEWAY_ADMIN_TOKEN": ADMIN_TOKEN,
    }
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    http = httpx.AsyncClient(timeout=30.0, limits=_NO_KEEPALIVE)
    with _spawn_gateway("test/gateway/serve-redis.mjs", env) as url:
        try:
            caps = StoreCapabilities(atomic_global_freeze=True)

            def bridge(token: str) -> _AsyncGatewayBridge:
                store = AsyncHttpGatewaySpendStore(
                    base_url=url, token=token, capabilities=caps, client=http
                )
                return _AsyncGatewayBridge(loop, store)

            check_durable_spend_store(
                connect_data=lambda: bridge(DATA_TOKEN),
                connect_admin=lambda: bridge(ADMIN_TOKEN),
                connect_admin_with_data_credential=lambda: bridge(DATA_TOKEN),
                reset=control.reset,
                set_backend_clock=control.set_backend_clock,
            )
        finally:
            asyncio.run_coroutine_threadsafe(http.aclose(), loop).result()
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=5)
            control_client.close()


# ── Worker gateway → Durable Object (both topologies, miniflare-served) ──


def _do_reset(http: httpx.Client, base: str) -> None:
    http.post(f"{base}/test/reset").raise_for_status()


def _do_clock(http: httpx.Client, base: str, now_epoch_ms: int) -> None:
    http.post(f"{base}/test/clock", params={"ms": now_epoch_ms}).raise_for_status()


# The DO launcher bundles the worker from SOURCE (esbuild): needs miniflare + node, no dist.
@pytest.mark.skipif(
    not _GATEWAY_ENABLED or _NODE is None or not _MINIFLARE_READY,
    reason="needs TX402_TEST_GATEWAY=1, node on PATH, and miniflare (pnpm install)",
)
@pytest.mark.parametrize(
    ("topology", "atomic_global_freeze"),
    [("id-per-scope", False), ("single-coordinator", True)],
)
def test_durable_object_behind_gateway(topology: str, atomic_global_freeze: bool) -> None:
    """The whole durable harness runs behind the reference Worker gateway fronting a DO, for
    both topologies — the reported capability selects the incapable/capable freeze arm."""
    with _spawn_gateway("test/gateway/serve-do.mjs", {}) as origin:
        base = f"{origin}/{topology}"
        http = httpx.Client(timeout=30.0, limits=_NO_KEEPALIVE)
        try:
            caps = http_gateway_spend_store(
                base_url=base, token=DATA_TOKEN, client=http
            ).capabilities
            assert caps.atomic_global_freeze is atomic_global_freeze

            def client(token: str) -> HttpGatewaySpendStore:
                return HttpGatewaySpendStore(
                    base_url=base, token=token, capabilities=caps, client=http
                )

            check_durable_spend_store(
                connect_data=lambda: client(DATA_TOKEN),
                connect_admin=lambda: client(ADMIN_TOKEN),
                connect_admin_with_data_credential=lambda: client(DATA_TOKEN),
                reset=lambda: _do_reset(http, base),
                set_backend_clock=lambda ms: _do_clock(http, base, ms),
            )
        finally:
            http.close()
