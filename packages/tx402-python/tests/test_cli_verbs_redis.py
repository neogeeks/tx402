"""The operator verbs against a LIVE raw ``redis://`` store.

The Python twin of ``packages/tx402/test/cli-verbs-redis.test.ts``'s raw-DSN arm. Skipped
unless ``TX402_TEST_REDIS_URL`` is set (mirrors ``test_redis_store.py`` / ``tools/durable-
check``), so the unit matrix stays infra-free; the ``durable-store`` CI job runs it. The
Python CLI's live-gateway path is covered separately by the CLI-json verb golden (a Node
gateway subprocess), so together the two show the verbs work against a Redis DSN and a
gateway URL. End-to-end proof that the CLI resolves the store from the environment, plumbs
the data vs admin credential to the right plane, and that each verb mutates/reads the
durable backend (ADR-023: tests run the behaviour).
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import pytest

from tx402 import cli as cli_module
from tx402.ledger import BudgetLimits, ReservationRef

# Defaulted to "" (not None) so it types as `str`; the skip guard means it is only ever used
# when actually set.
URL = os.environ.get("TX402_TEST_REDIS_URL", "")

pytestmark = pytest.mark.skipif(
    not URL, reason="TX402_TEST_REDIS_URL is not set; the durable-store CI job runs this."
)

NETWORK = "eip155:8453"
ASSET_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
ASSET_ID = f"{NETWORK}/erc20:{ASSET_ADDRESS}"
PIN_A = "0x1111111111111111111111111111111111111111"
PIN_B = "0x2222222222222222222222222222222222222222"
NEW_PIN = "0x3333333333333333333333333333333333333333"


def _run(argv: list[str], env: dict[str, str]) -> dict[str, Any]:
    out: list[str] = []
    err: list[str] = []
    io = cli_module.CliIo(argv=argv, env=env, stdout=out.append, stderr=err.append)
    code = cli_module.run_cli(io)
    return {"code": code, "out": "".join(out), "err": "".join(err)}


@pytest.fixture
def namespace() -> Any:
    import redis

    from tx402.stores.redis import RedisSpendStore

    ns = f"tx402-cli-py-{int(time.time() * 1000)}-{os.getpid()}"
    scope = f"merchant-{os.getpid()}.example"
    client = redis.Redis.from_url(URL, decode_responses=True)
    admin = RedisSpendStore(client, namespace=ns, admin=True)
    admin.reset()
    now = int(time.time() * 1000)
    admin.set_budget_limits(
        scope,
        ASSET_ID,
        BudgetLimits(max_per_hour_atomic="1000000", max_total_atomic="5000000"),
        now,
    )
    result = admin.reserve(
        reservation_id="seed",
        request_id="seed",
        policy_scope=scope,
        request_fingerprint="seed-fp",
        asset_id=ASSET_ID,
        amount_atomic="300000",
        max_per_hour_atomic="1000000",
        max_total_atomic="5000000",
        now_epoch_ms=now,
    )
    r = result.reservation
    admin.commit(
        ref=ReservationRef(
            reservation_id=r.reservation_id, policy_scope=scope, asset_id=ASSET_ID
        ),
        committed_at_epoch_ms=now,
    )
    admin.set_recipient_pins(scope, NETWORK, (PIN_A, PIN_B), now)
    try:
        yield ns, scope, admin
    finally:
        admin.reset()
        client.close()


def _data_env(ns: str) -> dict[str, str]:
    return {
        "TX402_SPEND_STORE": URL,
        "TX402_SPEND_STORE_TOKEN": URL,
        "TX402_SPEND_STORE_NAMESPACE": ns,
    }


def _admin_env(ns: str) -> dict[str, str]:
    return {**_data_env(ns), "TX402_SPEND_STORE_ADMIN": URL}


def test_all_five_verbs_against_live_redis(namespace: Any) -> None:
    ns, scope, admin = namespace

    assert _run(["freeze", scope], _admin_env(ns))["code"] == 0
    assert admin.is_frozen(scope=scope) is True
    assert _run(["unfreeze", scope], _admin_env(ns))["code"] == 0
    assert admin.is_frozen(scope=scope) is False

    budget = json.loads(
        _run(
            ["budget", scope, "--network", NETWORK, "--asset", ASSET_ADDRESS, "--json"],
            _data_env(ns),
        )["out"]
    )
    assert budget["committedAtomic"] == "300000"
    assert budget["limitSource"] == "administered"
    assert budget["availablePerHourAtomic"] == "700000"

    pins = json.loads(
        _run(["pins", scope, "--network", NETWORK, "--json"], _data_env(ns))["out"]
    )
    assert pins["recipients"] == [PIN_A, PIN_B]

    # A raw Redis backend is unified, so rotation is race-free — no §6.7 warning.
    rotate = _run(
        ["rotate-recipient", scope, "--network", NETWORK, "--to", NEW_PIN, "--json"],
        _admin_env(ns),
    )
    assert rotate["code"] == 0
    assert rotate["err"] == ""
    assert json.loads(rotate["out"])["recipients"] == [NEW_PIN]
    assert admin.get_recipient_pins(scope, NETWORK) == (NEW_PIN,)


def test_admin_verb_data_only_credential_refused(namespace: Any) -> None:
    ns, scope, admin = namespace
    result = _run(["freeze", scope, "--json"], _data_env(ns))
    assert result["code"] == 2
    assert json.loads(result["out"])["error"]["details"]["reason"] == (
        "admin-credential-required"
    )
    assert admin.is_frozen(scope=scope) is False
