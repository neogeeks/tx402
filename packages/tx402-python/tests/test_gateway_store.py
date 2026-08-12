"""The capability-gateway client (SPEC §12.5, ADR-023 — tests that RUN the behaviour).

Two always-on properties pin cross-language interoperability against the committed golden
(``core-spec/gateway/golden.json``), the same artifact the TypeScript
``test/gateway-golden.test.ts`` is held to:

  - **request parity** — the Python ``HttpGatewaySpendStore`` emits, for a canonical call of
    every method, the byte-identical ``POST /v1/{method}`` the golden records (named-field
    body, nested ``ReservationRef`` triple, version + auth headers).
  - **response mapping** — for every response fixture the client raises the EXACT typed
    error the golden records (an existing taxonomy code — no ``TX402_GATEWAY_FORBIDDEN``) or
    returns the value.

Plus, behind a live reference gateway, the whole ``check_durable_spend_store`` runs over
BOTH backends from the Python client (see ``test_gateway_durable.py``): a gateway-backed
store is byte-identical to a direct one.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from tx402.errors import Tx402Error
from tx402.ledger import BudgetLimits, ReservationRef, StoreCapabilities
from tx402.stores.gateway import HttpGatewaySpendStore

_GOLDEN = json.loads(
    (Path(__file__).parents[3] / "core-spec/gateway/golden.json").read_text()
)

SCOPE = "merchant.example"
ASSET = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
NETWORK = "eip155:8453"
RECIPIENT = "0x" + "1" * 40
FP = "sha256:" + "0" * 64
NOW = 1_800_000_000_000
REF = ReservationRef(reservation_id="res-1", policy_scope=SCOPE, asset_id=ASSET)
CAPS = StoreCapabilities(atomic_global_freeze=False)


def _canonical_calls(client: HttpGatewaySpendStore) -> list[tuple[str, Any]]:
    """One canonical call per method, mirroring the golden generator's calls exactly."""
    return [
        (
            "reserve",
            lambda: client.reserve(
                reservation_id="res-1",
                request_id="req-1",
                policy_scope=SCOPE,
                request_fingerprint=FP,
                asset_id=ASSET,
                amount_atomic="1500",
                max_per_hour_atomic="1000000",
                max_total_atomic="5000000",
                recipient_network=NETWORK,
                recipient_canonical=RECIPIENT,
                recipient_enforcement="tofu",
                now_epoch_ms=NOW,
            ),
        ),
        (
            "commit",
            lambda: client.commit(
                ref=REF, committed_at_epoch_ms=NOW + 10, settlement_id="0xsettlement"
            ),
        ),
        ("release", lambda: client.release(ref=REF, now_epoch_ms=NOW + 5)),
        ("expose", lambda: client.expose(ref=REF, now_epoch_ms=NOW + 5)),
        (
            "getBudgetState",
            lambda: client.get_budget_state(
                policy_scope=SCOPE, asset_id=ASSET, now_epoch_ms=NOW
            ),
        ),
        (
            "listExposed",
            lambda: client.list_exposed(
                policy_scope=SCOPE, asset_id=ASSET, now_epoch_ms=NOW
            ),
        ),
        ("isFrozen", lambda: client.is_frozen(scope=SCOPE)),
        ("getRecipientPins", lambda: client.get_recipient_pins(SCOPE, NETWORK)),
        ("getRecipientPolicy", lambda: client.get_recipient_policy(SCOPE)),
        ("capabilities", lambda: client.request_capabilities()),
        ("freeze", lambda: client.freeze(SCOPE, NOW)),
        ("unfreeze", lambda: client.unfreeze(SCOPE, NOW)),
        (
            "setRecipientPins",
            lambda: client.set_recipient_pins(SCOPE, NETWORK, (RECIPIENT,), NOW),
        ),
        (
            "setBudgetLimits",
            lambda: client.set_budget_limits(
                SCOPE,
                ASSET,
                BudgetLimits(max_per_hour_atomic="100", max_total_atomic="1000"),
                NOW,
            ),
        ),
        ("getBudgetLimits", lambda: client.get_budget_limits(SCOPE, ASSET)),
        (
            "setRecipientAssertionRequired",
            lambda: client.set_recipient_assertion_required(SCOPE, True, NOW),
        ),
        ("setTofuEnabled", lambda: client.set_tofu_enabled(SCOPE, True, NOW)),
        ("resolveExposed", lambda: client.resolve_exposed(REF, "committed", NOW)),
        ("resetCumulative", lambda: client.reset_cumulative(SCOPE, ASSET, NOW)),
    ]


def test_request_parity_with_golden() -> None:
    """Every method emits the byte-identical request the golden pins (§12.5)."""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"result": None})

    mock = httpx.Client(transport=httpx.MockTransport(handler))
    client = HttpGatewaySpendStore(
        base_url="http://gateway.local",
        token="golden-token",
        capabilities=CAPS,
        client=mock,
    )
    by_op = {request["op"]: request for request in _GOLDEN["requests"]}

    for op, call in _canonical_calls(client):
        captured.clear()
        # The canned `{result: null}` does not decode into every return type; the request
        # is what we assert, and it is captured before the client tries to decode.
        with contextlib.suppress(Exception):
            call()
        golden = by_op[op]
        assert captured["path"] == golden["path"], op
        assert captured["body"] == golden["body"], op
        for header_name, value in golden["headers"].items():
            assert captured["headers"][header_name] == value, f"{op} header {header_name}"


def _client_returning(status: int, body: Any) -> HttpGatewaySpendStore:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    mock = httpx.Client(transport=httpx.MockTransport(handler))
    return HttpGatewaySpendStore(
        base_url="http://gateway.local", token="t", capabilities=CAPS, client=mock
    )


def test_response_mapping_parity_with_golden() -> None:
    """Every response fixture maps to the exact typed error / value the golden records."""
    for response in _GOLDEN["responses"]:
        outcome = response["outcome"]
        client = _client_returning(response["status"], response["body"])
        if outcome["kind"] == "raise":
            with pytest.raises(Tx402Error) as exc_info:
                client.is_frozen(scope=SCOPE)
            error = exc_info.value
            assert type(error).__name__ == outcome["name"], response["condition"]
            assert error.code == outcome["code"], response["condition"]
            assert error.retryable == outcome["retryable"], response["condition"]
            assert dict(error.details) == outcome["details"], response["condition"]


def test_success_fixtures_decode() -> None:
    """The success fixtures decode into the right result types (no throw)."""
    by_condition = {response["condition"]: response for response in _GOLDEN["responses"]}

    reserve = _client_returning(200, by_condition["reserve-success"]["body"]).reserve(
        reservation_id="res-1",
        request_id="req-1",
        policy_scope=SCOPE,
        request_fingerprint=FP,
        asset_id=ASSET,
        amount_atomic="1500",
        max_per_hour_atomic="1000000",
        now_epoch_ms=NOW,
    )
    assert reserve.reservation.state == "reserved"
    assert reserve.recipient_pin_established is False

    caps_client = _client_returning(200, by_condition["capabilities-success"]["body"])
    assert caps_client.request_capabilities().atomic_global_freeze is False

    # A void method returns None on `{result: null}` and does not raise.
    _client_returning(200, by_condition["void-success"]["body"]).freeze(SCOPE, NOW)
