"""S13b audit-finding regressions (Python, ADR-023 — tests that RUN the behaviour).

Each test fails against the pre-fix code at f680b16 and passes after S13b. The
gateway-client sections mirror the TypeScript ``audit-regressions-s13b.test.ts``,
so the two SDKs reject the same malformed transport/response identically.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tx402.errors import ConfigurationError
from tx402.ledger import StoreCapabilities
from tx402.stores.gateway import HttpGatewaySpendStore

CAPS = StoreCapabilities(atomic_global_freeze=True)
SCOPE = "merchant.example"


def _client_returning(status: int, body: Any) -> HttpGatewaySpendStore:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    mock = httpx.Client(transport=httpx.MockTransport(handler))
    return HttpGatewaySpendStore(
        base_url="http://gateway.local", token="t", capabilities=CAPS, client=mock
    )


# ── O22 — HTTPS by default (a plaintext bearer is never sent in the clear) ──


def test_o22_rejects_plaintext_http_to_non_loopback() -> None:
    with pytest.raises(ConfigurationError) as exc:
        HttpGatewaySpendStore(
            base_url="http://collector.invalid/gw", token="secret", capabilities=CAPS
        )
    assert exc.value.details.get("reason") == "https-required"


def test_o22_permits_https_and_loopback_http() -> None:
    # Neither raises (no request is made at construction).
    HttpGatewaySpendStore(base_url="https://gw.example", token="t", capabilities=CAPS)
    HttpGatewaySpendStore(base_url="http://127.0.0.1:8787", token="t", capabilities=CAPS)


# ── O24 — the client validates the response envelope (no truthiness coercion) ──


def test_o24_refuses_string_false_for_boolean() -> None:
    client = _client_returning(200, {"result": "false"})
    with pytest.raises(ConfigurationError) as exc:
        client.is_frozen(scope=SCOPE)
    assert exc.value.details.get("reason") == "gateway-invalid-response"


def test_o24_refuses_config_invalid_missing_config_path() -> None:
    client = _client_returning(
        200, {"error": {"code": "TX402_CONFIG_INVALID", "details": {"reason": "x"}}}
    )
    with pytest.raises(ConfigurationError) as exc:
        client.is_frozen(scope=SCOPE)
    assert exc.value.details.get("reason") == "gateway-invalid-response"


def test_o24_refuses_unknown_error_code_as_protocol_violation() -> None:
    client = _client_returning(200, {"error": {"code": "TX402_MADE_UP", "details": {}}})
    with pytest.raises(ConfigurationError) as exc:
        client.is_frozen(scope=SCOPE)
    assert exc.value.details.get("reason") == "gateway-invalid-response"


def test_o24_still_round_trips_a_well_formed_boolean() -> None:
    assert _client_returning(200, {"result": True}).is_frozen(scope=SCOPE) is True


# ── O37 — the response envelope is a CLOSED shape, identical to TS ──
# The TS client validates the whole envelope against a `oneOf` of two closed
# (`additionalProperties: false`) envelopes, so it refuses an extra top-level key, both keys
# at once, or an over-width amount. These pin that the Python client refuses the SAME three
# shapes — each fails against the pre-S13d `_decode` (which ignored extra keys, read a
# two-key envelope as its error, and never width-capped amounts).


def test_o37_refuses_an_extra_top_level_key() -> None:
    # {result, extra}: the pre-fix _decode ignored `extra`; a closed envelope refuses it.
    client = _client_returning(200, {"result": True, "extra": 1})
    with pytest.raises(ConfigurationError) as exc:
        client.is_frozen(scope=SCOPE)
    assert exc.value.details.get("reason") == "gateway-invalid-response"


def test_o37_refuses_both_error_and_result() -> None:
    # {error, result}: the pre-fix _decode read this as the (valid) error and raised a
    # TransportError; a two-key envelope is a protocol violation, not an error.
    client = _client_returning(
        200, {"error": {"code": "TX402_TRANSPORT", "details": {}}, "result": True}
    )
    with pytest.raises(ConfigurationError) as exc:
        client.is_frozen(scope=SCOPE)
    assert exc.value.details.get("reason") == "gateway-invalid-response"


def test_o37_refuses_an_over_width_atomic_amount() -> None:
    # An `atomicAmount` over 78 digits is a protocol violation (TS $defs maxLength 78);
    # a 78-digit value still round-trips.
    over_width = _client_returning(200, {"result": {"maxPerHourAtomic": "9" * 79}})
    with pytest.raises(ConfigurationError) as exc:
        over_width.get_budget_limits("s", "a")
    assert exc.value.details.get("reason") == "gateway-invalid-response"
    at_cap = _client_returning(200, {"result": {"maxPerHourAtomic": "9" * 78}})
    assert at_cap.get_budget_limits("s", "a").max_per_hour_atomic == "9" * 78


def test_o37_leaves_lifetime_accumulators_uncapped() -> None:
    # atomicAccumulator fields (exposedAtomic / cumulative*) carry NO width cap (== TS);
    # the split is exact, not a blanket tightening. A 100-digit lifetime sum is valid.
    big = "9" * 100
    state = _client_returning(
        200,
        {
            "result": {
                "storeKind": "memory",
                "committedAtomic": "0",
                "reservedAtomic": "0",
                "exposedAtomic": big,
            }
        },
    ).get_budget_state(policy_scope="s", asset_id="a", now_epoch_ms=0)
    assert state.exposed_atomic == big


# ── O22 — the CLI store resolver requires HTTPS for a remote gateway ──

from tx402.cli import _redact_dsn, _resolve_store  # noqa: E402


def test_o22_cli_refuses_plaintext_http_to_non_loopback() -> None:
    with pytest.raises(ConfigurationError) as exc:
        _resolve_store(
            {
                "TX402_SPEND_STORE": "http://collector.invalid/gw",
                "TX402_SPEND_STORE_TOKEN": "t",
            },
            "data",
        )
    assert exc.value.details.get("reason") == "https-required"


def test_o22_cli_allows_loopback_http() -> None:
    # Loopback http is permitted (dev): the resolver gets past the scheme gate and fails on
    # connect, not with https-required.
    reason = None
    try:
        _resolve_store(
            {"TX402_SPEND_STORE": "http://127.0.0.1:59996", "TX402_SPEND_STORE_TOKEN": "t"},
            "data",
        )
    except Exception as error:
        reason = getattr(error, "details", {}).get("reason")
    assert reason != "https-required"


# ── O28 — a credential-bearing DSN never escapes into an error ──


def test_o28_redact_dsn_masks_userinfo() -> None:
    assert _redact_dsn("redis://user:s3cr3t@host:6379/0") == "redis://***@host:6379/0"
    assert _redact_dsn("user:s3cr3t@host:6379") == "***@host:6379"
    assert _redact_dsn("redis://host:6379/0") == "redis://host:6379/0"
    # O41l: an unencoded `@` must not leave its suffix in the clear — mask to the LAST
    # `@` before the host, matching the TS `redactDsn`.
    assert _redact_dsn("redis://user:p@ss@host:6379/0") == "redis://***@host:6379/0"
    assert _redact_dsn("rediss://u:a@b@c@d.example:6379") == "rediss://***@d.example:6379"


def test_o28_unsupported_dsn_error_never_contains_the_secret() -> None:
    with pytest.raises(ConfigurationError) as exc:
        _resolve_store({"TX402_SPEND_STORE": "weirdscheme://user:s3cr3t@host:9999"}, "data")
    serialized = f"{exc.value}\n{exc.value.details}"
    assert "s3cr3t" not in serialized
    assert exc.value.details.get("reason") == "unsupported-store-dsn"


# ── O20 — the README custom-store example is v2 and runnable, not the broken v1 shape ──


def test_o20_readme_custom_store_example_is_v2_and_runnable() -> None:
    from pathlib import Path

    from tx402.ledger import MemorySpendStore
    from tx402.spend_store_contract import check_spend_store

    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    # The old v1 stub (bare-id commit, missing capabilities/expose/is_frozen) is gone.
    assert "def commit(self, *, reservation_id, committed_at_epoch_ms" not in readme
    # It now points at the shipped v2 Redis adapter and the conformance suite.
    assert "from tx402.stores.redis import RedisSpendStore" in readme
    assert "from tx402.spend_store_contract import check_spend_store" in readme
    # And the documented v2 contract passes the shipped checker (execution, not text).
    check_spend_store(MemorySpendStore)
