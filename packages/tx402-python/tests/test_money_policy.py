from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from typing import Any

import pytest

from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.errors import (
    BudgetExceededError,
    ClockSkewError,
    ConfigurationError,
    DomainNotAllowedError,
    InvalidPaymentRequiredError,
    UnsupportedSchemeError,
)
from tx402.ledger import MemorySpendStore
from tx402.money import (
    MoneyAssetMetadata,
    MoneyParseError,
    format_money_decimal,
    parse_money_atomic,
    parse_positive_money_atomic,
)
from tx402.policy import (
    Policy,
    PolicyDecision,
    PolicyEngine,
    RoutingPolicy,
    normalize_policy_host,
)

USDC = MoneyAssetMetadata("USDC", 6)
NOW = 1_785_715_200_000
NETWORK = "eip155:8453"
ASSET = BUNDLED_MANIFEST["networks"][NETWORK]["assets"][0]["address"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("0 USDC", 0), ("0.000001 USDC", 1), ("0.50 USDC", 500_000), ("12 USDC", 12_000_000)],
)
def test_money_parses_atomic_strings(value: str, expected: int) -> None:
    assert parse_money_atomic(value, USDC) == expected


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (0.5, "number-not-allowed"),
        (1, "number-not-allowed"),
        (None, "expected-string"),
        ("01 USDC", "invalid-format"),
        ("1 EURC", "unexpected-symbol"),
        ("0.0000001 USDC", "fractional-precision-exceeded"),
    ],
)
def test_money_rejects_noncanonical_boundaries(value: object, reason: str) -> None:
    with pytest.raises(MoneyParseError) as raised:
        parse_money_atomic(value, USDC)
    assert raised.value.reason == reason


def test_money_metadata_positive_and_formatting_guards() -> None:
    with pytest.raises(MoneyParseError, match="metadata"):
        parse_money_atomic("1 USDC", MoneyAssetMetadata("bad", 6))
    with pytest.raises(MoneyParseError, match="metadata"):
        parse_money_atomic("1 USDC", MoneyAssetMetadata("USDC", True))
    with pytest.raises(MoneyParseError, match="78"):
        parse_money_atomic(f"{'1' * 79} USDC", USDC)
    with pytest.raises(MoneyParseError, match="positive"):
        parse_positive_money_atomic("0 USDC", USDC)
    assert format_money_decimal("500000", 6) == "0.5"
    assert format_money_decimal(12, 0) == "12"
    assert format_money_decimal(1, 2) == "0.01"
    with pytest.raises(MoneyParseError, match="decimals"):
        format_money_decimal(1, -1)
    with pytest.raises(MoneyParseError, match="negative"):
        format_money_decimal(-1, 6)


def requirement(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "index": 0,
        "scheme": "exact",
        "network": NETWORK,
        "asset": ASSET,
        "amountAtomic": "50000",
        "payTo": "0x1234567890AbcdEF1234567890aBcdef12345678",
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USD Coin", "version": "2"},
        "rawHash": "sha256:raw",
    }
    value.update(overrides)
    return value


def challenge(*requirements: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocolVersion": 2,
        "resource": {"url": "https://api.example.com/pay", "method": "POST"},
        "requirements": list(requirements or (requirement(),)),
        "receivedAt": "2026-08-03T00:00:00.000Z",
        "headerHash": "sha256:header",
    }


def evaluate(
    engine: PolicyEngine, document: dict[str, Any], store: MemorySpendStore | None = None
) -> PolicyDecision:
    return engine.evaluate(
        document,
        request_id="request",
        policy_scope="api.example.com",
        now_epoch_ms=NOW,
        spend_store=store or MemorySpendStore(),
    )


def test_policy_is_frozen_normalizes_aliases_and_domains() -> None:
    policy = Policy(allowed_networks=["solana:mainnet"], allowed_domains=["*.Example.COM."])
    assert policy.allowed_networks == ("solana:mainnet",)
    assert policy.allowed_domains == ("*.Example.COM.",)
    routing = RoutingPolicy(prefer_networks=["solana:mainnet"])
    engine = PolicyEngine(BUNDLED_MANIFEST, policy, routing)
    assert engine.prefer_networks == ("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",)
    assert engine.assert_domain("https://sub.example.com/path", "id") == "sub.example.com"
    assert normalize_policy_host("https://Example.COM./") == "example.com"
    with pytest.raises(DomainNotAllowedError):
        engine.assert_domain("https://example.com", "id")


@pytest.mark.parametrize(
    ("policy", "routing"),
    [
        (Policy(allowed_networks=[]), None),
        (Policy(allowed_networks=[1]), None),  # type: ignore[list-item]
        (Policy(allowed_networks=["eip155:9"]), None),
        (Policy(allowed_domains=[]), None),
        (Policy(allowed_domains=[1]), None),  # type: ignore[list-item]
        (Policy(allowed_domains=["https://bad"]), None),
        (Policy(max_paid_attempts=0), None),
        (Policy(max_paid_attempts=True), None),
        (Policy(max_per_request=0.5), None),
        (Policy(max_per_hour="0.01 USDC"), None),
        (None, RoutingPolicy(max_quote_age_ms=-1)),
        (None, RoutingPolicy(max_quote_age_ms=True)),
        (None, RoutingPolicy(prefer_networks=["eip155:9"])),
        (None, RoutingPolicy(prefer_networks=[1])),  # type: ignore[list-item]
    ],
)
def test_policy_rejects_invalid_configuration(
    policy: Policy | None, routing: RoutingPolicy | None
) -> None:
    with pytest.raises(ConfigurationError):
        PolicyEngine(BUNDLED_MANIFEST, policy, routing)


def test_policy_evaluates_in_spec_order_and_returns_manifest_asset() -> None:
    decision = evaluate(PolicyEngine(BUNDLED_MANIFEST), challenge())
    assert decision.normalized_host == "api.example.com"
    assert len(decision.requirements) == 1
    approved = decision.requirements[0]
    assert approved.asset_id == f"{NETWORK}/erc20:{ASSET}"
    assert approved.max_per_request_atomic == "500000"
    assert approved.max_per_hour_atomic == "10000000"
    assert approved.manifest_asset["symbol"] == "USDC"


def test_policy_rejects_network_scheme_asset_and_request_cap() -> None:
    engine = PolicyEngine(BUNDLED_MANIFEST)
    with pytest.raises(UnsupportedSchemeError, match="network"):
        evaluate(engine, challenge(requirement(network="eip155:84532")))
    with pytest.raises(UnsupportedSchemeError, match="scheme"):
        evaluate(engine, challenge(requirement(scheme="upto")))
    with pytest.raises(UnsupportedSchemeError, match="scheme"):
        evaluate(engine, challenge(requirement(asset="0x" + "0" * 40)))
    with pytest.raises(BudgetExceededError) as raised:
        evaluate(engine, challenge(requirement(amountAtomic="500001")))
    assert raised.value.details["capKind"] == "per-request"


def test_policy_rejects_rolling_budget_before_quote_age() -> None:
    engine = PolicyEngine(
        BUNDLED_MANIFEST, Policy(max_per_request="1.00 USDC", max_per_hour="1.00 USDC")
    )
    store = MemorySpendStore()
    store.reserve(
        reservation_id="held",
        request_id="other",
        policy_scope="api.example.com",
        request_fingerprint="sha256:x",
        asset_id=f"{NETWORK}/erc20:{ASSET}",
        amount_atomic="960000",
        max_per_hour_atomic="1000000",
        now_epoch_ms=NOW,
    )
    stale = requirement(extra={"timestamp": "2020-01-01T00:00:00Z"})
    with pytest.raises(BudgetExceededError) as raised:
        evaluate(engine, challenge(stale), store)
    assert raised.value.details["reservedAtomic"] == "960000"


def test_policy_quote_timestamp_invalid_future_stale_and_fresh() -> None:
    engine = PolicyEngine(BUNDLED_MANIFEST)
    invalid = requirement(extra={"timestamp": "not-a-date"})
    with pytest.raises(InvalidPaymentRequiredError) as raised:
        evaluate(engine, challenge(invalid))
    assert raised.value.details["reason"] == "quote-timestamp-invalid"

    future = requirement(extra={"timestamp": "2026-08-03T00:00:16Z"})
    with pytest.raises(ClockSkewError):
        evaluate(engine, challenge(future))

    stale = requirement(extra={"timestamp": "2026-08-02T23:59:54Z"})
    with pytest.raises(InvalidPaymentRequiredError) as raised:
        evaluate(engine, challenge(stale))
    assert raised.value.details["reason"] == "quote-expired"

    fresh = requirement(extra={"timestamp": "2026-08-02T23:59:56Z"})
    assert len(evaluate(engine, challenge(fresh)).requirements) == 1


def test_policy_keeps_viable_requirement_when_another_is_stale() -> None:
    first = requirement(index=0, extra={"timestamp": "2020-01-01T00:00:00Z"})
    second = deepcopy(requirement(index=1))
    decision = evaluate(PolicyEngine(BUNDLED_MANIFEST), challenge(first, second))
    assert [item.requirement["index"] for item in decision.requirements] == [1]


def test_t007_concurrent_reservations_enforce_the_cap_atomically() -> None:
    store = MemorySpendStore()

    def reserve(index: int) -> bool:
        try:
            store.reserve(
                reservation_id=f"reservation-{index}",
                request_id=f"request-{index}",
                policy_scope="scope",
                request_fingerprint=f"sha256:{index}",
                asset_id="eip155:8453/erc20:asset",
                amount_atomic="100",
                max_per_hour_atomic="1000",
                now_epoch_ms=NOW,
            )
            return True
        except BudgetExceededError:
            return False

    with ThreadPoolExecutor(max_workers=20) as executor:
        outcomes = list(executor.map(reserve, range(20)))
    assert outcomes.count(True) == 10
    state = store.get_budget_state(
        policy_scope="scope",
        asset_id="eip155:8453/erc20:asset",
        now_epoch_ms=NOW,
    )
    assert state.reserved_atomic == "1000"


class TestRpcOverrides:
    """ADR-015. Held to the same rules as the TypeScript engine, error for error."""

    @staticmethod
    def _engine(overrides: object) -> PolicyEngine:
        return PolicyEngine(
            BUNDLED_MANIFEST,
            Policy(allowed_networks=["eip155:84532"]),
            RoutingPolicy(rpc_overrides=overrides),  # type: ignore[arg-type]
        )

    def test_resolves_an_aliased_key_to_canonical_caip2(self) -> None:
        # `solana:devnet` is an alias; the adapter is handed the genesis-hash id, so an
        # override keyed by the alias has to land under the canonical name or it silently
        # never applies — which is the failure this resolution exists to prevent.
        engine = PolicyEngine(
            BUNDLED_MANIFEST,
            Policy(),
            RoutingPolicy(rpc_overrides={"solana:devnet": ["https://rpc.example.com/k"]}),
        )
        assert list(engine.rpc_overrides) == ["solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"]

    def test_defaults_to_no_overrides_so_the_manifest_decides(self) -> None:
        assert dict(PolicyEngine(BUNDLED_MANIFEST).rpc_overrides) == {}

    def test_rejects_an_unknown_network_rather_than_never_applying(self) -> None:
        with pytest.raises(ConfigurationError):
            self._engine({"eip155:999999": ["https://rpc.example.com"]})

    def test_rejects_an_empty_list(self) -> None:
        with pytest.raises(ConfigurationError, match="empty-list"):
            self._engine({"eip155:84532": []})

    def test_rejects_plaintext_http_off_localhost(self) -> None:
        # An RPC endpoint carries its API key in the URL, so plaintext leaks it.
        with pytest.raises(ConfigurationError, match="insecure-scheme"):
            self._engine({"eip155:84532": ["http://rpc.example.com/k"]})

    def test_allows_plaintext_http_on_localhost_for_a_local_validator(self) -> None:
        engine = self._engine({"eip155:84532": ["http://127.0.0.1:8899"]})
        assert engine.rpc_overrides["eip155:84532"] == ("http://127.0.0.1:8899",)

    def test_rejects_a_value_that_is_not_a_url(self) -> None:
        with pytest.raises(ConfigurationError, match="invalid-url"):
            self._engine({"eip155:84532": ["not a url"]})
