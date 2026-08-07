"""tx402 — resilient x402 buyer SDK.

Wraps a normal HTTP client, interprets ``402 Payment Required`` challenges, enforces
local spend policy *before* any key is touched, deterministically selects a payment
route across the networks the merchant offered, signs an authorization, and retries.

Example::

    from tx402 import Policy, Tx402Client

    client = Tx402Client(
        evm_signer=evm_signer,
        solana_signer=solana_signer,
        policy=Policy(
            max_per_request="0.50 USDC",
            max_per_hour="10.00 USDC",
            allowed_networks=["eip155:8453", "solana:mainnet"],
        ),
    )

    response = client.post(url, json={"prompt": "Hello"})

Chain support lives behind extras and is *not* re-exported here: ``tx402.solana`` imports
``solders``, so importing it from this module would make the core install depend on a chain
library. Reach it as ``from tx402.solana import SolanaSigner`` after installing
``tx402[svm]`` — the same split the TypeScript package draws with its ``tx402/solana``
subpath export.

Both SDKs are validated against the same frozen cross-language conformance fixtures.
"""

from __future__ import annotations

from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.chain import (
    MAX_AUTHORIZATION_SECONDS,
    MAX_PROVIDERS_PER_NETWORK,
    ChainAdapter,
    ChainAuthorization,
    ChainAuthorizationRequest,
    ChainRoute,
    ChainRouteRequest,
    chain_family,
    load_chain_adapter,
)
from tx402.client import (
    SPEND_STORE_COMMIT_FAILED_REASON,
    SPEND_STORE_UNAVAILABLE_CAUSE,
    AsyncTx402Client,
    AsyncTx402Transport,
    PaymentInspection,
    PaymentPlan,
    Tx402Client,
    Tx402Transport,
)
from tx402.completion import (
    MALFORMED_SETTLEMENT_CAUSE,
    MAX_PAID_ATTEMPTS_REASON,
    SETTLED_RESOURCE_UNUSABLE_REASON,
    PaidAttemptDisposition,
    PaidAttemptResult,
    classify_paid_attempt,
)
from tx402.diagnostics import (
    EVENT_NAMES,
    NOOP_LOGGER,
    LogLevel,
    NoopLogger,
    Tx402Logger,
)
from tx402.errors import (
    TX402_ERROR_CODES,
    TX402_ERROR_DESCRIPTORS,
    TX402_ERROR_TAXONOMY,
    AmbiguousPaymentError,
    BudgetExceededError,
    ClockSkewError,
    ConfigurationError,
    DomainNotAllowedError,
    InsufficientLiquidityError,
    InvalidPaymentRequiredError,
    NonReplayableRequestError,
    PaidRedirectBlockedError,
    ReservedHeaderError,
    ResourceDeliveryError,
    SignerError,
    TransportError,
    Tx402Error,
    Tx402ErrorContext,
    Tx402ErrorDescriptor,
    UnsupportedProtocolError,
    UnsupportedSchemeError,
    is_tx402_error,
)
from tx402.evm import (
    EvmChainAdapter,
    EvmRpcError,
    EvmRpcPool,
    EvmSigner,
    EvmSignerPresentation,
    EvmTypedDataRequest,
    ExactEvmPlan,
    create_evm_authorization,
    create_evm_chain_adapter,
    encode_balance_of_call_data,
    plan_exact_evm_authorization,
    resolve_evm_address,
)
from tx402.health import (
    HEALTH_NEW_ENDPOINT_SCORE,
    HEALTH_OPEN_MS,
    EndpointHealth,
    HealthIndex,
)
from tx402.ledger import (
    RESERVATION_TTL_MS,
    ROLLING_WINDOW_MS,
    BudgetState,
    MemorySpendStore,
    SpendEntry,
    SpendReservation,
    SpendStore,
    assert_spend_store,
)
from tx402.manifest import (
    assert_valid_release_manifest,
    require_network,
    resolve_network,
    verify_release_manifest,
)
from tx402.meta import (
    PACKAGE_NAME,
    PROJECT_URLS,
    PROTOCOL_HEADERS,
    REQUEST_ID_HEADER,
    RESERVED_REQUEST_HEADERS,
    X402_PROTOCOL_VERSION,
)
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
    PolicyRequirement,
    RoutingPolicy,
    normalize_policy_host,
)
from tx402.routing import (
    RouteCandidate,
    RoutePlan,
    order_route_candidates,
    plan_routes,
    plan_routes_async,
)
from tx402.spend_store_contract import SpendStoreContractError, check_spend_store
from tx402.trusted_keys import MANIFEST_SIGNING_DOMAIN, TRUSTED_MANIFEST_KEYS

__all__ = [
    "BUNDLED_MANIFEST",
    "EVENT_NAMES",
    "HEALTH_NEW_ENDPOINT_SCORE",
    "HEALTH_OPEN_MS",
    "MALFORMED_SETTLEMENT_CAUSE",
    "MANIFEST_SIGNING_DOMAIN",
    "MAX_AUTHORIZATION_SECONDS",
    "MAX_PAID_ATTEMPTS_REASON",
    "MAX_PROVIDERS_PER_NETWORK",
    "NOOP_LOGGER",
    "PACKAGE_NAME",
    "PROJECT_URLS",
    "PROTOCOL_HEADERS",
    "REQUEST_ID_HEADER",
    "RESERVATION_TTL_MS",
    "RESERVED_REQUEST_HEADERS",
    "ROLLING_WINDOW_MS",
    "SETTLED_RESOURCE_UNUSABLE_REASON",
    "SPEND_STORE_COMMIT_FAILED_REASON",
    "SPEND_STORE_UNAVAILABLE_CAUSE",
    "TRUSTED_MANIFEST_KEYS",
    "TX402_ERROR_CODES",
    "TX402_ERROR_DESCRIPTORS",
    "TX402_ERROR_TAXONOMY",
    "X402_PROTOCOL_VERSION",
    "AmbiguousPaymentError",
    "AsyncTx402Client",
    "AsyncTx402Transport",
    "BudgetExceededError",
    "BudgetState",
    "ChainAdapter",
    "ChainAuthorization",
    "ChainAuthorizationRequest",
    "ChainRoute",
    "ChainRouteRequest",
    "ClockSkewError",
    "ConfigurationError",
    "DomainNotAllowedError",
    "EndpointHealth",
    "EvmChainAdapter",
    "EvmRpcError",
    "EvmRpcPool",
    "EvmSigner",
    "EvmSignerPresentation",
    "EvmTypedDataRequest",
    "ExactEvmPlan",
    "HealthIndex",
    "InsufficientLiquidityError",
    "InvalidPaymentRequiredError",
    "LogLevel",
    "MemorySpendStore",
    "MoneyAssetMetadata",
    "MoneyParseError",
    "NonReplayableRequestError",
    "NoopLogger",
    "PaidAttemptDisposition",
    "PaidAttemptResult",
    "PaidRedirectBlockedError",
    "PaymentInspection",
    "PaymentPlan",
    "Policy",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRequirement",
    "ReservedHeaderError",
    "ResourceDeliveryError",
    "RouteCandidate",
    "RoutePlan",
    "RoutingPolicy",
    "SignerError",
    "SpendEntry",
    "SpendReservation",
    "SpendStore",
    "SpendStoreContractError",
    "TransportError",
    "Tx402Client",
    "Tx402Error",
    "Tx402ErrorContext",
    "Tx402ErrorDescriptor",
    "Tx402Logger",
    "Tx402Transport",
    "UnsupportedProtocolError",
    "UnsupportedSchemeError",
    "assert_spend_store",
    "assert_valid_release_manifest",
    "chain_family",
    "check_spend_store",
    "classify_paid_attempt",
    "create_evm_authorization",
    "create_evm_chain_adapter",
    "encode_balance_of_call_data",
    "format_money_decimal",
    "is_tx402_error",
    "load_chain_adapter",
    "normalize_policy_host",
    "order_route_candidates",
    "parse_money_atomic",
    "parse_positive_money_atomic",
    "plan_exact_evm_authorization",
    "plan_routes",
    "plan_routes_async",
    "require_network",
    "resolve_evm_address",
    "resolve_network",
    "verify_release_manifest",
]
