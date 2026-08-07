"""The seam between the core request loop and a chain adapter (SPEC §3, §6.4, §6.6).

Port of ``packages/tx402/src/core/chain.ts``. Core owns the state machine, the policy gate,
and the ledger. It knows nothing about EIP-712, SPL token accounts, or JSON-RPC. A chain
adapter answers exactly two questions — *can this requirement be paid?* and *what is the
signed authorization?*

Where TypeScript reaches its adapters through a lazy ``import()`` to keep them off the
size-gated core path, Python reaches them through a function-local import in
:func:`load_chain_adapter`. The effect that matters is the same in both languages: a caller
who never pays on Solana never imports ``solders``, and a missing optional extra surfaces
as a typed ``ConfigurationError`` naming what to install rather than as an ImportError at
package import time.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from tx402.health import HEALTH_OPEN_MS, HealthIndex
from tx402.policy import PolicyRequirement

#: Per-provider balance timeout (SPEC §6.4 step 15). Not configurable: it is a bound on the
#: <150 ms decision budget, not a caller preference.
BALANCE_TIMEOUT_MS: Final = 600

#: Maximum RPC providers consulted per network (SPEC §6.4 step 15).
MAX_PROVIDERS_PER_NETWORK: Final = 2

#: Default authorization lifetime in seconds (SPEC §6.6).
#:
#: The effective lifetime is ``min(60, merchant maxTimeoutSeconds)``. It may never exceed
#: the merchant bound, so the merchant's value is a ceiling and this is a cap tx402 applies
#: on top of it.
MAX_AUTHORIZATION_SECONDS: Final = 60

#: Circuit open duration for an RPC endpoint (SPEC §6.5).
#:
#: Re-exported from :mod:`tx402.health` rather than restated: the circuit lives entirely in
#: the HealthIndex, and two copies of this number could drift apart without any test
#: noticing which one an endpoint was actually using.
CIRCUIT_OPEN_MS: Final = HEALTH_OPEN_MS


@dataclass(frozen=True, slots=True)
class ChainRouteRequest:
    """Everything an adapter needs to score one policy-approved requirement."""

    request_id: str
    #: Canonical CAIP-2 identifier, already resolved through the manifest alias map.
    network_id: str
    network: Mapping[str, Any]
    #: The manifest asset the requirement was matched to, never the merchant's claim.
    asset: Mapping[str, Any]
    requirement: PolicyRequirement
    signer: object
    now_epoch_ms: int
    #: Deduplicates balance reads across requirements sharing network, asset, and owner
    #: (SPEC §6.4 step 15). Supplied by the route planner for one planning pass.
    balances: Any = None


@dataclass(frozen=True, slots=True)
class ChainAuthorizationRequest:
    """A route that has been selected, reserved against, and is ready to sign."""

    request_id: str
    network_id: str
    network: Mapping[str, Any]
    asset: Mapping[str, Any]
    requirement: PolicyRequirement
    signer: object
    now_epoch_ms: int
    #: Normalized host of the resource, for the SPEC §6.6 signer presentation.
    resource_host: str
    #: SEC-009 request fingerprint, presented to the signer as the request hash.
    request_hash: str
    #: Upper bound on authorization lifetime, in seconds (SPEC §6.6).
    max_authorization_seconds: int = MAX_AUTHORIZATION_SECONDS


@dataclass(frozen=True, slots=True)
class ChainRoute:
    """What an adapter can observe about one requirement (SPEC §5.2).

    ``health_score`` and ``rank`` are deliberately absent: they belong to the route planner,
    computed from the one shared :class:`~tx402.health.HealthIndex` rather than from
    anything an adapter keeps. An adapter reports which endpoint answered; the planner
    scores it.
    """

    requirement_index: int
    network_id: str
    scheme: str
    asset_id: str
    amount_atomic: str
    #: ``evm:0x…`` / ``solana:…``. Safe to log — it is a public address.
    signer_id: str
    balance_atomic: str
    viable: bool
    #: Stable machine-readable reasons. Never a raw provider message (SEC-003).
    rejection_reasons: tuple[str, ...] = ()
    #: Buyer-borne fee in atomic units of ``asset_id``. ``"0"`` for the exact scheme on
    #: both v0.1 networks, where the merchant bears settlement cost — but it is an ordering
    #: key in SPEC §6.4 step 18, so it is carried explicitly rather than assumed.
    estimated_fee_atomic: str = "0"
    #: The health-index key of the endpoint that served the balance, ``<caip2>|<host>``.
    endpoint_id: str | None = None


@dataclass(frozen=True, slots=True)
class ChainAuthorization:
    """The upstream payment payload, plus what core needs to bound and account for it."""

    x402_version: int
    #: The scheme payload. **Sensitive** — it contains the signature. It goes straight into
    #: the PAYMENT-SIGNATURE header and is never logged (SEC-003).
    payload: Mapping[str, Any]
    #: When the signed authorization stops being valid, from the signed message itself.
    expires_at_epoch_ms: int
    signer_id: str
    extensions: Mapping[str, Any] | None = field(default=None)


class ChainAdapter(Protocol):
    """A chain family's implementation of the two questions core asks.

    One instance is retained per client so its RPC endpoint pools survive across requests.
    The *health* those pools consult is not theirs: it lives in the client's shared
    :class:`~tx402.health.HealthIndex`, which is what ``reset_health()`` clears.
    """

    family: str

    def plan_route(self, request: ChainRouteRequest) -> ChainRoute: ...

    async def plan_route_async(self, request: ChainRouteRequest) -> ChainRoute: ...

    def create_authorization(
        self, request: ChainAuthorizationRequest
    ) -> ChainAuthorization: ...

    async def create_authorization_async(
        self, request: ChainAuthorizationRequest
    ) -> ChainAuthorization: ...

    def reset_health(self) -> None: ...


def chain_family(network_id: str) -> str:
    """The CAIP-2 namespace of a canonical network identifier."""
    return network_id.split(":", 1)[0]


def load_chain_adapter(
    family: str,
    *,
    health: HealthIndex,
    rpc_transport: object = None,
    rpc_overrides: Mapping[str, Sequence[str]] | None = None,
) -> ChainAdapter | None:
    """Loads the adapter for a chain family, or ``None`` when tx402 has none.

    The imports are function-local so that ``import tx402`` never pulls a chain library in.
    A missing optional extra surfaces here as :class:`ImportError`; the caller turns it into
    a ``ConfigurationError`` naming the extra to install.
    """
    if family == "eip155":
        from tx402.evm import create_evm_chain_adapter

        return create_evm_chain_adapter(
            health=health, rpc_transport=rpc_transport, rpc_overrides=rpc_overrides
        )
    if family == "solana":
        from tx402.solana import create_svm_chain_adapter

        return create_svm_chain_adapter(
            health=health, rpc_transport=rpc_transport, rpc_overrides=rpc_overrides
        )
    return None
