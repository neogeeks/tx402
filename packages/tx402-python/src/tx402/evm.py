"""Base/EVM exact-scheme planning, RPC validation, and signer adaptation (SPEC §7.1)."""

from __future__ import annotations

import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol, runtime_checkable

import httpx
from x402.schemas import PaymentRequirements

from tx402.chain import (
    MAX_AUTHORIZATION_SECONDS,
    MAX_PROVIDERS_PER_NETWORK,
    ChainAuthorization,
    ChainAuthorizationRequest,
    ChainRoute,
    ChainRouteRequest,
)
from tx402.deadline import with_deadline, with_deadline_async
from tx402.errors import (
    ConfigurationError,
    InvalidPaymentRequiredError,
    SignerError,
    TransportError,
    Tx402ErrorContext,
    UnsupportedSchemeError,
)
from tx402.health import HealthIndex
from tx402.money import format_money_decimal
from tx402.routing import BALANCE_KEY_SEPARATOR

BALANCE_OF_SELECTOR: Final = "0x70a08231"
SUPPORTED_ASSET_TRANSFER_METHOD: Final = "eip3009"
RPC_TIMEOUT_MS: Final = 600

_ADDRESS: Final = re.compile(r"^0x[0-9a-fA-F]{40}$")
_NONCE: Final = re.compile(r"^0x[0-9a-fA-F]{64}$")
_QUANTITY: Final = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")


@dataclass(frozen=True, slots=True)
class EvmSignerPresentation:
    network: str
    asset_id: str
    asset_symbol: str
    amount_atomic: str
    amount_decimal: str
    recipient: str
    resource_host: str
    domain_name: str
    expires_at: str
    request_hash: str


@dataclass(frozen=True, slots=True)
class EvmTypedDataRequest:
    domain: Mapping[str, Any]
    types: Mapping[str, tuple[Mapping[str, str], ...]]
    primary_type: str
    message: Mapping[str, Any]
    presentation: EvmSignerPresentation


@runtime_checkable
class EvmSigner(Protocol):
    """Caller-owned signer. It accepts a human-readable presentation, never a key."""

    kind: Literal["evm"]

    def get_address(self) -> str: ...

    def sign_typed_data(self, request: EvmTypedDataRequest) -> bytes | str: ...


@dataclass(frozen=True, slots=True)
class ExactEvmPlan:
    chain_id: int
    verifying_contract: str
    domain_name: str
    domain_version: str
    payer: str
    recipient: str
    value_atomic: str
    lifetime_seconds: int
    valid_after_seconds: int
    not_before_epoch_seconds: int
    not_after_epoch_seconds: int
    balance_of_call_data: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "chainId": self.chain_id,
            "verifyingContract": self.verifying_contract,
            "domainName": self.domain_name,
            "domainVersion": self.domain_version,
            "payer": self.payer,
            "recipient": self.recipient,
            "valueAtomic": self.value_atomic,
            "lifetimeSeconds": self.lifetime_seconds,
            "validAfterSeconds": self.valid_after_seconds,
            "notBeforeEpochSeconds": self.not_before_epoch_seconds,
            "notAfterEpochSeconds": self.not_after_epoch_seconds,
            "balanceOfCallData": self.balance_of_call_data,
        }


def _invalid(
    reason: str, schema_path: str, context: Tx402ErrorContext
) -> InvalidPaymentRequiredError:
    return InvalidPaymentRequiredError(
        f"Base payment requirement is unusable: {reason}",
        context=context,
        details={"reason": reason, "schemaPath": schema_path},
    )


def encode_balance_of_call_data(owner: str) -> str:
    if _ADDRESS.fullmatch(owner) is None:
        raise TypeError("balanceOf owner must be a 20-byte hex address")
    return f"{BALANCE_OF_SELECTOR}{owner[2:].lower().rjust(64, '0')}"


def plan_exact_evm_authorization(
    *,
    requirement: Mapping[str, Any],
    network_id: str,
    network: Mapping[str, Any],
    asset: Mapping[str, Any],
    payer: str,
    now_epoch_ms: int,
    max_authorization_seconds: int = MAX_AUTHORIZATION_SECONDS,
    context: Tx402ErrorContext,
) -> ExactEvmPlan:
    """Pure derivation of the EIP-3009 authorization tx402 is willing to sign."""
    if requirement["scheme"] != "exact":
        raise UnsupportedSchemeError(
            "Base supports only the exact payment scheme",
            context=context,
            details={
                "offeredSchemes": [requirement["scheme"]],
                "offeredNetworks": [requirement["network"]],
                "reason": "scheme-unsupported",
            },
        )
    extra: Mapping[str, Any] = requirement["extra"]
    transfer_method = extra.get("assetTransferMethod")
    if transfer_method is not None and transfer_method != SUPPORTED_ASSET_TRANSFER_METHOD:
        raise UnsupportedSchemeError(
            "Asset transfer method is not supported in v0.1",
            context=context,
            details={
                "offeredSchemes": [requirement["scheme"]],
                "offeredNetworks": [requirement["network"]],
                "reason": "asset-transfer-method-unsupported",
            },
        )
    chain_id = network.get("chainId")
    if isinstance(chain_id, bool) or not isinstance(chain_id, int):
        raise _invalid("network-chain-id-mismatch", "/accepts/*/network", context)
    if network_id != f"eip155:{chain_id}":
        raise _invalid("network-chain-id-mismatch", "/accepts/*/network", context)
    if requirement["network"] != network_id:
        raise _invalid("network-not-canonical", "/accepts/*/network", context)
    address = asset.get("address")
    if not isinstance(address, str) or address.lower() != requirement["asset"].lower():
        raise _invalid("asset-not-manifest-asset", "/accepts/*/asset", context)
    if _ADDRESS.fullmatch(requirement["payTo"]) is None:
        raise _invalid("pay-to-invalid", "/accepts/*/payTo", context)
    if _ADDRESS.fullmatch(address) is None:
        raise _invalid("asset-address-invalid", "/accepts/*/asset", context)
    if _ADDRESS.fullmatch(payer) is None:
        raise _invalid("payer-invalid", "/accepts/*/payTo", context)
    domain_name, domain_version = extra.get("name"), extra.get("version")
    if (
        not isinstance(domain_name, str)
        or not domain_name
        or not isinstance(domain_version, str)
        or not domain_version
    ):
        raise _invalid("eip712-domain-missing", "/accepts/*/extra", context)
    declared_version = asset.get("eip712Version")
    if declared_version is not None and declared_version != domain_version:
        raise _invalid("eip712-domain-mismatch", "/accepts/*/extra/version", context)
    timeout = requirement["maxTimeoutSeconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
        raise _invalid("max-timeout-invalid", "/accepts/*/maxTimeoutSeconds", context)
    amount = requirement["amountAtomic"]
    if not isinstance(amount, str) or re.fullmatch(r"[1-9][0-9]*", amount) is None:
        raise _invalid("amount-not-atomic-integer", "/accepts/*/amount", context)
    lifetime = min(max_authorization_seconds, timeout)
    now_seconds = now_epoch_ms // 1_000
    return ExactEvmPlan(
        chain_id,
        address,
        domain_name,
        domain_version,
        payer,
        requirement["payTo"],
        amount,
        lifetime,
        0,
        now_seconds,
        now_seconds + lifetime,
        encode_balance_of_call_data(payer),
    )


EvmRpcFailure = Literal[
    "chain-id-mismatch",
    "chain-id-unreadable",
    "balance-unreadable",
    "transport",
    "timeout",
    "protocol",
]


class EvmRpcError(Exception):
    def __init__(self, failure: EvmRpcFailure, message: str) -> None:
        super().__init__(message)
        self.failure = failure


@dataclass(frozen=True, slots=True)
class EvmBalanceReading:
    balance_atomic: int
    chain_id: int
    #: Host only. The full URL may carry a provider API key and never leaves this module.
    endpoint: str
    #: Health-index key of the endpoint that answered, for route scoring.
    endpoint_id: str = ""


#: Deadlines moved to :mod:`tx402.deadline` at M5 so the Solana pool shares one primitive.
#: Re-exported under their original private names because the M3 tests name them, and a
#: rename would make an unrelated diff look like a behaviour change.
_with_deadline = with_deadline
_with_deadline_async = with_deadline_async


@dataclass(frozen=True, slots=True)
class _Endpoint:
    url: str
    label: str
    #: ``<caip2>|<host>`` — this endpoint's key in the shared health index.
    health_id: str


def _safe_host(url: str) -> str:
    try:
        return httpx.URL(url).netloc.decode()
    except Exception:
        return "invalid-rpc-url"


class EvmRpcPool:
    """At most two manifest RPCs; chain identity is checked before every balance read.

    The pool holds no circuit state of its own (PLAN.md O19). It asks the client's shared
    :class:`~tx402.health.HealthIndex` whether an endpoint may be used and reports what
    happened, so one provider cannot be simultaneously open here and closed elsewhere.
    """

    def __init__(
        self,
        rpc_urls: Sequence[str],
        *,
        network_id: str = "eip155",
        health: HealthIndex | None = None,
        transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None = None,
        timeout_ms: int = RPC_TIMEOUT_MS,
    ) -> None:
        self._endpoints = tuple(
            _Endpoint(
                url, _safe_host(url), HealthIndex.endpoint_id(network_id, _safe_host(url))
            )
            for url in rpc_urls[:MAX_PROVIDERS_PER_NETWORK]
        )
        self._health = health or HealthIndex()
        self._transport = transport
        if (
            isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, int)
            or timeout_ms <= 0
        ):
            raise TypeError("timeout_ms must be a positive integer")
        self._timeout_ms = timeout_ms
        self._request_id = 0

    def reset_health(self) -> None:
        for endpoint in self._endpoints:
            self._health.forget(endpoint.health_id)

    def _payload(self, method: str, params: list[Any]) -> dict[str, Any]:
        self._request_id += 1
        return {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        }

    @staticmethod
    def _result(response: httpx.Response, method: str) -> Any:
        if not response.is_success:
            raise EvmRpcError("transport", f"{method} returned an HTTP error")
        try:
            document = response.json()
        except ValueError as error:
            raise EvmRpcError("protocol", f"{method} returned non-JSON") from error
        if (
            not isinstance(document, dict)
            or "error" in document
            or "result" not in document
        ):
            raise EvmRpcError("protocol", f"{method} returned an invalid envelope")
        return document["result"]

    def _call(
        self, client: httpx.Client, endpoint: _Endpoint, method: str, params: list[Any]
    ) -> Any:
        try:
            response = with_deadline(
                lambda: client.post(endpoint.url, json=self._payload(method, params)),
                self._timeout_ms,
            )
        except TimeoutError as error:
            raise EvmRpcError("timeout", f"{method} timed out") from error
        except httpx.HTTPError as error:
            raise EvmRpcError("transport", f"{method} failed") from error
        return self._result(response, method)

    async def _call_async(
        self, client: httpx.AsyncClient, endpoint: _Endpoint, method: str, params: list[Any]
    ) -> Any:
        try:
            response = await with_deadline_async(
                client.post(endpoint.url, json=self._payload(method, params)),
                self._timeout_ms,
            )
        except TimeoutError as error:
            raise EvmRpcError("timeout", f"{method} timed out") from error
        except httpx.HTTPError as error:
            raise EvmRpcError("transport", f"{method} failed") from error
        return self._result(response, method)

    @staticmethod
    def _chain_id(raw: Any) -> int:
        if not isinstance(raw, str) or _QUANTITY.fullmatch(raw) is None:
            raise EvmRpcError("chain-id-unreadable", "RPC returned a malformed chain ID")
        value = int(raw, 16)
        if value <= 0:
            raise EvmRpcError("chain-id-unreadable", "RPC returned an invalid chain ID")
        return value

    @staticmethod
    def _balance(raw: Any) -> int:
        if raw == "0x":
            return 0
        if not isinstance(raw, str) or re.fullmatch(r"0x[0-9a-fA-F]{1,64}", raw) is None:
            raise EvmRpcError("balance-unreadable", "RPC returned a malformed balance")
        return int(raw, 16)

    @staticmethod
    def _balance_params(token: str, owner: str) -> list[Any]:
        return [{"to": token, "data": encode_balance_of_call_data(owner)}, "latest"]

    def _order(
        self, now_epoch_ms: int, attempted: set[str]
    ) -> tuple[list[_Endpoint], bool]:
        """Usable endpoints, and whether every remaining one is open.

        SPEC §6.5: an open endpoint is a last resort, permitted only when all of them are.
        """
        available = [item for item in self._endpoints if item.url not in attempted]
        usable = [
            item
            for item in available
            if self._health.state(item.health_id, now_epoch_ms) != "open"
        ]
        last_resort = not usable
        return (available if last_resort else usable), last_resort

    def _record_endpoint_failure(
        self, endpoint: _Endpoint, error: EvmRpcError, now_epoch_ms: int
    ) -> None:
        if error.failure == "chain-id-mismatch":
            # SPEC §7.1: a mismatch is not a reliability sample to average into a window.
            # It says the endpoint is serving another chain, and the clause requires moving
            # to the next RPC now.
            self._health.open(endpoint.health_id, now_epoch_ms)
        else:
            self._health.record_failure(endpoint.health_id, now_epoch_ms)

    def _guard(self, chain_id: int, token: str, owner: str) -> None:
        if _ADDRESS.fullmatch(token) is None or _ADDRESS.fullmatch(owner) is None:
            raise EvmRpcError("protocol", "Token and owner must be 20-byte addresses")
        if not self._endpoints:
            raise EvmRpcError("transport", "No RPC endpoint is configured")

    def read_balance(
        self,
        *,
        chain_id: int,
        token: str,
        owner: str,
        now_epoch_ms: int | None = None,
    ) -> EvmBalanceReading:
        """Proves ``eth_chainId`` and reads ``balanceOf`` on the same endpoint (SPEC §7.1).

        Both calls go to one endpoint on purpose: a balance is only meaningful once the
        endpoint that served it has said which chain it speaks for.
        """
        self._guard(chain_id, token, owner)
        transport = self._transport
        if transport is not None and not isinstance(transport, httpx.BaseTransport):
            raise TypeError("Sync balance reads require an httpx.BaseTransport")
        now = int(time.time() * 1_000) if now_epoch_ms is None else now_epoch_ms
        last = EvmRpcError("transport", "No RPC endpoint answered")
        attempted: set[str] = set()
        with httpx.Client(transport=transport) as client:
            while len(attempted) < len(self._endpoints):
                order, last_resort = self._order(now, attempted)
                for endpoint in order:
                    attempted.add(endpoint.url)
                    if (
                        not last_resort
                        and self._health.admit(endpoint.health_id, now) == "open"
                    ):
                        last = EvmRpcError("transport", "Base RPC circuit is open")
                        continue
                    started = time.monotonic()
                    try:
                        observed = self._chain_id(
                            self._call(client, endpoint, "eth_chainId", [])
                        )
                        if observed != chain_id:
                            raise EvmRpcError(
                                "chain-id-mismatch", "RPC serves another chain"
                            )
                        balance = self._balance(
                            self._call(
                                client,
                                endpoint,
                                "eth_call",
                                self._balance_params(token, owner),
                            )
                        )
                    except EvmRpcError as error:
                        self._record_endpoint_failure(endpoint, error, now)
                        last = error
                        continue
                    self._health.record_success(
                        endpoint.health_id, (time.monotonic() - started) * 1_000, now
                    )
                    return EvmBalanceReading(
                        balance, observed, endpoint.label, endpoint.health_id
                    )
        raise last

    async def read_balance_async(
        self,
        *,
        chain_id: int,
        token: str,
        owner: str,
        now_epoch_ms: int | None = None,
    ) -> EvmBalanceReading:
        """Asynchronous counterpart to :meth:`read_balance`, with identical failover."""
        self._guard(chain_id, token, owner)
        transport = self._transport
        if transport is not None and not isinstance(transport, httpx.AsyncBaseTransport):
            raise TypeError("Async balance reads require an httpx.AsyncBaseTransport")
        now = int(time.time() * 1_000) if now_epoch_ms is None else now_epoch_ms
        last = EvmRpcError("transport", "No RPC endpoint answered")
        attempted: set[str] = set()
        async with httpx.AsyncClient(transport=transport) as client:
            while len(attempted) < len(self._endpoints):
                order, last_resort = self._order(now, attempted)
                for endpoint in order:
                    attempted.add(endpoint.url)
                    if (
                        not last_resort
                        and self._health.admit(endpoint.health_id, now) == "open"
                    ):
                        last = EvmRpcError("transport", "Base RPC circuit is open")
                        continue
                    started = time.monotonic()
                    try:
                        observed = self._chain_id(
                            await self._call_async(client, endpoint, "eth_chainId", [])
                        )
                        if observed != chain_id:
                            raise EvmRpcError(
                                "chain-id-mismatch", "RPC serves another chain"
                            )
                        balance = self._balance(
                            await self._call_async(
                                client,
                                endpoint,
                                "eth_call",
                                self._balance_params(token, owner),
                            )
                        )
                    except EvmRpcError as error:
                        self._record_endpoint_failure(endpoint, error, now)
                        last = error
                        continue
                    self._health.record_success(
                        endpoint.health_id, (time.monotonic() - started) * 1_000, now
                    )
                    return EvmBalanceReading(
                        balance, observed, endpoint.label, endpoint.health_id
                    )
        raise last


def resolve_evm_address(signer: EvmSigner, context: Tx402ErrorContext) -> str:
    try:
        address = signer.get_address()
    except BaseException as error:
        raise SignerError(
            "Signer address lookup failed",
            context=context,
            details={"signerKind": "evm", "causeCategory": "address-unavailable"},
            cause=error,
        ) from error
    if not isinstance(address, str) or _ADDRESS.fullmatch(address) is None:
        raise SignerError(
            "Signer returned a malformed EVM address",
            context=context,
            details={"signerKind": "evm", "causeCategory": "address-unavailable"},
        )
    return address


class _UpstreamSigner:
    def __init__(
        self,
        *,
        signer: EvmSigner,
        address: str,
        plan: ExactEvmPlan,
        presentation: Mapping[str, str],
        context: Tx402ErrorContext,
    ) -> None:
        self.address = address
        self._signer = signer
        self._plan = plan
        self._presentation = presentation
        self._context = context
        self.sign_count = 0
        self.expires_at_epoch_ms = 0

    def _failure(
        self, message: str, category: str, cause: BaseException | None = None
    ) -> SignerError:
        return SignerError(
            message,
            context=self._context,
            details={"signerKind": "evm", "causeCategory": category},
            cause=cause,
        )

    def sign_typed_data(
        self,
        domain: Any,
        types: Mapping[str, Sequence[Any]],
        primary_type: str,
        message: Mapping[str, Any],
    ) -> bytes:
        if self.sign_count:
            raise self._failure(
                "Scheme requested more than one signature", "duplicate-signature-request"
            )
        if hasattr(domain, "model_dump"):
            domain_dict = domain.model_dump(by_alias=True, exclude_none=True)
        elif hasattr(domain, "__dataclass_fields__"):
            domain_dict = {
                "name": domain.name,
                "version": domain.version,
                "chainId": domain.chain_id,
                "verifyingContract": domain.verifying_contract,
            }
        else:
            domain_dict = dict(domain)
        if primary_type != "TransferWithAuthorization":
            raise self._failure("Unexpected EIP-712 primary type", "plan-mismatch")
        plan = self._plan
        if domain_dict.get("chainId") != plan.chain_id:
            raise self._failure("EIP-712 chain ID changed", "plan-mismatch")
        contract = domain_dict.get("verifyingContract")
        if (
            not isinstance(contract, str)
            or contract.lower() != plan.verifying_contract.lower()
        ):
            raise self._failure("EIP-712 verifying contract changed", "plan-mismatch")
        if (
            domain_dict.get("name") != plan.domain_name
            or domain_dict.get("version") != plan.domain_version
        ):
            raise self._failure("EIP-712 token domain changed", "plan-mismatch")
        if not _same_address(message.get("from"), plan.payer):
            raise self._failure("Authorization payer changed", "plan-mismatch")
        if not _same_address(message.get("to"), plan.recipient):
            raise self._failure("Authorization recipient changed", "plan-mismatch")
        if _quantity(message.get("value"), self._context) != int(plan.value_atomic):
            raise self._failure("Authorization amount changed", "plan-mismatch")
        if _quantity(message.get("validAfter"), self._context) != 0:
            raise self._failure("Authorization is not valid immediately", "plan-mismatch")
        valid_before = _quantity(message.get("validBefore"), self._context)
        now_seconds = time.time_ns() // 1_000_000_000
        if (
            valid_before <= now_seconds
            or valid_before > now_seconds + plan.lifetime_seconds
        ):
            raise self._failure("Authorization lifetime changed", "plan-mismatch")
        nonce = message.get("nonce")
        nonce_valid = (isinstance(nonce, bytes) and len(nonce) == 32) or (
            isinstance(nonce, str) and _NONCE.fullmatch(nonce) is not None
        )
        if not nonce_valid:
            raise self._failure("Authorization nonce is not 32 bytes", "plan-mismatch")
        narrowed_types = {
            name: tuple(_typed_field(field, self._context) for field in fields)
            for name, fields in types.items()
        }
        self.sign_count += 1
        self.expires_at_epoch_ms = valid_before * 1_000
        request = EvmTypedDataRequest(
            domain_dict,
            narrowed_types,
            primary_type,
            dict(message),
            EvmSignerPresentation(
                network=self._presentation["network"],
                asset_id=self._presentation["assetId"],
                asset_symbol=self._presentation["assetSymbol"],
                amount_atomic=plan.value_atomic,
                amount_decimal=self._presentation["amountDecimal"],
                recipient=plan.recipient,
                resource_host=self._presentation["resourceHost"],
                domain_name=plan.domain_name,
                expires_at=time.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(valid_before)
                ),
                request_hash=self._presentation["requestHash"],
            ),
        )
        try:
            signature = self._signer.sign_typed_data(request)
        except BaseException as error:
            raise self._failure(
                "Signer rejected the authorization", "signer-rejected", error
            ) from error
        if isinstance(signature, str):
            if re.fullmatch(r"0x[0-9a-fA-F]+", signature) is None:
                raise self._failure(
                    "Signer returned a malformed signature", "malformed-signature"
                )
            return bytes.fromhex(signature[2:])
        if not isinstance(signature, bytes) or not signature:
            raise self._failure(
                "Signer returned a malformed signature", "malformed-signature"
            )
        return signature


def _same_address(value: object, expected: str) -> bool:
    return isinstance(value, str) and value.lower() == expected.lower()


def _quantity(value: object, context: Tx402ErrorContext) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        return int(value)
    raise SignerError(
        "Authorization quantity is malformed",
        context=context,
        details={"signerKind": "evm", "causeCategory": "plan-mismatch"},
    )


def _typed_field(field: Any, context: Tx402ErrorContext) -> Mapping[str, str]:
    if hasattr(field, "model_dump"):
        field = field.model_dump()
    elif hasattr(field, "__dataclass_fields__"):
        field = {"name": field.name, "type": field.type}
    if (
        isinstance(field, Mapping)
        and isinstance(field.get("name"), str)
        and isinstance(field.get("type"), str)
    ):
        return {"name": field["name"], "type": field["type"]}
    raise SignerError(
        "Authorization typed-data definition is malformed",
        context=context,
        details={"signerKind": "evm", "causeCategory": "plan-mismatch"},
    )


def create_evm_authorization(
    *,
    signer: EvmSigner,
    address: str,
    plan: ExactEvmPlan,
    requirement: Mapping[str, Any],
    asset: Mapping[str, Any],
    resource_host: str,
    request_hash: str,
    context: Tx402ErrorContext,
) -> tuple[dict[str, Any], int]:
    """Ask upstream to build EIP-3009, enforcing the approved plan at the key boundary."""
    # Optional dependency boundary: importing ``tx402`` stays core-only. The audited
    # upstream EVM implementation is loaded only when an EVM authorization is created.
    try:
        from x402.mechanisms.evm.exact.client import ExactEvmScheme
    except ImportError as error:
        raise SignerError(
            "EVM support is not installed",
            context=context,
            details={"signerKind": "evm", "causeCategory": "evm-extra-missing"},
            cause=error,
        ) from error

    adapter = _UpstreamSigner(
        signer=signer,
        address=address,
        plan=plan,
        presentation={
            "network": requirement["network"],
            "assetId": f"{requirement['network']}/erc20:{asset['address']}",
            "assetSymbol": asset["symbol"],
            "amountDecimal": format_money_decimal(plan.value_atomic, asset["decimals"]),
            "resourceHost": resource_host,
            "requestHash": request_hash,
        },
        context=context,
    )
    clamped = PaymentRequirements.model_validate(
        {
            "scheme": requirement["scheme"],
            "network": requirement["network"],
            "asset": requirement["asset"],
            "amount": requirement["amountAtomic"],
            "payTo": requirement["payTo"],
            "maxTimeoutSeconds": plan.lifetime_seconds,
            "extra": dict(requirement["extra"]),
        }
    )
    try:
        payload = ExactEvmScheme(adapter).create_payment_payload(clamped)
    except SignerError:
        raise
    except BaseException as error:
        raise SignerError(
            "Failed to create the Base payment authorization",
            context=context,
            details={"signerKind": "evm", "causeCategory": "payload-creation-failed"},
            cause=error,
        ) from error
    if adapter.sign_count != 1 or not payload:
        raise SignerError(
            "Scheme did not produce exactly one authorization",
            context=context,
            details={"signerKind": "evm", "causeCategory": "unexpected-signature-count"},
        )
    return payload, adapter.expires_at_epoch_ms


# ----------------------------------------------------------------------------------------
# Chain adapter
# ----------------------------------------------------------------------------------------


def _require_evm_signer(signer: object, context: Tx402ErrorContext) -> EvmSigner:
    if not (
        getattr(signer, "kind", None) == "evm"
        and callable(getattr(signer, "get_address", None))
        and callable(getattr(signer, "sign_typed_data", None))
    ):
        raise ConfigurationError(
            "A Base route requires an EvmSigner",
            context=context,
            details={"configPath": "signers.evm", "reason": "missing-evm-signer"},
        )
    return signer  # type: ignore[return-value]


class EvmChainAdapter:
    """The Base implementation of the two questions core asks (SPEC §7.1)."""

    family = "eip155"

    def __init__(
        self,
        *,
        health: HealthIndex,
        rpc_transport: object = None,
        rpc_overrides: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self._health = health
        self._rpc_transport = rpc_transport
        #: ADR-015. Already validated and alias-resolved by ``PolicyEngine``.
        self._rpc_overrides = rpc_overrides or {}
        self._pools: dict[str, EvmRpcPool] = {}

    def _pool(self, network_id: str, network: Mapping[str, Any]) -> EvmRpcPool:
        pool = self._pools.get(network_id)
        if pool is None:
            pool = EvmRpcPool(
                # ADR-015: a caller-supplied endpoint list replaces the manifest's for this
                # network, and nothing else about the network changes. The chain-identity
                # proof still runs against whatever endpoint is used.
                self._rpc_overrides.get(network_id) or network["rpcUrls"],
                network_id=network_id,
                health=self._health,
                transport=self._rpc_transport,  # type: ignore[arg-type]
            )
            self._pools[network_id] = pool
        return pool

    def _prepare(
        self,
        request: ChainRouteRequest | ChainAuthorizationRequest,
        phase: str,
    ) -> tuple[Tx402ErrorContext, EvmSigner, str, ExactEvmPlan]:
        offer = request.requirement.requirement
        context = Tx402ErrorContext(
            request_id=request.request_id,
            phase=phase,  # type: ignore[arg-type]
            network=request.network_id,
            scheme=offer["scheme"],
            amount_atomic=offer["amountAtomic"],
            asset_id=request.requirement.asset_id,
        )
        signer = _require_evm_signer(request.signer, context)
        address = resolve_evm_address(signer, context)
        plan = plan_exact_evm_authorization(
            requirement=offer,
            network_id=request.network_id,
            network=request.network,
            asset=request.asset,
            payer=address,
            now_epoch_ms=request.now_epoch_ms,
            context=context,
        )
        return context, signer, address, plan

    @staticmethod
    def _transport_error(error: EvmRpcError, context: Tx402ErrorContext) -> TransportError:
        return TransportError(
            "Base RPC is unavailable for payment planning",
            context=context,
            details={"causeCategory": error.failure},
            cause=error,
        )

    def _route(
        self, request: ChainRouteRequest, address: str, reading: EvmBalanceReading
    ) -> ChainRoute:
        offer = request.requirement.requirement
        viable = reading.balance_atomic >= int(offer["amountAtomic"])
        return ChainRoute(
            requirement_index=offer["index"],
            network_id=request.network_id,
            scheme=offer["scheme"],
            asset_id=request.requirement.asset_id,
            amount_atomic=offer["amountAtomic"],
            signer_id=f"evm:{address}",
            balance_atomic=str(reading.balance_atomic),
            viable=viable,
            rejection_reasons=() if viable else ("insufficient-balance",),
            # The merchant bears settlement gas for the exact scheme, so the buyer's
            # expected fee in the payment asset is zero (SPEC §7.1).
            estimated_fee_atomic="0",
            endpoint_id=reading.endpoint_id,
        )

    def plan_route(self, request: ChainRouteRequest) -> ChainRoute:
        context, _signer, address, plan = self._prepare(request, "route")
        pool = self._pool(request.network_id, request.network)
        key = BALANCE_KEY_SEPARATOR.join(
            [request.network_id, plan.verifying_contract, address]
        )

        def read() -> EvmBalanceReading:
            return pool.read_balance(
                chain_id=plan.chain_id,
                token=plan.verifying_contract,
                owner=address,
                now_epoch_ms=request.now_epoch_ms,
            )

        try:
            reading = (
                read() if request.balances is None else request.balances.read(key, read)
            )
        except EvmRpcError as error:
            raise self._transport_error(error, context) from error
        return self._route(request, address, reading)

    async def plan_route_async(self, request: ChainRouteRequest) -> ChainRoute:
        context, _signer, address, plan = self._prepare(request, "route")
        pool = self._pool(request.network_id, request.network)
        key = BALANCE_KEY_SEPARATOR.join(
            [request.network_id, plan.verifying_contract, address]
        )

        def read() -> Any:
            return pool.read_balance_async(
                chain_id=plan.chain_id,
                token=plan.verifying_contract,
                owner=address,
                now_epoch_ms=request.now_epoch_ms,
            )

        try:
            reading = (
                await read()
                if request.balances is None
                else await request.balances.read_async(key, read)
            )
        except EvmRpcError as error:
            raise self._transport_error(error, context) from error
        return self._route(request, address, reading)

    def create_authorization(
        self, request: ChainAuthorizationRequest
    ) -> ChainAuthorization:
        context, signer, address, plan = self._prepare(request, "sign")
        payload, expires = create_evm_authorization(
            signer=signer,
            address=address,
            plan=plan,
            requirement=request.requirement.requirement,
            asset=request.asset,
            resource_host=request.resource_host,
            request_hash=request.request_hash,
            context=context,
        )
        return ChainAuthorization(
            x402_version=2,
            payload=payload,
            expires_at_epoch_ms=expires,
            signer_id=f"evm:{address}",
        )

    async def create_authorization_async(
        self, request: ChainAuthorizationRequest
    ) -> ChainAuthorization:
        # Upstream's EVM scheme is synchronous and CPU-bound around one signer call; the
        # caller runs it off the event loop rather than this adapter pretending otherwise.
        return self.create_authorization(request)

    def reset_health(self) -> None:
        for pool in self._pools.values():
            pool.reset_health()


def create_evm_chain_adapter(
    *,
    health: HealthIndex,
    rpc_transport: object = None,
    rpc_overrides: Mapping[str, Sequence[str]] | None = None,
) -> EvmChainAdapter:
    return EvmChainAdapter(
        health=health, rpc_transport=rpc_transport, rpc_overrides=rpc_overrides
    )
