"""Solana / SVM exact-payment adapter (SPEC §7.2, ADR-010, ADR-013).

Counterpart to ``packages/tx402/src/solana/*``. Everything the TypeScript adapter does is
done here — canonical ATA derivation, genesis-proved balance reads, exact SPL USDC transfer
construction, and complete pre-sign transaction validation — with one structural difference
recorded in **ADR-013**: the transaction is compiled by tx402 from ``solders`` primitives
rather than delegated to PyPI ``x402``'s ``ExactSvmScheme``.

Two independent facts force that, and either alone would be sufficient:

- ``ExactSvmScheme`` reads ``signer.keypair`` and calls ``keypair.sign_message(...)``. Its
  signer contract *is* a raw Ed25519 key pair. SEC-001 forbids tx402's core from requiring
  one, and SPEC §7.2 requires the Solana signer to sign the transaction bytes "without
  exporting secret material". There is no shim that satisfies both.
- The module cannot be imported at all against the resolved dependency set: it does
  ``from solana.rpc.api import Client``, and ``solana`` 0.40 removed that module. tx402
  would not have an upstream SVM path available even if the signer contract fitted.

What is *not* re-implemented is anything SPEC §3.2 protects: base58, Ed25519, SHA-256, and
program-derived-address arithmetic all come from ``solders``, the same audited library
upstream builds on. The instruction layout, compute-budget defaults, account ordering, and
signature slots reproduce upstream's byte-for-byte, so a facilitator cannot tell a tx402
authorization from an ``ExactSvmScheme`` one.
"""

from __future__ import annotations

import base64
import binascii
import os
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol, TypeVar, runtime_checkable

import httpx
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

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
)
from tx402.health import HealthIndex
from tx402.money import format_money_decimal
from tx402.routing import BALANCE_KEY_SEPARATOR

#: Program identifiers, identical on every Solana cluster.
TOKEN_PROGRAM_ADDRESS: Final = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ADDRESS: Final = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ASSOCIATED_TOKEN_PROGRAM_ADDRESS: Final = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
COMPUTE_BUDGET_PROGRAM_ADDRESS: Final = "ComputeBudget111111111111111111111111111111"
MEMO_PROGRAM_ADDRESS: Final = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

#: Upstream's compute-budget defaults. Reproduced so the wire bytes match exactly.
DEFAULT_COMPUTE_UNIT_LIMIT: Final = 20_000
DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS: Final = 1
MAX_MEMO_BYTES: Final = 256

#: A Solana transaction may not exceed one IPv6 MTU-safe packet.
SOLANA_WIRE_TRANSACTION_MAX_BYTES: Final = 1232

SVM_RPC_TIMEOUT_MS: Final = 600

_UINT: Final = "0123456789"

#: RPC parameter shapes, declared once so sync and async cannot drift apart.
_BLOCKHASH_PARAMS: Final[list[Any]] = [{"commitment": "confirmed"}]


def _account_info_params(token_account: str) -> list[Any]:
    return [token_account, {"encoding": "jsonParsed", "commitment": "confirmed"}]


T = TypeVar("T")


# ----------------------------------------------------------------------------------------
# Public signer contract (SPEC §7.2, SEC-001)
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SolanaSignerPresentation:
    """Human-readable summary accompanying an SVM signing request (SPEC §6.6)."""

    network: str
    asset_id: str
    asset_symbol: str
    amount_atomic: str
    amount_decimal: str
    recipient: str
    resource_host: str
    fee_payer: str
    source_token_account: str
    destination_token_account: str
    #: Transaction lifetime as the last block height at which it may land.
    last_valid_block_height: str
    request_hash: str


@dataclass(frozen=True, slots=True)
class SolanaSignRequest:
    """The exact bytes an external Solana signer is asked to authorize.

    ``message_bytes`` are the bytes Ed25519 signs — the compiled message with its ``0x80``
    version prefix, exactly as the runtime will verify them. ``transaction_bytes`` are the
    complete *unsigned* wire transaction and exist so a hardware or KMS adapter can display
    or independently decode the same transaction. Both are Sensitive authorization material
    and must never be logged (SEC-003).
    """

    message_bytes: bytes
    transaction_bytes: bytes
    presentation: SolanaSignerPresentation


@runtime_checkable
class SolanaSigner(Protocol):
    """Caller-owned Solana signer. It receives bytes and a presentation, never a key."""

    kind: Literal["solana"]

    def get_public_key(self) -> str: ...

    #: Returns the 64-byte Ed25519 signature over ``request.message_bytes``.
    def sign_transaction(self, request: SolanaSignRequest) -> bytes: ...


def is_solana_signer(candidate: object) -> bool:
    """Structural check, not ``isinstance``.

    Callers routinely pass an object literal, a wallet wrapper, or a proxy around a remote
    signer. None of those share a base class with anything tx402 owns.
    """
    return (
        getattr(candidate, "kind", None) == "solana"
        and callable(getattr(candidate, "get_public_key", None))
        and callable(getattr(candidate, "sign_transaction", None))
    )


# ----------------------------------------------------------------------------------------
# Deterministic authorization plan (frozen for cross-language parity at M4)
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExactSvmPlan:
    network_id: str
    genesis_hash: str
    mint: str
    payer: str
    recipient: str
    fee_payer: str
    source_token_account: str
    destination_token_account: str
    amount_atomic: str
    decimals: int
    lifetime_seconds: int
    last_valid_block_height: str
    recent_blockhash: str | None = None
    memo: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """The frozen fixture shape. Optional members are omitted, never emitted as null."""
        document: dict[str, Any] = {
            "networkId": self.network_id,
            "genesisHash": self.genesis_hash,
            "mint": self.mint,
            "payer": self.payer,
            "recipient": self.recipient,
            "feePayer": self.fee_payer,
            "sourceTokenAccount": self.source_token_account,
            "destinationTokenAccount": self.destination_token_account,
            "amountAtomic": self.amount_atomic,
            "decimals": self.decimals,
            "lifetimeSeconds": self.lifetime_seconds,
        }
        if self.recent_blockhash is not None:
            document["recentBlockhash"] = self.recent_blockhash
        document["lastValidBlockHeight"] = self.last_valid_block_height
        if self.memo is not None:
            document["memo"] = self.memo
        return document


def _invalid(
    message: str,
    reason: str,
    schema_path: str,
    context: Tx402ErrorContext,
    cause: BaseException | None = None,
) -> InvalidPaymentRequiredError:
    return InvalidPaymentRequiredError(
        message,
        context=context,
        details={"reason": reason, "schemaPath": schema_path},
        cause=cause,
    )


def _checked_address(
    value: object, reason: str, path: str, context: Tx402ErrorContext
) -> str:
    if not isinstance(value, str):
        raise _invalid(
            "Solana requirement is missing an address",
            reason.replace("-invalid", "-missing"),
            path,
            context,
        )
    try:
        return str(Pubkey.from_string(value))
    except (ValueError, TypeError) as error:
        raise _invalid(
            "Solana requirement contains an invalid address", reason, path, context, error
        ) from error


def _last_valid_block_height(extra: Mapping[str, Any]) -> str:
    value = extra.get("lastValidBlockHeight")
    # Canonical unsigned decimal only: no sign, no leading zeros, no exponent. Anything else
    # is treated as absent rather than coerced, so the two languages agree on the string.
    if (
        isinstance(value, str)
        and value
        and all(character in _UINT for character in value)
        and (value == "0" or not value.startswith("0"))
    ):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return str(value)
    return "0"


def derive_associated_token_account(*, mint: str, owner: str) -> str:
    """Derives one canonical SPL associated token account.

    PDA seeds are ``[owner, token_program, mint]`` under the Associated Token Program, which
    is what every SPL wallet and the upstream scheme both use. Nothing is invented here:
    ``solders`` performs the SHA-256 and the off-curve search (SPEC §3.2).
    """
    address, _bump = Pubkey.find_program_address(
        [
            bytes(Pubkey.from_string(owner)),
            bytes(Pubkey.from_string(TOKEN_PROGRAM_ADDRESS)),
            bytes(Pubkey.from_string(mint)),
        ],
        Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM_ADDRESS),
    )
    return str(address)


def derive_payment_atas(*, mint: str, payer: str, recipient: str) -> tuple[str, str]:
    """The source and destination ATAs for one payment."""
    return (
        derive_associated_token_account(mint=mint, owner=payer),
        derive_associated_token_account(mint=mint, owner=recipient),
    )


def plan_exact_svm_authorization(
    *,
    requirement: Mapping[str, Any],
    network_id: str,
    network: Mapping[str, Any],
    asset: Mapping[str, Any],
    payer: str,
    max_authorization_seconds: int = MAX_AUTHORIZATION_SECONDS,
    context: Tx402ErrorContext,
) -> ExactSvmPlan:
    """Pure derivation of the SPL transfer tx402 is willing to sign.

    Reads no clock and performs no I/O, so the same inputs always produce the same plan —
    which is what lets the frozen ``svm.authorization-plan`` vectors pin it in both
    languages.
    """
    if asset.get("tokenProgram") != "spl-token":
        # Token-2022 is constructible but excluded from v0.1 (SPEC §7.2). It is rejected at
        # planning rather than at signing so no balance read is spent on it either.
        raise ConfigurationError(
            "Solana asset is not canonical SPL Token",
            context=context,
            details={"configPath": "manifest.networks", "reason": "token-2022-excluded"},
        )
    if (
        requirement["scheme"] != "exact"
        or requirement["network"] != network_id
        or requirement["asset"] != asset["mint"]
    ):
        raise _invalid(
            "Solana requirement does not match the manifest exact-payment asset",
            "svm-route-mismatch",
            "/accepts",
            context,
        )
    checked_payer = _checked_address(payer, "svm-payer-invalid", "/payer", context)
    recipient = _checked_address(
        requirement["payTo"], "svm-pay-to-invalid", "/payTo", context
    )
    extra: Mapping[str, Any] = requirement["extra"]
    fee_payer = _checked_address(
        extra.get("feePayer"), "svm-feePayer-invalid", "/extra/feePayer", context
    )
    source, destination = derive_payment_atas(
        mint=asset["mint"], payer=checked_payer, recipient=recipient
    )
    recent_blockhash = extra.get("recentBlockhash")
    memo = extra.get("memo")
    return ExactSvmPlan(
        network_id=network_id,
        genesis_hash=network["genesisHash"],
        mint=asset["mint"],
        payer=checked_payer,
        recipient=recipient,
        fee_payer=fee_payer,
        source_token_account=source,
        destination_token_account=destination,
        amount_atomic=requirement["amountAtomic"],
        decimals=asset["decimals"],
        lifetime_seconds=min(
            MAX_AUTHORIZATION_SECONDS,
            max_authorization_seconds,
            requirement["maxTimeoutSeconds"],
        ),
        last_valid_block_height=_last_valid_block_height(extra),
        recent_blockhash=recent_blockhash if isinstance(recent_blockhash, str) else None,
        memo=memo if isinstance(memo, str) else None,
    )


# ----------------------------------------------------------------------------------------
# RPC: cluster identity and canonical SPL ATA balances
# ----------------------------------------------------------------------------------------

SvmRpcFailure = Literal[
    "circuit-open",
    "genesis-hash-mismatch",
    "genesis-hash-unreadable",
    "account-unreadable",
    "transport",
    "timeout",
    "protocol",
]


class SvmRpcError(Exception):
    def __init__(self, failure: SvmRpcFailure, message: str) -> None:
        super().__init__(message)
        self.failure = failure


@dataclass(frozen=True, slots=True)
class SvmBalanceReading:
    balance_atomic: int
    token_account: str
    #: Host only. The full URL may carry a provider API key and never leaves this module.
    endpoint: str
    rpc_url: str
    #: Health-index key of the endpoint that answered, for route scoring.
    endpoint_id: str


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


class SvmRpcPool:
    """At most two manifest RPCs; the cluster is proved before every account read.

    The pool holds no circuit state of its own (PLAN.md O22). It asks the client's shared
    :class:`~tx402.health.HealthIndex` whether an endpoint may be used and reports what
    happened, so one provider cannot be simultaneously open here and closed elsewhere.
    """

    def __init__(
        self,
        rpc_urls: Sequence[str],
        *,
        network_id: str = "solana",
        health: HealthIndex | None = None,
        transport: object = None,
        timeout_ms: int = SVM_RPC_TIMEOUT_MS,
        max_providers: int = MAX_PROVIDERS_PER_NETWORK,
    ) -> None:
        self._endpoints = tuple(
            _Endpoint(
                url, _safe_host(url), HealthIndex.endpoint_id(network_id, _safe_host(url))
            )
            for url in rpc_urls[:max_providers]
        )
        self._health = health or HealthIndex()
        self._transport = transport
        self._timeout_ms = timeout_ms
        self._request_id = 0

    def reset_health(self) -> None:
        for endpoint in self._endpoints:
            self._health.forget(endpoint.health_id)

    # -- request plumbing ----------------------------------------------------------------

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
            raise SvmRpcError("transport", f"{method} returned HTTP {response.status_code}")
        try:
            document = response.json()
        except ValueError as error:
            raise SvmRpcError("protocol", f"{method} returned non-JSON") from error
        if (
            not isinstance(document, dict)
            or "error" in document
            or "result" not in document
        ):
            raise SvmRpcError("protocol", f"{method} returned a JSON-RPC error")
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
            raise SvmRpcError("timeout", f"{method} timed out") from error
        except httpx.HTTPError as error:
            raise SvmRpcError("transport", f"{method} failed") from error
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
            raise SvmRpcError("timeout", f"{method} timed out") from error
        except httpx.HTTPError as error:
            raise SvmRpcError("transport", f"{method} failed") from error
        return self._result(response, method)

    # -- endpoint selection --------------------------------------------------------------

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

    @staticmethod
    def _genesis_result(observed: Any, expected: str) -> None:
        if not isinstance(observed, str) or not observed:
            raise SvmRpcError(
                "genesis-hash-unreadable", "RPC returned a malformed genesis hash"
            )
        if observed != expected:
            raise SvmRpcError(
                "genesis-hash-mismatch", "RPC serves a different Solana cluster"
            )

    def _record_endpoint_failure(
        self, endpoint: _Endpoint, error: SvmRpcError, now_epoch_ms: int
    ) -> None:
        if error.failure == "genesis-hash-mismatch":
            # SPEC §7.2's counterpart to the EVM chain-ID rule: the wrong cluster is not a
            # reliability signal to average, it is grounds to stop using this endpoint now.
            self._health.open(endpoint.health_id, now_epoch_ms)
        else:
            self._health.record_failure(endpoint.health_id, now_epoch_ms)

    # -- one attempt loop, shared by every read ------------------------------------------

    def _sync_client(self) -> httpx.Client:
        transport = self._transport
        if transport is not None and not isinstance(transport, httpx.BaseTransport):
            raise TypeError("Sync Solana reads require an httpx.BaseTransport")
        return httpx.Client(transport=transport)

    def _async_client(self) -> httpx.AsyncClient:
        transport = self._transport
        if transport is not None and not isinstance(transport, httpx.AsyncBaseTransport):
            raise TypeError("Async Solana reads require an httpx.AsyncBaseTransport")
        return httpx.AsyncClient(transport=transport)

    def _use(
        self,
        *,
        genesis_hash: str,
        now_epoch_ms: int,
        failure_message: str,
        operation: Callable[[httpx.Client, _Endpoint], T],
    ) -> tuple[T, _Endpoint]:
        """Runs ``operation`` on the first endpoint that proves its cluster, else fails
        over.

        Genesis is proved on the *same* endpoint that will serve the operation, on every
        read (SPEC §7.2). The health observation spans the whole use — proof plus whatever
        it was proved for — because an endpoint that answers ``getGenesisHash`` quickly and
        then stalls on the account read has not been healthy.
        """
        if not self._endpoints:
            raise SvmRpcError("transport", "No RPC endpoint is configured for this cluster")
        last = SvmRpcError("transport", failure_message)
        attempted: set[str] = set()
        with self._sync_client() as client:
            while len(attempted) < len(self._endpoints):
                order, last_resort = self._order(now_epoch_ms, attempted)
                for endpoint in order:
                    attempted.add(endpoint.url)
                    if (
                        not last_resort
                        and self._health.admit(endpoint.health_id, now_epoch_ms) == "open"
                    ):
                        last = SvmRpcError("circuit-open", "Solana RPC circuit is open")
                        continue
                    started = time.monotonic()
                    try:
                        self._genesis_result(
                            self._call(client, endpoint, "getGenesisHash", []), genesis_hash
                        )
                        value = operation(client, endpoint)
                    except SvmRpcError as error:
                        self._record_endpoint_failure(endpoint, error, now_epoch_ms)
                        last = error
                        continue
                    self._health.record_success(
                        endpoint.health_id,
                        (time.monotonic() - started) * 1_000,
                        now_epoch_ms,
                    )
                    return value, endpoint
        raise last

    async def _use_async(
        self,
        *,
        genesis_hash: str,
        now_epoch_ms: int,
        failure_message: str,
        operation: Callable[[httpx.AsyncClient, _Endpoint], Awaitable[T]],
    ) -> tuple[T, _Endpoint]:
        """Asynchronous counterpart to :meth:`_use`, with identical failover semantics."""
        if not self._endpoints:
            raise SvmRpcError("transport", "No RPC endpoint is configured for this cluster")
        last = SvmRpcError("transport", failure_message)
        attempted: set[str] = set()
        async with self._async_client() as client:
            while len(attempted) < len(self._endpoints):
                order, last_resort = self._order(now_epoch_ms, attempted)
                for endpoint in order:
                    attempted.add(endpoint.url)
                    if (
                        not last_resort
                        and self._health.admit(endpoint.health_id, now_epoch_ms) == "open"
                    ):
                        last = SvmRpcError("circuit-open", "Solana RPC circuit is open")
                        continue
                    started = time.monotonic()
                    try:
                        self._genesis_result(
                            await self._call_async(client, endpoint, "getGenesisHash", []),
                            genesis_hash,
                        )
                        value = await operation(client, endpoint)
                    except SvmRpcError as error:
                        self._record_endpoint_failure(endpoint, error, now_epoch_ms)
                        last = error
                        continue
                    self._health.record_success(
                        endpoint.health_id,
                        (time.monotonic() - started) * 1_000,
                        now_epoch_ms,
                    )
                    return value, endpoint
        raise last

    # -- public reads --------------------------------------------------------------------

    def read_balance(
        self,
        *,
        genesis_hash: str,
        mint: str,
        owner: str,
        decimals: int,
        now_epoch_ms: int,
    ) -> SvmBalanceReading:
        token_account = derive_associated_token_account(mint=mint, owner=owner)

        def read(client: httpx.Client, endpoint: _Endpoint) -> int:
            return _parse_token_account(
                self._call(
                    client, endpoint, "getAccountInfo", _account_info_params(token_account)
                ),
                owner,
                mint,
                decimals,
            )

        balance, endpoint = self._use(
            genesis_hash=genesis_hash,
            now_epoch_ms=now_epoch_ms,
            failure_message="No Solana RPC returned an ATA balance",
            operation=read,
        )
        return SvmBalanceReading(
            balance_atomic=balance,
            token_account=token_account,
            endpoint=endpoint.label,
            rpc_url=endpoint.url,
            endpoint_id=endpoint.health_id,
        )

    async def read_balance_async(
        self,
        *,
        genesis_hash: str,
        mint: str,
        owner: str,
        decimals: int,
        now_epoch_ms: int,
    ) -> SvmBalanceReading:
        token_account = derive_associated_token_account(mint=mint, owner=owner)

        async def read(client: httpx.AsyncClient, endpoint: _Endpoint) -> int:
            return _parse_token_account(
                await self._call_async(
                    client, endpoint, "getAccountInfo", _account_info_params(token_account)
                ),
                owner,
                mint,
                decimals,
            )

        balance, endpoint = await self._use_async(
            genesis_hash=genesis_hash,
            now_epoch_ms=now_epoch_ms,
            failure_message="No Solana RPC returned an ATA balance",
            operation=read,
        )
        return SvmBalanceReading(
            balance_atomic=balance,
            token_account=token_account,
            endpoint=endpoint.label,
            rpc_url=endpoint.url,
            endpoint_id=endpoint.health_id,
        )

    def latest_blockhash(self, *, genesis_hash: str, now_epoch_ms: int) -> str:
        """Proves the cluster again, then reads a blockhash to bound the transaction.

        The proof is repeated immediately before signing rather than reused from planning:
        the endpoint that answered the balance read may have been swapped behind a load
        balancer since, and SPEC §7.2 makes cluster identity a precondition of *trusting*
        anything the endpoint says.
        """

        def read(client: httpx.Client, endpoint: _Endpoint) -> str:
            return _parse_blockhash(
                self._call(client, endpoint, "getLatestBlockhash", _BLOCKHASH_PARAMS)
            )

        blockhash, _endpoint = self._use(
            genesis_hash=genesis_hash,
            now_epoch_ms=now_epoch_ms,
            failure_message="No Solana RPC returned a blockhash",
            operation=read,
        )
        return blockhash

    async def latest_blockhash_async(self, *, genesis_hash: str, now_epoch_ms: int) -> str:
        async def read(client: httpx.AsyncClient, endpoint: _Endpoint) -> str:
            return _parse_blockhash(
                await self._call_async(
                    client, endpoint, "getLatestBlockhash", _BLOCKHASH_PARAMS
                )
            )

        blockhash, _endpoint = await self._use_async(
            genesis_hash=genesis_hash,
            now_epoch_ms=now_epoch_ms,
            failure_message="No Solana RPC returned a blockhash",
            operation=read,
        )
        return blockhash


def _parse_blockhash(result: Any) -> str:
    value = result.get("value") if isinstance(result, Mapping) else None
    blockhash = value.get("blockhash") if isinstance(value, Mapping) else None
    if not isinstance(blockhash, str) or not blockhash:
        raise SvmRpcError("protocol", "getLatestBlockhash returned no blockhash")
    return blockhash


def _parse_token_account(
    result: Any, expected_owner: str, expected_mint: str, expected_decimals: int
) -> int:
    """Reads a `jsonParsed` SPL token account, refusing anything that is not one.

    An absent account is a real zero balance — an ATA that has never received the token does
    not exist on chain — so it reports 0 rather than an error. Everything else must match
    the route exactly: an endpoint that returns *some* token account is not evidence about
    *this* one.
    """
    if not isinstance(result, Mapping) or "value" not in result:
        raise SvmRpcError("account-unreadable", "getAccountInfo returned no value member")
    value = result["value"]
    if value is None:
        return 0
    if not isinstance(value, Mapping) or value.get("owner") != TOKEN_PROGRAM_ADDRESS:
        raise SvmRpcError("account-unreadable", "ATA is not owned by SPL Token")
    data = value.get("data")
    parsed = data.get("parsed") if isinstance(data, Mapping) else None
    info = parsed.get("info") if isinstance(parsed, Mapping) else None
    token_amount = info.get("tokenAmount") if isinstance(info, Mapping) else None
    amount = token_amount.get("amount") if isinstance(token_amount, Mapping) else None
    if (
        not isinstance(info, Mapping)
        or info.get("owner") != expected_owner
        or info.get("mint") != expected_mint
        or not isinstance(token_amount, Mapping)
        or token_amount.get("decimals") != expected_decimals
        or not isinstance(amount, str)
        or not amount
        or not all(character in _UINT for character in amount)
    ):
        raise SvmRpcError("account-unreadable", "ATA contents do not match the route")
    return int(amount)


# ----------------------------------------------------------------------------------------
# Transaction construction and the pre-sign boundary
# ----------------------------------------------------------------------------------------


def _signer_failure(
    message: str,
    cause_category: str,
    context: Tx402ErrorContext,
    cause: BaseException | None = None,
) -> SignerError:
    return SignerError(
        message,
        context=context,
        details={"signerKind": "solana", "causeCategory": cause_category},
        cause=cause,
    )


def build_exact_svm_message(
    plan: ExactSvmPlan, blockhash: str, memo_bytes: bytes
) -> MessageV0:
    """Compiles the exact-scheme transfer message (ADR-013).

    Instruction order, compute-budget discriminators and defaults, ``TransferChecked``
    account ordering, and the fee payer at signature slot 0 all reproduce upstream's layout
    exactly, so a facilitator verifying the payload cannot distinguish this from one built
    by ``ExactSvmScheme``.
    """
    compute_budget = Pubkey.from_string(COMPUTE_BUDGET_PROGRAM_ADDRESS)
    return MessageV0.try_compile(
        payer=Pubkey.from_string(plan.fee_payer),
        instructions=[
            Instruction(
                program_id=compute_budget,
                accounts=[],
                data=bytes([2]) + DEFAULT_COMPUTE_UNIT_LIMIT.to_bytes(4, "little"),
            ),
            Instruction(
                program_id=compute_budget,
                accounts=[],
                data=bytes([3])
                + DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS.to_bytes(8, "little"),
            ),
            Instruction(
                program_id=Pubkey.from_string(TOKEN_PROGRAM_ADDRESS),
                accounts=[
                    AccountMeta(
                        Pubkey.from_string(plan.source_token_account),
                        is_signer=False,
                        is_writable=True,
                    ),
                    AccountMeta(
                        Pubkey.from_string(plan.mint), is_signer=False, is_writable=False
                    ),
                    AccountMeta(
                        Pubkey.from_string(plan.destination_token_account),
                        is_signer=False,
                        is_writable=True,
                    ),
                    AccountMeta(
                        Pubkey.from_string(plan.payer), is_signer=True, is_writable=False
                    ),
                ],
                data=bytes([12])
                + int(plan.amount_atomic).to_bytes(8, "little")
                + bytes([plan.decimals]),
            ),
            Instruction(
                program_id=Pubkey.from_string(MEMO_PROGRAM_ADDRESS),
                accounts=[],
                data=memo_bytes,
            ),
        ],
        address_lookup_table_accounts=[],
        recent_blockhash=Hash.from_string(blockhash),
    )


def _validate_transaction(
    message: MessageV0,
    transaction_bytes: bytes,
    plan: ExactSvmPlan,
    blockhash: str,
    memo_bytes: bytes,
    context: Tx402ErrorContext,
) -> None:
    """Validates the complete unsigned authorization at the last pre-sign boundary.

    Decoded from the serialized bytes rather than read off the builder's own objects: what
    matters is what the *wire* says, and re-reading it is the only check that would catch a
    construction bug rather than agreeing with it.
    """
    if len(transaction_bytes) > SOLANA_WIRE_TRANSACTION_MAX_BYTES:
        raise _signer_failure(
            "Solana transaction exceeds the serialized size limit",
            "transaction-too-large",
            context,
        )
    try:
        decoded = MessageV0.from_bytes(bytes(message))
    except Exception as error:
        raise _signer_failure(
            "Solana transaction message could not be decoded",
            "transaction-invalid",
            context,
            error,
        ) from error

    keys = list(decoded.account_keys)
    if str(keys[0]) != plan.fee_payer:
        raise _signer_failure(
            "Solana fee payer does not match the challenge", "plan-mismatch", context
        )
    if str(decoded.recent_blockhash) != blockhash:
        raise _signer_failure(
            "Solana transaction blockhash does not match the approved requirement",
            "plan-mismatch",
            context,
        )
    instructions = list(decoded.instructions)
    if len(instructions) != 4:
        raise _signer_failure(
            "Solana authorization has an unexpected instruction count",
            "account-constraints",
            context,
        )
    programs = [str(keys[item.program_id_index]) for item in instructions]
    if programs != [
        COMPUTE_BUDGET_PROGRAM_ADDRESS,
        COMPUTE_BUDGET_PROGRAM_ADDRESS,
        TOKEN_PROGRAM_ADDRESS,
        MEMO_PROGRAM_ADDRESS,
    ]:
        raise _signer_failure(
            "Solana authorization contains an unsupported program",
            "account-constraints",
            context,
        )

    transfer = instructions[2]
    accounts = list(transfer.accounts)
    data = bytes(transfer.data)
    if len(accounts) != 4 or len(data) != 10 or data[0] != 12:
        raise _signer_failure(
            "SPL transfer instruction is malformed", "transaction-invalid", context
        )
    observed = {
        "source": str(keys[accounts[0]]),
        "mint": str(keys[accounts[1]]),
        "destination": str(keys[accounts[2]]),
        "authority": str(keys[accounts[3]]),
        "amount": int.from_bytes(data[1:9], "little"),
        "decimals": data[9],
    }
    if observed != {
        "source": plan.source_token_account,
        "mint": plan.mint,
        "destination": plan.destination_token_account,
        "authority": plan.payer,
        "amount": int(plan.amount_atomic),
        "decimals": plan.decimals,
    }:
        raise _signer_failure(
            "SPL transfer accounts or amount do not match the approved route",
            "plan-mismatch",
            context,
        )

    if bytes(instructions[3].data) != memo_bytes:
        raise _signer_failure(
            "Solana transaction memo does not match the plan", "plan-mismatch", context
        )


def _memo_bytes(plan: ExactSvmPlan, context: Tx402ErrorContext) -> bytes:
    """The merchant's memo, or a fresh 16-byte nonce rendered as hex (SPEC §6.6).

    Every authorization must be unique. When the merchant does not dictate a memo, this is
    the uniqueness primitive the upstream scheme uses, and it is regenerated per attempt
    so a re-challenge never re-sends the same transaction.
    """
    if plan.memo is None:
        return binascii.hexlify(os.urandom(16))
    encoded = plan.memo.encode("utf-8")
    if len(encoded) > MAX_MEMO_BYTES:
        raise _signer_failure(
            "Merchant memo exceeds the SPL memo size limit", "plan-mismatch", context
        )
    return encoded


def create_svm_authorization(
    *,
    signer: SolanaSigner,
    plan: ExactSvmPlan,
    blockhash: str,
    presentation: SolanaSignerPresentation,
    lifetime_seconds: int,
    context: Tx402ErrorContext,
) -> tuple[dict[str, Any], int]:
    """Builds, validates, and signs one exact SPL USDC authorization.

    Returns the upstream-shaped payload and the epoch millisecond at which the signed
    authorization stops being valid. The clock is read only *after* the transaction exists,
    which is what makes the expiry a statement about the thing signed rather than about the
    moment planning happened (the S5 clock-boundary rule).
    """
    memo_bytes = _memo_bytes(plan, context)
    try:
        message = build_exact_svm_message(plan, blockhash, memo_bytes)
    except Exception as error:
        raise _signer_failure(
            "Solana transaction could not be constructed",
            "payload-creation-failed",
            context,
            error,
        ) from error

    unsigned = bytes(
        VersionedTransaction.populate(message, [Signature.default(), Signature.default()])
    )
    _validate_transaction(message, unsigned, plan, blockhash, memo_bytes, context)

    # The bytes Ed25519 actually covers: the compiled message behind its version prefix.
    message_bytes = bytes([0x80]) + bytes(message)
    expires_at_epoch_ms = int(time.time() * 1_000) + lifetime_seconds * 1_000

    try:
        raw_signature = signer.sign_transaction(
            SolanaSignRequest(
                message_bytes=message_bytes,
                transaction_bytes=unsigned,
                presentation=presentation,
            )
        )
    except SignerError:
        raise
    except BaseException as error:
        raise _signer_failure(
            "Solana signer rejected the transaction", "signing-failed", context, error
        ) from error
    if not isinstance(raw_signature, bytes) or len(raw_signature) != 64:
        raise _signer_failure(
            "Solana signer returned a malformed signature", "signature-malformed", context
        )

    # Slot 0 is the facilitator's fee-payer signature, which the buyer never produces; the
    # buyer's authority signature is slot 1. Leaving slot 0 as the default is precisely what
    # makes this a partially-signed transaction the facilitator completes.
    transaction = VersionedTransaction.populate(
        message, [Signature.default(), Signature.from_bytes(raw_signature)]
    )
    return (
        {"transaction": base64.b64encode(bytes(transaction)).decode("ascii")},
        expires_at_epoch_ms,
    )


# ----------------------------------------------------------------------------------------
# Chain adapter
# ----------------------------------------------------------------------------------------


def _require_signer(signer: object, context: Tx402ErrorContext) -> SolanaSigner:
    if not is_solana_signer(signer):
        raise ConfigurationError(
            "A Solana route requires a SolanaSigner",
            context=context,
            details={"configPath": "signers.solana", "reason": "missing-solana-signer"},
        )
    return signer  # type: ignore[return-value]


def resolve_solana_public_key(signer: SolanaSigner, context: Tx402ErrorContext) -> str:
    try:
        value = signer.get_public_key()
    except BaseException as error:
        raise _signer_failure(
            "Signer public-key lookup failed", "address-unavailable", context, error
        ) from error
    if not isinstance(value, str):
        raise _signer_failure(
            "Signer returned a malformed Solana public key", "address-unavailable", context
        )
    try:
        return str(Pubkey.from_string(value))
    except (ValueError, TypeError) as error:
        raise _signer_failure(
            "Signer returned a malformed Solana public key",
            "address-unavailable",
            context,
            error,
        ) from error


def _transport_error(error: BaseException, context: Tx402ErrorContext) -> TransportError:
    return TransportError(
        "Solana RPC is unavailable for payment planning",
        context=context,
        details={
            "causeCategory": error.failure
            if isinstance(error, SvmRpcError)
            else "transport"
        },
        cause=error,
    )


class SvmChainAdapter:
    """The Solana implementation of the two questions core asks (SPEC §7.2)."""

    family = "solana"

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
        self._pools: dict[str, SvmRpcPool] = {}

    def _pool(self, network_id: str, network: Mapping[str, Any]) -> SvmRpcPool:
        pool = self._pools.get(network_id)
        if pool is None:
            pool = SvmRpcPool(
                # ADR-015: a caller-supplied endpoint list replaces the manifest's for this
                # network, and nothing else about the network changes. The chain-identity
                # proof still runs against whatever endpoint is used.
                self._rpc_overrides.get(network_id) or network["rpcUrls"],
                network_id=network_id,
                health=self._health,
                transport=self._rpc_transport,
            )
            self._pools[network_id] = pool
        return pool

    def _prepare(
        self, request: ChainRouteRequest | ChainAuthorizationRequest, phase: str
    ) -> tuple[Tx402ErrorContext, SolanaSigner, str, ExactSvmPlan]:
        offer = request.requirement.requirement
        context = Tx402ErrorContext(
            request_id=request.request_id,
            phase=phase,  # type: ignore[arg-type]
            network=request.network_id,
            scheme=offer["scheme"],
            amount_atomic=offer["amountAtomic"],
            asset_id=request.requirement.asset_id,
        )
        if "genesisHash" not in request.network:
            raise ConfigurationError(
                "Manifest network is not a Solana network",
                context=context,
                details={"configPath": "manifest.networks", "reason": "not-an-svm-network"},
            )
        if "mint" not in request.asset:
            raise ConfigurationError(
                "Manifest asset is not a Solana asset",
                context=context,
                details={"configPath": "manifest.networks", "reason": "not-an-svm-asset"},
            )
        signer = _require_signer(request.signer, context)
        public_key = resolve_solana_public_key(signer, context)
        plan = plan_exact_svm_authorization(
            requirement=offer,
            network_id=request.network_id,
            network=request.network,
            asset=request.asset,
            payer=public_key,
            max_authorization_seconds=MAX_AUTHORIZATION_SECONDS,
            context=context,
        )
        return context, signer, public_key, plan

    def _route(
        self, request: ChainRouteRequest, public_key: str, reading: SvmBalanceReading
    ) -> ChainRoute:
        offer = request.requirement.requirement
        viable = reading.balance_atomic >= int(offer["amountAtomic"])
        return ChainRoute(
            requirement_index=offer["index"],
            network_id=request.network_id,
            scheme=offer["scheme"],
            asset_id=request.requirement.asset_id,
            amount_atomic=offer["amountAtomic"],
            signer_id=f"solana:{public_key}",
            balance_atomic=str(reading.balance_atomic),
            viable=viable,
            rejection_reasons=() if viable else ("insufficient-balance",),
            # The facilitator is the fee payer for the SVM exact scheme (SPEC §7.2), so the
            # buyer's expected fee in the payment asset is zero.
            estimated_fee_atomic="0",
            endpoint_id=reading.endpoint_id,
        )

    def plan_route(self, request: ChainRouteRequest) -> ChainRoute:
        context, _signer, public_key, plan = self._prepare(request, "route")
        pool = self._pool(request.network_id, request.network)
        key = BALANCE_KEY_SEPARATOR.join([request.network_id, plan.mint, public_key])

        def read() -> SvmBalanceReading:
            return pool.read_balance(
                genesis_hash=plan.genesis_hash,
                mint=plan.mint,
                owner=public_key,
                decimals=plan.decimals,
                now_epoch_ms=request.now_epoch_ms,
            )

        try:
            reading = (
                read() if request.balances is None else request.balances.read(key, read)
            )
        except SvmRpcError as error:
            raise _transport_error(error, context) from error
        return self._route(request, public_key, reading)

    async def plan_route_async(self, request: ChainRouteRequest) -> ChainRoute:
        context, _signer, public_key, plan = self._prepare(request, "route")
        pool = self._pool(request.network_id, request.network)
        key = BALANCE_KEY_SEPARATOR.join([request.network_id, plan.mint, public_key])

        def read() -> Any:
            return pool.read_balance_async(
                genesis_hash=plan.genesis_hash,
                mint=plan.mint,
                owner=public_key,
                decimals=plan.decimals,
                now_epoch_ms=request.now_epoch_ms,
            )

        try:
            reading = (
                await read()
                if request.balances is None
                else await request.balances.read_async(key, read)
            )
        except SvmRpcError as error:
            raise _transport_error(error, context) from error
        return self._route(request, public_key, reading)

    def _presentation(
        self, request: ChainAuthorizationRequest, plan: ExactSvmPlan
    ) -> SolanaSignerPresentation:
        offer = request.requirement.requirement
        return SolanaSignerPresentation(
            network=request.network_id,
            asset_id=request.requirement.asset_id,
            asset_symbol=request.asset["symbol"],
            amount_atomic=offer["amountAtomic"],
            amount_decimal=format_money_decimal(
                offer["amountAtomic"], request.asset["decimals"]
            ),
            recipient=plan.recipient,
            resource_host=request.resource_host,
            fee_payer=plan.fee_payer,
            source_token_account=plan.source_token_account,
            destination_token_account=plan.destination_token_account,
            last_valid_block_height=plan.last_valid_block_height,
            request_hash=request.request_hash,
        )

    def create_authorization(
        self, request: ChainAuthorizationRequest
    ) -> ChainAuthorization:
        context, signer, public_key, plan = self._prepare(request, "sign")
        blockhash = plan.recent_blockhash
        if blockhash is None:
            try:
                blockhash = self._pool(
                    request.network_id, request.network
                ).latest_blockhash(
                    genesis_hash=plan.genesis_hash, now_epoch_ms=request.now_epoch_ms
                )
            except SvmRpcError as error:
                raise _transport_error(error, context) from error
        payload, expires = create_svm_authorization(
            signer=signer,
            plan=plan,
            blockhash=blockhash,
            presentation=self._presentation(request, plan),
            lifetime_seconds=min(plan.lifetime_seconds, request.max_authorization_seconds),
            context=context,
        )
        return ChainAuthorization(
            x402_version=2,
            payload=payload,
            expires_at_epoch_ms=expires,
            signer_id=f"solana:{public_key}",
        )

    async def create_authorization_async(
        self, request: ChainAuthorizationRequest
    ) -> ChainAuthorization:
        context, signer, public_key, plan = self._prepare(request, "sign")
        blockhash = plan.recent_blockhash
        if blockhash is None:
            try:
                blockhash = await self._pool(
                    request.network_id, request.network
                ).latest_blockhash_async(
                    genesis_hash=plan.genesis_hash, now_epoch_ms=request.now_epoch_ms
                )
            except SvmRpcError as error:
                raise _transport_error(error, context) from error
        payload, expires = create_svm_authorization(
            signer=signer,
            plan=plan,
            blockhash=blockhash,
            presentation=self._presentation(request, plan),
            lifetime_seconds=min(plan.lifetime_seconds, request.max_authorization_seconds),
            context=context,
        )
        return ChainAuthorization(
            x402_version=2,
            payload=payload,
            expires_at_epoch_ms=expires,
            signer_id=f"solana:{public_key}",
        )

    def reset_health(self) -> None:
        for pool in self._pools.values():
            pool.reset_health()


def create_svm_chain_adapter(
    *,
    health: HealthIndex,
    rpc_transport: object = None,
    rpc_overrides: Mapping[str, Sequence[str]] | None = None,
) -> SvmChainAdapter:
    return SvmChainAdapter(
        health=health, rpc_transport=rpc_transport, rpc_overrides=rpc_overrides
    )
