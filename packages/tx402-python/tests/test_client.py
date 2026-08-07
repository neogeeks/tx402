from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable, Iterator
from typing import Any, Literal

import httpx
import pytest
from x402.http.utils import (
    decode_payment_signature_header,
    encode_payment_required_header,
    encode_payment_response_header,
)
from x402.schemas import (
    PaymentPayload,
    PaymentRequired,
    PaymentRequirements,
    ResourceInfo,
    SettleResponse,
)

from tx402 import (
    AmbiguousPaymentError,
    AsyncTx402Client,
    BudgetExceededError,
    ConfigurationError,
    DomainNotAllowedError,
    InsufficientLiquidityError,
    NonReplayableRequestError,
    Policy,
    ReservedHeaderError,
    ResourceDeliveryError,
    SignerError,
    TransportError,
    Tx402Client,
    UnsupportedSchemeError,
)
from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.evm import EvmTypedDataRequest
from tx402.ledger import MemorySpendStore

NETWORK = "eip155:8453"
ASSET = BUNDLED_MANIFEST["networks"][NETWORK]["assets"][0]["address"]
PAYER = "0x00000000000000000000000000000000000000A1"
RECIPIENT = "0x1234567890AbcdEF1234567890aBcdef12345678"
URL = "https://merchant.test/pay"


class Signer:
    kind: Literal["evm"] = "evm"

    def __init__(self, signature: bytes | str = b"s" * 65) -> None:
        self.signature = signature
        self.requests: list[EvmTypedDataRequest] = []

    def get_address(self) -> str:
        return PAYER

    def sign_typed_data(self, request: EvmTypedDataRequest) -> bytes | str:
        self.requests.append(request)
        return self.signature


def challenge_header(
    *,
    amount: str = "50000",
    network: str = NETWORK,
    scheme: str = "exact",
    asset: str = ASSET,
    url: str = URL,
) -> str:
    required = PaymentRequired(
        x402_version=2,
        resource=ResourceInfo(url=url),
        accepts=[
            PaymentRequirements(
                scheme=scheme,
                network=network,
                asset=asset,
                amount=amount,
                pay_to=RECIPIENT,
                max_timeout_seconds=60,
                extra={"name": "USD Coin", "version": "2"},
            )
        ],
    )
    return encode_payment_required_header(required)


def settlement_header(success: bool = True) -> str:
    return encode_payment_response_header(
        SettleResponse(
            success=success,
            transaction="0xtx",
            network=NETWORK,
            error_reason=None if success else "rejected",
        )
    )


def rpc_transport(balance: int = 100_000, *, chain_id: int = 8453) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        document = json.loads(request.read())
        result = hex(chain_id) if document["method"] == "eth_chainId" else hex(balance)
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": document["id"], "result": result}
        )

    return httpx.MockTransport(handler)


class Merchant:
    def __init__(
        self,
        *,
        header: str | None = None,
        paid_status: int = 200,
        payment_response: str | None = None,
        paid_exception: httpx.HTTPError | None = None,
        paid_delay_ms: int = 0,
    ) -> None:
        self.header = header or challenge_header()
        self.paid_status = paid_status
        self.payment_response = (
            settlement_header() if payment_response is None else payment_response
        )
        self.paid_exception = paid_exception
        self.paid_delay_ms = paid_delay_ms
        self.requests: list[tuple[bytes, httpx.Headers]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = request.read()
        self.requests.append((body, request.headers.copy()))
        if "payment-signature" not in request.headers:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": self.header})
        if self.paid_exception is not None:
            raise self.paid_exception
        if self.paid_delay_ms:
            time.sleep(self.paid_delay_ms / 1_000)
        headers = (
            {"PAYMENT-RESPONSE": self.payment_response} if self.payment_response else {}
        )
        return httpx.Response(self.paid_status, headers=headers, content=b"delivered")


def client(
    merchant: Callable[[httpx.Request], httpx.Response],
    *,
    signer: Signer | None = None,
    store: MemorySpendStore | None = None,
    rpc: httpx.BaseTransport | None = None,
    **kwargs: Any,
) -> Tx402Client:
    return Tx402Client(
        evm_signer=signer or Signer(),
        spend_store=store,
        transport=httpx.MockTransport(merchant),
        evm_rpc_transport=rpc or rpc_transport(),
        **kwargs,
    )


def test_t001_non_402_is_returned_unchanged_without_signing() -> None:
    signer = Signer()
    with client(lambda _request: httpx.Response(204), signer=signer) as sdk:
        response = sdk.get(URL)
    assert response.status_code == 204
    assert signer.requests == []


def test_t002_sync_paid_call_reserves_signs_retries_and_commits() -> None:
    merchant = Merchant()
    signer = Signer()
    store = MemorySpendStore()
    with client(merchant, signer=signer, store=store) as sdk:
        response = sdk.post(URL, json={"prompt": "hello"}, headers={"Idempotency-Key": "k"})
    assert response.status_code == 200
    assert response.content == b"delivered"
    assert len(merchant.requests) == 2
    assert merchant.requests[0][0] == merchant.requests[1][0]
    assert merchant.requests[1][1]["Idempotency-Key"] == "k"
    assert merchant.requests[1][1]["X-TX402-REQUEST-ID"]
    payload = decode_payment_signature_header(merchant.requests[1][1]["PAYMENT-SIGNATURE"])
    assert isinstance(payload, PaymentPayload)
    assert payload.accepted.amount == "50000"
    assert len(signer.requests) == 1
    state = store.get_budget_state(
        policy_scope="merchant.test",
        asset_id=f"{NETWORK}/erc20:{ASSET}",
        now_epoch_ms=int(time.time() * 1000),
    )
    assert state.committed_atomic == "50000"
    assert state.reserved_atomic == "0"
    assert state.entries[0].settlement_id == "0xtx"


@pytest.mark.asyncio
async def test_t002_async_paid_call_matches_sync() -> None:
    merchant = Merchant()
    signer = Signer()
    async with AsyncTx402Client(
        evm_signer=signer,
        transport=httpx.MockTransport(merchant),
        evm_rpc_transport=rpc_transport(),
    ) as sdk:
        response = await sdk.post(URL, content=b"body")
    assert response.status_code == 200
    assert [body for body, _headers in merchant.requests] == [b"body", b"body"]
    assert len(signer.requests) == 1


def test_inspect_stops_after_the_first_402() -> None:
    merchant = Merchant()
    signer = Signer()
    with client(merchant, signer=signer) as sdk:
        inspection = sdk.inspect("POST", URL, content=b"body")
    assert inspection.response.status_code == 402
    assert inspection.payment_required is not None
    assert inspection.payment_required["requirements"][0]["amountAtomic"] == "50000"
    assert len(merchant.requests) == 1
    assert signer.requests == []


@pytest.mark.asyncio
async def test_async_inspect_and_non_402() -> None:
    merchant = Merchant()
    async with AsyncTx402Client(
        transport=httpx.MockTransport(merchant), evm_rpc_transport=rpc_transport()
    ) as sdk:
        inspection = await sdk.inspect("GET", URL)
    assert inspection.payment_required is not None

    async with AsyncTx402Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(201))
    ) as sdk:
        inspection = await sdk.inspect("GET", URL)
        response = await sdk.get(URL)
    assert inspection.payment_required is None
    assert response.status_code == 201


def test_reserved_header_https_domain_and_stream_guards_precede_transport() -> None:
    calls = 0

    def merchant(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    with client(merchant) as sdk:
        with pytest.raises(ReservedHeaderError):
            sdk.get(URL, headers={"PAYMENT-SIGNATURE": "secret"})
        with pytest.raises(ConfigurationError):
            sdk.get("http://public.example/pay")
        with pytest.raises(DomainNotAllowedError):
            client(merchant, policy=Policy(allowed_domains=["safe.test"])).get(URL)

        def stream() -> Iterator[bytes]:
            yield b"one"

        with pytest.raises(NonReplayableRequestError):
            sdk.post(URL, content=stream())
    assert calls == 0


def test_insecure_localhost_body_factory_and_request_validation() -> None:
    local_url = "http://127.0.0.1:8000/pay"
    merchant = Merchant(header=challenge_header(url=local_url))
    bodies = iter((b"first", b"second"))
    with client(merchant, allow_insecure_localhost=True) as sdk:
        response = sdk.post(local_url, body_factory=lambda: next(bodies))
        assert response.status_code == 200
        with pytest.raises(TypeError, match="combined"):
            sdk.post(local_url, body_factory=lambda: b"x", content=b"y")
    assert [body for body, _headers in merchant.requests] == [b"first", b"second"]


@pytest.mark.parametrize(
    ("body_factory", "reason"),
    [
        (lambda: 1, "body-factory-invalid"),
        (lambda: (_ for _ in ()).throw(RuntimeError("secret")), "body-factory-failed"),
    ],
)
def test_body_factory_retry_failures_are_typed(
    body_factory: Callable[[], Any], reason: str
) -> None:
    calls = 0

    def factory() -> Any:
        nonlocal calls
        calls += 1
        return b"initial" if calls == 1 else body_factory()

    with client(Merchant()) as sdk, pytest.raises(NonReplayableRequestError) as raised:
        sdk.post(URL, body_factory=factory)
    assert raised.value.details["reason"] == reason


def test_policy_signer_liquidity_and_rpc_failures_never_sign() -> None:
    signer = Signer()
    with (
        client(Merchant(header=challenge_header(amount="500001")), signer=signer) as sdk,
        pytest.raises(BudgetExceededError),
    ):
        sdk.get(URL)
    with (
        client(Merchant(), signer=signer, rpc=rpc_transport(balance=1)) as sdk,
        pytest.raises(InsufficientLiquidityError),
    ):
        sdk.get(URL)
    with (
        client(Merchant(), signer=signer, rpc=rpc_transport(chain_id=1)) as sdk,
        pytest.raises(TransportError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.details["causeCategory"] == "chain-id-mismatch"
    assert signer.requests == []


def test_no_signer_or_non_evm_route_is_unsupported() -> None:
    merchant = Merchant()
    with (
        Tx402Client(
            transport=httpx.MockTransport(merchant), evm_rpc_transport=rpc_transport()
        ) as sdk,
        pytest.raises(UnsupportedSchemeError),
    ):
        sdk.get(URL)
    solana = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    header = challenge_header(
        network=solana,
        asset=BUNDLED_MANIFEST["networks"][solana]["assets"][0]["mint"],
    )
    with client(Merchant(header=header)) as sdk, pytest.raises(UnsupportedSchemeError):
        sdk.get(URL)


def test_signer_failure_releases_reservation() -> None:
    signer = Signer(signature="bad")
    store = MemorySpendStore()
    with client(Merchant(), signer=signer, store=store) as sdk, pytest.raises(SignerError):
        sdk.get(URL)
    state = store.get_budget_state(
        policy_scope="merchant.test",
        asset_id=f"{NETWORK}/erc20:{ASSET}",
        now_epoch_ms=int(time.time() * 1000),
    )
    assert [reservation.state for reservation in state.reservations] == ["released"]


def test_definitive_merchant_refusal_releases() -> None:
    """A 403 that claims *no* settlement is a refusal, and refusals give the budget back.

    ``payment_response=""`` is not decoration. Before S15b this fixture sent a
    **successful** settlement header on its 403 by default and the test asserted release —
    the audit
    filed that as O44, because the assertion was pinning the implementation rather than
    SPEC §5.3. The settled counterpart is
    :func:`test_settled_403_commits_and_reports_paid`.
    """
    store = MemorySpendStore()
    with (
        client(Merchant(paid_status=403, payment_response=""), store=store) as sdk,
        pytest.raises(ResourceDeliveryError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.context.paid is False
    assert raised.value.details["reason"] == "paid-request-rejected"
    assert [
        item.state
        for item in store.get_budget_state(
            policy_scope="merchant.test",
            asset_id=f"{NETWORK}/erc20:{ASSET}",
            now_epoch_ms=int(time.time() * 1000),
        ).reservations
    ] == ["released"]


@pytest.mark.parametrize(
    ("status", "category"), [(503, "server-error"), (307, "redirect-not-followed")]
)
def test_ambiguous_status_retains_reservation(status: int, category: str) -> None:
    store = MemorySpendStore()
    with (
        client(Merchant(paid_status=status, payment_response=""), store=store) as sdk,
        pytest.raises(AmbiguousPaymentError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.details["causeCategory"] == category
    assert [
        item.state
        for item in store.get_budget_state(
            policy_scope="merchant.test",
            asset_id=f"{NETWORK}/erc20:{ASSET}",
            now_epoch_ms=int(time.time() * 1000),
        ).reservations
    ] == ["reserved"]


def test_unsuccessful_settlement_releases() -> None:
    merchant = Merchant(payment_response=settlement_header(False))
    with client(merchant) as sdk, pytest.raises(ResourceDeliveryError) as raised:
        sdk.get(URL)
    assert raised.value.details["reason"] == "settlement-unsuccessful"


def test_absent_payment_response_still_delivers() -> None:
    """Upstream marks PAYMENT-RESPONSE optional, so its absence cannot fail a 2xx."""
    with client(Merchant(payment_response="")) as sdk:
        assert sdk.get(URL).status_code == 200


def test_malformed_payment_response_is_not_delivery(caplog: Any) -> None:
    """A header that is present and does not decode is a protocol violation (O53).

    It used to be folded in with an absent header and the resource returned as paid
    success. SPEC §6.7 makes parsing a precondition of paid-success, so the call now ends
    ambiguously — and, because a corrupt header is no evidence that nothing settled, the
    reservation is held rather than released.
    """
    del caplog
    store = MemorySpendStore()
    with (
        client(Merchant(payment_response="not-base64"), store=store) as sdk,
        pytest.raises(AmbiguousPaymentError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.details["causeCategory"] == "settlement-metadata-unparseable"
    assert [
        item.state
        for item in store.get_budget_state(
            policy_scope="merchant.test",
            asset_id=f"{NETWORK}/erc20:{ASSET}",
            now_epoch_ms=int(time.time() * 1000),
        ).reservations
    ] == ["reserved"]


def test_initial_and_paid_transport_failures_are_distinct() -> None:
    def initial(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret")

    with client(initial) as sdk, pytest.raises(TransportError) as raised:
        sdk.get(URL)
    assert raised.value.context.phase == "initial"

    merchant = Merchant(paid_exception=httpx.ConnectError("secret"))
    with client(merchant) as sdk, pytest.raises(AmbiguousPaymentError) as paid_raised:
        sdk.get(URL)
    assert paid_raised.value.details["causeCategory"] == "transport-after-signature"


def test_paid_retry_timeout_is_owned_by_tx402() -> None:
    """A deadline and a reset are the same fact about settlement (SPEC §6.7).

    Both report ``transport-after-signature``: the signature is on the wire either way, and
    the frozen ``completion.paid-attempt`` vectors give a transmission that never completed
    exactly one category in both languages.
    """
    with (
        client(Merchant(paid_delay_ms=1_100), payment_retry_timeout_ms=1_000) as sdk,
        pytest.raises(AmbiguousPaymentError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.details["causeCategory"] == "transport-after-signature"


@pytest.mark.asyncio
async def test_async_paid_retry_transport_failure_and_timeout() -> None:
    merchant = Merchant(paid_exception=httpx.ConnectError("secret"))
    async with AsyncTx402Client(
        evm_signer=Signer(),
        transport=httpx.MockTransport(merchant),
        evm_rpc_transport=rpc_transport(),
    ) as sdk:
        with pytest.raises(AmbiguousPaymentError) as raised:
            await sdk.get(URL)
    assert raised.value.details["causeCategory"] == "transport-after-signature"

    release = asyncio.Event()
    cancellation_seen = asyncio.Event()

    async def slow(request: httpx.Request) -> httpx.Response:
        if "payment-signature" not in request.headers:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": challenge_header()})
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancellation_seen.set()
            await release.wait()
        return httpx.Response(200)

    async with AsyncTx402Client(
        evm_signer=Signer(),
        transport=httpx.MockTransport(slow),
        evm_rpc_transport=rpc_transport(),
        payment_retry_timeout_ms=1_000,
    ) as sdk:

        async def assert_sdk_deadline() -> None:
            with pytest.raises(AmbiguousPaymentError) as raised:
                await sdk.get(URL)
            assert raised.value.details["causeCategory"] == "transport-after-signature"

        await asyncio.wait_for(assert_sdk_deadline(), timeout=2)
        await asyncio.sleep(0)
        assert cancellation_seen.is_set()
        release.set()
        await asyncio.sleep(0)


def test_constructor_and_budget_snapshot_contract() -> None:
    with pytest.raises(ConfigurationError):
        Tx402Client(payment_retry_timeout_ms=0)
    with pytest.raises(ConfigurationError):
        AsyncTx402Client(payment_retry_timeout_ms=0)
    sdk = Tx402Client(transport=httpx.MockTransport(lambda _request: httpx.Response(200)))
    state = sdk.get_budget_state(
        policy_scope="merchant.test", asset_id=f"{NETWORK}/erc20:{ASSET}", now_epoch_ms=0
    )
    sdk.close()
    assert state.store_kind == "memory"
