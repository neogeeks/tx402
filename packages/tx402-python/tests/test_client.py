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
    RecipientPolicy,
    RecipientUnpinnedError,
    ReservedHeaderError,
    ResourceDeliveryError,
    SignerError,
    SpendScopeFrozenError,
    TransportError,
    Tx402Client,
    UnsupportedSchemeError,
)
from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.evm import EvmTypedDataRequest
from tx402.ledger import BudgetState, MemorySpendStore, ReservationRef, SpendEntry
from tx402.policy import normalize_policy_host

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
    ] == ["exposed"]


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
    """A header that is present and does not decode is a protocol violation.

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
    ] == ["exposed"]


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
    """A deadline and a reset are the same fact about settlement.

    Both report ``transport-after-signature``: the signature is on the wire either way, and
    the frozen ``completion.paid-attempt`` vectors give a transmission that never completed
    exactly one category in both languages.
    """
    # The 1_000 ms deadline must fire before the paid attempt completes. ``with_deadline``
    # races the attempt on an abandoned daemon thread, so the margin is between the main
    # thread's ``queue.get`` timeout and that thread finishing its ``time.sleep``. A 100 ms
    # margin flaked on loaded CI (a late-scheduled ``get`` let the daemon post first); a
    # 5_000 ms delay makes the deadline win under any realistic jitter, and — because the
    # daemon is abandoned, never joined — the test still returns at ~1_000 ms, not 5_000 ms.
    with (
        client(Merchant(paid_delay_ms=5_000), payment_retry_timeout_ms=1_000) as sdk,
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


# --- SPEC §7 / ADR-026: the pre-transmission exposure fence ---------------------------


class _LevelLogger:
    """Captures every event with the level it was emitted at."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def debug(self, event: Any) -> None:
        self.events.append(("debug", dict(event)))

    def info(self, event: Any) -> None:
        self.events.append(("info", dict(event)))

    def warn(self, event: Any) -> None:
        self.events.append(("warn", dict(event)))

    def error(self, event: Any) -> None:
        self.events.append(("error", dict(event)))

    def exposed(self) -> list[tuple[str, dict[str, Any]]]:
        return [(lvl, e) for lvl, e in self.events if e.get("event") == "payment.exposed"]


class _FailingExposeStore:
    """A store whose ``expose`` fails like an outage; reserve/release still work."""

    kind = "expose-explodes"

    def __init__(self) -> None:
        self._inner = MemorySpendStore()
        self.capabilities = self._inner.capabilities

    def reserve(self, **kwargs: Any) -> Any:
        return self._inner.reserve(**kwargs)

    def commit(self, **kwargs: Any) -> Any:
        return self._inner.commit(**kwargs)

    def release(self, **kwargs: Any) -> Any:
        return self._inner.release(**kwargs)

    def expose(self, **kwargs: Any) -> Any:
        raise RuntimeError("fence backend unreachable")

    def get_budget_state(self, **kwargs: Any) -> Any:
        return self._inner.get_budget_state(**kwargs)

    def list_exposed(self, **kwargs: Any) -> Any:
        return self._inner.list_exposed(**kwargs)

    def is_frozen(self, **kwargs: Any) -> bool:
        return self._inner.is_frozen(**kwargs)


def _fence_budget(store: Any) -> Any:
    return store.get_budget_state(
        policy_scope="merchant.test",
        asset_id=f"{NETWORK}/erc20:{ASSET}",
        now_epoch_ms=int(time.time() * 1000),
    )


def test_exposure_fence_resolves_committed_and_emits_info_on_delivery() -> None:
    store = MemorySpendStore()
    logger = _LevelLogger()
    with client(Merchant(), store=store, logger=logger) as sdk:
        assert sdk.get(URL).status_code == 200
    state = _fence_budget(store)
    # The fence exposed the reservation before transmission; a delivered payment commits it,
    # so the amount lands in cumulativeCommitted with nothing stranded in exposedTotal.
    assert state.committed_atomic == "50000"
    assert state.exposed_atomic == "0"
    assert state.reserved_atomic == "0"
    exposed = logger.exposed()
    assert len(exposed) == 1
    assert exposed[0][0] == "info"
    assert exposed[0][1]["amountAtomic"] == "50000"


def test_exposure_fence_resolves_released_when_the_merchant_refuses() -> None:
    store = MemorySpendStore()
    with (
        client(Merchant(paid_status=403, payment_response=""), store=store) as sdk,
        pytest.raises(ResourceDeliveryError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.details["reason"] == "paid-request-rejected"
    # A definitive refusal is evidence nothing settled: the exposed reservation is released.
    state = _fence_budget(store)
    assert state.committed_atomic == "0"
    assert state.reserved_atomic == "0"
    assert state.exposed_atomic == "0"


def test_exposure_fence_failure_aborts_transmission_and_releases_sync() -> None:
    store = _FailingExposeStore()
    signer = Signer()
    merchant = Merchant()
    logger = _LevelLogger()
    # Constructed directly (not via the `client` helper) so the failing store types cleanly.
    with (
        Tx402Client(
            evm_signer=signer,
            spend_store=store,
            transport=httpx.MockTransport(merchant),
            evm_rpc_transport=rpc_transport(),
            logger=logger,
        ) as sdk,
        pytest.raises(TransportError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.retryable is True
    assert raised.value.details["causeCategory"] == "exposure-fence-failed"
    assert raised.value.details["storeKind"] == "expose-explodes"
    # Signed (the fence is after signing) but never transmitted: only the initial 402
    # request reached the merchant, and the reservation was released, so no budget is held.
    assert len(signer.requests) == 1
    assert len(merchant.requests) == 1
    state = _fence_budget(store)
    assert state.reserved_atomic == "0"
    assert state.exposed_atomic == "0"
    assert state.committed_atomic == "0"
    exposed = logger.exposed()
    assert len(exposed) == 1
    assert exposed[0][0] == "error"
    assert exposed[0][1]["reason"] == "exposure-fence-failed"


@pytest.mark.asyncio
async def test_exposure_fence_resolves_committed_on_the_async_path() -> None:
    store = MemorySpendStore()
    logger = _LevelLogger()
    async with AsyncTx402Client(
        evm_signer=Signer(),
        spend_store=store,
        transport=httpx.MockTransport(Merchant()),
        evm_rpc_transport=rpc_transport(),
        logger=logger,
    ) as sdk:
        assert (await sdk.get(URL)).status_code == 200
    state = _fence_budget(store)
    assert state.committed_atomic == "50000"
    assert state.exposed_atomic == "0"
    exposed = logger.exposed()
    assert len(exposed) == 1
    assert exposed[0][0] == "info"


@pytest.mark.asyncio
async def test_exposure_fence_failure_aborts_transmission_and_releases_async() -> None:
    store = _FailingExposeStore()
    signer = Signer()
    merchant = Merchant()
    async with AsyncTx402Client(
        evm_signer=signer,
        spend_store=store,
        transport=httpx.MockTransport(merchant),
        evm_rpc_transport=rpc_transport(),
    ) as sdk:
        with pytest.raises(TransportError) as raised:
            await sdk.get(URL)
    # The async fence runs through the same `_dispatch` seam as reserve and commit; a
    # failure aborts the transmit and releases exactly as the sync path does.
    assert raised.value.details["causeCategory"] == "exposure-fence-failed"
    assert len(signer.requests) == 1
    assert len(merchant.requests) == 1
    state = _fence_budget(store)
    assert state.reserved_atomic == "0"
    assert state.exposed_atomic == "0"


def _frozen_events(logger: _LevelLogger) -> list[tuple[str, dict[str, Any]]]:
    return [(lvl, e) for lvl, e in logger.events if e.get("event") == "spend.frozen"]


def test_kill_switch_denies_before_the_signer_and_emits_spend_frozen_sync() -> None:
    store = MemorySpendStore()
    # Whole-store freeze: atomic_global_freeze is True in-process, so "*" is a permitted
    # scope and blocks every reserve.
    store.freeze("*")
    signer = Signer()
    merchant = Merchant()
    logger = _LevelLogger()
    with (
        client(merchant, signer=signer, store=store, logger=logger) as sdk,
        pytest.raises(SpendScopeFrozenError) as raised,
    ):
        sdk.get(URL)
    # The freeze check is reserve step 2 — reached before any signer exists in scope
    # (SEC-002), so it is a non-retryable policy refusal and nothing is signed.
    assert raised.value.retryable is False
    assert raised.value.retryability == "no"
    assert raised.value.details["frozenScope"] == "*"
    assert signer.requests == []
    # Only the initial 402 probe reached the merchant; no paid retry was transmitted.
    assert len(merchant.requests) == 1
    frozen = _frozen_events(logger)
    assert len(frozen) == 1
    assert frozen[0][0] == "warn"


def test_kill_switch_admits_again_once_unfrozen_sync() -> None:
    store = MemorySpendStore()
    store.freeze("*")
    store.unfreeze("*")
    signer = Signer()
    with client(Merchant(), signer=signer, store=store) as sdk:
        assert sdk.get(URL).status_code == 200
    assert len(signer.requests) == 1


@pytest.mark.asyncio
async def test_kill_switch_denies_on_the_async_path_and_emits_spend_frozen() -> None:
    store = MemorySpendStore()
    store.freeze("*")
    signer = Signer()
    merchant = Merchant()
    logger = _LevelLogger()
    async with AsyncTx402Client(
        evm_signer=signer,
        spend_store=store,
        transport=httpx.MockTransport(merchant),
        evm_rpc_transport=rpc_transport(),
        logger=logger,
    ) as sdk:
        with pytest.raises(SpendScopeFrozenError) as raised:
            await sdk.get(URL)
    # The async reserve is offloaded through the same _dispatch seam; the frozen refusal
    # propagates and emits spend.frozen exactly as the sync path does.
    assert raised.value.details["frozenScope"] == "*"
    assert signer.requests == []
    assert len(merchant.requests) == 1
    frozen = _frozen_events(logger)
    assert len(frozen) == 1
    assert frozen[0][0] == "warn"


# ── SPEC §6 recipient pinning (ADR-023: run the behaviour) ──────────────────────────────

SCOPE = normalize_policy_host(URL)


def _recipient_events(logger: _LevelLogger, name: str) -> list[tuple[str, dict[str, Any]]]:
    return [(lvl, e) for lvl, e in logger.events if e.get("event") == name]


def test_recipient_tofu_establishes_pin_and_emits_recipient_pinned_sync() -> None:
    store = MemorySpendStore()
    store.set_tofu_enabled(SCOPE, True)
    signer = Signer()
    logger = _LevelLogger()
    with client(
        Merchant(),
        signer=signer,
        store=store,
        logger=logger,
        recipient_policy=RecipientPolicy(mode="tofu"),
    ) as sdk:
        assert sdk.get(URL).status_code == 200
    assert len(signer.requests) == 1
    # The claim happened in the reserve atom; the store pins the merchant's payTo,
    # canonicalized to lowercase hex.
    assert store.get_recipient_pins(SCOPE, NETWORK) == (RECIPIENT.lower(),)
    pinned = _recipient_events(logger, "recipient.pinned")
    assert len(pinned) == 1
    assert pinned[0][0] == "info"
    assert pinned[0][1]["network"] == NETWORK
    assert pinned[0][1]["recipient"] == RECIPIENT.lower()


def test_recipient_tofu_second_call_re_emits_nothing_sync() -> None:
    store = MemorySpendStore()
    store.set_tofu_enabled(SCOPE, True)
    logger = _LevelLogger()
    with client(
        Merchant(),
        store=store,
        logger=logger,
        recipient_policy=RecipientPolicy(mode="tofu"),
    ) as sdk:
        assert sdk.get(URL).status_code == 200
        assert sdk.get(URL).status_code == 200
    # The pin was claimed once; the second reserve matched it (replay-safe, ADR-028).
    assert len(_recipient_events(logger, "recipient.pinned")) == 1


class _FailingPinStore(MemorySpendStore):
    """A store whose advisory recipient read is DOWN — an infrastructure outage."""

    def get_recipient_pins(self, scope: str, network: str) -> tuple[str, ...]:
        raise RuntimeError("recipient pin store is down")


def test_o17_recipient_store_outage_fails_closed_sync() -> None:
    store = _FailingPinStore()
    store.set_tofu_enabled(SCOPE, True)
    signer = Signer()
    logger = _LevelLogger()
    with (
        client(
            Merchant(),
            signer=signer,
            store=store,
            logger=logger,
            recipient_policy=RecipientPolicy(mode="tofu"),
        ) as sdk,
        pytest.raises(TransportError) as raised,
    ):
        sdk.get(URL)
    # §6.3: an advisory recipient-store outage is a retryable TransportError, not a refusal.
    assert raised.value.details.get("causeCategory") == "recipient-store-unavailable"
    assert raised.value.retryable is True
    # Fail-closed: pre-signature, so nothing was signed; request.failed fired once.
    assert signer.requests == []
    assert len(_recipient_events(logger, "request.failed")) == 1


@pytest.mark.asyncio
async def test_o17_recipient_store_outage_fails_closed_async() -> None:
    # O38: the ASYNC recipient pre-filter (`_recipient_filter_async`) must fail closed
    # identically — the async path was byte-parallel to the sync one but had no regression.
    store = _FailingPinStore()
    store.set_tofu_enabled(SCOPE, True)
    signer = Signer()
    logger = _LevelLogger()
    with pytest.raises(TransportError) as raised:
        async with AsyncTx402Client(
            evm_signer=signer,
            spend_store=store,
            transport=httpx.MockTransport(Merchant()),
            evm_rpc_transport=rpc_transport(),
            recipient_policy=RecipientPolicy(mode="tofu"),
            logger=logger,
        ) as sdk:
            await sdk.get(URL)
    assert raised.value.details.get("causeCategory") == "recipient-store-unavailable"
    assert raised.value.retryable is True
    assert signer.requests == []
    assert len(_recipient_events(logger, "request.failed")) == 1


class _FailingRecipientPolicyStore(MemorySpendStore):
    """A store whose recipient PIN read succeeds (empty) but whose recipient POLICY read is
    DOWN. The second recipient read is reached only when there is no pin and TOFU is
    unprovisioned, so it exercises the store-outage arm the pin store misses."""

    def get_recipient_policy(self, scope: str) -> dict[str, bool]:
        raise RuntimeError("recipient policy store is down")


def test_o17_recipient_policy_read_outage_fails_closed_sync() -> None:
    store = _FailingRecipientPolicyStore()
    signer = Signer()
    logger = _LevelLogger()
    with (
        client(
            Merchant(),
            signer=signer,
            store=store,
            logger=logger,
            recipient_policy=RecipientPolicy(mode="tofu"),
        ) as sdk,
        pytest.raises(TransportError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.details.get("causeCategory") == "recipient-store-unavailable"
    assert raised.value.retryable is True
    assert signer.requests == []
    assert len(_recipient_events(logger, "request.failed")) == 1


@pytest.mark.asyncio
async def test_o17_recipient_policy_read_outage_fails_closed_async() -> None:
    store = _FailingRecipientPolicyStore()
    signer = Signer()
    logger = _LevelLogger()
    with pytest.raises(TransportError) as raised:
        async with AsyncTx402Client(
            evm_signer=signer,
            spend_store=store,
            transport=httpx.MockTransport(Merchant()),
            evm_rpc_transport=rpc_transport(),
            recipient_policy=RecipientPolicy(mode="tofu"),
            logger=logger,
        ) as sdk:
            await sdk.get(URL)
    assert raised.value.details.get("causeCategory") == "recipient-store-unavailable"
    assert raised.value.retryable is True
    assert signer.requests == []
    assert len(_recipient_events(logger, "request.failed")) == 1


class _NoneRecipientPolicyStore(MemorySpendStore):
    """A store whose recipient policy read returns ``None`` (no policy for the scope). TS
    treats ``policy?.tofuEnabled !== true`` as not-provisioned and fails closed; pre-S13d
    Python read ``None.get('tofu_enabled')`` OUTSIDE the try/except, raising a raw
    ``AttributeError`` with no ``request.failed``. The fix sends a ``None`` policy
    to the same closed ``recipient-tofu-not-provisioned`` refusal."""

    def get_recipient_policy(self, scope: str) -> dict[str, bool]:
        return None  # type: ignore[return-value]


def test_o38_none_recipient_policy_fails_closed_sync() -> None:
    store = _NoneRecipientPolicyStore()
    signer = Signer()
    logger = _LevelLogger()
    with (
        client(
            Merchant(),
            signer=signer,
            store=store,
            logger=logger,
            recipient_policy=RecipientPolicy(mode="tofu"),
        ) as sdk,
        pytest.raises(ConfigurationError) as raised,
    ):
        sdk.get(URL)
    # A None policy is "TOFU not provisioned", not a store outage — a fail-closed
    # ConfigurationError, never a raw AttributeError. Pre-signature: nothing signed,
    # request.failed fired exactly once.
    assert raised.value.details.get("reason") == "recipient-tofu-not-provisioned"
    assert signer.requests == []
    assert len(_recipient_events(logger, "request.failed")) == 1


@pytest.mark.asyncio
async def test_o38_none_recipient_policy_fails_closed_async() -> None:
    store = _NoneRecipientPolicyStore()
    signer = Signer()
    logger = _LevelLogger()
    with pytest.raises(ConfigurationError) as raised:
        async with AsyncTx402Client(
            evm_signer=signer,
            spend_store=store,
            transport=httpx.MockTransport(Merchant()),
            evm_rpc_transport=rpc_transport(),
            recipient_policy=RecipientPolicy(mode="tofu"),
            logger=logger,
        ) as sdk:
            await sdk.get(URL)
    assert raised.value.details.get("reason") == "recipient-tofu-not-provisioned"
    assert signer.requests == []
    assert len(_recipient_events(logger, "request.failed")) == 1


class _RecordingBudgetStore(MemorySpendStore):
    """Records the ``now_epoch_ms`` a default budget query resolves to."""

    def __init__(self) -> None:
        super().__init__()
        self.last_now: int | None = None

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        self.last_now = now_epoch_ms
        return super().get_budget_state(
            policy_scope=policy_scope, asset_id=asset_id, now_epoch_ms=now_epoch_ms
        )


def test_o19_default_budget_query_uses_configured_clock_sync() -> None:
    pinned = 1_800_000_000_000  # a fixed instant within the manifest window, != real now
    store = _RecordingBudgetStore()
    with client(Merchant(), store=store, clock=lambda: pinned) as sdk:
        sdk.get_budget_state(policy_scope=SCOPE, asset_id=ASSET)
    # The default query used the client's CONFIGURED clock, not _system_clock; the
    # pre-fix code used the system clock, so a live reservation read as expired.
    assert store.last_now == pinned


@pytest.mark.asyncio
async def test_o19_default_budget_query_uses_configured_clock_async() -> None:
    pinned = 1_800_000_000_000
    store = _RecordingBudgetStore()
    async with AsyncTx402Client(
        evm_signer=Signer(),
        spend_store=store,
        transport=httpx.MockTransport(Merchant()),
        evm_rpc_transport=rpc_transport(),
        clock=lambda: pinned,
    ) as sdk:
        await sdk.get_budget_state(policy_scope=SCOPE, asset_id=ASSET)
    assert store.last_now == pinned


class _CommitFailsStore(MemorySpendStore):
    """A store whose commit fails AFTER the merchant settled — money moved, not recorded."""

    def commit(
        self,
        *,
        ref: ReservationRef,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        raise RuntimeError("store down after settlement")


def test_o18_post_settlement_commit_failure_emits_request_failed_once() -> None:
    store = _CommitFailsStore()
    logger = _LevelLogger()
    with (
        client(Merchant(), store=store, logger=logger) as sdk,
        pytest.raises(ResourceDeliveryError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.code == "TX402_RESOURCE_DELIVERY"
    # The terminal event fired ONCE, not inside _commit_failure and again outside (§11).
    assert len(_recipient_events(logger, "request.failed")) == 1


def test_recipient_admin_allowlist_mismatch_refuses_before_signer_sync() -> None:
    store = MemorySpendStore()
    # An operator pins a DIFFERENT recipient; the client always sends its payTo, so the
    # authoritative reserve assertion refuses it whatever the caller's mode.
    store.set_recipient_pins(
        SCOPE, NETWORK, ("0x000000000000000000000000000000000000dead",)
    )
    signer = Signer()
    merchant = Merchant()
    logger = _LevelLogger()
    with (
        client(merchant, signer=signer, store=store, logger=logger) as sdk,
        pytest.raises(RecipientUnpinnedError) as raised,
    ):
        sdk.get(URL)
    assert raised.value.retryable is False
    assert raised.value.details["reason"] == "not-allowlisted"
    assert raised.value.details["presentedRecipient"] == RECIPIENT.lower()
    assert raised.value.details["expectedRecipients"] == [
        "0x000000000000000000000000000000000000dead"
    ]
    # Pre-signature policy refusal (SEC-002): nothing signed, only the 402 probe sent.
    assert signer.requests == []
    assert len(merchant.requests) == 1
    rejected = _recipient_events(logger, "recipient.rejected")
    assert len(rejected) == 1
    assert rejected[0][0] == "warn"
    assert rejected[0][1]["reason"] == "not-allowlisted"


def test_recipient_client_allowlist_admits_without_claiming_sync() -> None:
    store = MemorySpendStore()
    logger = _LevelLogger()
    with client(
        Merchant(),
        store=store,
        logger=logger,
        recipient_policy=RecipientPolicy(
            mode="allowlist",
            allow=[{"host": SCOPE, "network": NETWORK, "recipients": [RECIPIENT]}],
        ),
    ) as sdk:
        assert sdk.get(URL).status_code == 200
    # Allowlist mode never claims a pin (SPEC §6.2 "allowlist wins, TOFU fills gaps").
    assert store.get_recipient_pins(SCOPE, NETWORK) == ()
    assert _recipient_events(logger, "recipient.pinned") == []


class _DataOnlyStore:
    """A valid data-plane SpendStore with NO RecipientPinStore methods."""

    def __init__(self) -> None:
        self._inner = MemorySpendStore()
        self.kind = self._inner.kind
        self.capabilities = self._inner.capabilities

    def reserve(self, **kwargs: Any) -> Any:
        return self._inner.reserve(**kwargs)

    def commit(self, **kwargs: Any) -> Any:
        return self._inner.commit(**kwargs)

    def release(self, **kwargs: Any) -> Any:
        return self._inner.release(**kwargs)

    def expose(self, **kwargs: Any) -> Any:
        return self._inner.expose(**kwargs)

    def get_budget_state(self, **kwargs: Any) -> Any:
        return self._inner.get_budget_state(**kwargs)

    def list_exposed(self, **kwargs: Any) -> Any:
        return self._inner.list_exposed(**kwargs)

    def is_frozen(self, **kwargs: Any) -> Any:
        return self._inner.is_frozen(**kwargs)


def test_recipient_tofu_fails_closed_without_a_pin_store() -> None:
    # A store missing get_recipient_pins/get_recipient_policy cannot back TOFU.
    with pytest.raises(ConfigurationError) as raised:
        Tx402Client(
            evm_signer=Signer(),
            spend_store=_DataOnlyStore(),
            transport=httpx.MockTransport(Merchant()),
            evm_rpc_transport=rpc_transport(),
            recipient_policy=RecipientPolicy(mode="tofu"),
        )
    assert raised.value.details["reason"] == "recipient-tofu-needs-pin-store"


@pytest.mark.asyncio
async def test_recipient_tofu_establishes_pin_on_the_async_path() -> None:
    store = MemorySpendStore()
    store.set_tofu_enabled(SCOPE, True)
    signer = Signer()
    logger = _LevelLogger()
    async with AsyncTx402Client(
        evm_signer=signer,
        spend_store=store,
        transport=httpx.MockTransport(Merchant()),
        evm_rpc_transport=rpc_transport(),
        logger=logger,
        recipient_policy=RecipientPolicy(mode="tofu"),
    ) as sdk:
        assert (await sdk.get(URL)).status_code == 200
    # The async advisory read and reserve claim run through the _dispatch seam;
    # the pin is established and recipient.pinned emitted exactly as on the sync path.
    assert store.get_recipient_pins(SCOPE, NETWORK) == (RECIPIENT.lower(),)
    pinned = _recipient_events(logger, "recipient.pinned")
    assert len(pinned) == 1
    assert pinned[0][0] == "info"


def test_recipient_allowlist_recipients_string_is_rejected_not_iterated() -> None:
    # A bare string is a Sequence in Python; without the explicit str guard it would be
    # iterated per-character into the allow set (parity with the TS Array.isArray check).
    with pytest.raises(ConfigurationError) as raised:
        Tx402Client(
            evm_signer=Signer(),
            transport=httpx.MockTransport(Merchant()),
            evm_rpc_transport=rpc_transport(),
            recipient_policy=RecipientPolicy(
                mode="allowlist",
                allow=[{"host": SCOPE, "network": NETWORK, "recipients": RECIPIENT}],
            ),
        )
    assert raised.value.details["configPath"] == "recipient_policy.allow[0].recipients"
