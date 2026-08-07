from __future__ import annotations

import time
from typing import Any, Literal

import httpx
import pytest

from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.errors import (
    InvalidPaymentRequiredError,
    SignerError,
    Tx402ErrorContext,
    UnsupportedSchemeError,
)
from tx402.evm import (
    EvmRpcError,
    EvmRpcPool,
    EvmTypedDataRequest,
    ExactEvmPlan,
    _UpstreamSigner,
    _with_deadline,
    create_evm_authorization,
    encode_balance_of_call_data,
    plan_exact_evm_authorization,
    resolve_evm_address,
)

NETWORK_ID = "eip155:8453"
NETWORK = BUNDLED_MANIFEST["networks"][NETWORK_ID]
ASSET = NETWORK["assets"][0]
PAYER = "0x00000000000000000000000000000000000000A1"
RECIPIENT = "0x1234567890AbcdEF1234567890aBcdef12345678"


class RecordingSigner:
    kind: Literal["evm"] = "evm"

    def __init__(self, *, address: str = PAYER, signature: bytes | str = b"x" * 65) -> None:
        self.address = address
        self.signature = signature
        self.requests: list[EvmTypedDataRequest] = []

    def get_address(self) -> str:
        return self.address

    def sign_typed_data(self, request: EvmTypedDataRequest) -> bytes | str:
        self.requests.append(request)
        return self.signature


def requirement(**overrides: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "index": 0,
        "scheme": "exact",
        "network": NETWORK_ID,
        "asset": ASSET["address"],
        "amountAtomic": "50000",
        "payTo": RECIPIENT,
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USD Coin", "version": "2"},
    }
    result.update(overrides)
    return result


def context(phase: Literal["route", "sign"] = "route") -> Tx402ErrorContext:
    return Tx402ErrorContext(request_id="request", phase=phase)


def plan(**requirement_overrides: Any) -> ExactEvmPlan:
    return plan_exact_evm_authorization(
        requirement=requirement(**requirement_overrides),
        network_id=NETWORK_ID,
        network=NETWORK,
        asset=ASSET,
        payer=PAYER,
        now_epoch_ms=int(time.time() * 1000),
        context=context(),
    )


def test_evm_plan_additional_validation_boundaries() -> None:
    with pytest.raises(TypeError):
        encode_balance_of_call_data("bad")
    with pytest.raises(UnsupportedSchemeError):
        plan(scheme="upto")
    with pytest.raises(InvalidPaymentRequiredError) as raised:
        plan(payTo="bad")
    assert raised.value.details["reason"] == "pay-to-invalid"
    with pytest.raises(InvalidPaymentRequiredError):
        plan(network="eip155:84532")
    with pytest.raises(InvalidPaymentRequiredError):
        plan(maxTimeoutSeconds=0)
    with pytest.raises(InvalidPaymentRequiredError):
        plan(amountAtomic="0")

    bad_network = dict(NETWORK)
    bad_network["chainId"] = "8453"
    with pytest.raises(InvalidPaymentRequiredError):
        plan_exact_evm_authorization(
            requirement=requirement(),
            network_id=NETWORK_ID,
            network=bad_network,
            asset=ASSET,
            payer=PAYER,
            now_epoch_ms=0,
            context=context(),
        )


def rpc_handler(request: httpx.Request) -> httpx.Response:
    body = request.read()
    document = __import__("json").loads(body)
    if document["method"] == "eth_chainId":
        result = "0x1" if request.url.host == "wrong.test" else "0x2105"
    else:
        assert document["params"][0]["data"] == encode_balance_of_call_data(PAYER)
        result = "0x186a0"
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": document["id"], "result": result}
    )


def test_evm_rpc_verifies_chain_on_same_endpoint_and_fails_over() -> None:
    pool = EvmRpcPool(
        ["https://wrong.test/rpc", "https://good.test/secret"],
        transport=httpx.MockTransport(rpc_handler),
    )
    reading = pool.read_balance(chain_id=8453, token=ASSET["address"], owner=PAYER)
    assert reading.balance_atomic == 100_000
    assert reading.chain_id == 8453
    assert reading.endpoint == "good.test"


@pytest.mark.asyncio
async def test_evm_rpc_async_uses_the_same_identity_rule() -> None:
    pool = EvmRpcPool(["https://good.test"], transport=httpx.MockTransport(rpc_handler))
    reading = await pool.read_balance_async(
        chain_id=8453, token=ASSET["address"], owner=PAYER
    )
    assert reading.balance_atomic == 100_000


@pytest.mark.parametrize(
    ("response", "failure"),
    [
        (httpx.Response(503), "transport"),
        (httpx.Response(200, content=b"no"), "protocol"),
        (httpx.Response(200, json=[]), "protocol"),
        (httpx.Response(200, json={"error": {}}), "protocol"),
        (httpx.Response(200, json={"result": "garbage"}), "chain-id-unreadable"),
        (httpx.Response(200, json={"result": "0x0"}), "chain-id-unreadable"),
    ],
)
def test_evm_rpc_classifies_bad_chain_responses(
    response: httpx.Response, failure: str
) -> None:
    pool = EvmRpcPool(
        ["https://rpc.test"], transport=httpx.MockTransport(lambda _request: response)
    )
    with pytest.raises(EvmRpcError) as raised:
        pool.read_balance(chain_id=8453, token=ASSET["address"], owner=PAYER)
    assert raised.value.failure == failure


@pytest.mark.parametrize("balance", ["wat", None])
def test_evm_rpc_rejects_bad_balance(balance: object) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"result": "0x2105" if calls == 1 else balance})

    with pytest.raises(EvmRpcError) as raised:
        EvmRpcPool(
            ["https://rpc.test"], transport=httpx.MockTransport(handler)
        ).read_balance(chain_id=8453, token=ASSET["address"], owner=PAYER)
    assert raised.value.failure == "balance-unreadable"


def test_evm_rpc_empty_invalid_transport_and_timeout() -> None:
    with pytest.raises(EvmRpcError, match="addresses"):
        EvmRpcPool([]).read_balance(chain_id=8453, token="bad", owner=PAYER)
    with pytest.raises(EvmRpcError, match="No RPC"):
        EvmRpcPool([]).read_balance(chain_id=8453, token=ASSET["address"], owner=PAYER)
    with pytest.raises(TypeError, match="BaseTransport"):
        EvmRpcPool(["https://rpc.test"], transport=httpx.AsyncHTTPTransport()).read_balance(
            chain_id=8453, token=ASSET["address"], owner=PAYER
        )

    def slow(_request: httpx.Request) -> httpx.Response:
        time.sleep(0.05)
        return httpx.Response(200, json={"result": "0x2105"})

    with pytest.raises(EvmRpcError) as raised:
        EvmRpcPool(
            ["https://rpc.test"],
            transport=httpx.MockTransport(slow),
            timeout_ms=1,
        ).read_balance(chain_id=8453, token=ASSET["address"], owner=PAYER)
    assert raised.value.failure == "timeout"

    def broken(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret")

    with pytest.raises(EvmRpcError) as raised:
        EvmRpcPool(
            ["https://rpc.test"], transport=httpx.MockTransport(broken)
        ).read_balance(chain_id=8453, token=ASSET["address"], owner=PAYER)
    assert raised.value.failure == "transport"


@pytest.mark.asyncio
async def test_evm_rpc_async_guards_transport_and_empty_pool() -> None:
    with pytest.raises(EvmRpcError, match="addresses"):
        await EvmRpcPool([]).read_balance_async(chain_id=8453, token="bad", owner=PAYER)
    with pytest.raises(EvmRpcError, match="No RPC"):
        await EvmRpcPool([]).read_balance_async(
            chain_id=8453, token=ASSET["address"], owner=PAYER
        )
    with pytest.raises(TypeError, match="AsyncBaseTransport"):
        await EvmRpcPool(
            ["https://rpc.test"], transport=httpx.HTTPTransport()
        ).read_balance_async(chain_id=8453, token=ASSET["address"], owner=PAYER)


def test_deadline_returns_values_and_propagates_failures() -> None:
    assert _with_deadline(lambda: 3, 1) == 3
    with pytest.raises(RuntimeError, match="boom"):
        _with_deadline(lambda: (_ for _ in ()).throw(RuntimeError("boom")), 1)


def test_resolve_signer_address_and_create_upstream_authorization() -> None:
    signer = RecordingSigner(signature="0x" + "11" * 65)
    assert resolve_evm_address(signer, context()) == PAYER
    selected = requirement()
    result, expires = create_evm_authorization(
        signer=signer,
        address=PAYER,
        plan=plan(),
        requirement=selected,
        asset=ASSET,
        resource_host="api.example.com",
        request_hash="sha256:request",
        context=context("sign"),
    )
    assert result["authorization"]["from"] == PAYER
    assert result["signature"].startswith("0x")
    assert expires > int(time.time() * 1000)
    assert len(signer.requests) == 1
    presentation = signer.requests[0].presentation
    assert presentation.amount_atomic == "50000"
    assert presentation.amount_decimal == "0.05"
    assert presentation.asset_symbol == "USDC"


def test_resolve_signer_redacts_failures_and_validates_address() -> None:
    bad = RecordingSigner(address="bad")
    with pytest.raises(SignerError) as raised:
        resolve_evm_address(bad, context())
    assert raised.value.details["causeCategory"] == "address-unavailable"

    class Broken(RecordingSigner):
        def get_address(self) -> str:
            raise RuntimeError("secret")

    with pytest.raises(SignerError) as raised:
        resolve_evm_address(Broken(), context())
    assert "secret" not in raised.value.message


def adapter() -> _UpstreamSigner:
    return _UpstreamSigner(
        signer=RecordingSigner(),
        address=PAYER,
        plan=plan(),
        presentation={
            "network": NETWORK_ID,
            "assetId": f"{NETWORK_ID}/erc20:{ASSET['address']}",
            "assetSymbol": "USDC",
            "amountDecimal": "0.05",
            "resourceHost": "api.example.com",
            "requestHash": "sha256:request",
        },
        context=context("sign"),
    )


def typed_data(
    **message_overrides: Any,
) -> tuple[dict[str, Any], dict[str, list[dict[str, str]]], str, dict[str, Any]]:
    now = int(time.time())
    message = {
        "from": PAYER,
        "to": RECIPIENT,
        "value": "50000",
        "validAfter": "0",
        "validBefore": str(now + 60),
        "nonce": "0x" + "00" * 32,
    }
    message.update(message_overrides)
    return (
        {
            "name": "USD Coin",
            "version": "2",
            "chainId": 8453,
            "verifyingContract": ASSET["address"],
        },
        {"TransferWithAuthorization": [{"name": "from", "type": "address"}]},
        "TransferWithAuthorization",
        message,
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda values: (values[0], values[1], "Wrong", values[3]),
        lambda values: ({**values[0], "chainId": 1}, values[1], values[2], values[3]),
        lambda values: (
            {**values[0], "verifyingContract": RECIPIENT},
            values[1],
            values[2],
            values[3],
        ),
        lambda values: ({**values[0], "name": "Fake"}, values[1], values[2], values[3]),
        lambda values: (values[0], values[1], values[2], {**values[3], "from": RECIPIENT}),
        lambda values: (values[0], values[1], values[2], {**values[3], "to": PAYER}),
        lambda values: (values[0], values[1], values[2], {**values[3], "value": "1"}),
        lambda values: (values[0], values[1], values[2], {**values[3], "validAfter": "1"}),
        lambda values: (values[0], values[1], values[2], {**values[3], "validBefore": "0"}),
        lambda values: (values[0], values[1], values[2], {**values[3], "nonce": "bad"}),
    ],
)
def test_signer_adapter_rejects_any_plan_mutation(mutate: Any) -> None:
    values = mutate(typed_data())
    with pytest.raises(SignerError) as raised:
        adapter().sign_typed_data(*values)
    assert raised.value.details["causeCategory"] == "plan-mismatch"


def test_signer_adapter_rejects_duplicate_malformed_types_and_signature() -> None:
    instance = adapter()
    instance.sign_typed_data(*typed_data())
    with pytest.raises(SignerError) as raised:
        instance.sign_typed_data(*typed_data())
    assert raised.value.details["causeCategory"] == "duplicate-signature-request"

    values = typed_data()
    with pytest.raises(SignerError, match="definition"):
        adapter().sign_typed_data(values[0], {"Bad": [object()]}, values[2], values[3])

    malformed = _UpstreamSigner(
        signer=RecordingSigner(signature="bad"),
        address=PAYER,
        plan=plan(),
        presentation=adapter()._presentation,
        context=context("sign"),
    )
    with pytest.raises(SignerError) as raised:
        malformed.sign_typed_data(*typed_data())
    assert raised.value.details["causeCategory"] == "malformed-signature"


def test_create_authorization_wraps_upstream_and_signer_failures() -> None:
    class Refusing(RecordingSigner):
        def sign_typed_data(self, request: EvmTypedDataRequest) -> bytes | str:
            raise RuntimeError("sensitive payload")

    with pytest.raises(SignerError) as raised:
        create_evm_authorization(
            signer=Refusing(),
            address=PAYER,
            plan=plan(),
            requirement=requirement(),
            asset=ASSET,
            resource_host="api.example.com",
            request_hash="sha256:request",
            context=context("sign"),
        )
    assert raised.value.details["causeCategory"] == "signer-rejected"
    assert "sensitive" not in raised.value.message
