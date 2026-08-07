"""End-to-end payment paths through the real client (M4 to M6).

Covers what the frozen vectors cannot: the state machine actually running. T-003 (a Solana
paid call), T-004/T-005 (deterministic selection across two offered networks), T-020 (a dark
primary RPC), and T-010/T-011/T-012 (the re-challenge loop and its money rules).

Every merchant and RPC here is an ``httpx.MockTransport``. Per PLAN.md open item O24 the
transports never rebuild an outbound request: a shim that does drops the deadline the SDK
owns, and against a stub that never answers that is not a slow test, it is no deadline.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Literal

import httpx
import pytest
from x402.http.utils import encode_payment_required_header, encode_payment_response_header
from x402.schemas import (
    PaymentRequired,
    PaymentRequirements,
    ResourceInfo,
    SettleResponse,
)

from tx402 import (
    AmbiguousPaymentError,
    AsyncTx402Client,
    InsufficientLiquidityError,
    MemorySpendStore,
    PaidRedirectBlockedError,
    Policy,
    ResourceDeliveryError,
    RoutingPolicy,
    TransportError,
    Tx402Client,
)
from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.evm import EvmTypedDataRequest
from tx402.solana import TOKEN_PROGRAM_ADDRESS, SolanaSignRequest

URL = "https://merchant.test/pay"
BASE = "eip155:8453"
SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOLANA_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
BASE_ASSET: Any = BUNDLED_MANIFEST["networks"][BASE]["assets"][0]["address"]
SOLANA_MINT: Any = BUNDLED_MANIFEST["networks"][SOLANA]["assets"][0]["mint"]
EVM_PAYER = "0x00000000000000000000000000000000000000A1"
EVM_RECIPIENT = "0x1234567890AbcdEF1234567890aBcdef12345678"
SVM_PAYER = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
SVM_RECIPIENT = "11111111111111111111111111111111"
BLOCKHASH = "11111111111111111111111111111111"


class EvmSigner:
    kind: Literal["evm"] = "evm"

    def __init__(self) -> None:
        self.requests: list[EvmTypedDataRequest] = []

    def get_address(self) -> str:
        return EVM_PAYER

    def sign_typed_data(self, request: EvmTypedDataRequest) -> bytes:
        self.requests.append(request)
        return b"s" * 65


class SolanaSigner:
    kind: Literal["solana"] = "solana"

    def __init__(self) -> None:
        self.requests: list[SolanaSignRequest] = []

    def get_public_key(self) -> str:
        return SVM_PAYER

    def sign_transaction(self, request: SolanaSignRequest) -> bytes:
        self.requests.append(request)
        return bytes([len(self.requests)]) * 64


def evm_requirement(amount: str = "50000") -> dict[str, Any]:
    return {
        "scheme": "exact",
        "network": BASE,
        "asset": BASE_ASSET,
        "amount": amount,
        "payTo": EVM_RECIPIENT,
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USD Coin", "version": "2"},
    }


def svm_requirement(amount: str = "50000") -> dict[str, Any]:
    return {
        "scheme": "exact",
        "network": SOLANA,
        "asset": SOLANA_MINT,
        "amount": amount,
        "payTo": SVM_RECIPIENT,
        "maxTimeoutSeconds": 60,
        "extra": {"feePayer": SVM_RECIPIENT, "recentBlockhash": BLOCKHASH},
    }


def challenge(*requirements: dict[str, Any]) -> str:
    return encode_payment_required_header(
        PaymentRequired(
            x402_version=2,
            resource=ResourceInfo(url=URL),
            accepts=[PaymentRequirements.model_validate(item) for item in requirements],
        )
    )


def settlement(success: bool = True) -> str:
    return encode_payment_response_header(
        SettleResponse(
            success=success,
            transaction="0xtx",
            network=BASE,
            error_reason=None if success else "rejected",
        )
    )


class Merchant:
    """A deterministic 402 server that can re-price its offer between attempts."""

    def __init__(
        self,
        *,
        offers: list[str] | None = None,
        paid_statuses: list[int] | None = None,
        paid_headers: dict[str, str] | None = None,
    ) -> None:
        self.offers = offers or [challenge(evm_requirement())]
        self.paid_statuses = paid_statuses or [200]
        self.paid_headers = paid_headers or {}
        self.paid = 0
        #: SHA-256 of each PAYMENT-SIGNATURE. The header itself is never retained (SEC-003);
        #: a digest answers "were these two different?" without keeping anything sensitive.
        self.signature_digests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        signature = request.headers.get("payment-signature")
        if signature is None:
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": self.offers[0]})
        self.signature_digests.append(hashlib.sha256(signature.encode()).hexdigest())
        status = self.paid_statuses[min(self.paid, len(self.paid_statuses) - 1)]
        self.paid += 1
        if status == 402:
            offer = self.offers[min(self.paid, len(self.offers) - 1)]
            return httpx.Response(402, headers={"PAYMENT-REQUIRED": offer})
        headers = dict(self.paid_headers)
        if status == 200 and "PAYMENT-RESPONSE" not in headers:
            headers["PAYMENT-RESPONSE"] = settlement()
        return httpx.Response(status, headers=headers, content=b"delivered")


def evm_rpc(
    balance: int = 5_000_000, *, chain_id: int = 8453, dark_hosts: tuple[str, ...] = ()
) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.host in dark_hosts:
            # The observable behaviour of total packet loss: accept and never answer. The
            # SDK's own deadline is what must end this, not the transport.
            time.sleep(5)
        document = json.loads(request.read())
        result = hex(chain_id) if document["method"] == "eth_chainId" else hex(balance)
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": document["id"], "result": result}
        )

    return httpx.MockTransport(handle)


def svm_rpc(
    balance: str = "5000000", *, genesis: str = SOLANA_GENESIS
) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        document = json.loads(request.read())
        method = document["method"]
        if method == "getGenesisHash":
            result: Any = genesis
        elif method == "getLatestBlockhash":
            result = {"value": {"blockhash": BLOCKHASH}}
        else:
            result = {
                "value": {
                    "owner": TOKEN_PROGRAM_ADDRESS,
                    "data": {
                        "parsed": {
                            "info": {
                                "owner": SVM_PAYER,
                                "mint": SOLANA_MINT,
                                "tokenAmount": {"amount": balance, "decimals": 6},
                            }
                        }
                    },
                }
            }
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": document["id"], "result": result}
        )

    return httpx.MockTransport(handle)


def client(merchant: Any, **kwargs: Any) -> Tx402Client:
    defaults: dict[str, Any] = {
        "evm_signer": EvmSigner(),
        "solana_signer": SolanaSigner(),
        "transport": httpx.MockTransport(merchant),
        "evm_rpc_transport": evm_rpc(),
        "solana_rpc_transport": svm_rpc(),
    }
    defaults.update(kwargs)
    return Tx402Client(**defaults)


def budget(store: MemorySpendStore, asset_id: str) -> Any:
    return store.get_budget_state(
        policy_scope="merchant.test",
        asset_id=asset_id,
        now_epoch_ms=int(time.time() * 1000),
    )


class TestSolanaPaidCall:
    def test_t003_one_reservation_one_svm_signature_one_paid_retry(self) -> None:
        merchant = Merchant(offers=[challenge(svm_requirement())])
        signer = SolanaSigner()
        store = MemorySpendStore()
        with client(merchant, solana_signer=signer, spend_store=store) as sdk:
            response = sdk.post(URL, json={"prompt": "hello"})
        assert response.status_code == 200
        assert len(signer.requests) == 1
        assert merchant.paid == 1
        state = budget(store, f"{SOLANA}/token:{SOLANA_MINT}")
        assert state.committed_atomic == "50000"
        assert state.reserved_atomic == "0"

    def test_sec_002_an_insufficient_svm_balance_never_reaches_the_signer(self) -> None:
        merchant = Merchant(offers=[challenge(svm_requirement())])
        signer = SolanaSigner()
        with (
            client(
                merchant, solana_signer=signer, solana_rpc_transport=svm_rpc(balance="1")
            ) as sdk,
            pytest.raises(InsufficientLiquidityError),
        ):
            sdk.get(URL)
        assert signer.requests == []

    def test_a_wrong_cluster_is_a_liquidity_free_transport_failure(self) -> None:
        merchant = Merchant(offers=[challenge(svm_requirement())])
        signer = SolanaSigner()
        with (
            client(
                merchant,
                solana_signer=signer,
                solana_rpc_transport=svm_rpc(genesis="wrong"),
            ) as sdk,
            pytest.raises(TransportError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.details["causeCategory"] == "genesis-hash-mismatch"
        assert signer.requests == []

    @pytest.mark.asyncio
    async def test_the_async_svm_path_matches_the_sync_one(self) -> None:
        merchant = Merchant(offers=[challenge(svm_requirement())])
        signer = SolanaSigner()
        async with AsyncTx402Client(
            solana_signer=signer,
            transport=httpx.MockTransport(merchant),
            solana_rpc_transport=svm_rpc(),
        ) as sdk:
            response = await sdk.post(URL, content=b"body")
        assert response.status_code == 200
        assert len(signer.requests) == 1


class TestMultiNetworkRouting:
    def test_t004_preferred_base_wins_when_both_are_viable(self) -> None:
        merchant = Merchant(offers=[challenge(svm_requirement(), evm_requirement())])
        evm, svm = EvmSigner(), SolanaSigner()
        with client(
            merchant,
            evm_signer=evm,
            solana_signer=svm,
            routing=RoutingPolicy(prefer_networks=[BASE]),
        ) as sdk:
            assert sdk.get(URL).status_code == 200
        # Base is offered *second* — preference outranks the merchant's own ordering.
        assert len(evm.requests) == 1
        assert svm.requests == []

    def test_t005_an_underfunded_preference_loses_to_a_viable_network(self) -> None:
        merchant = Merchant(offers=[challenge(evm_requirement(), svm_requirement())])
        evm, svm = EvmSigner(), SolanaSigner()
        with client(
            merchant,
            evm_signer=evm,
            solana_signer=svm,
            evm_rpc_transport=evm_rpc(balance=1),
            routing=RoutingPolicy(prefer_networks=[BASE]),
        ) as sdk:
            assert sdk.get(URL).status_code == 200
        # Viability is the first ordering key; no preference can lift a candidate above it.
        assert evm.requests == []
        assert len(svm.requests) == 1

    def test_a_network_without_a_signer_is_a_candidate_not_a_silent_skip(self) -> None:
        merchant = Merchant(offers=[challenge(svm_requirement(), evm_requirement())])
        evm = EvmSigner()
        with client(merchant, evm_signer=evm, solana_signer=None) as sdk:
            assert sdk.get(URL).status_code == 200
        assert len(evm.requests) == 1

    def test_selection_is_identical_across_repeated_runs(self) -> None:
        """SPEC §6.4 step 19: identical inputs and health state, identical output.

        The preference matters to the *test*, not just to the scenario, and PLAN.md open
        item O34 is why. Step 19 conditions determinism on health state, and both keys
        below preference — ``health_score`` and ``observed_latency_ms`` — are derived from
        a fresh wall-clock measurement of the balance probe. Two candidates that tie on
        viability, circuit, preference and fee therefore get separated by microseconds of
        scheduler noise, which is a different health state each pass rather than a
        violation of step 19. Pinning a preference holds every key above the measured ones
        fixed, so this asserts the ordering rules instead of the machine's timing. The
        pure-function half of step 19 is asserted directly in ``test_routing.py``.
        """
        merchant = Merchant(offers=[challenge(svm_requirement(), evm_requirement())])
        evm, svm = EvmSigner(), SolanaSigner()
        with client(
            merchant,
            evm_signer=evm,
            solana_signer=svm,
            routing=RoutingPolicy(prefer_networks=[SOLANA]),
        ) as sdk:
            for _ in range(5):
                assert sdk.get(URL).status_code == 200
        # Five passes, same challenge, same health state: the same chain every time.
        assert len(svm.requests) == 5
        assert evm.requests == []


class TestRpcFailover:
    def test_t020_a_dark_primary_rpc_is_replaced_by_the_backup(self) -> None:
        """100 % packet loss on the manifest's first Base RPC; the second is healthy."""
        primary = BUNDLED_MANIFEST["networks"][BASE]["rpcUrls"][0]
        dark_host = httpx.URL(primary).host
        merchant = Merchant()
        evm = EvmSigner()
        with client(
            merchant,
            evm_signer=evm,
            evm_rpc_transport=evm_rpc(dark_hosts=(dark_host,)),
        ) as sdk:
            assert sdk.get(URL).status_code == 200
        assert len(evm.requests) == 1

    def test_a_sustained_outage_opens_the_primary_circuit_and_stops_paying_its_deadline(
        self,
    ) -> None:
        primary = BUNDLED_MANIFEST["networks"][BASE]["rpcUrls"][0]
        dark_host = httpx.URL(primary).host
        contacted = 0

        def handle(request: httpx.Request) -> httpx.Response:
            nonlocal contacted
            if request.url.host == dark_host:
                contacted += 1
                time.sleep(5)
            document = json.loads(request.read())
            result = hex(8453) if document["method"] == "eth_chainId" else hex(5_000_000)
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": document["id"], "result": result}
            )

        merchant = Merchant(paid_statuses=[200] * 8)
        with client(merchant, evm_rpc_transport=httpx.MockTransport(handle)) as sdk:
            for _ in range(8):
                assert sdk.get(URL).status_code == 200
        # Warming is the property under test: the primary costs its deadline five times and
        # then never again, because its circuit is open (SPEC §6.5).
        assert contacted == 5

    def test_reset_health_clears_the_index_without_touching_the_ledger(self) -> None:
        store = MemorySpendStore()
        merchant = Merchant()
        with client(merchant, spend_store=store) as sdk:
            sdk.get(URL)
            sdk.reset_health()
            state = budget(store, f"{BASE}/erc20:{BASE_ASSET}")
        assert state.committed_atomic == "50000"


class TestRechallengeLoop:
    def test_t010_a_repriced_rechallenge_is_replanned_and_resigned(self) -> None:
        merchant = Merchant(
            offers=[
                challenge(evm_requirement("50000")),
                challenge(evm_requirement("60000")),
            ],
            paid_statuses=[402, 200],
        )
        evm = EvmSigner()
        store = MemorySpendStore()
        with client(merchant, evm_signer=evm, spend_store=store) as sdk:
            assert sdk.get(URL).status_code == 200

        assert merchant.paid == 2
        # Signature freshness, two ways: distinct EIP-712 nonces at the signer boundary, and
        # distinct digests of the raw header the merchant received.
        nonces = {request.message["nonce"] for request in evm.requests}
        assert len(nonces) == 2
        assert len(set(merchant.signature_digests)) == 2
        # The second attempt was re-planned from the *new* challenge, not the first one.
        assert evm.requests[1].message["value"] == 60000

        state = budget(store, f"{BASE}/erc20:{BASE_ASSET}")
        assert state.committed_atomic == "60000"
        assert [item.state for item in state.reservations] == ["released", "committed"]

    def test_exhausting_max_paid_attempts_is_a_typed_terminal_error(self) -> None:
        merchant = Merchant(paid_statuses=[402, 402])
        store = MemorySpendStore()
        with (
            client(merchant, spend_store=store) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.details["reason"] == "max-paid-attempts-exhausted"
        assert raised.value.details["attempt"] == 2
        assert raised.value.context.paid is False
        assert merchant.paid == 2
        state = budget(store, f"{BASE}/erc20:{BASE_ASSET}")
        assert [item.state for item in state.reservations] == ["released", "released"]

    def test_max_paid_attempts_of_one_exhausts_on_the_first_rechallenge(self) -> None:
        """There is no second pass for a loop guard to prevent, which is the whole reason
        exhaustion is decided inside the 402 branch of the disposition table.
        """
        merchant = Merchant(paid_statuses=[402, 200])
        with (
            client(merchant, policy=Policy(max_paid_attempts=1)) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.details["reason"] == "max-paid-attempts-exhausted"
        assert merchant.paid == 1

    @pytest.mark.parametrize("status", [503, 307])
    def test_t011_an_ambiguous_outcome_ends_the_loop_rather_than_consuming_an_attempt(
        self, status: int
    ) -> None:
        """Retrying here is precisely what SPEC §6.7 forbids without an idempotency
        strategy, and tx402 has none to offer because merchant semantics are unknown.
        """
        merchant = Merchant(paid_statuses=[status, 200])
        store = MemorySpendStore()
        with (
            client(merchant, spend_store=store, policy=Policy(max_paid_attempts=3)) as sdk,
            pytest.raises(AmbiguousPaymentError),
        ):
            sdk.get(URL)
        assert merchant.paid == 1
        state = budget(store, f"{BASE}/erc20:{BASE_ASSET}")
        assert [item.state for item in state.reservations] == ["reserved"]

    def test_t012_a_cross_origin_redirect_raises_paid_redirect_blocked(self) -> None:
        """SPEC §6.1: "Cross-origin redirect raises ``PaidRedirectBlockedError``."

        Two separate facts, and the audit's O52 was that only one of them held. The
        **money** fact is that SEC-005 stopped the follow-up, not the original transmission
        — the merchant already has the signature and may well have settled against it — so
        the reservation is retained. The **identity** fact is that SPEC §6.1 and ADR-014
        both name ``PaidRedirectBlockedError``, and the high-level client used to catch it
        and re-raise a generic ``AmbiguousPaymentError``, so the class the specification
        promises was unreachable from the only entry point callers use. The error still
        carries the origins SPEC §8 requires of its code.
        """
        merchant = Merchant(
            paid_statuses=[307, 200],
            paid_headers={"location": "https://elsewhere.test/resource"},
        )
        store = MemorySpendStore()
        with (
            client(merchant, spend_store=store, policy=Policy(max_paid_attempts=3)) as sdk,
            pytest.raises(PaidRedirectBlockedError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.code == "TX402_REDIRECT_BLOCKED"
        assert raised.value.retryable is False
        assert raised.value.context.paid == "unknown"
        assert raised.value.details["fromOrigin"] == "https://merchant.test"
        assert raised.value.details["toOrigin"] == "https://elsewhere.test"
        assert raised.value.details["causeCategory"] == "redirect-blocked"
        assert raised.value.__cause__ is not None
        assert merchant.paid == 1
        state = budget(store, f"{BASE}/erc20:{BASE_ASSET}")
        assert [item.state for item in state.reservations] == ["reserved"]

    def test_a_same_origin_redirect_is_not_followed_and_is_not_a_refusal(self) -> None:
        merchant = Merchant(paid_statuses=[307], paid_headers={"location": "/delivered"})
        with client(merchant) as sdk, pytest.raises(AmbiguousPaymentError) as raised:
            sdk.get(URL)
        assert raised.value.details["causeCategory"] == "redirect-not-followed"

    def test_a_rechallenge_that_fails_to_decode_fails_cleanly(self) -> None:
        """The reservation is released before the fresh challenge is parsed, so a malformed
        one cannot strand budget.

        **The error class changed at ADR-022 and the release did not.** This used to assert
        ``InvalidPaymentRequiredError``, which maps to exit 5 — a band documented as "no
        signature was ever produced", though one had been sent. It is now a
        ``ResourceDeliveryError`` with ``paid: False``: signature sent, nothing delivered,
        no money moved. The budget assertion below must not move, and does not.
        """
        merchant = Merchant(paid_statuses=[402])
        merchant.offers = [challenge(evm_requirement()), "not-base64!"]
        store = MemorySpendStore()
        with (
            client(merchant, spend_store=store) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.context.paid is False
        assert raised.value.details["reason"] == "rechallenge-undecodable"
        state = budget(store, f"{BASE}/erc20:{BASE_ASSET}")
        assert [item.state for item in state.reservations] == ["released"]

    @pytest.mark.asyncio
    async def test_the_async_loop_re_signs_the_same_way(self) -> None:
        merchant = Merchant(
            offers=[
                challenge(evm_requirement("50000")),
                challenge(evm_requirement("60000")),
            ],
            paid_statuses=[402, 200],
        )
        evm = EvmSigner()
        async with AsyncTx402Client(
            evm_signer=evm,
            transport=httpx.MockTransport(merchant),
            evm_rpc_transport=evm_rpc(),
        ) as sdk:
            assert (await sdk.get(URL)).status_code == 200
        assert len(evm.requests) == 2
        assert len(set(merchant.signature_digests)) == 2


class TestRequestIdHeader:
    def test_the_diagnostic_header_can_be_disabled_for_strict_integrations(self) -> None:
        seen: list[httpx.Headers] = []

        class Recording(Merchant):
            def __call__(self, request: httpx.Request) -> httpx.Response:
                seen.append(request.headers.copy())
                return super().__call__(request)

        with client(Recording(), disable_request_id_header=True) as sdk:
            sdk.get(URL)
        assert "x-tx402-request-id" not in seen[1]
