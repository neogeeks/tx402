"""Regressions for the S15 pre-publication audit findings O44-O46 and O52-O54.

Every case here was written from the governing text — SPEC §5.3, §6.1, §6.7, §4.3, and
ADR-016/017/018 — and *then* run against the S15 commit to confirm it failed there. That
ordering matters more than usual for this file: the audit's central complaint was that the
existing green suite asserted what the implementation did rather than what the
specification required, so a regression derived from the implementation would have been
worth nothing.

The TypeScript counterpart is ``packages/tx402/test/audit-regressions.test.ts``, and the
two are deliberately close: an asymmetric fix is how the languages drift.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Literal

import httpx
import pytest
from x402.http.utils import (
    encode_payment_required_header,
    encode_payment_response_header,
)
from x402.schemas import (
    PaymentRequired,
    PaymentRequirements,
    ResourceInfo,
    SettleResponse,
)

from tx402 import (
    AmbiguousPaymentError,
    BudgetExceededError,
    ConfigurationError,
    MemorySpendStore,
    Policy,
    ResourceDeliveryError,
    SpendStore,
    TransportError,
    Tx402Client,
    check_spend_store,
    normalize_policy_host,
)
from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.client import (
    SPEND_STORE_COMMIT_FAILED_REASON,
    SPEND_STORE_UNAVAILABLE_CAUSE,
)
from tx402.errors import Tx402ErrorContext
from tx402.evm import EvmTypedDataRequest
from tx402.ledger import SpendEntry, SpendReservation
from tx402.spend_store_contract import SpendStoreContractError

URL = "https://merchant.test/pay"
OTHER_URL = "https://other-merchant.test/pay"
BASE = "eip155:8453"
BASE_ASSET: Any = BUNDLED_MANIFEST["networks"][BASE]["assets"][0]["address"]
ASSET_ID = f"{BASE}/erc20:{BASE_ASSET}"
EVM_PAYER = "0x00000000000000000000000000000000000000A1"
EVM_RECIPIENT = "0x1234567890AbcdEF1234567890aBcdef12345678"
AMOUNT = "50000"


class EvmSigner:
    kind: Literal["evm"] = "evm"

    def __init__(self) -> None:
        self.requests: list[EvmTypedDataRequest] = []

    def get_address(self) -> str:
        return EVM_PAYER

    def sign_typed_data(self, request: EvmTypedDataRequest) -> bytes:
        self.requests.append(request)
        return b"s" * 65


def challenge(url: str = URL, amount: str = AMOUNT) -> str:
    return encode_payment_required_header(
        PaymentRequired(
            x402_version=2,
            resource=ResourceInfo(url=url),
            accepts=[
                PaymentRequirements.model_validate(
                    {
                        "scheme": "exact",
                        "network": BASE,
                        "asset": BASE_ASSET,
                        "amount": amount,
                        "payTo": EVM_RECIPIENT,
                        "maxTimeoutSeconds": 60,
                        "extra": {"name": "USD Coin", "version": "2"},
                    }
                )
            ],
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
    """One 402, then one answer the caller chooses, with a header the caller chooses.

    ``payment_response`` is an explicit argument with **no default**: the audit found the
    old fixture supplying a successful settlement header on every status silently, which is
    exactly how a settled 403 came to be asserted as a release (O44).
    """

    def __init__(
        self,
        *,
        status: int,
        payment_response: str | None,
        headers: dict[str, str] | None = None,
        url: str = URL,
    ) -> None:
        self.status = status
        self.payment_response = payment_response
        self.headers = headers or {}
        self.url = url
        self.paid = 0
        self.signature_digests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        signature = request.headers.get("payment-signature")
        if signature is None:
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": challenge(str(request.url))}
            )
        self.signature_digests.append(hashlib.sha256(signature.encode()).hexdigest())
        self.paid += 1
        headers = dict(self.headers)
        if self.payment_response is not None:
            headers["PAYMENT-RESPONSE"] = self.payment_response
        return httpx.Response(self.status, headers=headers, content=b"delivered")


def evm_rpc(balance: int = 5_000_000) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        document = json.loads(request.read())
        result = hex(8453) if document["method"] == "eth_chainId" else hex(balance)
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": document["id"], "result": result}
        )

    return httpx.MockTransport(handle)


def client(merchant: Any, **kwargs: Any) -> Tx402Client:
    defaults: dict[str, Any] = {
        "evm_signer": EvmSigner(),
        "transport": httpx.MockTransport(merchant),
        "evm_rpc_transport": evm_rpc(),
    }
    defaults.update(kwargs)
    return Tx402Client(**defaults)


def budget(store: SpendStore, *, scope: str = "merchant.test") -> Any:
    return store.get_budget_state(
        policy_scope=scope, asset_id=ASSET_ID, now_epoch_ms=int(time.time() * 1000)
    )


class TestO44SettlementPrecedence:
    """SPEC §5.3, verbatim.

    "If payment settlement is reported successful but resource response is unusable, the
    spend remains committed and the SDK raises ResourceDeliveryError with paid=true."

    Nothing in that sentence mentions the status line, and the whole point of the finding is
    that the implementation consulted the status line first.
    """

    @pytest.mark.parametrize("status", [403, 404, 409, 410, 500, 503, 302])
    def test_a_settled_but_unusable_response_stays_committed(self, status: int) -> None:
        merchant = Merchant(status=status, payment_response=settlement(True))
        store = MemorySpendStore()
        with (
            client(merchant, spend_store=store) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)

        assert raised.value.context.paid is True
        assert raised.value.retryable is False
        assert raised.value.details["reason"] == "settlement-succeeded-resource-unusable"

        state = budget(store)
        assert state.committed_atomic == AMOUNT, (
            "the merchant said it settled, so the spend must count against the hourly cap"
        )
        assert state.reserved_atomic == "0"

    def test_a_settled_402_does_not_re_challenge_into_a_second_payment(self) -> None:
        """The sharpest case, and the one that costs real money.

        A repeated 402 is normally the strongest possible evidence that nothing settled, so
        it releases and the loop signs again. A 402 that *also* reports a successful
        settlement is a merchant contradicting itself, and re-signing on it pays twice for
        one resource. Exactly one signature must ever reach the merchant here.
        """
        merchant = Merchant(status=402, payment_response=settlement(True))
        store = MemorySpendStore()
        with (
            client(merchant, spend_store=store, policy=Policy(max_paid_attempts=3)) as sdk,
            pytest.raises(ResourceDeliveryError),
        ):
            sdk.get(URL)

        assert merchant.paid == 1, "a settled 402 must not be retried"
        assert len(set(merchant.signature_digests)) == 1
        assert budget(store).committed_atomic == AMOUNT

    def test_an_unsettled_refusal_still_releases(self) -> None:
        """The other half of the rule, so the fix cannot be "always commit".

        A merchant that refuses *and* claims no settlement has told us nothing moved, and
        holding the budget would be a silent overcharge against the hourly cap.
        """
        merchant = Merchant(status=403, payment_response=None)
        store = MemorySpendStore()
        with (
            client(merchant, spend_store=store) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.context.paid is False
        assert raised.value.details["reason"] == "paid-request-rejected"
        assert budget(store).reserved_atomic == "0"
        assert budget(store).committed_atomic == "0"

    def test_a_settled_call_leaves_no_room_under_a_cap_it_consumed(self) -> None:
        """The consequence the finding names: an autonomous caller paying twice.

        The cap admits one payment. The first is settled and undelivered. The second must
        be refused by the *budget*, not by luck — which only happens if the first committed.
        """
        store = MemorySpendStore()
        policy = Policy(max_per_request="0.05 USDC", max_per_hour="0.05 USDC")
        with (
            client(
                Merchant(status=403, payment_response=settlement(True)),
                spend_store=store,
                policy=policy,
            ) as sdk,
            pytest.raises(ResourceDeliveryError),
        ):
            sdk.get(URL)

        with (
            client(
                Merchant(status=200, payment_response=settlement(True)),
                spend_store=store,
                policy=policy,
            ) as sdk,
            pytest.raises(BudgetExceededError),
        ):
            sdk.get(URL)


class TestO45PolicyScope:
    """SPEC §5.3's ``policyScope``, and SPEC §4.3's "shared" spend store.

    A shared store is only shareable if two processes calling one merchant agree on the key.
    """

    def test_two_clients_sharing_a_store_share_one_hosts_cap(self) -> None:
        store = MemorySpendStore()
        policy = Policy(max_per_request="0.05 USDC", max_per_hour="0.05 USDC")
        merchant = Merchant(status=200, payment_response=settlement(True))
        with client(merchant, spend_store=store, policy=policy) as first:
            assert first.get(URL).status_code == 200

        # A *different* client object, the same store, the same merchant host. Before S15b
        # each client minted its own UUID scope, so this second call saw an empty ledger.
        with (
            client(
                Merchant(status=200, payment_response=settlement(True)),
                spend_store=store,
                policy=policy,
            ) as second,
            pytest.raises(BudgetExceededError),
        ):
            second.get(URL)

    def test_one_client_calling_two_hosts_keeps_two_ledgers(self) -> None:
        """The same defect in the other direction: one scope across unrelated merchants.

        A per-host cap that is actually per-client would refuse a second merchant because
        the first had spent, which is not what ``max_per_hour`` promises.
        """
        store = MemorySpendStore()
        policy = Policy(max_per_request="0.05 USDC", max_per_hour="0.05 USDC")
        with client(
            Merchant(status=200, payment_response=settlement(True)),
            spend_store=store,
            policy=policy,
        ) as sdk:
            assert sdk.get(URL).status_code == 200
        with client(
            Merchant(status=200, payment_response=settlement(True), url=OTHER_URL),
            spend_store=store,
            policy=policy,
        ) as sdk:
            assert sdk.get(OTHER_URL).status_code == 200

        assert budget(store, scope="merchant.test").committed_atomic == AMOUNT
        assert budget(store, scope="other-merchant.test").committed_atomic == AMOUNT

    def test_the_scope_is_the_normalized_host_a_caller_can_derive(self) -> None:
        """A caller cannot query a ledger whose key they cannot compute."""
        store = MemorySpendStore()
        with client(
            Merchant(status=200, payment_response=settlement(True)), spend_store=store
        ) as sdk:
            sdk.get(URL)
        scope = normalize_policy_host(URL)
        assert scope == "merchant.test"
        state = sdk.get_budget_state(policy_scope=scope, asset_id=ASSET_ID)
        assert state.committed_atomic == AMOUNT
        assert state.policy_scope == scope
        assert state.asset_id == ASSET_ID


class _FailingCommitStore:
    """A store whose ``commit`` fails the way a database outage does.

    Deliberately not a tx402 error: the audit's reproduction used a raw ``RuntimeError``,
    and the point of the finding is that an adapter's own exception type is not tx402's to
    choose.
    """

    kind = "failing-commit"

    def __init__(self) -> None:
        self._inner = MemorySpendStore()
        self.commit_calls = 0

    def reserve(self, **kwargs: Any) -> SpendReservation:
        return self._inner.reserve(**kwargs)

    def commit(self, **kwargs: Any) -> SpendEntry:
        self.commit_calls += 1
        raise RuntimeError("ledger backend unreachable")

    def release(self, **kwargs: Any) -> SpendReservation:
        return self._inner.release(**kwargs)

    def get_budget_state(self, **kwargs: Any) -> Any:
        return self._inner.get_budget_state(**kwargs)


class _FailingReserveStore:
    kind = "failing-reserve"

    def __init__(self) -> None:
        self._inner = MemorySpendStore()

    def reserve(self, **kwargs: Any) -> SpendReservation:
        raise RuntimeError("ledger backend unreachable")

    def commit(self, **kwargs: Any) -> SpendEntry:
        return self._inner.commit(**kwargs)

    def release(self, **kwargs: Any) -> SpendReservation:
        return self._inner.release(**kwargs)

    def get_budget_state(self, **kwargs: Any) -> Any:
        return self._inner.get_budget_state(**kwargs)


class TestO46StoreFailureSemantics:
    """ADR-017. A broken ledger is not a broken settlement, and must not read as one."""

    def test_a_commit_outage_after_settlement_is_typed_paid_and_not_retryable(
        self,
    ) -> None:
        store = _FailingCommitStore()
        merchant = Merchant(status=200, payment_response=settlement(True))
        with (
            client(merchant, spend_store=store) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)

        assert store.commit_calls == 1
        error = raised.value
        assert error.code == "TX402_RESOURCE_DELIVERY"
        assert error.context.paid is True, "the merchant reported a settled payment"
        assert error.context.phase == "complete"
        assert error.retryable is False, (
            "retrying a settled payment is the one action that can pay twice"
        )
        assert error.details["reason"] == SPEND_STORE_COMMIT_FAILED_REASON
        assert error.details["storeKind"] == "failing-commit"
        assert isinstance(error.__cause__, RuntimeError)

    def test_a_commit_outage_does_not_release_the_reservation(self) -> None:
        """Money moved. Handing the budget straight back would be the worst of both."""
        store = _FailingCommitStore()
        with (
            client(
                Merchant(status=200, payment_response=settlement(True)),
                spend_store=store,
            ) as sdk,
            pytest.raises(ResourceDeliveryError),
        ):
            sdk.get(URL)
        state = budget(store)
        assert state.reserved_atomic == AMOUNT
        assert [item.state for item in state.reservations] == ["reserved"]

    def test_a_reserve_outage_is_typed_retryable_and_never_reaches_the_signer(
        self,
    ) -> None:
        """The mirror image, and it classifies the other way for a reason.

        Nothing has been signed, so no money can have moved and a retry is genuinely safe.
        """
        signer = EvmSigner()
        with (
            client(
                Merchant(status=200, payment_response=settlement(True)),
                spend_store=_FailingReserveStore(),
                evm_signer=signer,
            ) as sdk,
            pytest.raises(TransportError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.retryable is True
        assert raised.value.details["causeCategory"] == SPEND_STORE_UNAVAILABLE_CAUSE
        assert signer.requests == [], "SEC-002: no signature without a reservation"

    def test_a_release_outage_does_not_mask_the_original_failure(self) -> None:
        """``release_quietly`` suppressed only ``Tx402Error`` before S15b.

        An adapter raising anything else replaced the precise pre-transmission error with a
        stack trace from the cleanup path. The caller must still see the refusal.
        """

        class ReleaseExplodes(MemorySpendStore):
            kind = "release-explodes"

            def release(self, **kwargs: Any) -> SpendReservation:
                raise RuntimeError("cleanup path is not the error path")

        merchant = Merchant(status=403, payment_response=None)
        with (
            client(merchant, spend_store=ReleaseExplodes()) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.details["reason"] == "paid-request-rejected"


class TestO53MalformedSettlementEnvelope:
    """SPEC §6.7: a 2xx is paid-success "only when ... PAYMENT-RESPONSE parses"."""

    def test_a_corrupt_header_on_a_2xx_is_not_delivery(self) -> None:
        store = MemorySpendStore()
        with (
            client(
                Merchant(status=200, payment_response="not-base64!!"), spend_store=store
            ) as sdk,
            pytest.raises(AmbiguousPaymentError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.details["causeCategory"] == "settlement-metadata-unparseable"
        assert raised.value.context.paid == "unknown"
        assert budget(store).reserved_atomic == AMOUNT, (
            "a corrupt header is not evidence that nothing settled, so it cannot release"
        )

    def test_an_absent_header_on_a_2xx_still_delivers(self) -> None:
        """The distinction the fix rests on. Absent is forgiven; malformed is not."""
        store = MemorySpendStore()
        with client(Merchant(status=200, payment_response=None), spend_store=store) as sdk:
            assert sdk.get(URL).status_code == 200
        assert budget(store).committed_atomic == AMOUNT

    def test_a_header_that_decodes_to_the_wrong_shape_is_also_malformed(self) -> None:
        """Valid base64 is not a valid envelope; only parsing counts."""
        import base64

        payload = base64.b64encode(json.dumps({"not": "a settle response"}).encode())
        with (
            client(Merchant(status=200, payment_response=payload.decode())) as sdk,
            pytest.raises(AmbiguousPaymentError) as raised,
        ):
            sdk.get(URL)
        assert raised.value.details["causeCategory"] == "settlement-metadata-unparseable"


class TestO54SpendStoreContract:
    """SPEC §4.3 makes ``spend_store`` a supported extension point."""

    def test_the_protocol_is_exported_and_memory_store_satisfies_it(self) -> None:
        assert isinstance(MemorySpendStore(), SpendStore)

    def test_a_falsey_but_valid_adapter_is_not_replaced_by_memory(self) -> None:
        """``spend_store or MemorySpendStore()`` silently discarded this store.

        An adapter backed by an empty table is falsey if it defines ``__len__``, and a
        fleet-wide cap quietly became per-process with no error anywhere.
        """

        class EmptyIsFalsey(MemorySpendStore):
            kind = "falsey"

            def __len__(self) -> int:
                return 0

        store = EmptyIsFalsey()
        assert not store
        with client(
            Merchant(status=200, payment_response=settlement(True)), spend_store=store
        ) as sdk:
            sdk.get(URL)
        assert budget(store).committed_atomic == AMOUNT

    def test_a_lookalike_missing_a_method_is_refused_at_construction(self) -> None:
        """Not mid-payment, after a signature has already been produced."""

        class NotAStore:
            kind = "lookalike"

            def reserve(self, **kwargs: Any) -> None: ...
            def release(self, **kwargs: Any) -> None: ...

        with pytest.raises(ConfigurationError) as raised:
            Tx402Client(spend_store=NotAStore())  # type: ignore[arg-type]
        assert raised.value.details["reason"] == "invalid-spend-store"
        assert raised.value.details["missing"] == ["commit", "get_budget_state"]

    def test_the_shipped_contract_suite_passes_for_the_built_in_store(self) -> None:
        check_spend_store(MemorySpendStore)

    def test_the_shipped_contract_suite_catches_a_non_atomic_store(self) -> None:
        """The suite has to be able to fail, or it proves nothing.

        This store does exactly what a naive adapter does: read the total, decide, then
        insert. It passes every other rule and loses money only under contention.
        """

        class RaceySpendStore(MemorySpendStore):
            kind = "racey"

            def reserve(self, **kwargs: Any) -> SpendReservation:
                cap = int(kwargs["max_per_hour_atomic"])
                state = self.get_budget_state(
                    policy_scope=kwargs["policy_scope"],
                    asset_id=kwargs["asset_id"],
                    now_epoch_ms=kwargs["now_epoch_ms"],
                )
                used = int(state.committed_atomic) + int(state.reserved_atomic)
                time.sleep(0.005)  # the window a real adapter leaves open
                if used + int(kwargs["amount_atomic"]) > cap:
                    raise BudgetExceededError(
                        "Hourly spend limit would be exceeded",
                        context=Tx402ErrorContext(
                            request_id=kwargs["request_id"], phase="policy"
                        ),
                        details={
                            "requestedAtomic": kwargs["amount_atomic"],
                            "capAtomic": kwargs["max_per_hour_atomic"],
                            "committedAtomic": state.committed_atomic,
                            "reservedAtomic": state.reserved_atomic,
                            "capKind": "per-hour",
                        },
                    )
                # The insert itself skips the cap, so only the racey check above decides.
                return super().reserve(**{**kwargs, "max_per_hour_atomic": str(cap * 100)})

        with pytest.raises(SpendStoreContractError, match="atomic"):
            check_spend_store(RaceySpendStore)
