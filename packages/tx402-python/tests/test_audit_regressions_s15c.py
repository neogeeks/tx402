"""Regressions for the S15c audit re-run's findings O57 and O58.

Written from the governing text — SPEC §5.3, §6.7, §10, and ADR-016/018 — and run against
the S15c commit ``38155c3`` first, to confirm they failed there. The S15 audit's central
complaint was that the green suite asserted what the implementation did rather than what the
contract required, so a regression derived from the implementation is worth nothing.

``CANONICAL_HOSTS`` is deliberately the *same table* as the one in
``packages/tx402/test/audit-regressions-s15c.test.ts``. O58 was two helpers, documented as
interchangeable, returning different strings for the same URL; the only test that could have
caught it is one both languages answer.
"""

from __future__ import annotations

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
    MemorySpendStore,
    Policy,
    ResourceDeliveryError,
    SpendStore,
    Tx402Client,
    normalize_policy_host,
)
from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.evm import EvmTypedDataRequest

URL = "https://merchant.test/pay"
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


class RecordingLogger:
    """Every event, at the level it was emitted, in order."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def _record(self, level: str, event: Any) -> None:
        self.events.append((level, dict(event)))

    def debug(self, event: Any) -> None:
        self._record("debug", event)

    def info(self, event: Any) -> None:
        self._record("info", event)

    def warn(self, event: Any) -> None:
        self._record("warn", event)

    def error(self, event: Any) -> None:
        self._record("error", event)

    def names(self) -> list[str]:
        return [str(event.get("event")) for _, event in self.events]

    def named(self, name: str) -> list[tuple[str, dict[str, Any]]]:
        return [entry for entry in self.events if entry[1].get("event") == name]


def challenge(url: str = URL) -> str:
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
                        "amount": AMOUNT,
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
    """One 402, then one answer the caller chooses, with the header the caller chooses.

    ``payment_response`` has no default on purpose: a fixture that supplies a successful
    settlement header on every status is what let a settled 403 be asserted as a release
    (O44), and these cases are precisely about the header being absent.
    """

    def __init__(self, *, status: int, payment_response: str | None) -> None:
        self.status = status
        self.payment_response = payment_response
        self.paid = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("payment-signature") is None:
            return httpx.Response(
                402, headers={"PAYMENT-REQUIRED": challenge(str(request.url))}
            )
        self.paid += 1
        headers = {}
        if self.payment_response is not None:
            headers["PAYMENT-RESPONSE"] = self.payment_response
        return httpx.Response(self.status, headers=headers, content=b"delivered")


class AlwaysRechallenges:
    """402 and a fresh challenge to every request, signed or not, never a settlement."""

    def __init__(self) -> None:
        self.paid = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("payment-signature") is not None:
            self.paid += 1
        return httpx.Response(
            402, headers={"PAYMENT-REQUIRED": challenge(str(request.url))}
        )


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


def budget(store: SpendStore, scope: str) -> Any:
    return store.get_budget_state(
        policy_scope=scope, asset_id=ASSET_ID, now_epoch_ms=int(time.time() * 1000)
    )


class TestO57CompletionFollowsTheDisposition:
    """SPEC §10 gives ``payment.completed`` the field ``paid``; SPEC §6.7 decides its value.

    Until S15d the settlement-header reader emitted the event itself, from a branch that
    knew only that the header was missing. Absent metadata is forgiven on a delivered 2xx
    and means nothing at all anywhere else, so the event fired for calls that paid nothing.
    """

    def test_a_headerless_refusal_emits_no_completion(self) -> None:
        """A 403 with no settlement claim is proof that no payment occurred.

        The reservation is released and the error carries ``paid=False``. Announcing a
        completed payment for the same request id tells a reconciliation system the opposite
        of what the SDK concluded a microsecond later.
        """
        logger = RecordingLogger()
        merchant = Merchant(status=403, payment_response=None)
        with (
            client(merchant, logger=logger) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)

        assert raised.value.context.paid is False
        assert logger.named("payment.completed") == []
        assert logger.named("request.failed")[0][1]["paid"] is False

    def test_a_headerless_rechallenge_emits_no_completion(self) -> None:
        """The loudest form: a false completion per signed attempt, then an unpaid error."""
        logger = RecordingLogger()
        merchant = AlwaysRechallenges()
        with (
            client(merchant, logger=logger, policy=Policy(max_paid_attempts=2)) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)

        assert raised.value.context.paid is False
        assert logger.named("payment.completed") == []
        # The attempts really happened — this does not pass because nothing was signed.
        assert merchant.paid == 2
        assert len(logger.named("request.retried")) == 2

    def test_a_delivered_2xx_still_reports_the_permitted_absent_header(self) -> None:
        """The other half, so the fix cannot be "stop emitting the event".

        SPEC §6.7 forgives a missing PAYMENT-RESPONSE because the pinned protocol marks it
        optional, and this is the one disposition where an absent header accompanies a real
        payment. One event, at ``warn``, with the reason and SPEC §10's required fields.
        """
        logger = RecordingLogger()
        merchant = Merchant(status=200, payment_response=None)
        with client(merchant, logger=logger) as sdk:
            assert sdk.get(URL).status_code == 200

        completed = logger.named("payment.completed")
        assert len(completed) == 1
        level, event = completed[0]
        assert level == "warn"
        assert event["paid"] is True
        assert event["reason"] == "payment-response-absent"
        assert isinstance(event["totalSdkOverheadMs"], (int, float))

    def test_an_unparseable_header_is_reported_as_unknown_after_the_table_decides(
        self,
    ) -> None:
        """ADR-016: a present header that does not decode is evidence in neither direction.

        The money is retained and the outcome unknown, and the completion event says exactly
        that — emitted from the ambiguous branch, so it cannot outlive a future change to
        what a malformed header means.
        """
        logger = RecordingLogger()
        merchant = Merchant(status=200, payment_response="!!!not-base64~~~")
        with (
            client(merchant, logger=logger) as sdk,
            pytest.raises(AmbiguousPaymentError),
        ):
            sdk.get(URL)

        completed = logger.named("payment.completed")
        assert len(completed) == 1
        assert completed[0][1]["paid"] == "unknown"
        assert completed[0][1]["reason"] == "payment-response-unparseable"
        names = logger.names()
        assert names.index("payment.completed") < names.index("request.failed")

    @pytest.mark.parametrize(
        ("status", "payment_response"),
        [(403, None), (200, "unsuccessful"), (404, None)],
    )
    def test_no_event_claims_paid_when_the_error_says_unpaid(
        self, status: int, payment_response: str | None
    ) -> None:
        """The invariant behind the four cases above.

        A stream that contradicts the SDK's own conclusion is worse than a silent one,
        because it is the stream an operator reconciles against.
        """
        logger = RecordingLogger()
        header = settlement(False) if payment_response == "unsuccessful" else None
        merchant = Merchant(status=status, payment_response=header)
        with (
            client(merchant, logger=logger) as sdk,
            pytest.raises(ResourceDeliveryError) as raised,
        ):
            sdk.get(URL)

        assert raised.value.context.paid is False
        assert [event for _, event in logger.events if event.get("paid") is True] == []


#: The parity table, identical to the TypeScript suite's. Changing either helper alone must
#: fail a test rather than wait for an audit to notice (ADR-018 amendment).
CANONICAL_HOSTS: list[tuple[str, str]] = [
    ("https://bücher.example/x", "xn--bcher-kva.example"),
    ("https://xn--bcher-kva.example/x", "xn--bcher-kva.example"),
    ("https://BÜCHER.example/x", "xn--bcher-kva.example"),
    ("https://faß.de/", "xn--fa-hia.de"),
    ("https://日本.example:8443/a?b=c", "xn--wgv71a.example"),
    ("https://EXAMPLE.com:443/a", "example.com"),
    ("https://a.test./x", "a.test"),
    ("https://a.test../x", "a.test."),
    ("https://[2001:DB8::1]:9/x", "[2001:db8::1]"),
    ("https://127.0.0.1:8787/x", "127.0.0.1"),
    ("https://./x", ""),
]


class TestO58CanonicalPolicyHost:
    """ADR-018 makes this helper "the public way to derive the exact key a client reserves
    under", and its amendment fixes that key's form as the A-label."""

    @pytest.mark.parametrize(("url", "expected"), CANONICAL_HOSTS)
    def test_the_canonical_form_is_the_a_label(self, url: str, expected: str) -> None:
        assert normalize_policy_host(url) == expected

    def test_unicode_and_punycode_spellings_share_one_ledger_key(self) -> None:
        assert normalize_policy_host("https://bücher.example/one") == normalize_policy_host(
            "https://xn--bcher-kva.example/two"
        )

    def test_the_helper_names_the_ledger_the_client_actually_wrote(self) -> None:
        """The finding, end to end.

        httpx punycodes the request URL before it reaches the wire, so the client reserved
        under ``xn--bcher-kva.example`` while the public helper returned ``bücher.example``.
        A caller following the documented API queried a ledger that was always empty.
        """
        store = MemorySpendStore()
        merchant = Merchant(status=200, payment_response=settlement(True))
        unicode_url = "https://bücher.example/pay"
        with client(merchant, spend_store=store) as sdk:
            assert sdk.get(unicode_url).status_code == 200

        scope = normalize_policy_host(unicode_url)
        assert scope == "xn--bcher-kva.example"
        assert budget(store, scope).committed_atomic == AMOUNT
        # And the ASCII spelling of the same merchant is the same ledger, not a second one.
        assert budget(store, normalize_policy_host("https://xn--bcher-kva.example/pay"))

    def test_a_unicode_allowlist_entry_admits_the_real_request_host(self) -> None:
        """Python failed closed here where TypeScript allowed the same call.

        The allowlist normalized the entry to a U-label while the request host was already
        punycoded, so no Unicode domain could ever match. Restrictive, and still wrong: the
        two SDKs disagreed about which merchants a caller may pay.
        """
        merchant = Merchant(status=200, payment_response=settlement(True))
        policy = Policy(allowed_domains=("bücher.example",))
        with client(merchant, policy=policy) as sdk:
            assert sdk.get("https://bücher.example/pay").status_code == 200

    def test_an_unencodable_host_is_a_configuration_error_not_a_scope(self) -> None:
        """Failing loudly beats reserving under a string no URL parser would produce."""
        with pytest.raises(ValueError, match="not a valid IDN"):
            normalize_policy_host("https://" + "a" * 64 + "\udce9.example/x")
