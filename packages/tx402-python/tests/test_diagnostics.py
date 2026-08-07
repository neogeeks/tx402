"""T-015: the logger receives seeded secrets and none of them appear (SPEC §12.2, §10).

The approach is deliberately adversarial rather than illustrative. Every input the request
path touches is seeded with a unique, searchable marker — the key material the signer holds,
the signature bytes it produces, the merchant's settlement identifier, the bearer token on
the outbound request, a query-string credential, and the request body — and then the whole
event stream from a real paid call is serialised and searched for every marker.

That ordering matters. A test that asserts "the event has these four fields" passes forever
while a fifth field quietly carries a key. Asserting on the *absence of the secrets* tests
SEC-003's actual property, and it keeps working when someone adds a field later, which is
precisely when the guarantee is most likely to break.

The signature is also checked in its encoded forms. A signature that reaches a log as
base64 or hex has still leaked, and searching only for the raw bytes would miss it.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Literal

import httpx
import pytest

from tests.test_payment_paths import (
    BASE,
    BASE_ASSET,
    EVM_PAYER,
    URL,
    Merchant,
    challenge,
    evm_requirement,
    evm_rpc,
    svm_rpc,
)
from tx402 import (
    BudgetExceededError,
    InsufficientLiquidityError,
    MemorySpendStore,
    Policy,
    Tx402Client,
)
from tx402.diagnostics import (
    EVENT_NAMES,
    NOOP_LOGGER,
    elapsed_ms,
    emit,
    settlement_id_hash,
)
from tx402.evm import EvmTypedDataRequest

# Each marker is long, unique, and contains no substring of the others, so a hit is always
# attributable to exactly one seed rather than to an accidental overlap.
SEED_PRIVATE_KEY = "SEEDdeadbeefPRIVATEKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01"
SEED_SIGNATURE_MARKER = b"SEEDSIGNATUREbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02"
SEED_SETTLEMENT_ID = "SEEDSETTLEMENTcccccccccccccccccccccccccccccccccccccccccccccccc03"
SEED_BEARER = "SEEDBEARERdddddddddddddddddddddddddddddddddddddddddddddddddddd04"
SEED_QUERY_CREDENTIAL = "SEEDQUERYeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee05"
SEED_BODY = "SEEDBODYffffffffffffffffffffffffffffffffffffffffffffffffffffff06"

ALL_SEEDS = (
    SEED_PRIVATE_KEY,
    SEED_SIGNATURE_MARKER.decode(),
    SEED_SETTLEMENT_ID,
    SEED_BEARER,
    SEED_QUERY_CREDENTIAL,
    SEED_BODY,
)


class RecordingLogger:
    """Captures every event at every level, in order."""

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

    def find(self, name: str) -> dict[str, Any]:
        for _, event in self.events:
            if event.get("event") == name:
                return event
        raise AssertionError(f"no {name} event in {self.names()}")

    def serialised(self) -> str:
        """Everything the logger saw, as one searchable string.

        ``default=repr`` matters: a value that is not JSON-serialisable would otherwise
        raise and the search would never run, which is a silent pass. Rendering it instead
        means an exotic object still gets searched for seeds.
        """
        return json.dumps(self.events, default=repr)


class LeakySigner:
    """Holds seeded key material and produces a seeded signature."""

    kind: Literal["evm"] = "evm"

    def __init__(self) -> None:
        # Deliberately reachable from the object the SDK is handed. If any diagnostic ever
        # serialises the signer itself, this is what would come out.
        self.private_key = SEED_PRIVATE_KEY
        self.requests: list[EvmTypedDataRequest] = []

    def get_address(self) -> str:
        return EVM_PAYER

    def sign_typed_data(self, request: EvmTypedDataRequest) -> bytes:
        self.requests.append(request)
        # 65 bytes, the EVM signature length, carrying the marker in the clear.
        return SEED_SIGNATURE_MARKER[:64] + b"\x1b"


def seeded_settlement() -> str:
    from x402.http.utils import encode_payment_response_header
    from x402.schemas import SettleResponse

    return encode_payment_response_header(
        SettleResponse(
            success=True,
            transaction=SEED_SETTLEMENT_ID,
            network=BASE,
            error_reason=None,
        )
    )


def paid_call(logger: RecordingLogger, **kwargs: Any) -> httpx.Response:
    """One full, successful paid call with every seed in place."""
    merchant = Merchant(
        offers=[challenge(evm_requirement())],
        paid_headers={"PAYMENT-RESPONSE": seeded_settlement()},
    )
    defaults: dict[str, Any] = {
        "evm_signer": LeakySigner(),
        "transport": httpx.MockTransport(merchant),
        "evm_rpc_transport": evm_rpc(),
        "solana_rpc_transport": svm_rpc(),
        "logger": logger,
    }
    defaults.update(kwargs)
    with Tx402Client(**defaults) as sdk:
        return sdk.post(
            f"{URL}?api_key={SEED_QUERY_CREDENTIAL}",
            headers={"Authorization": f"Bearer {SEED_BEARER}"},
            json={"prompt": SEED_BODY},
        )


class TestT015NoSeededSecretReachesTheLogger:
    def test_a_successful_paid_call_leaks_nothing(self) -> None:
        logger = RecordingLogger()
        response = paid_call(logger)
        assert response.status_code == 200

        # The call really did exercise the paying path, so "nothing leaked" is not merely
        # "nothing happened". Without this the test would pass against a no-op SDK.
        assert "sign.completed" in logger.names()
        assert "payment.completed" in logger.names()

        blob = logger.serialised()
        for seed in ALL_SEEDS:
            assert seed not in blob, f"seeded secret {seed[:12]}… reached the logger"

    def test_the_signature_leaks_in_no_encoding(self) -> None:
        """Raw bytes are the obvious leak; base64 and hex are the ones that get missed."""
        logger = RecordingLogger()
        paid_call(logger)
        blob = logger.serialised()

        signature = SEED_SIGNATURE_MARKER[:64] + b"\x1b"
        assert base64.b64encode(signature).decode() not in blob
        assert base64.b64encode(signature).decode().rstrip("=") not in blob
        assert signature.hex() not in blob
        assert f"0x{signature.hex()}" not in blob

    def test_a_policy_rejection_leaks_nothing_either(self) -> None:
        """The failure path builds different events, so it needs its own assertion.

        A rejection happens before any signer call, but it still logs `request.failed`
        with an error whose details are assembled from the challenge — which is exactly
        where an over-eager "include the context for debugging" change would leak.
        """
        logger = RecordingLogger()
        merchant = Merchant(offers=[challenge(evm_requirement())])
        with (
            Tx402Client(
                evm_signer=LeakySigner(),
                transport=httpx.MockTransport(merchant),
                evm_rpc_transport=evm_rpc(balance=1),
                solana_rpc_transport=svm_rpc(),
                logger=logger,
            ) as sdk,
            pytest.raises(InsufficientLiquidityError),
        ):
            sdk.post(
                f"{URL}?api_key={SEED_QUERY_CREDENTIAL}",
                headers={"Authorization": f"Bearer {SEED_BEARER}"},
                json={"prompt": SEED_BODY},
            )

        assert "request.failed" in logger.names()
        blob = logger.serialised()
        for seed in ALL_SEEDS:
            assert seed not in blob, f"seeded secret {seed[:12]}… reached the logger"

    def test_the_settlement_id_is_hashed_not_omitted(self) -> None:
        """Absence would also pass the leak test, so pin that the hash is really there.

        Otherwise a change that simply dropped the field would look like a security fix
        while removing the operator's only way to correlate a log line with a settlement.
        """
        logger = RecordingLogger()
        paid_call(logger)
        completed = logger.find("payment.completed")
        assert completed["settlementIdHash"] == settlement_id_hash(SEED_SETTLEMENT_ID)
        assert completed["settlementIdHash"].startswith("sha256:")


class TestSpecSection10EventContract:
    """SPEC §10's table is a minimum field set; each row is pinned here."""

    def test_every_event_carries_its_minimum_fields(self) -> None:
        logger = RecordingLogger()
        paid_call(logger)
        required: dict[str, set[str]] = {
            "request.started": {"requestId", "method", "normalizedHost"},
            "payment.required": {"requestId", "requirementCount", "headerHash"},
            "policy.checked": {"requestId", "outcome", "policyCode"},
            "route.planned": {
                "requestId",
                "candidateCount",
                "selectedNetwork",
                "selectedScheme",
            },
            "budget.reserved": {
                "requestId",
                "reservationId",
                "assetId",
                "amountAtomic",
            },
            "sign.started": {"requestId", "signerKind"},
            "sign.completed": {"requestId", "signerKind", "durationMs"},
            "request.retried": {"requestId", "attempt", "selectedNetwork"},
            "payment.completed": {"requestId", "paid", "totalSdkOverheadMs"},
        }
        for name, fields in required.items():
            assert fields <= set(logger.find(name)), f"{name} is missing fields"

    def test_a_successful_call_emits_the_documented_sequence(self) -> None:
        logger = RecordingLogger()
        paid_call(logger)
        assert logger.names() == [
            "request.started",
            "payment.required",
            "policy.checked",
            "route.planned",
            "budget.reserved",
            "sign.started",
            "sign.completed",
            "request.retried",
            "payment.completed",
        ]

    def test_every_emitted_name_is_declared_in_event_names(self) -> None:
        logger = RecordingLogger()
        paid_call(logger)
        assert set(logger.names()) <= set(EVENT_NAMES)

    def test_durations_are_non_negative_and_monotonic_sourced(self) -> None:
        logger = RecordingLogger()
        paid_call(logger)
        assert logger.find("sign.completed")["durationMs"] >= 0
        assert logger.find("payment.completed")["totalSdkOverheadMs"] >= 0

    def test_events_reach_the_logger_immutable(self) -> None:
        """SPEC §10 hands out a structured object; a sink must not be able to corrupt it.

        Two sinks sharing one event is normal in a fan-out logger, and a mutable mapping
        would let the first one rewrite what the second sees.
        """
        captured: list[Any] = []

        class Capturing(RecordingLogger):
            """Keeps the mapping the SDK handed over, rather than a copy of it."""

            def _record(self, level: str, event: Any) -> None:
                captured.append(event)
                super()._record(level, event)

        paid_call(Capturing())
        assert captured
        with pytest.raises(TypeError):
            captured[0]["event"] = "tampered"


class TestLoggerIsolation:
    def test_a_logger_that_raises_never_fails_the_payment(self) -> None:
        """The worst outcome for an observability feature is failing a settled payment."""

        class ExplodingLogger:
            def debug(self, event: Any) -> None:
                raise RuntimeError("disk full")

            def info(self, event: Any) -> None:
                raise RuntimeError("disk full")

            def warn(self, event: Any) -> None:
                raise RuntimeError("disk full")

            def error(self, event: Any) -> None:
                raise RuntimeError("disk full")

        merchant = Merchant(offers=[challenge(evm_requirement())])
        store = MemorySpendStore()
        with Tx402Client(
            evm_signer=LeakySigner(),
            transport=httpx.MockTransport(merchant),
            evm_rpc_transport=evm_rpc(),
            solana_rpc_transport=svm_rpc(),
            logger=ExplodingLogger(),
            spend_store=store,
        ) as sdk:
            response = sdk.get(URL)

        assert response.status_code == 200
        # And the money still moved, so the isolation did not skip the commit.
        state = store.get_budget_state(
            policy_scope="merchant.test",
            # CAIP-19 for an ERC-20; SPL mints use the `token:` namespace instead.
            asset_id=f"{BASE}/erc20:{BASE_ASSET}",
            now_epoch_ms=int(time.time() * 1000),
        )
        assert state.committed_atomic == "50000"

    def test_keyboard_interrupt_from_a_logger_still_propagates(self) -> None:
        """Isolation covers logger failures, not the user asking the process to stop."""

        class InterruptingLogger:
            def debug(self, event: Any) -> None: ...
            def info(self, event: Any) -> None:
                raise KeyboardInterrupt

            def warn(self, event: Any) -> None: ...
            def error(self, event: Any) -> None: ...

        with pytest.raises(KeyboardInterrupt):
            emit(InterruptingLogger(), "info", {"event": "request.started"})

    def test_the_default_logger_discards_silently(self) -> None:
        for level in ("debug", "info", "warn", "error"):
            emit(NOOP_LOGGER, level, {"event": "request.started"})


class TestDurationHelpers:
    def test_elapsed_is_floored_at_zero_for_a_backwards_clock(self) -> None:
        assert elapsed_ms(lambda: 5.0, 10.0) == 0.0

    def test_elapsed_reports_the_difference(self) -> None:
        assert elapsed_ms(lambda: 30.0, 10.0) == 20.0


class TestPolicyRejectionStillLogs:
    def test_a_budget_refusal_logs_request_failed_with_the_error_code(self) -> None:
        logger = RecordingLogger()
        merchant = Merchant(offers=[challenge(evm_requirement())])
        with (
            Tx402Client(
                evm_signer=LeakySigner(),
                transport=httpx.MockTransport(merchant),
                evm_rpc_transport=evm_rpc(),
                solana_rpc_transport=svm_rpc(),
                policy=Policy(max_per_request="0.01 USDC"),
                logger=logger,
            ) as sdk,
            pytest.raises(BudgetExceededError),
        ):
            sdk.get(URL)

        failed = logger.find("request.failed")
        assert failed["errorCode"].startswith("TX402_")
        assert failed["paid"] is False
        # Policy is evaluated before any signer call (SEC-002), so nothing was signed.
        assert "sign.started" not in logger.names()
