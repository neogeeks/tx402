"""Regressions for the sixth fresh-eyes UX pass (§11.3), open items O96 and O97.

Run against ``08df8f7`` first and observed to fail there.

Both are language-bearing and both are fixed in both languages — see ADR-022. The Python
twin matters more than usual here, because the two implementations were wrong in
*different* ways: TypeScript emitted ``request.failed`` twice on every ambiguous path,
Python emitted it once but always at ``error``. A fix applied only where the pass
demonstrated the defect would have left Python still disagreeing with the documented
contract, and the two languages still disagreeing with each other.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tests.test_payment_paths import (
    URL,
    Merchant,
    challenge,
    evm_requirement,
    evm_rpc,
    settlement,
    svm_rpc,
)
from tx402.client import Tx402Client
from tx402.errors import Tx402Error

BAD_HEADER = "!!! not base64 !!!"


class _Signer:
    kind = "evm"

    def get_address(self) -> str:
        return "0xaad1566216D2447B530E04945dfEefD04C84967B"

    def sign_typed_data(self, request: Any) -> bytes:
        return b"s" * 65


class _Recorder:
    """Captures the level each event was emitted at, which is the contract under test."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    def _at(self, level: str) -> Any:
        def record(event: dict[str, Any]) -> None:
            self.seen.append((level, str(event.get("event"))))

        return record

    def __getattr__(self, name: str) -> Any:
        if name in {"debug", "info", "warn", "error"}:
            return self._at(name)
        raise AttributeError(name)

    def levels_for(self, event: str) -> list[str]:
        return [level for level, name in self.seen if name == event]


def _call(merchant: Merchant) -> tuple[Tx402Error, _Recorder]:
    recorder = _Recorder()
    with (
        Tx402Client(
            evm_signer=_Signer(),
            transport=httpx.MockTransport(merchant),
            evm_rpc_transport=evm_rpc(),
            solana_rpc_transport=svm_rpc(),
            logger=recorder,
            allow_insecure_localhost=True,
        ) as client,
        pytest.raises(Tx402Error) as caught,
    ):
        client.get(URL)
    return caught.value, recorder


def test_an_undecodable_rechallenge_is_a_delivery_failure() -> None:
    """O96 — a re-challenge after the signature, with a header that does not decode.

    Before ADR-022 this raised ``TX402_PAYMENT_REQUIRED_INVALID`` with **no** ``paid``
    context and exit ``5`` — the band documented as "no signature was ever produced",
    whose advice is that nothing local helps. A signature had been produced and sent.
    """
    # The fixture serves `offers[n]` on the nth challenge and ignores `paid_headers` for a
    # 402, so the malformed header goes in the *second* offer: valid challenge, signature,
    # then a re-challenge that does not decode.
    merchant = Merchant(
        offers=[challenge(evm_requirement()), BAD_HEADER],
        paid_statuses=[402],
    )
    error, _ = _call(merchant)
    assert error.code == "TX402_RESOURCE_DELIVERY"
    assert error.context.paid is False
    assert error.details["reason"] == "rechallenge-undecodable"


def test_it_keeps_the_decode_diagnostic() -> None:
    """Re-banding the outcome must not cost the operator the only actionable detail.

    **This passes at ``08df8f7`` too — a do-not-regress guard rather than evidence.** The
    old error was the decode error itself, so it carried ``schemaPath`` for free; the new
    one has to carry it deliberately. The assertion is identical either side, which is what
    makes it useful — it fails only if the fix drops the detail on the floor.
    """
    # The fixture serves `offers[n]` on the nth challenge and ignores `paid_headers` for a
    # 402, so the malformed header goes in the *second* offer: valid challenge, signature,
    # then a re-challenge that does not decode.
    merchant = Merchant(
        offers=[challenge(evm_requirement()), BAD_HEADER],
        paid_statuses=[402],
    )
    error, _ = _call(merchant)
    assert "decodeReason" in error.details or "schemaPath" in error.details


def test_a_malformed_first_challenge_is_untouched() -> None:
    """The do-not-regress half. Before any signature, exit 5 with no ``paid`` is correct."""
    merchant = Merchant(offers=[BAD_HEADER])
    error, _ = _call(merchant)
    assert error.code == "TX402_PAYMENT_REQUIRED_INVALID"
    assert error.context.paid is None


def test_request_failed_is_emitted_once_at_warn_when_ambiguous() -> None:
    """O97 — one emission, and the level comes from ``paid``.

    Python previously emitted this once but always at ``error``, so it never produced the
    ``warn`` the documentation promises for an ambiguous outcome.
    """
    merchant = Merchant(
        offers=[challenge(evm_requirement())],
        paid_statuses=[200],
        paid_headers={"PAYMENT-RESPONSE": "!!! undecodable !!!"},
    )
    error, recorder = _call(merchant)
    assert error.context.paid == "unknown"
    assert recorder.levels_for("request.failed") == ["warn"]


def test_request_failed_is_emitted_once_at_error_otherwise() -> None:
    """And exactly once for a settled-enough outcome, at ``error``."""
    merchant = Merchant(offers=[BAD_HEADER])
    _error, recorder = _call(merchant)
    assert recorder.levels_for("request.failed") == ["error"]


def test_a_settled_but_refused_call_still_reports_paid() -> None:
    """Settlement evidence still outranks the status line: the guarantee O96 must keep."""
    merchant = Merchant(
        offers=[challenge(evm_requirement())],
        paid_statuses=[403],
        paid_headers={"PAYMENT-RESPONSE": settlement()},
    )
    error, _ = _call(merchant)
    assert error.code == "TX402_RESOURCE_DELIVERY"
    assert error.context.paid is True
