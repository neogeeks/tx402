"""Error-model behavior the conformance vectors cannot cover.

``errors.taxonomy.frozen`` pins the *table* — codes, class names, retryability. These tests
cover what instances actually do: redaction, the context/details split, and the predicate.

Mirrors ``packages/tx402/test/errors.test.ts``.
"""

from __future__ import annotations

import json
from typing import Final

import pytest

from tx402.errors import (
    TX402_ERROR_TAXONOMY,
    AmbiguousPaymentError,
    BudgetExceededError,
    ConfigurationError,
    TransportError,
    Tx402Error,
    Tx402ErrorContext,
    is_tx402_error,
)

CONTEXT: Final = Tx402ErrorContext(request_id="req-1", phase="policy")


class TestTx402Error:
    def test_subclasses_share_the_base_class_and_builtin_exception(self) -> None:
        error = BudgetExceededError("over cap", context=CONTEXT)
        assert isinstance(error, BudgetExceededError)
        assert isinstance(error, Tx402Error)
        assert isinstance(error, Exception)

    def test_derives_retryable_from_retryability(self) -> None:
        """Only transport is automatically retryable (ADR-011)."""
        transport = TransportError("reset", context=CONTEXT)
        assert transport.retryable is True
        assert transport.retryability == "caller-policy"

        # Conditional, after-correction, and no-automatic-retry all mean "not without the
        # caller doing something first", so all three report False.
        ambiguous = AmbiguousPaymentError("timed out", context=CONTEXT)
        assert ambiguous.retryable is False
        assert ambiguous.retryability == "no-automatic-retry"

    def test_details_are_read_only(self) -> None:
        error = ConfigurationError(
            "bad",
            context=CONTEXT,
            details={
                "configPath": "policy.max_per_hour",
                "reason": "below-per-request-cap",
            },
        )
        with pytest.raises(TypeError):
            error.details["reason"] = "tampered"  # type: ignore[index]
        assert error.details["reason"] == "below-per-request-cap"

    def test_omits_cause_and_traceback_from_to_dict(self) -> None:
        """SEC-003.

        The underlying error routinely comes from a signer or an HTTP client and may carry
        a payload, a URL with credentials, or a traceback referencing either. Serializing it
        would leak all of that into whatever consumes the diagnostic stream.
        """
        cause = ValueError("signer said: private key 0xdeadbeefcafe")
        error = AmbiguousPaymentError(
            "outcome unknown",
            context=Tx402ErrorContext(
                request_id="req-1", phase="retry", paid="unknown", reservation_id="r-1"
            ),
            details={"reservationExpiresAtEpochMs": 1, "causeCategory": "timeout"},
            cause=cause,
        )

        serialized = json.dumps(error.to_dict())
        assert "deadbeef" not in serialized
        assert "private key" not in serialized
        assert "cause" not in error.to_dict()

        # Still reachable for debugging, just never serialized.
        assert error.cause is cause
        assert error.__cause__ is cause

    def test_paid_unknown_is_a_distinct_third_state(self) -> None:
        error = AmbiguousPaymentError(
            "outcome unknown",
            context=Tx402ErrorContext(request_id="req-1", phase="retry", paid="unknown"),
        )
        assert error.context.paid == "unknown"
        assert error.to_dict()["context"]["paid"] == "unknown"

    def test_context_serializes_to_the_camel_case_wire_form(self) -> None:
        """The wire shape must match TypeScript's exactly (ADR-005)."""
        context = Tx402ErrorContext(
            request_id="req-1",
            phase="route",
            amount_atomic="50000",
            asset_id="eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            reservation_id="0198f0d4-0000-7000-8000-000000000000",
        )
        assert context.to_dict() == {
            "requestId": "req-1",
            "phase": "route",
            "amountAtomic": "50000",
            "assetId": "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "reservationId": "0198f0d4-0000-7000-8000-000000000000",
        }

    def test_context_omits_unset_fields_rather_than_emitting_nulls(self) -> None:
        assert CONTEXT.to_dict() == {"requestId": "req-1", "phase": "policy"}

    def test_rejects_a_code_outside_the_taxonomy(self) -> None:
        class MadeUpError(Tx402Error):
            code = "TX402_MADE_UP"

        with pytest.raises(ValueError, match="Unknown tx402 error code"):
            MadeUpError("nope", context=CONTEXT)


class TestIsTx402Error:
    def test_accepts_every_class_in_the_taxonomy(self) -> None:
        assert is_tx402_error(ConfigurationError("bad", context=CONTEXT))
        assert is_tx402_error(TransportError("reset", context=CONTEXT))

    def test_accepts_a_structurally_valid_error_from_another_module_instance(self) -> None:
        """A subprocess or a reloaded module produces an error that is not this class.

        The predicate checks shape as well as type so those are still recognized.
        """

        class Lookalike:
            code = "TX402_TRANSPORT"
            context = CONTEXT

        assert is_tx402_error(Lookalike())

    def test_rejects_plain_exceptions_and_lookalikes_with_an_unknown_code(self) -> None:
        assert not is_tx402_error(ValueError("boom"))
        assert not is_tx402_error(None)
        assert not is_tx402_error("TX402_TRANSPORT")

        class UnknownCode:
            code = "TX402_NOT_REAL"
            context = CONTEXT

        assert not is_tx402_error(UnknownCode())


class TestTaxonomyTable:
    def test_has_a_unique_code_and_class_name_per_entry(self) -> None:
        codes = [entry.code for entry in TX402_ERROR_TAXONOMY]
        class_names = [entry.class_name for entry in TX402_ERROR_TAXONOMY]
        assert len(set(codes)) == len(codes)
        assert len(set(class_names)) == len(class_names)

    def test_gives_every_entry_at_least_one_required_detail_key(self) -> None:
        """SPEC §8's "required context" column is non-empty for every row.

        An error that reports nothing specific is not actionable.
        """
        for entry in TX402_ERROR_TAXONOMY:
            assert len(entry.required_details) > 0

    def test_every_declared_class_exists_and_carries_its_code(self) -> None:
        import tx402.errors as errors_module

        for entry in TX402_ERROR_TAXONOMY:
            cls = getattr(errors_module, entry.class_name)
            assert issubclass(cls, Tx402Error)
            assert cls.code == entry.code
