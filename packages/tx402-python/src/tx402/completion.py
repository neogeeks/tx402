"""SPEC §6.7's completion table, as a pure function (M6).

Port of ``packages/tx402/src/core/completion.ts``, and deliberately a close one: the
``completion.paid-attempt`` conformance vectors drive this function directly in both
languages, so the money rule is inherited rather than re-derived from prose.

What happens to a reservation after a signature has been transmitted is the single most
consequential decision in the SDK, and it is scattered across five clauses of §6.7. Stating
it once, as data-in / data-out, buys three things:

1. **The ordering of the branches is normative.** A 402 is checked before a 5xx check could
   ever see it, and the ``max_paid_attempts`` boundary is checked *inside* the 402 branch —
   not as a separate loop guard — so exhaustion is a typed terminal outcome rather than a
   loop that quietly stops.
2. **The money rule stays out of the control flow.** In :mod:`tx402.client` the disposition
   is looked up and then obeyed; there is no ``if`` in the request path that can drift from
   the specification independently.
3. **Both languages are pinned by the same fixtures.**

The asymmetry the table encodes: **before** a signature reaches the merchant, a failure
releases the reservation. **After** it does, only evidence that no settlement occurred may
release it. A fresh 402 for the same resource is exactly that evidence — the merchant is
still asking to be paid — which is why a re-challenge releases while a 5xx retains.
Releasing on anything ambiguous would let the same money be spent twice against the cap.

**S15b (ADR-016) made that asymmetry actually hold.** Until then the status line was
consulted first, so a 403 carrying a successful ``PAYMENT-RESPONSE`` released the
reservation and reported the call unpaid — the audit's O44. Settlement evidence is now read
on every status and outranks the status line, and a present-but-undecodable header is its
own fourth evidence value rather than being folded into "absent".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Literal

from tx402.errors import TX402_ERROR_CODES

#: Raised when the merchant re-challenges on the last permitted signed attempt.
MAX_PAID_ATTEMPTS_REASON: Final = "max-paid-attempts-exhausted"

#: What the merchant's PAYMENT-RESPONSE proves about settlement.
#:
#: Four values, not three. Until S15b ``"unknown"`` covered both an absent header and one
#: that does not decode, and the audit's O53 showed why that conflation is wrong: SPEC §6.7
#: accepts *missing* metadata because the pinned upstream protocol marks the header
#: optional, and says a 2xx is paid-success "only when any required upstream
#: PAYMENT-RESPONSE parses successfully". See ADR-016.
#:
#: - ``"success"`` — decoded, and ``success: true``.
#: - ``"unsuccessful"`` — decoded, and ``success: false``. The merchant did not settle.
#: - ``"absent"`` — no header at all. Permitted; a diagnostic warning is emitted.
#: - ``"malformed"`` — a header is present and does not decode. A protocol violation, and
#:   never evidence in either direction, so it can neither commit nor release.
SettlementEvidence = Literal["success", "unsuccessful", "absent", "malformed"]

#: SPEC §5.3: settlement succeeded, resource unusable. Recorded in ADR-016.
SETTLED_RESOURCE_UNUSABLE_REASON: Final = "settlement-succeeded-resource-unusable"

#: ADR-016: a present PAYMENT-RESPONSE that does not decode is never evidence.
MALFORMED_SETTLEMENT_CAUSE: Final = "settlement-metadata-unparseable"


@dataclass(frozen=True, slots=True)
class PaidAttemptResult:
    """How the one signature-bearing request of an attempt ended.

    ``kind`` is one of ``"response"`` (the merchant answered, and ``status`` is that
    answer), ``"redirect-blocked"`` (the answer was a cross-origin redirect, refused by
    SEC-005 *after* transmission), or ``"transport-failure"`` (no answer at all:
    connection failure, reset, or the tx402 deadline expiring).
    """

    kind: Literal["response", "redirect-blocked", "transport-failure"]
    status: int | None = None
    settlement: SettlementEvidence = "absent"


@dataclass(frozen=True, slots=True)
class PaidAttemptDisposition:
    """What the request path must do with the reservation, and what it must report.

    ``kind`` is the money disposition; ``error_code`` is the public error identity. They
    are two fields rather than one because SPEC §6.1 names a specific error for a
    cross-origin redirect whose money disposition is the ordinary retained one — which is
    what let S15b fix O52 without touching what happens to the money.
    """

    kind: Literal["commit", "rechallenge", "failed", "paid-undelivered", "ambiguous"]
    reservation: Literal["committed", "released", "retained"]
    error_code: str | None = None
    reason: str | None = None
    cause_category: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """The vector-facing shape: only the members the disposition actually carries."""
        document: dict[str, Any] = {"kind": self.kind, "reservation": self.reservation}
        if self.error_code is not None:
            document["errorCode"] = self.error_code
        if self.reason is not None:
            document["reason"] = self.reason
        if self.cause_category is not None:
            document["causeCategory"] = self.cause_category
        return document


_COMMIT: Final = PaidAttemptDisposition(kind="commit", reservation="committed")
_RECHALLENGE: Final = PaidAttemptDisposition(kind="rechallenge", reservation="released")


def _failed(reason: str) -> PaidAttemptDisposition:
    return PaidAttemptDisposition(
        kind="failed",
        reservation="released",
        error_code=TX402_ERROR_CODES["resource_delivery"],
        reason=reason,
    )


def _paid_undelivered(reason: str) -> PaidAttemptDisposition:
    """SPEC §5.3: settlement succeeded, resource unusable. Commits *and* raises."""
    return PaidAttemptDisposition(
        kind="paid-undelivered",
        reservation="committed",
        error_code=TX402_ERROR_CODES["resource_delivery"],
        reason=reason,
    )


def _ambiguous(
    cause_category: str, error_code: str | None = None
) -> PaidAttemptDisposition:
    return PaidAttemptDisposition(
        kind="ambiguous",
        reservation="retained",
        error_code=error_code or TX402_ERROR_CODES["payment_ambiguous"],
        cause_category=cause_category,
    )


def _is_success_status(status: int) -> bool:
    return 200 <= status < 300


def classify_paid_attempt(
    *,
    attempt: int,
    max_paid_attempts: int,
    result: PaidAttemptResult,
) -> PaidAttemptDisposition:
    """Decides one signed attempt's outcome (SPEC §6.7).

    Pure: no clock, no I/O, no state. Branch order is part of the contract and is asserted
    by the conformance vectors.

    ``attempt`` is 1-based and counts signed retries only — never the initial unpaid
    request. ``max_paid_attempts`` is ``policy.max_paid_attempts``, already validated to
    the range 1 to 3 (SPEC §4.3).
    """
    # Nothing came back. The signature is on the wire either way, so this is the canonical
    # ambiguous case — the one SPEC §6.7 names explicitly.
    if result.kind == "transport-failure":
        return _ambiguous("transport-after-signature")

    # SEC-005 stopped the *follow-up*, not the original transmission. The merchant already
    # has the signature and may well have settled against it, so the reservation is
    # retained — but the public error is the one SPEC §6.1 names, not a generic ambiguity
    # (O52).
    if result.kind == "redirect-blocked":
        return _ambiguous("redirect-blocked", TX402_ERROR_CODES["redirect_blocked"])

    status = result.status
    if status is None:  # pragma: no cover - a "response" without a status is unreachable
        raise ValueError("A response outcome must carry a status")

    # **Settlement evidence outranks the status line** (SPEC §5.3, O44). A merchant that
    # reports a successful settlement has said the money moved; whether it then managed to
    # hand over the resource is a separate fact. Releasing the reservation here would give
    # back budget for a payment that really happened, and an autonomous caller would be
    # free to pay for the same thing again. Checked before every status branch precisely so
    # no status can reach a branch that releases.
    if result.settlement == "success" and not _is_success_status(status):
        return _paid_undelivered(SETTLED_RESOURCE_UNUSABLE_REASON)

    # A present header that does not decode is a protocol violation and is evidence of
    # nothing (ADR-016). It cannot commit — SPEC §6.7 makes parsing a precondition of
    # paid-success — and it must not release, because the merchant plainly attempted to
    # report a settlement. Retention is the only disposition left, on any status.
    if result.settlement == "malformed":
        return _ambiguous(MALFORMED_SETTLEMENT_CAUSE)

    if status == 402:
        # Checked here rather than as a loop guard: an exhausted budget of attempts must be
        # a typed terminal error, and this is the only place that knows it was a
        # re-challenge that exhausted it.
        return (
            _RECHALLENGE
            if attempt < max_paid_attempts
            else _failed(MAX_PAID_ATTEMPTS_REASON)
        )

    # A server error is not a refusal. It says the merchant could not finish telling tx402
    # what happened, which is not the same as saying nothing happened.
    if status >= 500:
        return _ambiguous("server-error")

    # A same-origin redirect reaches here because v0.1 does not follow one (SPEC §6.1's
    # exception is not implemented — PLAN.md open item O26). A redirect is *not* a refusal:
    # the merchant may have settled and be pointing at the delivered resource. Releasing on
    # it would give back budget for money that moved, so it is ambiguous rather than failed.
    if 300 <= status < 400:
        return _ambiguous("redirect-not-followed")

    # Any other non-2xx is the merchant declining the request outright, *without* claiming
    # a settlement — the success case was taken above. Declining is a statement that it did
    # not settle.
    if not _is_success_status(status):
        return _failed("paid-request-rejected")

    # A 2xx whose own PAYMENT-RESPONSE says ``success: false`` is a merchant contradicting
    # itself. tx402 believes the payment metadata, not the status line.
    if result.settlement == "unsuccessful":
        return _failed("settlement-unsuccessful")

    # ``"success"`` and ``"absent"`` both land here. Absent is permitted because the pinned
    # upstream protocol marks the header optional (SPEC §6.7); a warning is emitted at the
    # read site rather than changing the money.
    return _COMMIT
