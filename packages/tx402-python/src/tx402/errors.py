"""The complete tx402 error taxonomy (SPEC §8).

Mirrors ``packages/tx402/src/core/errors.ts`` exactly. Frozen at M0: the fifteen codes and
fifteen class names are a cross-language contract, and the conformance vector
``errors.taxonomy.frozen`` fails if either language drifts (ADR-005).

Two rules that are easy to get wrong, both recorded in ADR-011:

- **``retryable`` is derived, not chosen.** SPEC §8's ``Retryable`` column has six distinct
  values, not two, so the boolean alone cannot carry it. The full classification lives in
  ``retryability``; ``retryable`` is true only for ``caller-policy``, meaning "safe to retry
  as-is, without the caller first changing something". ``InsufficientLiquidityError`` is
  retryable *after funding*, ``ClockSkewError`` *after correction* — neither is
  automatically retryable, so both report ``retryable is False``.

- **``context`` and ``details`` are different things.** ``context`` is the fixed diagnostic
  envelope from SPEC §8 (``request_id``, ``phase``, ...), identical across every error.
  ``details`` carries what the §8 "required context" column asks each individual error to
  report. Splitting them keeps the context object closed, which is what lets the redaction
  tests (SEC-003) enumerate it exhaustively.

Python attributes are snake_case; ``Tx402ErrorContext.to_dict()`` emits the camelCase form
used on the diagnostic event stream and in conformance fixtures, so the wire shape stays
identical to TypeScript's.

Nothing in this module ever holds a signature, a key, an authorization payload, a header
value, or a request body.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Literal

__all__ = [
    "TX402_ERROR_CODES",
    "TX402_ERROR_DESCRIPTORS",
    "TX402_ERROR_TAXONOMY",
    "AmbiguousPaymentError",
    "BudgetExceededError",
    "ClockSkewError",
    "ConfigurationError",
    "DomainNotAllowedError",
    "InsufficientLiquidityError",
    "InvalidPaymentRequiredError",
    "NonReplayableRequestError",
    "PaidRedirectBlockedError",
    "Phase",
    "ResourceDeliveryError",
    "Retryability",
    "SignerError",
    "TransportError",
    "Tx402Error",
    "Tx402ErrorContext",
    "Tx402ErrorDescriptor",
    "UnsupportedProtocolError",
    "UnsupportedSchemeError",
    "is_tx402_error",
]


# ----------------------------------------------------------------------------------------
# Codes
# ----------------------------------------------------------------------------------------

#: Every tx402 error code (SPEC §8).
#:
#: Adding a code is a minor release; changing or removing one is a breaking change
#: (SPEC §15). Callers switch on these rather than on class identity, because the code is
#: what survives a serialization boundary.
TX402_ERROR_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "config_invalid": "TX402_CONFIG_INVALID",
        "reserved_header": "TX402_RESERVED_HEADER",
        "non_replayable": "TX402_NON_REPLAYABLE",
        "protocol_unsupported": "TX402_PROTOCOL_UNSUPPORTED",
        "scheme_unsupported": "TX402_SCHEME_UNSUPPORTED",
        "payment_required_invalid": "TX402_PAYMENT_REQUIRED_INVALID",
        "policy_budget": "TX402_POLICY_BUDGET",
        "policy_domain": "TX402_POLICY_DOMAIN",
        "liquidity": "TX402_LIQUIDITY",
        "signer": "TX402_SIGNER",
        "clock_skew": "TX402_CLOCK_SKEW",
        "payment_ambiguous": "TX402_PAYMENT_AMBIGUOUS",
        "resource_delivery": "TX402_RESOURCE_DELIVERY",
        "redirect_blocked": "TX402_REDIRECT_BLOCKED",
        "transport": "TX402_TRANSPORT",
    }
)

#: SPEC §8's ``Retryable`` column, verbatim rather than collapsed to a boolean.
#:
#: - ``no`` — the request cannot succeed without a different request.
#: - ``conditional`` — may succeed later once an external precondition changes (funding,
#:   signer availability). Never retried automatically.
#: - ``after-correction`` — the caller must fix something first (clock skew).
#: - ``no-automatic-retry`` — retrying risks paying twice. Requires an idempotency strategy.
#: - ``app-dependent`` — money moved; whether to retry is a business decision.
#: - ``caller-policy`` — a plain transport failure. The only automatically retryable class.
Retryability = Literal[
    "no",
    "conditional",
    "after-correction",
    "no-automatic-retry",
    "app-dependent",
    "caller-policy",
]

#: Request-execution phase (SPEC §8), aligned to the SPEC §6 state machine.
Phase = Literal["initial", "parse", "policy", "route", "sign", "retry", "complete"]


@dataclass(frozen=True, slots=True)
class Tx402ErrorContext:
    """The fixed diagnostic envelope carried by every tx402 error (SPEC §8).

    Deliberately closed. Per-error data goes in ``details``.
    """

    request_id: str
    phase: Phase
    network: str | None = None
    scheme: str | None = None
    amount_atomic: str | None = None
    asset_id: str | None = None
    #: ``"unknown"`` is a real third state, not a missing boolean — it is precisely what an
    #: ambiguous outcome reports (SPEC §6.7).
    paid: bool | Literal["unknown"] | None = None
    reservation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Emit the camelCase wire form shared with TypeScript. Omits unset fields."""
        mapping: list[tuple[str, Any]] = [
            ("requestId", self.request_id),
            ("phase", self.phase),
            ("network", self.network),
            ("scheme", self.scheme),
            ("amountAtomic", self.amount_atomic),
            ("assetId", self.asset_id),
            ("paid", self.paid),
            ("reservationId", self.reservation_id),
        ]
        return {key: value for key, value in mapping if value is not None}


# ----------------------------------------------------------------------------------------
# Taxonomy table
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Tx402ErrorDescriptor:
    """One frozen row of SPEC §8."""

    code: str
    class_name: str
    retryability: Retryability
    #: Derived from ``retryability``. See :func:`_is_retryable`.
    retryable: bool
    #: Keys the SPEC §8 "required context" column obliges this error to report.
    required_details: tuple[str, ...] = field(default=())


def _is_retryable(retryability: Retryability) -> bool:
    """The single derivation rule for ``retryable`` (ADR-011).

    Only a transport failure can be retried without the caller doing something first.
    """
    return retryability == "caller-policy"


def _descriptor(
    code: str,
    class_name: str,
    retryability: Retryability,
    required_details: tuple[str, ...],
) -> Tx402ErrorDescriptor:
    return Tx402ErrorDescriptor(
        code=code,
        class_name=class_name,
        retryability=retryability,
        retryable=_is_retryable(retryability),
        required_details=required_details,
    )


#: SPEC §8 as data, in specification order.
#:
#: The conformance vector compares against this table field for field, so a change here
#: that is not mirrored in TypeScript and in the fixture fails CI in three places at once.
TX402_ERROR_TAXONOMY: Final[tuple[Tx402ErrorDescriptor, ...]] = (
    _descriptor(
        TX402_ERROR_CODES["config_invalid"],
        "ConfigurationError",
        "no",
        ("configPath", "reason"),
    ),
    _descriptor(
        TX402_ERROR_CODES["reserved_header"],
        "ReservedHeaderError",
        "no",
        ("headerName",),
    ),
    _descriptor(
        TX402_ERROR_CODES["non_replayable"],
        "NonReplayableRequestError",
        "no",
        ("reason",),
    ),
    _descriptor(
        TX402_ERROR_CODES["protocol_unsupported"],
        "UnsupportedProtocolError",
        "no",
        ("observedVersion", "supportedVersions"),
    ),
    _descriptor(
        TX402_ERROR_CODES["scheme_unsupported"],
        "UnsupportedSchemeError",
        "no",
        ("offeredSchemes", "offeredNetworks"),
    ),
    _descriptor(
        TX402_ERROR_CODES["payment_required_invalid"],
        "InvalidPaymentRequiredError",
        "no",
        ("reason", "schemaPath"),
    ),
    _descriptor(
        TX402_ERROR_CODES["policy_budget"],
        "BudgetExceededError",
        "no",
        ("requestedAtomic", "capAtomic", "committedAtomic", "reservedAtomic", "capKind"),
    ),
    _descriptor(
        TX402_ERROR_CODES["policy_domain"],
        "DomainNotAllowedError",
        "no",
        ("normalizedHost",),
    ),
    _descriptor(
        TX402_ERROR_CODES["liquidity"],
        "InsufficientLiquidityError",
        "conditional",
        ("deficits",),
    ),
    _descriptor(
        TX402_ERROR_CODES["signer"],
        "SignerError",
        "conditional",
        ("signerKind", "causeCategory"),
    ),
    _descriptor(
        TX402_ERROR_CODES["clock_skew"],
        "ClockSkewError",
        "after-correction",
        ("observedSkewMs", "thresholdMs"),
    ),
    _descriptor(
        TX402_ERROR_CODES["payment_ambiguous"],
        "AmbiguousPaymentError",
        "no-automatic-retry",
        ("reservationExpiresAtEpochMs", "causeCategory"),
    ),
    _descriptor(
        TX402_ERROR_CODES["resource_delivery"],
        "ResourceDeliveryError",
        "app-dependent",
        ("status", "reason"),
    ),
    _descriptor(
        TX402_ERROR_CODES["redirect_blocked"],
        "PaidRedirectBlockedError",
        "no",
        ("fromOrigin", "toOrigin"),
    ),
    _descriptor(
        TX402_ERROR_CODES["transport"],
        "TransportError",
        "caller-policy",
        ("causeCategory",),
    ),
)

#: Descriptor lookup by code.
TX402_ERROR_DESCRIPTORS: Final[Mapping[str, Tx402ErrorDescriptor]] = MappingProxyType(
    {entry.code: entry for entry in TX402_ERROR_TAXONOMY}
)


# ----------------------------------------------------------------------------------------
# Base class
# ----------------------------------------------------------------------------------------


class Tx402Error(Exception):
    """Base class for every typed tx402 error (SPEC §4.2).

    ``cause`` is retained for debugging but is **never** serialized by :meth:`to_dict`: the
    underlying error frequently comes from a signer or an HTTP client and may carry a
    payload, a URL with credentials, or a traceback referencing either. SEC-003 makes that
    a redaction failure, so the boundary is drawn here once rather than at every log site.
    """

    #: Set by each subclass. The base class is never raised directly.
    code: str = ""

    def __init__(
        self,
        message: str,
        *,
        context: Tx402ErrorContext,
        details: Mapping[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)

        descriptor = TX402_ERROR_DESCRIPTORS.get(type(self).code)
        if descriptor is None:
            # Unreachable through the exported subclasses; guards a hand-rolled code.
            raise ValueError(f"Unknown tx402 error code: {type(self).code!r}")

        self.message: str = message
        self.retryability: Retryability = descriptor.retryability
        self.retryable: bool = descriptor.retryable
        self.context: Tx402ErrorContext = context
        self.details: Mapping[str, Any] = MappingProxyType(dict(details or {}))
        self.cause: BaseException | None = cause
        if cause is not None:
            self.__cause__ = cause

    @property
    def descriptor(self) -> Tx402ErrorDescriptor:
        """The frozen SPEC §8 row for this error."""
        return TX402_ERROR_DESCRIPTORS[type(self).code]

    def to_dict(self) -> dict[str, Any]:
        """Redaction-safe serialization for logs and the CLI's ``--json`` output.

        Excludes ``cause`` and the traceback by design — see the class note.
        """
        return {
            "name": type(self).__name__,
            "code": type(self).code,
            "message": self.message,
            "retryable": self.retryable,
            "retryability": self.retryability,
            "context": self.context.to_dict(),
            "details": dict(self.details),
        }

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={type(self).code!r}, message={self.message!r})"


def is_tx402_error(error: object) -> bool:
    """Predicate for every tx402 typed error, mirroring TypeScript's ``isTx402Error``.

    Checks the shape as well as the type so that an error crossing a module-reload or
    subprocess boundary is still recognized.
    """
    if isinstance(error, Tx402Error):
        return True
    code = getattr(error, "code", None)
    context = getattr(error, "context", None)
    return isinstance(code, str) and code in TX402_ERROR_DESCRIPTORS and context is not None


# ----------------------------------------------------------------------------------------
# Subclasses — one per SPEC §8 row
# ----------------------------------------------------------------------------------------


class ConfigurationError(Tx402Error):
    """Invalid configuration. Raised eagerly from the client constructor (SPEC §4.2)."""

    code = TX402_ERROR_CODES["config_invalid"]


class ReservedHeaderError(Tx402Error):
    """The caller supplied a protocol-owned header (SPEC §6.1)."""

    code = TX402_ERROR_CODES["reserved_header"]


class NonReplayableRequestError(Tx402Error):
    """The request body cannot be replayed on the paid retry (SPEC §6.1).

    Raised *before* the initial request, not after — discovering this after a 402 would
    mean the caller's stream had already been consumed.
    """

    code = TX402_ERROR_CODES["non_replayable"]


class UnsupportedProtocolError(Tx402Error):
    """Observed a protocol version this build does not implement (ADR-004)."""

    code = TX402_ERROR_CODES["protocol_unsupported"]


class UnsupportedSchemeError(Tx402Error):
    """No offered scheme/network pair is supported (ADR-004). Reports what was offered."""

    code = TX402_ERROR_CODES["scheme_unsupported"]


class InvalidPaymentRequiredError(Tx402Error):
    """The challenge failed strict decoding, schema validation, or binding (SPEC §6.2)."""

    code = TX402_ERROR_CODES["payment_required_invalid"]


class BudgetExceededError(Tx402Error):
    """The price exceeds a configured cap (SPEC §6.3 steps 10-11).

    Evaluated entirely locally and before any signer or balance call, which is why T-006
    asserts a signer-invocation count of zero and a sub-2 ms decision.
    """

    code = TX402_ERROR_CODES["policy_budget"]


class DomainNotAllowedError(Tx402Error):
    """The normalized host is not in ``policy.allowed_domains`` (SPEC §6.3 step 7)."""

    code = TX402_ERROR_CODES["policy_domain"]


class InsufficientLiquidityError(Tx402Error):
    """No offered route has sufficient balance (SPEC §6.4 step 20)."""

    code = TX402_ERROR_CODES["liquidity"]


class SignerError(Tx402Error):
    """The signer refused, failed, or was unavailable.

    ``causeCategory`` is a coarse label — never the signer's own message, which may embed
    key material or a full transaction (SEC-003).
    """

    code = TX402_ERROR_CODES["signer"]


class ClockSkewError(Tx402Error):
    """Observed clock skew above the 15 s threshold (SPEC §6.6).

    The SDK never adjusts the system clock.
    """

    code = TX402_ERROR_CODES["clock_skew"]


class AmbiguousPaymentError(Tx402Error):
    """The signature was transmitted but the outcome is unknown (SPEC §6.7).

    The reservation is deliberately **retained** until its TTL rather than released: the
    payment may have settled, and releasing would let it be spent twice against the cap.
    ``context.paid`` is ``"unknown"``.
    """

    code = TX402_ERROR_CODES["payment_ambiguous"]


class ResourceDeliveryError(Tx402Error):
    """Settlement succeeded but the resource response was unusable (SPEC §5.3).

    The spend stays committed and ``context.paid`` is ``True``. The money moved regardless
    of what came back.
    """

    code = TX402_ERROR_CODES["resource_delivery"]


class PaidRedirectBlockedError(Tx402Error):
    """A paid retry attempted a cross-origin redirect (SEC-005)."""

    code = TX402_ERROR_CODES["redirect_blocked"]


class TransportError(Tx402Error):
    """A network-level failure. The only automatically retryable error."""

    code = TX402_ERROR_CODES["transport"]
