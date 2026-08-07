"""tx402-owned synchronous and asynchronous HTTPX transports (SPEC §4.2, §6).

The ordering in :meth:`_Core.attempt` is the security-critical part of this module and is
not an implementation detail::

    parse → policy → plan → **reserve** → sign → retry → commit

SEC-002 requires every policy check and the budget reservation to complete before a signer
is invoked, and SPEC §6.6 requires the reservation to exist before signing. Both hold on
*every* attempt, not only the first: a second pass re-reserves before it re-signs exactly
as the first did.

The other rule that shapes the code is SPEC §6.7's asymmetry after a signature is
transmitted. Before transmission, a failure releases the reservation. After transmission,
the outcome may be a settled payment tx402 never saw, so the reservation is **retained**
until its TTL and the caller gets ``AmbiguousPaymentError``. Releasing there would let the
same money be spent twice against the hourly cap. That rule is not branched on here — it
lives in :func:`tx402.completion.classify_paid_attempt`, and this module looks the
disposition up and obeys it.
"""

from __future__ import annotations

import dataclasses
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Final, Literal, TypeVar
from urllib.parse import urlsplit

import httpx
from x402.http.utils import (
    decode_payment_response_header,
    encode_payment_signature_header,
)
from x402.schemas import PaymentPayload, PaymentRequirements, ResourceInfo

from tx402.bundled_manifest import BUNDLED_MANIFEST
from tx402.chain import (
    MAX_AUTHORIZATION_SECONDS,
    ChainAdapter,
    ChainAuthorizationRequest,
    ChainRouteRequest,
    chain_family,
    load_chain_adapter,
)
from tx402.completion import (
    MALFORMED_SETTLEMENT_CAUSE,
    MAX_PAID_ATTEMPTS_REASON,
    PaidAttemptDisposition,
    PaidAttemptResult,
    SettlementEvidence,
    classify_paid_attempt,
)
from tx402.deadline import with_deadline, with_deadline_async
from tx402.diagnostics import (
    NOOP_LOGGER,
    Monotonic,
    Tx402Logger,
    elapsed_ms,
    emit,
    monotonic_ms,
    settlement_id_hash,
)
from tx402.errors import (
    TX402_ERROR_CODES,
    AmbiguousPaymentError,
    ConfigurationError,
    NonReplayableRequestError,
    PaidRedirectBlockedError,
    Phase,
    ReservedHeaderError,
    ResourceDeliveryError,
    TransportError,
    Tx402Error,
    Tx402ErrorContext,
    UnsupportedSchemeError,
)
from tx402.fingerprint import fingerprint_request
from tx402.health import HealthIndex
from tx402.ledger import (
    BudgetState,
    MemorySpendStore,
    SpendReservation,
    SpendStore,
    assert_spend_store,
)
from tx402.manifest import assert_valid_release_manifest
from tx402.meta import PROTOCOL_HEADERS, REQUEST_ID_HEADER, RESERVED_REQUEST_HEADERS
from tx402.policy import (
    Policy,
    PolicyDecision,
    PolicyEngine,
    PolicyRequirement,
    RoutingPolicy,
    normalize_policy_host,
)
from tx402.protocol import decode_payment_required
from tx402.routing import (
    BalanceProbeCache,
    RouteCandidate,
    RoutePlan,
    RouteProbeOutcome,
    plan_routes,
    plan_routes_async,
)

BodyFactory = Callable[[], bytes | str]
Clock = Callable[[], int]
_BODY_FACTORY_EXTENSION: Final = "tx402.body_factory"
_PAYMENT_RETRY_TIMEOUT_MS: Final = 10_000
_MIN_PAYMENT_RETRY_TIMEOUT_MS: Final = 1_000
_REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})

#: ``details["reason"]`` when settlement succeeded and the store could not record it.
#:
#: Exported so a caller can branch on it without matching a message string (ADR-017).
SPEND_STORE_COMMIT_FAILED_REASON: Final = "spend-store-commit-failed"

#: ``details["causeCategory"]`` when the store failed before anything was signed.
SPEND_STORE_UNAVAILABLE_CAUSE: Final = "spend-store-unavailable"

ClientT = TypeVar("ClientT", bound="Tx402Client")
AsyncClientT = TypeVar("AsyncClientT", bound="AsyncTx402Client")


@dataclass(frozen=True, slots=True)
class PaymentInspection:
    request_id: str
    response: httpx.Response
    payment_required: Mapping[str, Any] | None


@dataclass(frozen=True, slots=True)
class PaymentPlan:
    """What a real call would have done, decided by the code that would decide it.

    Port of ``PaymentPlan`` in ``packages/tx402/src/core/client.ts``. Everything after
    :attr:`payment_required` is ``None`` when the resource answered something other than
    402 — there was nothing to plan.

    This exists on the client rather than in the CLI so that ``--dry-run`` exercises *the
    shipped decision path*. Rebuilding policy evaluation and route planning inside the CLI
    would make ``--dry-run`` report what a second implementation thought would happen,
    which is worth less than nothing: the point of a dry run is to predict the real one.
    """

    request_id: str
    response: httpx.Response
    payment_required: Mapping[str, Any] | None = None
    #: Every requirement considered, ranked. Non-viable candidates are retained.
    candidates: tuple[RouteCandidate, ...] | None = None
    #: The candidate that would have been paid.
    selected: RouteCandidate | None = None
    amount_atomic: str | None = None
    asset_id: str | None = None


def _system_clock() -> int:
    return time.time_ns() // 1_000_000


def _request_id(now_epoch_ms: int) -> str:
    """UUIDv7-compatible diagnostic ID without depending on Python 3.14's ``uuid7``."""
    timestamp = now_epoch_ms & ((1 << 48) - 1)
    random = secrets.randbits(74)
    value = (
        (timestamp << 80)
        | (0x7 << 76)
        | (((random >> 62) & 0xFFF) << 64)
        | (0b10 << 62)
        | (random & ((1 << 62) - 1))
    )
    text = f"{value:032x}"
    return f"{text[:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:]}"


def _configuration(path: str, reason: str) -> ConfigurationError:
    return ConfigurationError(
        f"Invalid {path}: {reason}",
        context=Tx402ErrorContext(request_id="configuration", phase="initial"),
        details={"configPath": path, "reason": reason},
    )


def _assert_url(request: httpx.Request, allow_insecure_localhost: bool) -> None:
    if request.url.scheme == "https":
        return
    host = request.url.host.lower()
    if (
        allow_insecure_localhost
        and request.url.scheme == "http"
        and host in {"localhost", "127.0.0.1", "::1"}
    ):
        return
    raise _configuration("url", "https-required")


def _assert_headers(request: httpx.Request, request_id: str) -> None:
    for header in RESERVED_REQUEST_HEADERS:
        if header in request.headers:
            raise ReservedHeaderError(
                f"Caller supplied reserved header {header}",
                context=Tx402ErrorContext(request_id=request_id, phase="initial"),
                details={"headerName": header},
            )


def _assert_replayable(request: httpx.Request, request_id: str) -> None:
    if isinstance(request.stream, httpx.ByteStream):
        return
    if request.extensions.get(_BODY_FACTORY_EXTENSION) is not None:
        return
    raise NonReplayableRequestError(
        "Streaming request body cannot be replayed",
        context=Tx402ErrorContext(request_id=request_id, phase="initial"),
        details={"reason": "stream-without-body-factory"},
    )


def _fresh_body(request: httpx.Request, captured: bytes, request_id: str) -> bytes:
    """One transmission's body. With a factory the caller owns replay; else replay bytes."""
    factory = request.extensions.get(_BODY_FACTORY_EXTENSION)
    if factory is None:
        return captured
    try:
        value = factory()
    except BaseException as error:
        raise NonReplayableRequestError(
            "body_factory failed while preparing the paid retry",
            context=Tx402ErrorContext(request_id=request_id, phase="retry"),
            details={"reason": "body-factory-failed"},
            cause=error,
        ) from error
    if isinstance(value, str):
        return value.encode()
    if isinstance(value, bytes):
        return value
    raise NonReplayableRequestError(
        "body_factory must return bytes or str",
        context=Tx402ErrorContext(request_id=request_id, phase="retry"),
        details={"reason": "body-factory-invalid"},
    )


def _payment_requirements(requirement: Mapping[str, Any]) -> PaymentRequirements:
    """The merchant's own offer, unmodified, as it goes back on the wire as ``accepted``.

    The lifetime clamp SPEC §6.6 applies is handed to the scheme separately; a facilitator
    comparing the payload against the merchant's published offer must see exactly what the
    merchant published.
    """
    return PaymentRequirements.model_validate(
        {
            "scheme": requirement["scheme"],
            "network": requirement["network"],
            "asset": requirement["asset"],
            "amount": requirement["amountAtomic"],
            "payTo": requirement["payTo"],
            "maxTimeoutSeconds": requirement["maxTimeoutSeconds"],
            "extra": dict(requirement["extra"]),
        }
    )


def _retry_request(
    request: httpx.Request,
    body: bytes,
    signature: str,
    request_id: str,
    *,
    disable_request_id_header: bool,
) -> httpx.Request:
    """Clones the original request and adds exactly one PAYMENT-SIGNATURE (SPEC §6.7).

    A caller's ``Idempotency-Key`` survives because the whole header set is copied; tx402
    never synthesizes one, because merchant semantics are unknown.
    """
    headers = request.headers.copy()
    headers[PROTOCOL_HEADERS["payment_signature"]] = signature
    if not disable_request_id_header:
        headers[REQUEST_ID_HEADER] = request_id
    return httpx.Request(
        request.method,
        request.url,
        headers=headers,
        content=body,
        extensions=request.extensions,
    )


def _transport_error(error: BaseException, request_id: str, phase: str) -> TransportError:
    return TransportError(
        "HTTP transport failed",
        context=Tx402ErrorContext(request_id=request_id, phase=phase),  # type: ignore[arg-type]
        details={"causeCategory": "transport"},
        cause=error,
    )


def _blocked_redirect(
    response: httpx.Response, request: httpx.Request, request_id: str
) -> PaidRedirectBlockedError | None:
    """SEC-005: a paid retry may not follow a redirect to another origin.

    The block happens after the merchant already has the signature, so it is *not* proof
    that nothing settled — which is why the caller hands it to the disposition table as
    ``redirect-blocked`` rather than releasing the reservation here.
    """
    if response.status_code not in _REDIRECT_STATUSES:
        return None
    location = response.headers.get("location")
    if location is None:
        return None
    destination = request.url.join(location)
    source, target = _origin(request.url), _origin(destination)
    if source == target:
        return None
    return PaidRedirectBlockedError(
        "Paid retry redirect crossed origins",
        context=Tx402ErrorContext(request_id=request_id, phase="retry"),
        details={"fromOrigin": source, "toOrigin": target},
    )


def _origin(url: httpx.URL) -> str:
    parsed = urlsplit(str(url))
    return f"{parsed.scheme}://{parsed.netloc}".lower()


#: Diagnostic reason for a merchant that sent no settlement metadata at all.
SETTLEMENT_ABSENT_REASON: Final = "payment-response-absent"

#: A 402 re-challenge whose ``PAYMENT-REQUIRED`` does not decode, after a
#: signature (ADR-022).
RECHALLENGE_UNDECODABLE_REASON: Final = "rechallenge-undecodable"

#: Diagnostic reason for a merchant whose settlement metadata does not decode.
SETTLEMENT_UNPARSEABLE_REASON: Final = "payment-response-unparseable"


def _read_payment_response(
    response: httpx.Response,
) -> tuple[SettlementEvidence, str | None]:
    """Reads PAYMENT-RESPONSE, on **every** status (SPEC §5.3, ADR-016).

    Three things about this function are load-bearing, and each was wrong once:

    - It is called whatever the merchant's status line says. A 403 or a 500 carrying a
      successful settlement is exactly the case SPEC §5.3 legislates for, and it cannot be
      handled by a disposition table that never sees the evidence (O44).
    - Absent and undecodable are **different** evidence values. Upstream marks the header
      optional, so absent is forgiven; a header that is present and does not decode is a
      protocol violation and is evidence of nothing (O53).
    - **It emits nothing.** Evidence is not an outcome. Until S15d the absent branch logged
      ``payment.completed`` with ``paid=True`` from here, which is only true when that
      evidence later reaches the table's commit row — a headerless 403 refusal and a
      headerless 402 re-challenge both produced a paid-success event for a call that paid
      nothing (O57). The reader now returns evidence and the disposition decides what, if
      anything, is reported. The two reasons stay distinct wherever they are reported:
      "the merchant sent no settlement metadata" and "the merchant sent metadata I could
      not parse" point at different bugs on the merchant's side.
    """
    header = response.headers.get(PROTOCOL_HEADERS["payment_response"])
    if not header:
        return "absent", None
    try:
        settlement = decode_payment_response_header(header)
    except (ValueError, TypeError):
        return "malformed", None
    if not settlement.success:
        return "unsuccessful", None
    transaction = settlement.transaction
    return "success", transaction if isinstance(transaction, str) and transaction else None


@dataclass(frozen=True, slots=True)
class _Prepared:
    """The initial request, plus everything needed to reissue it byte-for-byte."""

    request: httpx.Request
    body: bytes
    host: str
    #: Monotonic reading taken before the initial request, for ``totalSdkOverheadMs``.
    #: Carried here rather than passed alongside because every emit site that needs it
    #: already has the prepared request, and a second parallel parameter is a second
    #: thing to forget to thread through the async path.
    started_at: float = 0.0


@dataclass(frozen=True, slots=True)
class _Selection:
    plan: RoutePlan
    requirement: PolicyRequirement
    adapter: ChainAdapter
    network: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _Delivered:
    response: httpx.Response


@dataclass(frozen=True, slots=True)
class _Rechallenged:
    challenge: Mapping[str, Any]


class _Core:
    """Everything both transports share. Holds no per-request state."""

    def __init__(
        self,
        *,
        evm_signer: object,
        solana_signer: object,
        policy: PolicyEngine,
        spend_store: SpendStore,
        manifest: Mapping[str, Any],
        clock: Clock,
        evm_rpc_transport: object,
        solana_rpc_transport: object,
        allow_insecure_localhost: bool,
        initial_request_timeout_ms: int | None,
        payment_retry_timeout_ms: int,
        disable_request_id_header: bool,
        logger: Tx402Logger,
        monotonic: Monotonic,
    ) -> None:
        self.evm_signer = evm_signer
        self.solana_signer = solana_signer
        self.policy = policy
        self.spend_store = spend_store
        self.manifest = manifest
        self.clock = clock
        self.allow_insecure_localhost = allow_insecure_localhost
        self.initial_request_timeout_ms = initial_request_timeout_ms
        self.payment_retry_timeout_ms = payment_retry_timeout_ms
        self.disable_request_id_header = disable_request_id_header
        self.logger = logger
        self.monotonic = monotonic
        #: The one health index (SPEC §6.5). Every RPC pool in every adapter reports here.
        self.health = HealthIndex()
        self._rpc_transports = {
            "eip155": evm_rpc_transport,
            "solana": solana_rpc_transport,
        }
        self._adapters: dict[str, ChainAdapter | None] = {}
        self.policy_scope_default = ""

    # -- configuration surface -----------------------------------------------------------

    def signer_for(self, family: str) -> object:
        if family == "eip155":
            return self.evm_signer
        if family == "solana":
            return self.solana_signer
        return None

    def adapter_for(self, family: str, context: Tx402ErrorContext) -> ChainAdapter | None:
        if family in self._adapters:
            return self._adapters[family]
        try:
            adapter = load_chain_adapter(
                family,
                health=self.health,
                rpc_transport=self._rpc_transports.get(family),
                rpc_overrides=self.policy.rpc_overrides,
            )
        except ImportError as error:
            # A missing optional extra arrives here as a module resolution failure. The
            # caller is told which extra to install rather than which module was absent.
            raise ConfigurationError(
                f"Paying on {family} requires the matching tx402 extra to be installed",
                context=context,
                details={
                    "configPath": f"signers.{family}",
                    "reason": "chain-adapter-unavailable",
                },
                cause=error,
            ) from error
        self._adapters[family] = adapter
        return adapter

    def reset_health(self) -> None:
        """Clears in-memory health metrics. Never touches the spend ledger (SPEC §4.1)."""
        self.health.reset()

    # -- diagnostics (SPEC §10) ----------------------------------------------------------
    #
    # These live on the core rather than in each transport so the sync and async paths emit
    # identical streams by construction. Duplicating them per transport is how the two
    # would quietly drift, and a diagnostic difference between `client.get()` and
    # `await client.get()` is exactly the kind of bug nobody looks for.

    def log_request_started(self, request_id: str, request: httpx.Request) -> None:
        emit(
            self.logger,
            "info",
            {
                "event": "request.started",
                "requestId": request_id,
                "method": request.method,
                "normalizedHost": normalize_policy_host(str(request.url)),
            },
        )

    def log_payment_required(
        self,
        request_id: str,
        challenge: Mapping[str, Any],
        *,
        attempt: int | None = None,
        started_at: float | None = None,
    ) -> None:
        """One event, three call sites: initial decode, ``inspect``, and a re-challenge.

        ``attempt`` and ``totalSdkOverheadMs`` are each present only where the TypeScript
        reference includes them — ``inspect`` reports overhead because parsing is the whole
        operation, whereas on the paying path the overhead is reported once at
        ``payment.completed`` for the call as a whole.
        """
        event: dict[str, object] = {
            "event": "payment.required",
            "requestId": request_id,
            "requirementCount": len(challenge["requirements"]),
            "headerHash": challenge["headerHash"],
        }
        if attempt is not None:
            event["attempt"] = attempt
        if started_at is not None:
            event["totalSdkOverheadMs"] = elapsed_ms(self.monotonic, started_at)
        emit(self.logger, "info", event)

    def log_request_retried(
        self, request_id: str, attempt: int, selection: _Selection
    ) -> None:
        emit(
            self.logger,
            "info",
            {
                "event": "request.retried",
                "requestId": request_id,
                "attempt": attempt,
                "selectedNetwork": selection.requirement.requirement["network"],
            },
        )

    def log_request_failed(self, error: Tx402Error) -> None:
        """The one place ``request.failed`` is emitted, at a level derived from ``paid``.

        ``warn`` while the money is still reserved and the outcome unknown, ``error`` for
        everything settled enough to act on. TypeScript emits at the same single point on
        the same rule; before ADR-022 it emitted twice on every ambiguous path and Python
        emitted once but always at ``error``, so neither matched the documented contract
        nor each other.
        """
        paid = error.context.paid if error.context.paid is not None else False
        emit(
            self.logger,
            "warn" if paid == "unknown" else "error",
            {
                "event": "request.failed",
                "requestId": error.context.request_id,
                "errorCode": error.code,
                "phase": error.context.phase,
                "paid": paid,
            },
        )

    # -- request preparation -------------------------------------------------------------

    def prepare(self, request: httpx.Request, request_id: str) -> tuple[bytes, str]:
        _assert_url(request, self.allow_insecure_localhost)
        _assert_headers(request, request_id)
        host = self.policy.assert_domain(str(request.url), request_id)
        _assert_replayable(request, request_id)
        return request.read(), host

    async def prepare_async(
        self, request: httpx.Request, request_id: str
    ) -> tuple[bytes, str]:
        _assert_url(request, self.allow_insecure_localhost)
        _assert_headers(request, request_id)
        host = self.policy.assert_domain(str(request.url), request_id)
        _assert_replayable(request, request_id)
        return await request.aread(), host

    def decode(
        self, response: httpx.Response, request: httpx.Request, request_id: str
    ) -> Mapping[str, Any]:
        return decode_payment_required(
            response.headers.get(PROTOCOL_HEADERS["payment_required"]),
            request_url=str(request.url),
            request_method=request.method,
            request_id=request_id,
            clock_epoch_ms=self.clock(),
        )

    def decide(
        self, payment_required: Mapping[str, Any], request_id: str, host: str
    ) -> PolicyDecision:
        decision = self.policy.evaluate(
            payment_required,
            request_id=request_id,
            policy_scope=host,
            now_epoch_ms=self.clock(),
            spend_store=self.spend_store,
        )
        # Only the allowed outcome is emitted here because a rejection raises rather than
        # returning: the refusal is already reported by `request.failed` carrying the
        # specific policy error code, and emitting both would double-count it.
        emit(
            self.logger,
            "info",
            {
                "event": "policy.checked",
                "requestId": request_id,
                "outcome": "allowed",
                "policyCode": "allowed",
            },
        )
        return decision

    # -- route planning ------------------------------------------------------------------

    def _probe_inputs(
        self, requirement: PolicyRequirement, request_id: str, now_epoch_ms: int
    ) -> tuple[ChainAdapter, ChainRouteRequest] | RouteProbeOutcome:
        """Resolves signer, adapter, and manifest network, or says why it could not.

        Each failure is a *candidate* rejection rather than a fatal error: SPEC §6.4 step 20
        distinguishes "nothing was even attempted" from "everything attempted fell short",
        and that distinction is only available if unattempted requirements survive as
        candidates.
        """
        network_id = requirement.requirement["network"]
        family = chain_family(network_id)
        context = Tx402ErrorContext(request_id=request_id, phase="route")
        if self.signer_for(family) is None:
            return RouteProbeOutcome(kind="rejected", reason="no-signer-configured")
        adapter = self.adapter_for(family, context)
        if adapter is None:
            return RouteProbeOutcome(kind="rejected", reason="scheme-unsupported")
        network = self.manifest["networks"].get(network_id)
        if network is None:
            return RouteProbeOutcome(kind="rejected", reason="network-not-in-manifest")
        return adapter, ChainRouteRequest(
            request_id=request_id,
            network_id=network_id,
            network=network,
            asset=requirement.manifest_asset,
            requirement=requirement,
            signer=self.signer_for(family),
            now_epoch_ms=now_epoch_ms,
        )

    @staticmethod
    def _classify_route_failure(error: BaseException) -> RouteProbeOutcome:
        """Maps an adapter failure onto the vocabulary the RouteCandidate schema allows.

        A ``TransportError`` from a chain adapter is an RPC that could not answer, which
        makes one candidate non-viable — not the whole plan fatal. Anything else (a missing
        extra, a manifest inconsistency) is a configuration problem the caller has to see,
        and reporting it as "insufficient liquidity" sends them looking at their wallet.
        """
        if not isinstance(error, TransportError):
            return RouteProbeOutcome(
                kind="failed", reason="balance-unavailable", error=error, fatal=True
            )
        category = error.details.get("causeCategory")
        if category in {"chain-id-mismatch", "genesis-hash-mismatch"}:
            reason = "chain-identity-mismatch"
        elif category == "circuit-open":
            reason = "circuit-open"
        else:
            reason = "balance-unavailable"
        return RouteProbeOutcome(kind="failed", reason=reason, error=error, fatal=False)

    def plan(
        self, decision: PolicyDecision, request_id: str, now_epoch_ms: int
    ) -> _Selection:
        def probe(
            requirement: PolicyRequirement, balances: BalanceProbeCache
        ) -> RouteProbeOutcome:
            resolved = self._probe_inputs(requirement, request_id, now_epoch_ms)
            if isinstance(resolved, RouteProbeOutcome):
                return resolved
            adapter, route_request = resolved
            try:
                route = adapter.plan_route(
                    dataclasses.replace(route_request, balances=balances)
                )
            except BaseException as error:
                return self._classify_route_failure(error)
            return RouteProbeOutcome(kind="route", route=route)

        plan = plan_routes(
            requirements=decision.requirements,
            prefer_networks=self.policy.prefer_networks,
            health=self.health,
            now_epoch_ms=now_epoch_ms,
            context=Tx402ErrorContext(request_id=request_id, phase="route"),
            probe=probe,
        )
        return self._selection(plan, request_id)

    async def plan_async(
        self, decision: PolicyDecision, request_id: str, now_epoch_ms: int
    ) -> _Selection:
        async def probe(
            requirement: PolicyRequirement, balances: BalanceProbeCache
        ) -> RouteProbeOutcome:
            resolved = self._probe_inputs(requirement, request_id, now_epoch_ms)
            if isinstance(resolved, RouteProbeOutcome):
                return resolved
            adapter, route_request = resolved
            try:
                route = await adapter.plan_route_async(
                    dataclasses.replace(route_request, balances=balances)
                )
            except BaseException as error:
                return self._classify_route_failure(error)
            return RouteProbeOutcome(kind="route", route=route)

        plan = await plan_routes_async(
            requirements=decision.requirements,
            prefer_networks=self.policy.prefer_networks,
            health=self.health,
            now_epoch_ms=now_epoch_ms,
            context=Tx402ErrorContext(request_id=request_id, phase="route"),
            probe=probe,
        )
        return self._selection(plan, request_id)

    def _selection(self, plan: RoutePlan, request_id: str) -> _Selection:
        network_id = plan.selected_requirement.requirement["network"]
        context = Tx402ErrorContext(request_id=request_id, phase="route")
        adapter = self.adapter_for(chain_family(network_id), context)
        network = self.manifest["networks"].get(network_id)
        if adapter is None or network is None:  # pragma: no cover - probed successfully
            raise UnsupportedSchemeError(
                "Selected network lost its chain adapter",
                context=context,
                details={
                    "offeredSchemes": [plan.selected_requirement.requirement["scheme"]],
                    "offeredNetworks": [network_id],
                },
            )
        selection = _Selection(plan, plan.selected_requirement, adapter, network)
        # Redaction-safe by construction: a candidate carries public identifiers and atomic
        # figures only, and never an RPC URL (SEC-003).
        emit(
            self.logger,
            "info",
            {
                "event": "route.planned",
                "requestId": request_id,
                "candidateCount": len(plan.candidates),
                "selectedNetwork": selection.requirement.requirement["network"],
                "selectedScheme": selection.requirement.requirement["scheme"],
                "selectedHealthScore": plan.selected.health_score,
                "selectedRank": plan.selected.rank,
            },
        )
        return selection

    # -- reservation and signing ---------------------------------------------------------

    def reserve(
        self,
        *,
        selection: _Selection,
        prepared: _Prepared,
        request_id: str,
        challenge_hash: str,
    ) -> tuple[SpendReservation, str]:
        """Atomic reservation, before a signer is reachable (SEC-002, SPEC §6.6)."""
        item = selection.requirement
        now = self.clock()
        request_hash = fingerprint_request(
            method=prepared.request.method,
            url=str(prepared.request.url),
            body=prepared.body,
            challenge_hash=challenge_hash,
        )
        reservation = self.spend_store.reserve(
            reservation_id=_request_id(now),
            request_id=request_id,
            policy_scope=prepared.host,
            request_fingerprint=request_hash,
            asset_id=item.asset_id,
            amount_atomic=item.requirement["amountAtomic"],
            max_per_hour_atomic=item.max_per_hour_atomic,
            now_epoch_ms=now,
        )
        emit(
            self.logger,
            "info",
            {
                "event": "budget.reserved",
                "requestId": request_id,
                "reservationId": reservation.reservation_id,
                "assetId": reservation.asset_id,
                "amountAtomic": reservation.amount_atomic,
            },
        )
        return reservation, request_hash

    def _authorization_request(
        self,
        *,
        selection: _Selection,
        prepared: _Prepared,
        request_id: str,
        request_hash: str,
    ) -> ChainAuthorizationRequest:
        item = selection.requirement
        return ChainAuthorizationRequest(
            request_id=request_id,
            network_id=item.requirement["network"],
            network=selection.network,
            asset=item.manifest_asset,
            requirement=item,
            signer=self.signer_for(chain_family(item.requirement["network"])),
            now_epoch_ms=self.clock(),
            resource_host=normalize_policy_host(str(prepared.request.url)),
            request_hash=request_hash,
            max_authorization_seconds=MAX_AUTHORIZATION_SECONDS,
        )

    @staticmethod
    def _signer_kind(selection: _Selection) -> str:
        family = chain_family(selection.requirement.requirement["network"])
        return "evm" if family == "eip155" else "solana"

    def _log_sign_started(self, request_id: str, selection: _Selection) -> float:
        """Emits ``sign.started`` and returns the monotonic mark for ``sign.completed``.

        SPEC §10 requires the duration to come from a monotonic clock, and pairing the two
        emits in one helper is what stops a later edit from timing the span against the
        wall clock that the rest of the request path uses for authorization bounds.
        """
        emit(
            self.logger,
            "debug",
            {
                "event": "sign.started",
                "requestId": request_id,
                "signerKind": self._signer_kind(selection),
            },
        )
        return self.monotonic()

    def _log_sign_completed(
        self, request_id: str, selection: _Selection, started_at: float
    ) -> None:
        emit(
            self.logger,
            "debug",
            {
                "event": "sign.completed",
                "requestId": request_id,
                "signerKind": self._signer_kind(selection),
                "durationMs": elapsed_ms(self.monotonic, started_at),
            },
        )

    @staticmethod
    def _signature_header(selection: _Selection, authorization: Any, url: str) -> str:
        return encode_payment_signature_header(
            PaymentPayload(
                x402_version=authorization.x402_version,
                payload=dict(authorization.payload),
                accepted=_payment_requirements(selection.requirement.requirement),
                resource=ResourceInfo(url=url),
            )
        )

    def sign(
        self,
        *,
        selection: _Selection,
        prepared: _Prepared,
        request_id: str,
        request_hash: str,
    ) -> str:
        signing_started_at = self._log_sign_started(request_id, selection)
        authorization = selection.adapter.create_authorization(
            self._authorization_request(
                selection=selection,
                prepared=prepared,
                request_id=request_id,
                request_hash=request_hash,
            )
        )
        self._log_sign_completed(request_id, selection, signing_started_at)
        return self._signature_header(selection, authorization, str(prepared.request.url))

    async def sign_async(
        self,
        *,
        selection: _Selection,
        prepared: _Prepared,
        request_id: str,
        request_hash: str,
    ) -> str:
        signing_started_at = self._log_sign_started(request_id, selection)
        authorization = await selection.adapter.create_authorization_async(
            self._authorization_request(
                selection=selection,
                prepared=prepared,
                request_id=request_id,
                request_hash=request_hash,
            )
        )
        self._log_sign_completed(request_id, selection, signing_started_at)
        return self._signature_header(selection, authorization, str(prepared.request.url))

    # -- disposition ---------------------------------------------------------------------

    def release_quietly(self, reservation_id: str) -> None:
        """Releases without letting a store failure mask the original error.

        A reservation expires on its own after 120 s, so a store that cannot release is not
        a reason to replace a precise failure with a vaguer one.

        ``Exception`` rather than ``Tx402Error``: before S15b only tx402's own errors were
        suppressed, so an adapter raising an ordinary ``KeyError`` or a driver error from
        its own transport replaced a precise pre-transmission failure with a stack trace
        from the cleanup path (O46). ``BaseException`` is deliberately *not* caught —
        cancellation and ``KeyboardInterrupt`` must still propagate.
        """
        with suppress(Exception):
            self.spend_store.release(
                reservation_id=reservation_id, now_epoch_ms=self.clock()
            )

    def reserve_or_fail(
        self,
        *,
        selection: _Selection,
        prepared: _Prepared,
        request_id: str,
        challenge_hash: str,
    ) -> tuple[SpendReservation, str]:
        """:meth:`reserve`, with any store outage converted to a typed failure (O46).

        Nothing has been signed here, so a retry is genuinely safe and ``TransportError`` —
        the one ``caller-policy`` retryable code — is the honest classification.
        ``BudgetExceededError`` and anything else already typed pass through untouched: a
        refused budget is not an outage.
        """
        try:
            return self.reserve(
                selection=selection,
                prepared=prepared,
                request_id=request_id,
                challenge_hash=challenge_hash,
            )
        except Tx402Error:
            raise
        except Exception as error:
            raise TransportError(
                "The spend store could not take a reservation",
                context=Tx402ErrorContext(
                    request_id=request_id,
                    phase="policy",
                    amount_atomic=selection.requirement.requirement["amountAtomic"],
                    asset_id=selection.requirement.asset_id,
                ),
                details={
                    "causeCategory": SPEND_STORE_UNAVAILABLE_CAUSE,
                    "storeKind": getattr(self.spend_store, "kind", "unknown"),
                },
                cause=error,
            ) from error

    @staticmethod
    def _route_context(
        selection: _Selection,
        request_id: str,
        phase: Phase,
        *,
        paid: bool | Literal["unknown"] | None = None,
        reservation_id: str | None = None,
    ) -> Tx402ErrorContext:
        """The post-routing error context, carrying the selected route (SPEC §8).

        TypeScript builds one such object the moment a route is chosen and spreads it into
        every downstream failure (``client.ts:928``); Python built a bare
        ``request_id``/``phase`` context at each site, so ``--json``'s ``error.context``
        dropped ``network``/``scheme``/``amountAtomic``/``assetId`` on every post-routing
        failure — the parity break S34 found (O107). This is that one object, so the two
        CLIs emit the same document. Every field it carries is a public identifier or an
        atomic figure, never a signer payload or an RPC URL (SEC-003).
        """
        requirement = selection.requirement.requirement
        return Tx402ErrorContext(
            request_id=request_id,
            phase=phase,
            network=requirement["network"],
            scheme=requirement["scheme"],
            amount_atomic=requirement["amountAtomic"],
            asset_id=selection.requirement.asset_id,
            paid=paid,
            reservation_id=reservation_id,
        )

    def commit_or_fail(
        self,
        *,
        selection: _Selection,
        request_id: str,
        reservation: SpendReservation,
        settlement_id: str | None,
        status: int,
    ) -> None:
        """Commits, or converts the store's failure into one honest typed outcome (ADR-017).

        The payment has already settled by the time this runs. A store that cannot record
        it has broken tx402's *accounting*, not the merchant's *settlement*, and the two
        must not be conflated:

        - It is **not** a transport failure, and it is not an untyped ``RuntimeError``
          escaping to the caller, which is what the audit reproduced (O46).
          ``ResourceDeliveryError`` is ``app-dependent``, so ``retryable`` is ``False``.
        - ``paid`` is **``True``**, not ``"unknown"``. The merchant's own metadata reported
          a successful settlement; tx402 knows the money moved and says so.
        - The reservation is deliberately **not** released. It still counts against the
          hourly cap until its TTL, which is the conservative direction to be wrong in.
        """
        try:
            self.spend_store.commit(
                reservation_id=reservation.reservation_id,
                committed_at_epoch_ms=self.clock(),
                settlement_id=settlement_id,
            )
        except Exception as error:
            emit(
                self.logger,
                "error",
                {
                    "event": "request.failed",
                    "requestId": request_id,
                    "errorCode": TX402_ERROR_CODES["resource_delivery"],
                    "phase": "complete",
                    "paid": True,
                },
            )
            raise ResourceDeliveryError(
                "The payment settled but the spend store could not record it",
                context=self._route_context(
                    selection,
                    request_id,
                    "complete",
                    paid=True,
                    reservation_id=reservation.reservation_id,
                ),
                details={
                    "status": status,
                    "reason": SPEND_STORE_COMMIT_FAILED_REASON,
                    "reservationExpiresAtEpochMs": reservation.expires_at_epoch_ms,
                    "storeKind": getattr(self.spend_store, "kind", "unknown"),
                },
                cause=error,
            ) from error

    def unresolved(
        self,
        *,
        selection: _Selection,
        request_id: str,
        reservation: SpendReservation,
        disposition: PaidAttemptDisposition,
        cause: BaseException | None = None,
    ) -> Tx402Error:
        """The typed error for a signature transmitted without a resolved outcome.

        Which class is raised comes from the disposition's ``error_code``, not from this
        method: SPEC §6.1 requires a cross-origin redirect to raise
        ``PaidRedirectBlockedError``, and before S15b the high-level client swallowed it and
        reported ``AmbiguousPaymentError`` instead (O52). The money disposition is identical
        either way — retained to TTL — so the fix is an identity fix and nothing more.
        """
        context = self._route_context(
            selection,
            request_id,
            "retry",
            paid="unknown",
            reservation_id=reservation.reservation_id,
        )
        cause_category = disposition.cause_category or "unknown"

        if disposition.error_code == TX402_ERROR_CODES["redirect_blocked"]:
            # SPEC §8 requires ``fromOrigin``/``toOrigin`` on this code, and the block site
            # already computed them — so they are carried over rather than recomputed.
            origins = cause.details if isinstance(cause, PaidRedirectBlockedError) else {}
            return PaidRedirectBlockedError(
                "Paid retry redirect crossed origins after the signature had been "
                "transmitted",
                context=context,
                details={
                    "fromOrigin": origins.get("fromOrigin"),
                    "toOrigin": origins.get("toOrigin"),
                    "reservationExpiresAtEpochMs": reservation.expires_at_epoch_ms,
                    "causeCategory": cause_category,
                },
                cause=cause,
            )

        return AmbiguousPaymentError(
            "The payment was transmitted but its outcome is unknown",
            context=context,
            details={
                "reservationExpiresAtEpochMs": reservation.expires_at_epoch_ms,
                "causeCategory": cause_category,
            },
            cause=cause,
        )

    def transmission_failed(
        self,
        *,
        selection: _Selection,
        request_id: str,
        reservation: SpendReservation,
        attempt: int,
        cause: BaseException,
    ) -> Tx402Error:
        """A signature-bearing request that never completed (SPEC §6.7).

        Routed through the disposition table rather than categorized here, so the category
        is the one the frozen ``completion.paid-attempt`` vectors pin in both languages.
        """
        disposition = classify_paid_attempt(
            attempt=attempt,
            max_paid_attempts=self.policy.max_paid_attempts,
            result=PaidAttemptResult(kind="transport-failure"),
        )
        return self.unresolved(
            selection=selection,
            request_id=request_id,
            reservation=reservation,
            disposition=disposition,
            cause=cause,
        )

    def settle(
        self,
        *,
        selection: _Selection,
        response: httpx.Response,
        request: httpx.Request,
        prepared: _Prepared,
        request_id: str,
        reservation: SpendReservation,
        attempt: int,
    ) -> _Delivered | _Rechallenged:
        """Applies SPEC §6.7's disposition to one completed signature-bearing attempt."""
        blocked = _blocked_redirect(response, request, request_id)
        if blocked is not None:
            disposition = classify_paid_attempt(
                attempt=attempt,
                max_paid_attempts=self.policy.max_paid_attempts,
                result=PaidAttemptResult(kind="redirect-blocked"),
            )
            raise self.unresolved(
                selection=selection,
                request_id=request_id,
                reservation=reservation,
                disposition=disposition,
                cause=blocked,
            )

        # PAYMENT-RESPONSE is read *before* the disposition is taken, and on every status:
        # "the merchant reports a successful settlement" is one of the table's inputs, not a
        # check after the fact, and gating the read on 2xx is what hid O44.
        settlement: SettlementEvidence
        settlement_id: str | None
        settlement, settlement_id = _read_payment_response(response)

        disposition = classify_paid_attempt(
            attempt=attempt,
            max_paid_attempts=self.policy.max_paid_attempts,
            result=PaidAttemptResult(
                kind="response", status=response.status_code, settlement=settlement
            ),
        )

        if disposition.kind == "ambiguous":
            # Reported here rather than at the read site, because "the merchant's
            # settlement metadata does not decode" only becomes a completion once the table
            # has said the money is retained and the outcome unknown (O57). ``"unknown"``
            # is the honest value and it is what this disposition means.
            if disposition.cause_category == MALFORMED_SETTLEMENT_CAUSE:
                emit(
                    self.logger,
                    "warn",
                    {
                        "event": "payment.completed",
                        "requestId": request_id,
                        "paid": "unknown",
                        "reason": SETTLEMENT_UNPARSEABLE_REASON,
                    },
                )
            raise self.unresolved(
                selection=selection,
                request_id=request_id,
                reservation=reservation,
                disposition=disposition,
            )

        # SPEC §5.3: the settlement stands and the resource does not. Commit first — the
        # money moved — and only then report the delivery failure, with ``paid=True``.
        if disposition.kind == "paid-undelivered":
            self.commit_or_fail(
                selection=selection,
                request_id=request_id,
                reservation=reservation,
                settlement_id=settlement_id,
                status=response.status_code,
            )
            emit(
                self.logger,
                "warn",
                {
                    "event": "payment.completed",
                    "requestId": request_id,
                    "paid": True,
                    "reason": disposition.reason,
                },
            )
            raise ResourceDeliveryError(
                "The merchant reported a successful settlement but did not deliver "
                "the resource",
                context=self._route_context(
                    selection,
                    request_id,
                    "complete",
                    paid=True,
                    reservation_id=reservation.reservation_id,
                ),
                details={
                    "status": response.status_code,
                    "reason": disposition.reason,
                    "attempt": attempt,
                    "maxPaidAttempts": self.policy.max_paid_attempts,
                },
            )

        # Both remaining non-commit dispositions release: the merchant either re-challenged
        # or refused, and each is evidence that no settlement occurred (SPEC §6.7).
        if disposition.kind != "commit":
            self.release_quietly(reservation.reservation_id)

        if disposition.kind == "rechallenge":
            # Parsed from scratch, with the same binding checks the first challenge got.
            #
            # **A decode failure here is a post-transmission outcome and is classified as
            # one.** The reservation is already released above — an HTTP ``402`` is
            # intelligible whatever its header says, and it is the merchant declining the
            # payment, so releasing stays right and settlement evidence still outranks the
            # status line. What was wrong was letting the raw
            # ``PaymentRequiredInvalidError``
            # escape: it carries no ``paid`` context and maps to exit ``5``, a band
            # documented
            # as "no signature was ever produced". A signature *was* produced and
            # transmitted.
            # See ADR-022.
            try:
                return _Rechallenged(self.decode(response, prepared.request, request_id))
            except Tx402Error as error:
                # Mirrors the TypeScript reference exactly (``client.ts:1129``) so the two
                # CLIs emit the same ``--json`` (O107): spread the decode failure's own
                # details first — that is what keeps ``schemaPath`` — then let this error's
                # ``status`` and ``reason`` win. The route context carries the reservation,
                # which the bare context previously dropped here alone.
                raise ResourceDeliveryError(
                    "Merchant re-challenged undecodably",
                    context=self._route_context(
                        selection,
                        request_id,
                        "complete",
                        paid=False,
                        reservation_id=reservation.reservation_id,
                    ),
                    details={
                        **error.details,
                        "status": response.status_code,
                        "reason": RECHALLENGE_UNDECODABLE_REASON,
                    },
                    cause=error,
                ) from error

        if disposition.kind == "failed":
            raise ResourceDeliveryError(
                f"Merchant re-challenged every one of the "
                f"{self.policy.max_paid_attempts} permitted paid attempts"
                if disposition.reason == MAX_PAID_ATTEMPTS_REASON
                else "Merchant did not deliver the paid resource",
                context=self._route_context(
                    selection,
                    request_id,
                    "complete"
                    if disposition.reason == "settlement-unsuccessful"
                    else "retry",
                    paid=False,
                    reservation_id=reservation.reservation_id,
                ),
                details={
                    "status": response.status_code,
                    "reason": disposition.reason,
                    "attempt": attempt,
                    "maxPaidAttempts": self.policy.max_paid_attempts,
                },
            )

        self.commit_or_fail(
            selection=selection,
            request_id=request_id,
            reservation=reservation,
            settlement_id=settlement_id,
            status=response.status_code,
        )
        # The one place a payment really did complete, and therefore the only place an
        # absent header may be reported as a completed payment (O57). SPEC §6.7 forgives the
        # missing metadata — the pinned protocol marks it optional — so the money is
        # unaffected and only the severity moves: ``warn`` and a ``reason``, because a
        # merchant that never sends it cannot be reconciled against, and an operator should
        # be able to see that from the log stream alone.
        completed: dict[str, object] = {
            "event": "payment.completed",
            "requestId": request_id,
            "paid": True,
        }
        if settlement == "absent":
            completed["reason"] = SETTLEMENT_ABSENT_REASON
        if settlement_id is not None:
            # Hashed, never raw: see `settlement_id_hash`. The key is absent rather than
            # null when the merchant supplied no identifier, matching the TypeScript
            # reference's conditional spread so both streams have the same shape.
            completed["settlementIdHash"] = settlement_id_hash(settlement_id)
        completed["totalSdkOverheadMs"] = elapsed_ms(self.monotonic, prepared.started_at)
        emit(self.logger, "warn" if settlement == "absent" else "info", completed)
        return _Delivered(response)


def _plan_from(
    request_id: str,
    response: httpx.Response,
    challenge: Mapping[str, Any],
    selection: _Selection,
) -> PaymentPlan:
    """Projects the internal selection onto the public :class:`PaymentPlan`.

    Written once and shared by both transports so the sync and async dry runs cannot
    report different shapes for the same decision.
    """
    return PaymentPlan(
        request_id=request_id,
        response=response,
        payment_required=challenge,
        candidates=selection.plan.candidates,
        selected=selection.plan.selected,
        amount_atomic=selection.requirement.requirement["amountAtomic"],
        asset_id=selection.requirement.asset_id,
    )


def _validate_retry_timeout(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < _MIN_PAYMENT_RETRY_TIMEOUT_MS
    ):
        raise _configuration("payment_retry_timeout_ms", "below-minimum")
    return value


def _validate_initial_timeout(value: object) -> int | None:
    """SPEC §4.3 ``timeouts.initialRequestMs`` — absent, or a positive integer.

    Absent is the default and is the specified behaviour: the SDK never silently shortens a
    caller's own timeout, so with nothing set the httpx timeout the caller configured is the
    only deadline. Supplying one adds a deadline *alongside* that, never replacing it.

    The ``configPath`` reported on failure is the **Python** keyword, not SPEC's
    ``timeouts.initialRequestMs``. An earlier revision reported the SPEC name, reasoning
    that one spelling across both languages diagnoses the same mistake identically
    (ADR-005). That trade was wrong in both directions: every other Python ``configPath``
    uses the Python spelling — including this field's own sibling
    ``payment_retry_timeout_ms`` — and the SPEC name points at a nested ``timeouts`` object
    that Python does not accept, so the diagnostic named a path the caller could not have
    used and could not switch to. A path a reader can act on beats one that matches the
    other language. See the ADR-021 amendment.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _configuration("initial_request_timeout_ms", "expected-positive-integer")
    return value


def _validate_logger(logger: object) -> None:
    """Reject a logger that cannot receive events, rather than dropping them in silence.

    SPEC §10 specifies the sink as an *object* carrying ``debug``/``info``/``warn``/
    ``error``. ``emit`` suppresses logger failures on purpose — a logger fault must never
    fail a payment that already settled — and that isolation is exactly what turned a
    misconfigured hook into perfect silence: a callable passed where an object belongs
    produced zero events and no error (PLAN.md O71). The suppression stays; accepting a
    value that can never work does not. The TypeScript client checks the same four
    attributes at the same point (ADR-005).
    """
    if not all(
        callable(getattr(logger, name, None)) for name in ("debug", "info", "warn", "error")
    ):
        raise _configuration("logger", "invalid-logger")


def _build_core(
    *,
    evm_signer: object,
    solana_signer: object,
    policy: Policy | None,
    routing: RoutingPolicy | None,
    spend_store: SpendStore | None,
    manifest: Mapping[str, Any],
    clock: Clock,
    evm_rpc_transport: object,
    solana_rpc_transport: object,
    allow_insecure_localhost: bool,
    initial_request_timeout_ms: int | None,
    payment_retry_timeout_ms: int,
    disable_request_id_header: bool,
    logger: Tx402Logger,
    monotonic: Monotonic,
) -> tuple[_Core, SpendStore]:
    """Validates configuration synchronously and returns an immutable core (SPEC §4.1)."""
    verified = assert_valid_release_manifest(
        manifest,
        context=Tx402ErrorContext(request_id="configuration", phase="initial"),
        now_epoch_ms=clock(),
    )
    _validate_initial_timeout(initial_request_timeout_ms)
    _validate_retry_timeout(payment_retry_timeout_ms)
    _validate_logger(logger)
    # `is None`, not `or`: a perfectly valid adapter that defines `__len__` or `__bool__`
    # — an empty-at-startup database-backed store is the obvious one — is falsey, and `or`
    # silently replaced it with an in-memory store, so a fleet-wide cap became per-process
    # without any error (O54). The structural check then rejects a lookalike loudly rather
    # than letting duck typing discover the missing method mid-payment.
    store: SpendStore = MemorySpendStore() if spend_store is None else spend_store
    assert_spend_store(store)
    core = _Core(
        evm_signer=evm_signer,
        solana_signer=solana_signer,
        policy=PolicyEngine(verified, policy, routing),
        spend_store=store,
        manifest=verified,
        clock=clock,
        evm_rpc_transport=evm_rpc_transport,
        solana_rpc_transport=solana_rpc_transport,
        allow_insecure_localhost=allow_insecure_localhost,
        initial_request_timeout_ms=initial_request_timeout_ms,
        payment_retry_timeout_ms=payment_retry_timeout_ms,
        disable_request_id_header=disable_request_id_header,
        logger=logger,
        monotonic=monotonic,
    )
    return core, store


class Tx402Transport(httpx.BaseTransport):
    """Synchronous HTTPX transport implementing the full tx402 request path."""

    def __init__(self, inner: httpx.BaseTransport, core: _Core) -> None:
        self._inner = inner
        self._core = core

    def _issue_initial(self, request: httpx.Request, request_id: str) -> httpx.Response:
        """The unpaid request, under the caller's deadline plus any the SDK was given.

        SPEC §4.3's ``timeouts.initialRequestMs`` is absent by default, in which case this
        is exactly the call it always was and httpx's own timeout is the only bound. When
        one is configured it is added *alongside* that, never in place of it: the SDK does
        not silently shorten a caller's timeout, and it cannot lengthen one either.

        Nothing has been signed at this point, so a deadline here is unambiguously safe —
        unlike the paid retry, where a timeout means the signature is already on the wire.
        """
        core = self._core
        try:
            if core.initial_request_timeout_ms is None:
                return self._inner.handle_request(request)
            return with_deadline(
                lambda: self._inner.handle_request(request),
                core.initial_request_timeout_ms,
            )
        except (TimeoutError, httpx.HTTPError) as error:
            raise _transport_error(error, request_id, "initial") from error

    def inspect(self, request: httpx.Request) -> PaymentInspection:
        core = self._core
        started_at = core.monotonic()
        request_id = _request_id(core.clock())
        try:
            core.prepare(request, request_id)
            core.log_request_started(request_id, request)
            response = self._issue_initial(request, request_id)
            if response.status_code != 402:
                return PaymentInspection(request_id, response, None)
            response.read()
            challenge = core.decode(response, request, request_id)
            core.log_payment_required(request_id, challenge, started_at=started_at)
            return PaymentInspection(request_id, response, challenge)
        except Tx402Error as error:
            core.log_request_failed(error)
            raise

    def plan(self, request: httpx.Request) -> PaymentPlan:
        """Everything :meth:`handle_request` would do up to — but not including — reserving.

        **No signature is produced and no budget is reserved.** Route planning does read
        the payer's address and balance, because a route cannot be scored without knowing
        whether it is fundable — SPEC §11's "MUST NOT invoke a signer" is about producing a
        signature, and the CLI suite pins that ``sign_typed_data`` and ``sign_transaction``
        are never reached on this path.
        """
        core = self._core
        started_at = core.monotonic()
        request_id = _request_id(core.clock())
        try:
            _body, host = core.prepare(request, request_id)
            core.log_request_started(request_id, request)
            response = self._issue_initial(request, request_id)
            if response.status_code != 402:
                return PaymentPlan(request_id, response)
            response.read()
            challenge = core.decode(response, request, request_id)
            core.log_payment_required(request_id, challenge, started_at=started_at)
            decision = core.decide(challenge, request_id, host)
            selection = core.plan(decision, request_id, core.clock())
            return _plan_from(request_id, response, challenge, selection)
        except Tx402Error as error:
            core.log_request_failed(error)
            raise

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        try:
            return self._handle(request)
        except Tx402Error as error:
            # One place for `request.failed`, wrapping the whole paid path including the
            # re-challenge loop. Emitting from each raise site instead would mean every new
            # failure mode has to remember to log itself, and the ones that forget are
            # invisible precisely when diagnostics matter most.
            self._core.log_request_failed(error)
            raise

    def _handle(self, request: httpx.Request) -> httpx.Response:
        core = self._core
        started_at = core.monotonic()
        request_id = _request_id(core.clock())
        body, host = core.prepare(request, request_id)
        core.log_request_started(request_id, request)
        response = self._issue_initial(request, request_id)
        if response.status_code != 402:
            return response
        response.read()
        prepared = _Prepared(request, body, host, started_at)
        challenge = core.decode(response, request, request_id)
        core.log_payment_required(request_id, challenge)

        # The re-challenge loop (SPEC §6.7). Nothing carries over between attempts: each
        # pass re-evaluates policy, re-plans from the new challenge, takes its own
        # reservation, and produces its own signature. The bound lives in the disposition
        # table, not here — `classify_paid_attempt` returns "rechallenge" only while
        # attempts remain, and turns the last one into a typed terminal error.
        attempt = 1
        while True:
            outcome = self._attempt(prepared, request_id, challenge, attempt)
            if isinstance(outcome, _Delivered):
                return outcome.response
            challenge = outcome.challenge
            attempt += 1
            core.log_payment_required(request_id, challenge, attempt=attempt)

    def _attempt(
        self,
        prepared: _Prepared,
        request_id: str,
        challenge: Mapping[str, Any],
        attempt: int,
    ) -> _Delivered | _Rechallenged:
        core = self._core
        decision = core.decide(challenge, request_id, prepared.host)
        selection = core.plan(decision, request_id, core.clock())
        reservation, request_hash = core.reserve_or_fail(
            selection=selection,
            prepared=prepared,
            request_id=request_id,
            challenge_hash=challenge["headerHash"],
        )
        try:
            signature = core.sign(
                selection=selection,
                prepared=prepared,
                request_id=request_id,
                request_hash=request_hash,
            )
            retry = _retry_request(
                prepared.request,
                _fresh_body(prepared.request, prepared.body, request_id),
                signature,
                request_id,
                disable_request_id_header=core.disable_request_id_header,
            )
        except BaseException:
            # Still pre-transmission: nothing reached the merchant, so the budget goes back.
            core.release_quietly(reservation.reservation_id)
            raise

        core.log_request_retried(request_id, attempt, selection)
        try:
            paid = with_deadline(
                lambda: self._inner.handle_request(retry),
                core.payment_retry_timeout_ms,
            )
        except (TimeoutError, httpx.HTTPError) as error:
            # From here the signature is on the wire, so no failure path may assume
            # otherwise. A transmission that never completed is ambiguous whatever the cause
            # — a deadline and a reset are the same fact about settlement — so both reach
            # the disposition table as one input and share its category.
            raise core.transmission_failed(
                selection=selection,
                request_id=request_id,
                reservation=reservation,
                attempt=attempt,
                cause=error,
            ) from error
        paid.read()
        return core.settle(
            selection=selection,
            response=paid,
            request=retry,
            prepared=prepared,
            request_id=request_id,
            reservation=reservation,
            attempt=attempt,
        )

    def close(self) -> None:
        self._inner.close()


class AsyncTx402Transport(httpx.AsyncBaseTransport):
    """Asynchronous counterpart to :class:`Tx402Transport`."""

    def __init__(self, inner: httpx.AsyncBaseTransport, core: _Core) -> None:
        self._inner = inner
        self._core = core

    async def _issue_initial(
        self, request: httpx.Request, request_id: str
    ) -> httpx.Response:
        """Asynchronous counterpart to :meth:`Tx402Transport._issue_initial`."""
        core = self._core
        try:
            if core.initial_request_timeout_ms is None:
                return await self._inner.handle_async_request(request)
            return await with_deadline_async(
                self._inner.handle_async_request(request),
                core.initial_request_timeout_ms,
            )
        except (TimeoutError, httpx.HTTPError) as error:
            raise _transport_error(error, request_id, "initial") from error

    async def inspect(self, request: httpx.Request) -> PaymentInspection:
        core = self._core
        started_at = core.monotonic()
        request_id = _request_id(core.clock())
        try:
            await core.prepare_async(request, request_id)
            core.log_request_started(request_id, request)
            response = await self._issue_initial(request, request_id)
            if response.status_code != 402:
                return PaymentInspection(request_id, response, None)
            await response.aread()
            challenge = core.decode(response, request, request_id)
            core.log_payment_required(request_id, challenge, started_at=started_at)
            return PaymentInspection(request_id, response, challenge)
        except Tx402Error as error:
            core.log_request_failed(error)
            raise

    async def plan(self, request: httpx.Request) -> PaymentPlan:
        """Asynchronous counterpart to :meth:`Tx402Transport.plan`."""
        core = self._core
        started_at = core.monotonic()
        request_id = _request_id(core.clock())
        try:
            _body, host = await core.prepare_async(request, request_id)
            core.log_request_started(request_id, request)
            response = await self._issue_initial(request, request_id)
            if response.status_code != 402:
                return PaymentPlan(request_id, response)
            await response.aread()
            challenge = core.decode(response, request, request_id)
            core.log_payment_required(request_id, challenge, started_at=started_at)
            decision = core.decide(challenge, request_id, host)
            selection = await core.plan_async(decision, request_id, core.clock())
            return _plan_from(request_id, response, challenge, selection)
        except Tx402Error as error:
            core.log_request_failed(error)
            raise

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        try:
            return await self._handle(request)
        except Tx402Error as error:
            self._core.log_request_failed(error)
            raise

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        core = self._core
        started_at = core.monotonic()
        request_id = _request_id(core.clock())
        body, host = await core.prepare_async(request, request_id)
        core.log_request_started(request_id, request)
        response = await self._issue_initial(request, request_id)
        if response.status_code != 402:
            return response
        await response.aread()
        prepared = _Prepared(request, body, host, started_at)
        challenge = core.decode(response, request, request_id)
        core.log_payment_required(request_id, challenge)

        attempt = 1
        while True:
            outcome = await self._attempt(prepared, request_id, challenge, attempt)
            if isinstance(outcome, _Delivered):
                return outcome.response
            challenge = outcome.challenge
            attempt += 1
            core.log_payment_required(request_id, challenge, attempt=attempt)

    async def _attempt(
        self,
        prepared: _Prepared,
        request_id: str,
        challenge: Mapping[str, Any],
        attempt: int,
    ) -> _Delivered | _Rechallenged:
        core = self._core
        decision = core.decide(challenge, request_id, prepared.host)
        selection = await core.plan_async(decision, request_id, core.clock())
        reservation, request_hash = core.reserve_or_fail(
            selection=selection,
            prepared=prepared,
            request_id=request_id,
            challenge_hash=challenge["headerHash"],
        )
        try:
            signature = await core.sign_async(
                selection=selection,
                prepared=prepared,
                request_id=request_id,
                request_hash=request_hash,
            )
            retry = _retry_request(
                prepared.request,
                _fresh_body(prepared.request, prepared.body, request_id),
                signature,
                request_id,
                disable_request_id_header=core.disable_request_id_header,
            )
        except BaseException:
            core.release_quietly(reservation.reservation_id)
            raise

        core.log_request_retried(request_id, attempt, selection)
        try:
            paid = await with_deadline_async(
                self._inner.handle_async_request(retry),
                core.payment_retry_timeout_ms,
            )
        except (TimeoutError, httpx.HTTPError) as error:
            raise core.transmission_failed(
                selection=selection,
                request_id=request_id,
                reservation=reservation,
                attempt=attempt,
                cause=error,
            ) from error
        await paid.aread()
        return core.settle(
            selection=selection,
            response=paid,
            request=retry,
            prepared=prepared,
            request_id=request_id,
            reservation=reservation,
            attempt=attempt,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


class Tx402Client:
    """Synchronous HTTPX-compatible buyer client backed by :class:`Tx402Transport`."""

    def __init__(
        self,
        *,
        evm_signer: object = None,
        solana_signer: object = None,
        policy: Policy | None = None,
        routing: RoutingPolicy | None = None,
        spend_store: SpendStore | None = None,
        transport: httpx.BaseTransport | None = None,
        evm_rpc_transport: httpx.BaseTransport | None = None,
        solana_rpc_transport: httpx.BaseTransport | None = None,
        manifest: Mapping[str, Any] = BUNDLED_MANIFEST,
        clock: Clock = _system_clock,
        allow_insecure_localhost: bool = False,
        initial_request_timeout_ms: int | None = None,
        payment_retry_timeout_ms: int = _PAYMENT_RETRY_TIMEOUT_MS,
        disable_request_id_header: bool = False,
        logger: Tx402Logger = NOOP_LOGGER,
        monotonic: Monotonic = monotonic_ms,
    ) -> None:
        core, store = _build_core(
            evm_signer=evm_signer,
            solana_signer=solana_signer,
            policy=policy,
            routing=routing,
            spend_store=spend_store,
            manifest=manifest,
            clock=clock,
            evm_rpc_transport=evm_rpc_transport,
            solana_rpc_transport=solana_rpc_transport,
            allow_insecure_localhost=allow_insecure_localhost,
            initial_request_timeout_ms=initial_request_timeout_ms,
            payment_retry_timeout_ms=payment_retry_timeout_ms,
            disable_request_id_header=disable_request_id_header,
            logger=logger,
            monotonic=monotonic,
        )
        self._core = core
        self._store = store
        self._transport = Tx402Transport(transport or httpx.HTTPTransport(), core)
        # Redirects are surfaced rather than followed so a cross-origin `Location` is
        # refused before a second request could carry the signature elsewhere (SEC-005).
        self._client = httpx.Client(transport=self._transport, follow_redirects=False)

    def request(
        self,
        method: str,
        url: str,
        *,
        body_factory: BodyFactory | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        request = _build_request(self._client, method, url, body_factory, kwargs)
        return self._client.send(request)

    def inspect(self, method: str, url: str, **kwargs: Any) -> PaymentInspection:
        return self._transport.inspect(self._client.build_request(method, url, **kwargs))

    def plan(self, method: str, url: str, **kwargs: Any) -> PaymentPlan:
        """Plans a payment without reserving budget or producing a signature (SPEC §11)."""
        return self._transport.plan(self._client.build_request(method, url, **kwargs))

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int | None = None
    ) -> BudgetState:
        return self._store.get_budget_state(
            policy_scope=policy_scope,
            asset_id=asset_id,
            now_epoch_ms=_system_clock() if now_epoch_ms is None else now_epoch_ms,
        )

    def reset_health(self) -> None:
        """Clears in-memory health metrics; does not clear the spend ledger (SPEC §4.1)."""
        self._core.reset_health()

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self: ClientT) -> ClientT:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class AsyncTx402Client:
    """Asynchronous HTTPX-compatible buyer client."""

    def __init__(
        self,
        *,
        evm_signer: object = None,
        solana_signer: object = None,
        policy: Policy | None = None,
        routing: RoutingPolicy | None = None,
        spend_store: SpendStore | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        evm_rpc_transport: httpx.AsyncBaseTransport | None = None,
        solana_rpc_transport: httpx.AsyncBaseTransport | None = None,
        manifest: Mapping[str, Any] = BUNDLED_MANIFEST,
        clock: Clock = _system_clock,
        allow_insecure_localhost: bool = False,
        initial_request_timeout_ms: int | None = None,
        payment_retry_timeout_ms: int = _PAYMENT_RETRY_TIMEOUT_MS,
        disable_request_id_header: bool = False,
        logger: Tx402Logger = NOOP_LOGGER,
        monotonic: Monotonic = monotonic_ms,
    ) -> None:
        core, store = _build_core(
            evm_signer=evm_signer,
            solana_signer=solana_signer,
            policy=policy,
            routing=routing,
            spend_store=spend_store,
            manifest=manifest,
            clock=clock,
            evm_rpc_transport=evm_rpc_transport,
            solana_rpc_transport=solana_rpc_transport,
            allow_insecure_localhost=allow_insecure_localhost,
            initial_request_timeout_ms=initial_request_timeout_ms,
            payment_retry_timeout_ms=payment_retry_timeout_ms,
            disable_request_id_header=disable_request_id_header,
            logger=logger,
            monotonic=monotonic,
        )
        self._core = core
        self._store = store
        self._transport = AsyncTx402Transport(transport or httpx.AsyncHTTPTransport(), core)
        self._client = httpx.AsyncClient(transport=self._transport, follow_redirects=False)

    async def request(
        self,
        method: str,
        url: str,
        *,
        body_factory: BodyFactory | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        request = _build_request(self._client, method, url, body_factory, kwargs)
        return await self._client.send(request)

    async def inspect(self, method: str, url: str, **kwargs: Any) -> PaymentInspection:
        return await self._transport.inspect(
            self._client.build_request(method, url, **kwargs)
        )

    async def plan(self, method: str, url: str, **kwargs: Any) -> PaymentPlan:
        """Plans a payment without reserving budget or producing a signature (SPEC §11)."""
        return await self._transport.plan(self._client.build_request(method, url, **kwargs))

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int | None = None
    ) -> BudgetState:
        return self._store.get_budget_state(
            policy_scope=policy_scope,
            asset_id=asset_id,
            now_epoch_ms=_system_clock() if now_epoch_ms is None else now_epoch_ms,
        )

    def reset_health(self) -> None:
        self._core.reset_health()

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self: AsyncClientT) -> AsyncClientT:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()


def _build_request(
    client: httpx.Client | httpx.AsyncClient,
    method: str,
    url: str,
    body_factory: BodyFactory | None,
    kwargs: dict[str, Any],
) -> httpx.Request:
    """Builds the initial request, capturing a replayable body before it is sent.

    SPEC §6.1 requires the replayable representation to exist *before* the first send —
    discovering after a 402 that the body cannot be replayed would mean the caller's stream
    was already gone.
    """
    if body_factory is not None:
        if any(key in kwargs for key in ("content", "data", "files", "json")):
            raise TypeError("body_factory cannot be combined with another request body")
        kwargs["content"] = body_factory()
    request = client.build_request(method, url, **kwargs)
    if body_factory is not None:
        request.extensions[_BODY_FACTORY_EXTENSION] = body_factory
    return request


__all__: Sequence[str] = [
    "AsyncTx402Client",
    "AsyncTx402Transport",
    "BodyFactory",
    "PaymentInspection",
    "PaymentPlan",
    "Tx402Client",
    "Tx402Transport",
]
