"""The capability-gateway :class:`~tx402.ledger.SpendStore` client (SPEC §12.5).

``HttpGatewaySpendStore`` (sync, over ``httpx.Client``) and ``AsyncHttpGatewaySpendStore``
(async, over ``httpx.AsyncClient``) speak the §12.5 wire protocol to any conformant
gateway, holding only a bearer token — never a raw Redis/DO credential. The wire contract
is fixed and pinned by ``core-spec/gateway/golden.json``, so this client and the TypeScript
``httpGatewaySpendStore`` produce byte-identical requests and map responses/errors the same
way: a gateway-backed store is byte-identical to a direct one and passes the same
``check_durable_spend_store`` suite. ``httpx`` is a core dependency, so no extra is needed.

Capabilities are fetched ONCE at construction (via :func:`http_gateway_spend_store`), so
``check_durable_spend_store`` selects the right freeze arm — the incapable id-per-scope-DO
/ Redis-Cluster arm, or the capable single-coordinator-DO / single-instance-Redis arm —
behind the gateway. The data/admin boundary is enforced server-side where the raw
credential lives (SPEC §9.1): an admin method presented with a data token is refused
``403`` → a typed ``admin-credential-required`` ``ConfigurationError``. It does NOT close
the compromised-application spending path (that is 0.3.0, SPEC §1).
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from tx402.errors import (
    AmbiguousPaymentError,
    BudgetExceededError,
    ClockSkewError,
    ConfigurationError,
    DomainNotAllowedError,
    InsufficientLiquidityError,
    InvalidPaymentRequiredError,
    NonReplayableRequestError,
    PaidRedirectBlockedError,
    RecipientUnpinnedError,
    ReservedHeaderError,
    ResourceDeliveryError,
    SignerError,
    SpendScopeFrozenError,
    TransportError,
    Tx402Error,
    Tx402ErrorContext,
    UnsupportedProtocolError,
    UnsupportedSchemeError,
)
from tx402.ledger import (
    BudgetLimits,
    BudgetState,
    ReservationRef,
    ReserveSpendResult,
    SpendEntry,
    SpendReservation,
    StoreCapabilities,
)

__all__ = [
    "AsyncHttpGatewaySpendStore",
    "HttpGatewaySpendStore",
    "async_http_gateway_spend_store",
    "http_gateway_spend_store",
]

# ── the wire protocol constants (SPEC §12.5), identical to the TypeScript wire module ──
GATEWAY_PROTOCOL_VERSION = 1
GATEWAY_VERSION_HEADER = "TX402-Gateway-Version"
GATEWAY_PATH_PREFIX = f"/v{GATEWAY_PROTOCOL_VERSION}"

# ── error translation (SPEC §12.5): every condition maps to an EXISTING taxonomy code ──
_ERROR_CLASSES: dict[str, type[Tx402Error]] = {
    "TX402_CONFIG_INVALID": ConfigurationError,
    "TX402_RESERVED_HEADER": ReservedHeaderError,
    "TX402_NON_REPLAYABLE": NonReplayableRequestError,
    "TX402_PROTOCOL_UNSUPPORTED": UnsupportedProtocolError,
    "TX402_SCHEME_UNSUPPORTED": UnsupportedSchemeError,
    "TX402_PAYMENT_REQUIRED_INVALID": InvalidPaymentRequiredError,
    "TX402_POLICY_BUDGET": BudgetExceededError,
    "TX402_POLICY_DOMAIN": DomainNotAllowedError,
    "TX402_LIQUIDITY": InsufficientLiquidityError,
    "TX402_SIGNER": SignerError,
    "TX402_CLOCK_SKEW": ClockSkewError,
    "TX402_PAYMENT_AMBIGUOUS": AmbiguousPaymentError,
    "TX402_RESOURCE_DELIVERY": ResourceDeliveryError,
    "TX402_REDIRECT_BLOCKED": PaidRedirectBlockedError,
    "TX402_TRANSPORT": TransportError,
    "TX402_SPEND_FROZEN": SpendScopeFrozenError,
    "TX402_RECIPIENT_UNPINNED": RecipientUnpinnedError,
}


def _context_from_wire(wire: dict[str, Any] | None) -> Tx402ErrorContext:
    ctx = wire or {"requestId": "gateway", "phase": "policy"}
    return Tx402ErrorContext(
        request_id=ctx.get("requestId", "gateway"),
        phase=ctx.get("phase", "policy"),
        network=ctx.get("network"),
        scheme=ctx.get("scheme"),
        amount_atomic=ctx.get("amountAtomic"),
        asset_id=ctx.get("assetId"),
        paid=ctx.get("paid"),
        reservation_id=ctx.get("reservationId"),
    )


def deserialize_tx402_error(wire: dict[str, Any]) -> Tx402Error:
    """Reconstruct the EXACT typed error from a wire payload (SPEC §12.5).

    A tx402 typed error the store raised is returned at HTTP 200 as ``{"error": to_dict()}``
    rethrown unchanged here, so a domain refusal round-trips as its exact class and code.
    """
    cls = _ERROR_CLASSES.get(wire["code"], ConfigurationError)
    return cls(
        wire.get("message", ""),
        context=_context_from_wire(wire.get("context")),
        details=wire.get("details") or {},
    )


def gateway_condition_error(status: int) -> Tx402Error:
    """The typed error a non-200 gateway status maps to (SPEC §12.5 error table)."""
    ctx = Tx402ErrorContext(request_id="gateway", phase="policy")
    if status == 400:
        return ConfigurationError(
            "The gateway rejected the request as malformed",
            context=ctx,
            details={"configPath": "gateway.request", "reason": "gateway-bad-request"},
        )
    if status == 401:
        return ConfigurationError(
            "The gateway bearer token is missing or unrecognized",
            context=ctx,
            details={"configPath": "gateway.auth", "reason": "gateway-unauthorized"},
        )
    if status == 403:
        return ConfigurationError(
            "An admin credential is required for this operation",
            context=ctx,
            details={"configPath": "gateway.auth", "reason": "admin-credential-required"},
        )
    if status == 426:
        return ConfigurationError(
            "The gateway does not support this protocol version",
            context=ctx,
            details={
                "configPath": "gateway.version",
                "reason": "gateway-version-unsupported",
            },
        )
    return TransportError(
        "The capability gateway is unavailable",
        context=ctx,
        details={"causeCategory": "gateway-unavailable"},
    )


def _unavailable(cause: BaseException | None = None) -> TransportError:
    return TransportError(
        "The capability gateway is unreachable",
        context=Tx402ErrorContext(request_id="gateway", phase="policy"),
        details={"causeCategory": "gateway-unavailable"},
        cause=cause,
    )


# ── request encoding + response decoding (shared by the sync and async clients) ──


def _ref_to_wire(ref: ReservationRef) -> dict[str, str]:
    return {
        "reservationId": ref.reservation_id,
        "policyScope": ref.policy_scope,
        "assetId": ref.asset_id,
    }


def _headers(token: str) -> dict[str, str]:
    return {
        "content-type": "application/json",
        GATEWAY_VERSION_HEADER: str(GATEWAY_PROTOCOL_VERSION),
        "authorization": f"Bearer {token}",
    }


def _reservation(raw: dict[str, Any]) -> SpendReservation:
    return SpendReservation(
        reservation_id=raw["reservationId"],
        policy_scope=raw["policyScope"],
        request_fingerprint=raw["requestFingerprint"],
        asset_id=raw["assetId"],
        amount_atomic=raw["amountAtomic"],
        created_at_epoch_ms=raw["createdAtEpochMs"],
        expires_at_epoch_ms=raw["expiresAtEpochMs"],
        state=raw["state"],
    )


def _entry(raw: dict[str, Any]) -> SpendEntry:
    return SpendEntry(
        reservation_id=raw["reservationId"],
        request_fingerprint=raw["requestFingerprint"],
        asset_id=raw["assetId"],
        amount_atomic=raw["amountAtomic"],
        committed_at_epoch_ms=raw["committedAtEpochMs"],
        settlement_id=raw.get("settlementId"),
    )


def _budget_state(raw: dict[str, Any]) -> BudgetState:
    return BudgetState(
        store_kind=raw["storeKind"],
        committed_atomic=raw["committedAtomic"],
        reserved_atomic=raw["reservedAtomic"],
        entries=tuple(_entry(item) for item in raw.get("entries", [])),
        reservations=tuple(_reservation(item) for item in raw.get("reservations", [])),
        policy_scope=raw.get("policyScope"),
        asset_id=raw.get("assetId"),
        exposed_atomic=raw.get("exposedAtomic"),
        cumulative_committed_atomic=raw.get("cumulativeCommittedAtomic"),
        cumulative_consumed_atomic=raw.get("cumulativeConsumedAtomic"),
        per_hour_limit_atomic=raw.get("perHourLimitAtomic"),
        cumulative_limit_atomic=raw.get("cumulativeLimitAtomic"),
        available_per_hour_atomic=raw.get("availablePerHourAtomic"),
        available_cumulative_atomic=raw.get("availableCumulativeAtomic"),
        frozen=raw.get("frozen"),
    )


def _budget_limits(raw: dict[str, Any]) -> BudgetLimits:
    return BudgetLimits(
        max_per_hour_atomic=raw.get("maxPerHourAtomic"),
        max_total_atomic=raw.get("maxTotalAtomic"),
    )


def _reserve_body(
    *,
    reservation_id: str,
    request_id: str,
    policy_scope: str,
    request_fingerprint: str,
    asset_id: str,
    amount_atomic: str,
    max_per_hour_atomic: str,
    max_total_atomic: str | None,
    recipient_network: str | None,
    recipient_canonical: str | None,
    recipient_enforcement: str | None,
    now_epoch_ms: int,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "reservationId": reservation_id,
        "requestId": request_id,
        "policyScope": policy_scope,
        "requestFingerprint": request_fingerprint,
        "assetId": asset_id,
        "amountAtomic": amount_atomic,
        "maxPerHourAtomic": max_per_hour_atomic,
    }
    if max_total_atomic is not None:
        body["maxTotalAtomic"] = max_total_atomic
    if recipient_network is not None:
        body["recipientNetwork"] = recipient_network
    if recipient_canonical is not None:
        body["recipientCanonical"] = recipient_canonical
    if recipient_enforcement is not None:
        body["recipientEnforcement"] = recipient_enforcement
    body["nowEpochMs"] = now_epoch_ms
    return body


def _limits_body(limits: BudgetLimits) -> dict[str, str]:
    body: dict[str, str] = {}
    if limits.max_per_hour_atomic is not None:
        body["maxPerHourAtomic"] = limits.max_per_hour_atomic
    if limits.max_total_atomic is not None:
        body["maxTotalAtomic"] = limits.max_total_atomic
    return body


# ── response-envelope validation (SPEC §12.5, O24) ──
#
# Validate every 200 envelope against the method's expected shape before trusting it: a
# mistyped result (a string ``"false"`` for a boolean — the previous ``bool()`` coercion
# turned it into ``True``), a missing field, or an unknown error code is a protocol
# violation the client refuses, like the TypeScript client's schema check. No coercion.

# An ``atomicAmount`` (SPEC ``common.schema.json``): a non-negative integer STRING, capped
# at 78 digits, matching the TS ``$defs/atomicAmount`` (``maxLength: 78``). Every input
# amount and cap is an ``atomicAmount``; an over-width value is a protocol violation the
# client refuses, identically to TS (O37).
_ATOMIC_RE = re.compile(r"(?:0|[1-9][0-9]{0,77})")
# An ``atomicAccumulator``: a lifetime aggregate with NO width cap (a cumulative sum can
# carry past 78 digits). Only ``exposedAtomic`` and the ``cumulative*Atomic`` sums use it,
# mirroring the TS ``$defs/atomicAccumulator`` (no ``maxLength``).
_ACCUMULATOR_RE = re.compile(r"(?:0|[1-9][0-9]*)")
_STATES = frozenset({"reserved", "committed", "released", "expired", "exposed"})


def _invalid_response() -> ConfigurationError:
    """A malformed gateway response the client refuses (non-retryable), matching TS."""
    return ConfigurationError(
        "The gateway returned a malformed response",
        context=Tx402ErrorContext(request_id="gateway", phase="policy"),
        details={"configPath": "gateway.response", "reason": "gateway-invalid-response"},
    )


def _require(condition: bool) -> None:
    if not condition:
        raise _invalid_response()


def _is_atomic(value: Any) -> bool:
    return isinstance(value, str) and _ATOMIC_RE.fullmatch(value) is not None


def _is_accumulator(value: Any) -> bool:
    return isinstance(value, str) and _ACCUMULATOR_RE.fullmatch(value) is not None


def _is_epoch(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _check_reservation(raw: Any) -> None:
    _require(isinstance(raw, dict))
    _require(isinstance(raw.get("reservationId"), str))
    _require(isinstance(raw.get("policyScope"), str))
    _require(isinstance(raw.get("requestFingerprint"), str))
    _require(isinstance(raw.get("assetId"), str))
    _require(_is_atomic(raw.get("amountAtomic")))
    _require(_is_epoch(raw.get("createdAtEpochMs")))
    _require(_is_epoch(raw.get("expiresAtEpochMs")))
    _require(raw.get("state") in _STATES)


def _check_entry(raw: Any) -> None:
    _require(isinstance(raw, dict))
    _require(isinstance(raw.get("reservationId"), str))
    _require(isinstance(raw.get("requestFingerprint"), str))
    _require(isinstance(raw.get("assetId"), str))
    _require(_is_atomic(raw.get("amountAtomic")))
    _require(_is_epoch(raw.get("committedAtEpochMs")))
    if "settlementId" in raw:
        _require(isinstance(raw["settlementId"], str))


def _check_budget_state(raw: Any) -> None:
    _require(isinstance(raw, dict))
    _require(isinstance(raw.get("storeKind"), str))
    _require(_is_atomic(raw.get("committedAtomic")))
    _require(_is_atomic(raw.get("reservedAtomic")))
    # Lifetime accumulators carry no width cap (atomicAccumulator); every other amount is a
    # 78-capped atomicAmount — the exact split the TS budgetState schema draws (O37).
    for field in (
        "exposedAtomic",
        "cumulativeCommittedAtomic",
        "cumulativeConsumedAtomic",
    ):
        if raw.get(field) is not None:
            _require(_is_accumulator(raw[field]))
    for field in (
        "perHourLimitAtomic",
        "cumulativeLimitAtomic",
        "availablePerHourAtomic",
        "availableCumulativeAtomic",
    ):
        if raw.get(field) is not None:
            _require(_is_atomic(raw[field]))
    if raw.get("frozen") is not None:
        _require(isinstance(raw["frozen"], bool))
    entries = raw.get("entries", [])
    _require(isinstance(entries, list))
    for item in entries:
        _check_entry(item)
    reservations = raw.get("reservations", [])
    _require(isinstance(reservations, list))
    for item in reservations:
        _check_reservation(item)


def _check_budget_limits(raw: Any) -> None:
    _require(isinstance(raw, dict))
    for field in ("maxPerHourAtomic", "maxTotalAtomic"):
        if raw.get(field) is not None:
            _require(_is_atomic(raw[field]))


def _check_recipient_policy(raw: Any) -> None:
    _require(isinstance(raw, dict))
    _require(isinstance(raw.get("tofuEnabled"), bool))
    _require(isinstance(raw.get("recipientAssertionRequired"), bool))


def _check_capabilities(raw: Any) -> None:
    _require(isinstance(raw, dict))
    _require(isinstance(raw.get("atomicGlobalFreeze"), bool))


def _check_reserve_result(raw: Any) -> None:
    _require(isinstance(raw, dict))
    _check_reservation(raw.get("reservation"))
    _require(isinstance(raw.get("recipientPinEstablished"), bool))


def _check_bool(raw: Any) -> None:
    _require(isinstance(raw, bool))


def _check_str_list(raw: Any) -> None:
    _require(isinstance(raw, list) and all(isinstance(item, str) for item in raw))


def _check_reservation_list(raw: Any) -> None:
    _require(isinstance(raw, list))
    for item in raw:
        _check_reservation(item)


def _check_null(raw: Any) -> None:
    _require(raw is None)


_RESULT_VALIDATORS = {
    "reserve": _check_reserve_result,
    "commit": _check_entry,
    "release": _check_reservation,
    "expose": _check_reservation,
    "getBudgetState": _check_budget_state,
    "listExposed": _check_reservation_list,
    "isFrozen": _check_bool,
    "getRecipientPins": _check_str_list,
    "getRecipientPolicy": _check_recipient_policy,
    "capabilities": _check_capabilities,
    "freeze": _check_null,
    "unfreeze": _check_null,
    "setRecipientPins": _check_null,
    "setBudgetLimits": _check_null,
    "getBudgetLimits": _check_budget_limits,
    "setRecipientAssertionRequired": _check_null,
    "setTofuEnabled": _check_null,
    "resolveExposed": _check_null,
    "resetCumulative": _check_null,
}


def _validate_wire_error(wire: Any) -> None:
    """A 200 error envelope must name a known taxonomy code, and a CONFIG_INVALID must carry
    ``configPath`` — an unknown code is a protocol violation, matching TS (no divergent
    fallback to ``ConfigurationError``)."""
    _require(isinstance(wire, dict))
    if wire.get("code") not in _ERROR_CLASSES:
        raise _invalid_response()
    if wire["code"] == "TX402_CONFIG_INVALID":
        details = wire.get("details")
        _require(isinstance(details, dict) and isinstance(details.get("configPath"), str))


def _decode(method: str, payload: Any) -> Any:
    """The validated result of a 200 response, rethrowing a typed error (SPEC §12.5).

    The envelope is a CLOSED shape: exactly ``{"error": …}`` OR exactly ``{"result": …}``
    and nothing else, matching the TS ``oneOf`` of two ``additionalProperties: false``
    envelopes. An extra top-level key (``{result, extra}``) or both keys at once
    (``{error, result}``) is a protocol violation the client refuses — not silently ignored
    or read as the error (O37)."""
    _require(isinstance(payload, dict))
    keys = set(payload)
    if keys == {"error"}:
        wire = payload["error"]
        _validate_wire_error(wire)
        raise deserialize_tx402_error(wire)
    _require(keys == {"result"})
    validator = _RESULT_VALIDATORS.get(method)
    if validator is None:
        raise _invalid_response()
    validator(payload["result"])
    return payload["result"]


# ── transport hardening (SPEC §12.5, O22) ──


def _is_loopback_host(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1", "[::1]")


def _assert_gateway_url(base_url: str) -> None:
    """Require HTTPS; plaintext ``http://`` is permitted only to a loopback host for local
    development, so the bearer is never sent in the clear (O22). Only checked when this
    client owns the default transport — a caller-supplied ``httpx`` client owns its own
    (and is how the fixture-replay tests use an ``http://gateway.local`` placeholder)."""
    parts = urlsplit(base_url)
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and _is_loopback_host(parts.hostname or ""):
        return
    raise ConfigurationError(
        "The gateway transport must be HTTPS; plaintext http:// is permitted only to a "
        "loopback host for local development",
        context=Tx402ErrorContext(request_id="gateway", phase="policy"),
        details={"configPath": "base_url", "reason": "https-required"},
    )


class HttpGatewaySpendStore:
    """The sync capability-gateway store (``httpx.Client``); see the module docstring."""

    kind = "gateway"

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        capabilities: StoreCapabilities,
        client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self.capabilities = capabilities
        if client is not None:
            self._client = client
        else:
            _assert_gateway_url(self._base_url)
            # Never follow a redirect: a 3xx must not carry the bearer elsewhere (O22).
            self._client = httpx.Client(follow_redirects=False)

    def build_request(
        self, method: str, body: dict[str, Any]
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        """The exact ``(path, headers, body)`` this client posts — pinned by the golden."""
        return (f"{GATEWAY_PATH_PREFIX}/{method}", _headers(self._token), body)

    def _request(self, method: str, body: dict[str, Any]) -> Any:
        path, headers, json_body = self.build_request(method, body)
        try:
            response = self._client.post(
                self._base_url + path, headers=headers, content=json.dumps(json_body)
            )
        except httpx.HTTPError as exc:
            raise _unavailable(exc) from exc
        if response.status_code != 200:
            raise gateway_condition_error(response.status_code)
        try:
            payload = response.json()
        except ValueError as exc:
            raise _unavailable(exc) from exc
        return _decode(method, payload)

    # ── data plane ──

    def reserve(
        self,
        *,
        reservation_id: str,
        request_id: str,
        policy_scope: str,
        request_fingerprint: str,
        asset_id: str,
        amount_atomic: str,
        max_per_hour_atomic: str,
        max_total_atomic: str | None = None,
        recipient_network: str | None = None,
        recipient_canonical: str | None = None,
        recipient_enforcement: str | None = None,
        now_epoch_ms: int,
    ) -> ReserveSpendResult:
        result = self._request(
            "reserve",
            _reserve_body(
                reservation_id=reservation_id,
                request_id=request_id,
                policy_scope=policy_scope,
                request_fingerprint=request_fingerprint,
                asset_id=asset_id,
                amount_atomic=amount_atomic,
                max_per_hour_atomic=max_per_hour_atomic,
                max_total_atomic=max_total_atomic,
                recipient_network=recipient_network,
                recipient_canonical=recipient_canonical,
                recipient_enforcement=recipient_enforcement,
                now_epoch_ms=now_epoch_ms,
            ),
        )
        return ReserveSpendResult(
            reservation=_reservation(result["reservation"]),
            recipient_pin_established=result["recipientPinEstablished"],
        )

    def commit(
        self,
        *,
        ref: ReservationRef,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        body: dict[str, Any] = {
            "ref": _ref_to_wire(ref),
            "committedAtEpochMs": committed_at_epoch_ms,
        }
        if settlement_id is not None:
            body["settlementId"] = settlement_id
        return _entry(self._request("commit", body))

    def release(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return _reservation(
            self._request("release", {"ref": _ref_to_wire(ref), "nowEpochMs": now_epoch_ms})
        )

    def expose(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return _reservation(
            self._request("expose", {"ref": _ref_to_wire(ref), "nowEpochMs": now_epoch_ms})
        )

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        return _budget_state(
            self._request(
                "getBudgetState",
                {
                    "policyScope": policy_scope,
                    "assetId": asset_id,
                    "nowEpochMs": now_epoch_ms,
                },
            )
        )

    def list_exposed(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> tuple[SpendReservation, ...]:
        raw = self._request(
            "listExposed",
            {"policyScope": policy_scope, "assetId": asset_id, "nowEpochMs": now_epoch_ms},
        )
        return tuple(_reservation(item) for item in raw)

    def is_frozen(self, *, scope: str) -> bool:
        return bool(self._request("isFrozen", {"scope": scope}))

    def get_recipient_pins(self, scope: str, network: str) -> tuple[str, ...]:
        raw = self._request("getRecipientPins", {"scope": scope, "network": network})
        return tuple(raw)

    def get_recipient_policy(self, scope: str) -> dict[str, bool]:
        result = self._request("getRecipientPolicy", {"scope": scope})
        return {
            "tofu_enabled": bool(result["tofuEnabled"]),
            "recipient_assertion_required": bool(result["recipientAssertionRequired"]),
        }

    def request_capabilities(self) -> StoreCapabilities:
        """Fetch the backend's capabilities via the data-plane ``capabilities`` method."""
        result = self._request("capabilities", {})
        return StoreCapabilities(atomic_global_freeze=bool(result["atomicGlobalFreeze"]))

    # ── admin plane (a data token is refused 403 → admin-credential-required) ──

    def freeze(self, scope: str, now_epoch_ms: int) -> None:
        self._request("freeze", {"scope": scope, "nowEpochMs": now_epoch_ms})

    def unfreeze(self, scope: str, now_epoch_ms: int) -> None:
        self._request("unfreeze", {"scope": scope, "nowEpochMs": now_epoch_ms})

    def set_recipient_pins(
        self, scope: str, network: str, recipients: tuple[str, ...], now_epoch_ms: int
    ) -> None:
        self._request(
            "setRecipientPins",
            {
                "scope": scope,
                "network": network,
                "recipients": list(recipients),
                "nowEpochMs": now_epoch_ms,
            },
        )

    def set_budget_limits(
        self, scope: str, asset_id: str, limits: BudgetLimits, now_epoch_ms: int
    ) -> None:
        self._request(
            "setBudgetLimits",
            {
                "scope": scope,
                "assetId": asset_id,
                "limits": _limits_body(limits),
                "nowEpochMs": now_epoch_ms,
            },
        )

    def get_budget_limits(self, scope: str, asset_id: str) -> BudgetLimits:
        return _budget_limits(
            self._request("getBudgetLimits", {"scope": scope, "assetId": asset_id})
        )

    def set_recipient_assertion_required(
        self, scope: str, required: bool, now_epoch_ms: int
    ) -> None:
        self._request(
            "setRecipientAssertionRequired",
            {"scope": scope, "required": required, "nowEpochMs": now_epoch_ms},
        )

    def set_tofu_enabled(self, scope: str, enabled: bool, now_epoch_ms: int) -> None:
        self._request(
            "setTofuEnabled",
            {"scope": scope, "enabled": enabled, "nowEpochMs": now_epoch_ms},
        )

    def resolve_exposed(
        self,
        ref: ReservationRef,
        outcome: Literal["committed", "released"],
        now_epoch_ms: int,
    ) -> None:
        self._request(
            "resolveExposed",
            {"ref": _ref_to_wire(ref), "outcome": outcome, "nowEpochMs": now_epoch_ms},
        )

    def reset_cumulative(self, scope: str, asset_id: str, now_epoch_ms: int) -> None:
        self._request(
            "resetCumulative",
            {"scope": scope, "assetId": asset_id, "nowEpochMs": now_epoch_ms},
        )


class AsyncHttpGatewaySpendStore:
    """The async capability-gateway store (``httpx.AsyncClient``). Same wire contract."""

    kind = "gateway"

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        capabilities: StoreCapabilities,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self.capabilities = capabilities
        if client is not None:
            self._client = client
        else:
            _assert_gateway_url(self._base_url)
            # Never follow a redirect: a 3xx must not carry the bearer elsewhere (O22).
            self._client = httpx.AsyncClient(follow_redirects=False)

    def build_request(
        self, method: str, body: dict[str, Any]
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        return (f"{GATEWAY_PATH_PREFIX}/{method}", _headers(self._token), body)

    async def _request(self, method: str, body: dict[str, Any]) -> Any:
        path, headers, json_body = self.build_request(method, body)
        try:
            response = await self._client.post(
                self._base_url + path, headers=headers, content=json.dumps(json_body)
            )
        except httpx.HTTPError as exc:
            raise _unavailable(exc) from exc
        if response.status_code != 200:
            raise gateway_condition_error(response.status_code)
        try:
            payload = response.json()
        except ValueError as exc:
            raise _unavailable(exc) from exc
        return _decode(method, payload)

    async def reserve(
        self,
        *,
        reservation_id: str,
        request_id: str,
        policy_scope: str,
        request_fingerprint: str,
        asset_id: str,
        amount_atomic: str,
        max_per_hour_atomic: str,
        max_total_atomic: str | None = None,
        recipient_network: str | None = None,
        recipient_canonical: str | None = None,
        recipient_enforcement: str | None = None,
        now_epoch_ms: int,
    ) -> ReserveSpendResult:
        result = await self._request(
            "reserve",
            _reserve_body(
                reservation_id=reservation_id,
                request_id=request_id,
                policy_scope=policy_scope,
                request_fingerprint=request_fingerprint,
                asset_id=asset_id,
                amount_atomic=amount_atomic,
                max_per_hour_atomic=max_per_hour_atomic,
                max_total_atomic=max_total_atomic,
                recipient_network=recipient_network,
                recipient_canonical=recipient_canonical,
                recipient_enforcement=recipient_enforcement,
                now_epoch_ms=now_epoch_ms,
            ),
        )
        return ReserveSpendResult(
            reservation=_reservation(result["reservation"]),
            recipient_pin_established=result["recipientPinEstablished"],
        )

    async def commit(
        self,
        *,
        ref: ReservationRef,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        body: dict[str, Any] = {
            "ref": _ref_to_wire(ref),
            "committedAtEpochMs": committed_at_epoch_ms,
        }
        if settlement_id is not None:
            body["settlementId"] = settlement_id
        return _entry(await self._request("commit", body))

    async def release(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return _reservation(
            await self._request(
                "release", {"ref": _ref_to_wire(ref), "nowEpochMs": now_epoch_ms}
            )
        )

    async def expose(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        return _reservation(
            await self._request(
                "expose", {"ref": _ref_to_wire(ref), "nowEpochMs": now_epoch_ms}
            )
        )

    async def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        return _budget_state(
            await self._request(
                "getBudgetState",
                {
                    "policyScope": policy_scope,
                    "assetId": asset_id,
                    "nowEpochMs": now_epoch_ms,
                },
            )
        )

    async def list_exposed(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> tuple[SpendReservation, ...]:
        raw = await self._request(
            "listExposed",
            {"policyScope": policy_scope, "assetId": asset_id, "nowEpochMs": now_epoch_ms},
        )
        return tuple(_reservation(item) for item in raw)

    async def is_frozen(self, *, scope: str) -> bool:
        return bool(await self._request("isFrozen", {"scope": scope}))

    async def get_recipient_pins(self, scope: str, network: str) -> tuple[str, ...]:
        raw = await self._request("getRecipientPins", {"scope": scope, "network": network})
        return tuple(raw)

    async def get_recipient_policy(self, scope: str) -> dict[str, bool]:
        result = await self._request("getRecipientPolicy", {"scope": scope})
        return {
            "tofu_enabled": bool(result["tofuEnabled"]),
            "recipient_assertion_required": bool(result["recipientAssertionRequired"]),
        }

    async def request_capabilities(self) -> StoreCapabilities:
        result = await self._request("capabilities", {})
        return StoreCapabilities(atomic_global_freeze=bool(result["atomicGlobalFreeze"]))

    async def freeze(self, scope: str, now_epoch_ms: int) -> None:
        await self._request("freeze", {"scope": scope, "nowEpochMs": now_epoch_ms})

    async def unfreeze(self, scope: str, now_epoch_ms: int) -> None:
        await self._request("unfreeze", {"scope": scope, "nowEpochMs": now_epoch_ms})

    async def set_recipient_pins(
        self, scope: str, network: str, recipients: tuple[str, ...], now_epoch_ms: int
    ) -> None:
        await self._request(
            "setRecipientPins",
            {
                "scope": scope,
                "network": network,
                "recipients": list(recipients),
                "nowEpochMs": now_epoch_ms,
            },
        )

    async def set_budget_limits(
        self, scope: str, asset_id: str, limits: BudgetLimits, now_epoch_ms: int
    ) -> None:
        await self._request(
            "setBudgetLimits",
            {
                "scope": scope,
                "assetId": asset_id,
                "limits": _limits_body(limits),
                "nowEpochMs": now_epoch_ms,
            },
        )

    async def get_budget_limits(self, scope: str, asset_id: str) -> BudgetLimits:
        return _budget_limits(
            await self._request("getBudgetLimits", {"scope": scope, "assetId": asset_id})
        )

    async def set_recipient_assertion_required(
        self, scope: str, required: bool, now_epoch_ms: int
    ) -> None:
        await self._request(
            "setRecipientAssertionRequired",
            {"scope": scope, "required": required, "nowEpochMs": now_epoch_ms},
        )

    async def set_tofu_enabled(self, scope: str, enabled: bool, now_epoch_ms: int) -> None:
        await self._request(
            "setTofuEnabled",
            {"scope": scope, "enabled": enabled, "nowEpochMs": now_epoch_ms},
        )

    async def resolve_exposed(
        self,
        ref: ReservationRef,
        outcome: Literal["committed", "released"],
        now_epoch_ms: int,
    ) -> None:
        await self._request(
            "resolveExposed",
            {"ref": _ref_to_wire(ref), "outcome": outcome, "nowEpochMs": now_epoch_ms},
        )

    async def reset_cumulative(self, scope: str, asset_id: str, now_epoch_ms: int) -> None:
        await self._request(
            "resetCumulative",
            {"scope": scope, "assetId": asset_id, "nowEpochMs": now_epoch_ms},
        )


def http_gateway_spend_store(
    *,
    base_url: str,
    token: str,
    capabilities: StoreCapabilities | None = None,
    client: httpx.Client | None = None,
) -> HttpGatewaySpendStore:
    """Construct a gateway-backed store, fetching capabilities ONCE unless given (§12.5)."""
    if capabilities is not None:
        return HttpGatewaySpendStore(
            base_url=base_url, token=token, capabilities=capabilities, client=client
        )
    probe = HttpGatewaySpendStore(
        base_url=base_url,
        token=token,
        capabilities=StoreCapabilities(atomic_global_freeze=False),
        client=client,
    )
    return HttpGatewaySpendStore(
        base_url=base_url,
        token=token,
        capabilities=probe.request_capabilities(),
        client=client,
    )


async def async_http_gateway_spend_store(
    *,
    base_url: str,
    token: str,
    capabilities: StoreCapabilities | None = None,
    client: httpx.AsyncClient | None = None,
) -> AsyncHttpGatewaySpendStore:
    """The async twin of :func:`http_gateway_spend_store`."""
    if capabilities is not None:
        return AsyncHttpGatewaySpendStore(
            base_url=base_url, token=token, capabilities=capabilities, client=client
        )
    probe = AsyncHttpGatewaySpendStore(
        base_url=base_url,
        token=token,
        capabilities=StoreCapabilities(atomic_global_freeze=False),
        client=client,
    )
    return AsyncHttpGatewaySpendStore(
        base_url=base_url,
        token=token,
        capabilities=await probe.request_capabilities(),
        client=client,
    )
