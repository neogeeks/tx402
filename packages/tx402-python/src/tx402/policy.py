"""Local policy evaluation in the exact SPEC §6.3 order."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from tx402.errors import (
    BudgetExceededError,
    ClockSkewError,
    ConfigurationError,
    DomainNotAllowedError,
    InvalidPaymentRequiredError,
    RecipientUnpinnedError,
    TransportError,
    Tx402Error,
    Tx402ErrorContext,
    UnsupportedSchemeError,
)
from tx402.ledger import BudgetState, SpendStore, canonicalize_recipient
from tx402.manifest import require_network
from tx402.money import MoneyAssetMetadata, MoneyParseError, parse_positive_money_atomic


def _recipient_store_outage(
    error: BaseException, context: Tx402ErrorContext
) -> BaseException:
    """A recipient-pin/policy STORE read failure in the advisory pre-filter is an
    infra outage — a retryable ``TransportError`` (``recipient-store-unavailable``),
    fail-closed before any signature. A typed refusal passes through."""
    if isinstance(error, Tx402Error):
        return error
    return TransportError(
        "The recipient pin store is unavailable",
        context=context,
        details={"causeCategory": "recipient-store-unavailable"},
        cause=error,
    )


DEFAULT_MAX_PER_REQUEST: Final = "0.50 USDC"
DEFAULT_MAX_PER_HOUR: Final = "10.00 USDC"
DEFAULT_MAX_QUOTE_AGE_MS: Final = 5_000
MAX_FUTURE_SKEW_MS: Final = 15_000


@dataclass(frozen=True, slots=True)
class Policy:
    max_per_request: object = DEFAULT_MAX_PER_REQUEST
    max_per_hour: object = DEFAULT_MAX_PER_HOUR
    #: Optional per-scope+asset lifetime ceiling (D-A1, SPEC §4.1). A decimal-``<SYMBOL>``
    #: string; ``max_total >= max_per_hour >= max_per_request`` or ``ConfigurationError``.
    #: ``None`` ⇒ no caller cumulative cap (an administered one may still bind, §4.3).
    max_total: object | None = None
    allowed_networks: Sequence[str] | None = None
    allowed_domains: Sequence[str] = ("*",)
    max_paid_attempts: int = 2

    def __post_init__(self) -> None:
        if self.allowed_networks is not None:
            object.__setattr__(self, "allowed_networks", tuple(self.allowed_networks))
        object.__setattr__(self, "allowed_domains", tuple(self.allowed_domains))


@dataclass(frozen=True, slots=True)
class RoutingPolicy:
    max_quote_age_ms: int = DEFAULT_MAX_QUOTE_AGE_MS
    prefer_networks: Sequence[str] = ()
    #: Replaces the signed manifest's RPC endpoints for specific networks.
    #:
    #: Keyed by CAIP-2 identifier or alias; the value replaces ``rpcUrls`` for that network
    #: and nothing else. Every other manifest fact — which networks exist, which assets they
    #: carry, a token's decimals — still comes from the signed document.
    #:
    #: This does not weaken the manifest's integrity guarantee. SPEC §7.1 and §7.2 require
    #: chain identity to be proven on the same endpoint that serves the balance, on every
    #: read, and that check runs against whatever endpoint is used — so an override pointing
    #: at the wrong chain opens its circuit and is skipped rather than trusted.
    rpc_overrides: Mapping[str, Sequence[str]] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "prefer_networks", tuple(self.prefer_networks))


@dataclass(frozen=True, slots=True)
class RecipientPolicy:
    """Recipient pinning config, passed to :class:`PolicyEngine`.

    ``mode`` defaults to ``"off"`` (behaviour identical to v0.1.0). ``"allowlist"`` requires
    ``allow``. ``"tofu"`` requires the configured store to implement
    :class:`~tx402.ledger.RecipientPinStore` (checked at client construction, else
    ``ConfigurationError recipient-tofu-needs-pin-store``); ``allow`` MAY also be present
    (allowlist wins, TOFU fills gaps). Each ``allow`` entry is
    ``{"host": ..., "network": ..., "recipients": [...]}``; the host is normalized and the
    network resolved through the manifest at construction. The client-side allow-list is an
    advisory pre-filter only — the store holds the authoritative recipient set (§6.2).
    """

    mode: str = "off"
    allow: Sequence[Mapping[str, Any]] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "allow", tuple(self.allow))


@dataclass(frozen=True, slots=True)
class PolicyRequirement:
    requirement: Mapping[str, Any]
    asset_id: str
    manifest_asset: Mapping[str, Any]
    max_per_request_atomic: str
    max_per_hour_atomic: str
    #: Present only when a caller cumulative cap is configured.
    max_total_atomic: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    normalized_host: str
    requirements: tuple[PolicyRequirement, ...]


@dataclass(frozen=True, slots=True)
class _PreparedAsset:
    manifest: Mapping[str, Any]
    asset_id: str
    max_per_request: int
    max_per_hour: int
    max_total: int | None = None


def _configuration(
    path: str, reason: str, cause: BaseException | None = None
) -> ConfigurationError:
    return ConfigurationError(
        f"Invalid {path}: {reason}",
        context=Tx402ErrorContext(request_id="configuration", phase="initial"),
        details={"configPath": path, "reason": reason},
        cause=cause,
    )


def normalize_policy_host(url: str) -> str:
    """The canonical policy host of ``url``.

    The canonical form is the **A-label (ASCII) host**: what a WHATWG URL parser produces,
    lowercased, with one trailing root dot removed. ``https://bücher.example/x`` and
    ``https://xn--bcher-kva.example/x`` are therefore one merchant with one ledger and one
    allowlist entry, in both languages.

    Punycoding is delegated to ``httpx`` rather than reimplemented, and that is the whole
    point: the same parser converts the host of every request this SDK sends. Previously
    this function returned the U-label the caller happened to type while the client stored
    the punycoded host httpx had already produced, so a caller following the documented API
    queried a ledger the client had never written to, and a Unicode ``allowed_domains``
    entry could never match a real request host (O57's sibling finding, O58). Deriving both
    from one parser makes that class of drift unrepresentable rather than merely fixed.

    :raises ValueError: if ``url`` has no host, or its host is not a valid IDN.
    """
    parsed = urlsplit(url)
    if parsed.hostname is None:
        raise ValueError("Policy URL must be absolute")
    try:
        host = httpx.URL(url).raw_host.decode("ascii").lower()
    except (httpx.InvalidURL, UnicodeDecodeError, UnicodeError) as error:
        raise ValueError(f"Policy URL host is not a valid IDN: {parsed.hostname!r}") from (
            error
        )
    # An IPv6 literal keeps its brackets, because that is the host a WHATWG parser reports
    # and the scope has to be one string in both languages. httpx strips them; TypeScript
    # does not.
    if parsed.netloc.rpartition("@")[2].startswith("["):
        host = f"[{host}]"
    # One dot, not every dot: `a.test.` is `a.test`, and `a.test..` keeps the inner one,
    # matching TypeScript's single-anchor strip. The root-label host `.` normalizes to the
    # empty string in both languages — an accepted, non-routable edge.
    return host[:-1] if host.endswith(".") else host


def _normalize_domain_pattern(value: str, index: int) -> str:
    if value == "*":
        return value
    wildcard = value.startswith("*.")
    candidate = value[2:] if wildcard else value
    if not candidate or any(character in candidate for character in ":/@"):
        raise _configuration(f"policy.allowed_domains[{index}]", "invalid-domain-pattern")
    try:
        host = normalize_policy_host(f"https://{candidate}")
    except ValueError as error:
        raise _configuration(
            f"policy.allowed_domains[{index}]", "invalid-domain-pattern", error
        ) from error
    return f"*.{host}" if wildcard else host


def _domain_matches(host: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    if not pattern.startswith("*."):
        return host == pattern
    suffix = pattern[1:]
    return host.endswith(suffix) and len(host) > len(suffix)


def _asset_reference(asset: Mapping[str, Any]) -> str:
    reference = asset.get("address", asset.get("mint"))
    if not isinstance(reference, str):
        raise ValueError("Manifest asset has no address or mint")
    return reference


def _asset_matches(
    network: Mapping[str, Any], asset: Mapping[str, Any], offered: str
) -> bool:
    expected = _asset_reference(asset)
    return (
        expected.lower() == offered.lower() if "chainId" in network else expected == offered
    )


def _asset_id(network_id: str, network: Mapping[str, Any], asset: Mapping[str, Any]) -> str:
    namespace = "erc20" if "chainId" in network else "token"
    return f"{network_id}/{namespace}:{_asset_reference(asset)}"


def _timestamp_from_extra(extra: Mapping[str, Any]) -> int | None:
    if "timestamp" not in extra:
        return None
    value = extra["timestamp"]
    if isinstance(value, str) and value.endswith("Z"):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            epoch = datetime.fromisoformat("1970-01-01T00:00:00+00:00")
            delta = parsed - epoch
            return (
                delta.days * 86_400_000
                + delta.seconds * 1_000
                + delta.microseconds // 1_000
            )
        except ValueError:
            pass
    raise TypeError("quote-timestamp-invalid")


class PolicyEngine:
    """Immutable policy evaluator. It performs no network or signer calls."""

    def __init__(
        self,
        manifest: Mapping[str, Any],
        policy: Policy | None = None,
        routing: RoutingPolicy | None = None,
        recipient_policy: RecipientPolicy | None = None,
    ) -> None:
        configured = policy or Policy()
        route_policy = routing or RoutingPolicy()
        recipient_config = recipient_policy or RecipientPolicy()
        networks: Mapping[str, Mapping[str, Any]] = manifest["networks"]
        selected = configured.allowed_networks
        if selected is None:
            selected = tuple(
                network_id
                for network_id, network in networks.items()
                if network.get("environment") == "production"
            )
        if not selected:
            raise _configuration("policy.allowed_networks", "empty-list")
        resolved: list[str] = []
        for index, configured_network in enumerate(selected):
            if not isinstance(configured_network, str):
                raise _configuration(f"policy.allowed_networks[{index}]", "expected-string")
            resolved.append(
                require_network(
                    manifest,
                    configured_network,
                    Tx402ErrorContext(request_id="configuration", phase="initial"),
                    f"policy.allowed_networks[{index}]",
                )
            )
        self._manifest = manifest
        self._allowed_networks = frozenset(resolved)

        if not configured.allowed_domains:
            raise _configuration("policy.allowed_domains", "empty-list")
        self._allowed_domains = tuple(
            _normalize_domain_pattern(pattern, index)
            if isinstance(pattern, str)
            else (_raise_expected_domain(index))
            for index, pattern in enumerate(configured.allowed_domains)
        )
        if (
            isinstance(configured.max_paid_attempts, bool)
            or not isinstance(configured.max_paid_attempts, int)
            or not 1 <= configured.max_paid_attempts <= 3
        ):
            raise _configuration("policy.max_paid_attempts", "integer-out-of-range")
        self.max_paid_attempts = configured.max_paid_attempts
        if (
            isinstance(route_policy.max_quote_age_ms, bool)
            or not isinstance(route_policy.max_quote_age_ms, int)
            or route_policy.max_quote_age_ms < 0
        ):
            raise _configuration(
                "routing.max_quote_age_ms", "expected-non-negative-integer"
            )
        self._max_quote_age_ms = route_policy.max_quote_age_ms
        preferences: list[str] = []
        for index, preferred_network in enumerate(route_policy.prefer_networks):
            if not isinstance(preferred_network, str):
                raise _configuration(f"routing.prefer_networks[{index}]", "expected-string")
            preferences.append(
                require_network(
                    manifest,
                    preferred_network,
                    Tx402ErrorContext(request_id="configuration", phase="initial"),
                    f"routing.prefer_networks[{index}]",
                )
            )
        self.prefer_networks = tuple(preferences)

        # Resolved through the manifest for the same reason preferences are: an override
        # keyed by a misspelled or aliased network must fail at construction rather than
        # silently never applying, which would leave the operator believing their keyed
        # endpoint is in use while every read still goes to the public one.
        overrides: dict[str, tuple[str, ...]] = {}
        configured_overrides = route_policy.rpc_overrides or {}
        if not isinstance(configured_overrides, Mapping):
            raise _configuration("routing.rpc_overrides", "expected-object")
        for network, urls in configured_overrides.items():
            path = f"routing.rpc_overrides[{network}]"
            resolved_network = require_network(
                manifest,
                network,
                Tx402ErrorContext(request_id="configuration", phase="initial"),
                path,
            )
            if isinstance(urls, str) or not isinstance(urls, Sequence) or len(urls) == 0:
                raise _configuration(path, "empty-list")
            checked: list[str] = []
            for index, url in enumerate(urls):
                if not isinstance(url, str):
                    raise _configuration(f"{path}[{index}]", "expected-string")
                parsed = urlsplit(url)
                # An RPC endpoint carries an API key in its path or query often enough that
                # plaintext http would leak it. Localhost is exempt because a local
                # validator has no transport to intercept.
                local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
                if parsed.scheme == "https" or (parsed.scheme == "http" and local):
                    if parsed.hostname is None:
                        raise _configuration(f"{path}[{index}]", "invalid-url")
                    checked.append(url)
                    continue
                if parsed.scheme in ("http", "https"):
                    raise _configuration(f"{path}[{index}]", "insecure-scheme")
                raise _configuration(f"{path}[{index}]", "invalid-url")
            overrides[resolved_network] = tuple(checked)
        self.rpc_overrides: Mapping[str, Sequence[str]] = MappingProxyType(overrides)

        assets: dict[str, _PreparedAsset] = {}
        for network_id in self._allowed_networks:
            manifest_network = networks[network_id]
            manifest_assets: Sequence[Mapping[str, Any]] = manifest_network["assets"]
            for asset in manifest_assets:
                metadata = MoneyAssetMetadata(asset["symbol"], asset["decimals"])
                try:
                    per_request = parse_positive_money_atomic(
                        configured.max_per_request, metadata
                    )
                except MoneyParseError as error:
                    raise _configuration(
                        "policy.max_per_request", error.reason, error
                    ) from error
                try:
                    per_hour = parse_positive_money_atomic(
                        configured.max_per_hour, metadata
                    )
                except MoneyParseError as error:
                    raise _configuration(
                        "policy.max_per_hour", error.reason, error
                    ) from error
                if per_hour < per_request:
                    raise _configuration("policy.max_per_hour", "below-max-per-request")
                max_total: int | None = None
                if configured.max_total is not None:
                    try:
                        max_total = parse_positive_money_atomic(
                            configured.max_total, metadata
                        )
                    except MoneyParseError as error:
                        raise _configuration(
                            "policy.max_total", error.reason, error
                        ) from error
                    # Ordering: max_total >= max_per_hour >= max_per_request.
                    if max_total < per_hour:
                        raise _configuration("policy.max_total", "below-max-per-hour")
                reference = _asset_reference(asset)
                assets[f"{network_id}\0{reference}"] = _PreparedAsset(
                    MappingProxyType(dict(asset)),
                    _asset_id(network_id, manifest_network, asset),
                    per_request,
                    per_hour,
                    max_total,
                )
        self._assets = MappingProxyType(assets)

        # Recipient policy. ``mode`` defaults to "off" (opt-in, §14).
        # ``allow`` entries are the advisory pre-filter only; the store is authoritative.
        self.recipient_mode = recipient_config.mode
        if self.recipient_mode not in ("off", "allowlist", "tofu"):
            raise _configuration("recipient_policy.mode", "unexpected-value")
        if self.recipient_mode == "allowlist" and not recipient_config.allow:
            raise _configuration("recipient_policy.allow", "empty-list")
        recipient_allow: dict[tuple[str, str], frozenset[str]] = {}
        for index, entry in enumerate(recipient_config.allow):
            path = f"recipient_policy.allow[{index}]"
            host_value = entry.get("host")
            if not isinstance(host_value, str) or not host_value:
                raise _configuration(f"{path}.host", "expected-string")
            # Host and network share the pin's identity with the budget scope;
            # resolve the network so a misspelled one fails here, not silently later.
            host = normalize_policy_host(f"https://{host_value}")
            network_value = entry.get("network")
            if not isinstance(network_value, str) or not network_value:
                raise _configuration(f"{path}.network", "expected-string")
            network = require_network(
                manifest,
                network_value,
                Tx402ErrorContext(request_id="configuration", phase="initial"),
                f"{path}.network",
            )
            recipients = entry.get("recipients")
            # A ``str`` is a Sequence, so exclude it explicitly or it would be iterated
            # character-by-character (the same guard rpc_overrides uses) — parity with the
            # TypeScript ``Array.isArray`` check.
            if (
                isinstance(recipients, str)
                or not isinstance(recipients, Sequence)
                or not recipients
            ):
                raise _configuration(f"{path}.recipients", "empty-list")
            canonical: set[str] = set()
            for r, recipient in enumerate(recipients):
                if not isinstance(recipient, str) or not recipient:
                    raise _configuration(f"{path}.recipients[{r}]", "expected-string")
                canonical.add(canonicalize_recipient(network, recipient))
            recipient_allow[(host, network)] = frozenset(canonical)
        self._recipient_allow = recipient_allow

    def assert_domain(self, url: str, request_id: str, phase: str = "initial") -> str:
        host = normalize_policy_host(url)
        if not any(_domain_matches(host, pattern) for pattern in self._allowed_domains):
            raise DomainNotAllowedError(
                "Destination domain is not allowed",
                context=Tx402ErrorContext(request_id=request_id, phase=phase),  # type: ignore[arg-type]
                details={"normalizedHost": host},
            )
        return host

    def evaluate(
        self,
        payment_required: Mapping[str, Any],
        *,
        request_id: str,
        policy_scope: str,
        now_epoch_ms: int,
        spend_store: SpendStore,
    ) -> PolicyDecision:
        """Synchronous policy evaluation: the budget read is a blocking store call.

        The classification (:meth:`_candidates`) and final decision (:meth:`_finalize`) are
        pure and shared with :meth:`evaluate_async`, so sync and async paths cannot
        report different outcomes for the same store state.
        """
        host, context, supported = self._candidates(payment_required, request_id=request_id)
        # 9a. Recipient (advisory, SPEC §6.2) — read-only, before the per-request cap.
        if self.recipient_mode != "off":
            supported = self._recipient_filter(supported, host, context, spend_store)
            if not supported:
                raise self._recipient_unpinned_all_dropped(host, context)
        under_cap = self._under_request_cap(supported, request_id=request_id)
        states = {
            asset.asset_id: spend_store.get_budget_state(
                policy_scope=policy_scope,
                asset_id=asset.asset_id,
                now_epoch_ms=now_epoch_ms,
            )
            for _requirement, asset in under_cap
        }
        return self._finalize(
            host,
            context,
            under_cap,
            states,
            request_id=request_id,
            now_epoch_ms=now_epoch_ms,
        )

    async def evaluate_async(
        self,
        payment_required: Mapping[str, Any],
        *,
        request_id: str,
        policy_scope: str,
        now_epoch_ms: int,
        read_budget_state: Callable[..., Awaitable[BudgetState]],
        read_recipient_pins: Callable[..., Awaitable[Sequence[str]]] | None = None,
        read_recipient_policy: Callable[..., Awaitable[Mapping[str, Any]]] | None = None,
    ) -> PolicyDecision:
        """Async policy evaluation: the advisory reads are awaited.

        ``read_budget_state`` / ``read_recipient_pins`` / ``read_recipient_policy`` are the
        client's dispatchers, which await an async store or offload a sync one to a thread —
        so the policy pre-check never blocks the event loop.
        """
        host, context, supported = self._candidates(payment_required, request_id=request_id)
        # 9a. Recipient (advisory, SPEC §6.2) — read-only, before the per-request cap.
        if self.recipient_mode != "off":
            assert read_recipient_pins is not None
            assert read_recipient_policy is not None
            supported = await self._recipient_filter_async(
                supported, host, context, read_recipient_pins, read_recipient_policy
            )
            if not supported:
                raise self._recipient_unpinned_all_dropped(host, context)
        under_cap = self._under_request_cap(supported, request_id=request_id)
        states: dict[str, BudgetState] = {}
        for _requirement, asset in under_cap:
            if asset.asset_id not in states:
                states[asset.asset_id] = await read_budget_state(
                    policy_scope=policy_scope,
                    asset_id=asset.asset_id,
                    now_epoch_ms=now_epoch_ms,
                )
        return self._finalize(
            host,
            context,
            under_cap,
            states,
            request_id=request_id,
            now_epoch_ms=now_epoch_ms,
        )

    def _candidates(
        self, payment_required: Mapping[str, Any], *, request_id: str
    ) -> tuple[str, Tx402ErrorContext, list[tuple[Mapping[str, Any], _PreparedAsset]]]:
        """Pure candidate selection through scheme/asset — before the recipient advisory
         and the per-request cap, both of which run in ``evaluate``/
        ``evaluate_async`` so the recipient read can be sync or async."""
        context = Tx402ErrorContext(request_id=request_id, phase="policy")
        host = self.assert_domain(payment_required["resource"]["url"], request_id, "policy")
        requirements: list[Mapping[str, Any]] = payment_required["requirements"]

        allowed = [
            requirement
            for requirement in requirements
            if requirement["network"] in self._allowed_networks
            and requirement["network"] in self._manifest["networks"]
        ]
        if not allowed:
            raise UnsupportedSchemeError(
                "No allowed payment network was offered",
                context=context,
                details=_offered(requirements),
            )

        supported: list[tuple[Mapping[str, Any], _PreparedAsset]] = []
        for requirement in allowed:
            network = self._manifest["networks"][requirement["network"]]
            if requirement["scheme"] != "exact":
                continue
            match = next(
                (
                    asset
                    for asset in network["assets"]
                    if requirement["scheme"] in asset["schemes"]
                    and _asset_matches(network, asset, requirement["asset"])
                ),
                None,
            )
            if match is not None:
                prepared = self._assets.get(
                    f"{requirement['network']}\0{_asset_reference(match)}"
                )
                if prepared is not None:
                    supported.append((requirement, prepared))
        if not supported:
            raise UnsupportedSchemeError(
                "No supported payment scheme and asset was offered",
                context=context,
                details=_offered(allowed),
            )
        return host, context, supported

    def _under_request_cap(
        self,
        supported: list[tuple[Mapping[str, Any], _PreparedAsset]],
        *,
        request_id: str,
    ) -> list[tuple[Mapping[str, Any], _PreparedAsset]]:
        """The per-request cap filter (SPEC §6.3 step 10). Pure; runs after the recipient
        advisory step so the SPEC evaluation order holds (recipient → per-request)."""
        under_cap = [
            pair
            for pair in supported
            if int(pair[0]["amountAtomic"]) <= pair[1].max_per_request
        ]
        if not under_cap:
            requirement, asset = min(
                supported, key=lambda pair: int(pair[0]["amountAtomic"])
            )
            raise BudgetExceededError(
                "Payment exceeds the per-request limit",
                context=Tx402ErrorContext(
                    request_id=request_id,
                    phase="policy",
                    network=requirement["network"],
                    scheme=requirement["scheme"],
                    amount_atomic=requirement["amountAtomic"],
                    asset_id=asset.asset_id,
                ),
                details={
                    "requestedAtomic": requirement["amountAtomic"],
                    "capAtomic": str(asset.max_per_request),
                    "committedAtomic": "0",
                    "reservedAtomic": "0",
                    "capKind": "per-request",
                },
            )
        return under_cap

    def _recipient_unpinned_all_dropped(
        self, host: str, context: Tx402ErrorContext
    ) -> RecipientUnpinnedError:
        """Every route dropped for a recipient reason. Advisory, so a fast
        user-facing rejection — the store asserts authoritatively in reserve (§3.4)."""
        return RecipientUnpinnedError(
            "No offered recipient is pinned for this scope",
            context=context,
            details={"merchantScope": host, "reason": "not-allowlisted"},
        )

    def _recipient_static_verdict(
        self,
        host: str,
        network: str,
        canonical: str,
    ) -> bool | None:
        """The pure, store-free part of the advisory filter. Returns True (keep)
        or False (drop) when a static allow entry decides the pair or the mode is
        ``allowlist``; ``None`` means "defer to the store" (tofu, no static entry)."""
        allow = self._recipient_allow.get((host, network))
        if allow is not None:
            return canonical in allow  # allowlist wins (§6.1)
        if self.recipient_mode == "allowlist":
            return False  # no static entry admits this pair
        return None  # tofu, no static entry — the store read decides

    def _recipient_pins_match(
        self, network: str, canonical: str, pins: Sequence[str]
    ) -> bool:
        """Whether the presented recipient matches an existing tofu pin."""
        return canonical in [canonicalize_recipient(network, pin) for pin in pins]

    @staticmethod
    def _policy_tofu_enabled(policy: Any) -> bool:
        """TOFU is provisioned only when the policy read returns a mapping whose
        ``tofu_enabled`` is truthy. A ``None`` / non-mapping policy (a store with no policy
        for this scope, or a pin store missing the method) is 'not provisioned', so it fails
        closed via :meth:`_recipient_no_pin_keep`, not with a raw ``AttributeError``. This
        matches the TS ``policy?.tofuEnabled !== true`` guard; the callers already map
        a store outage (an exception on the read) to a retryable outage, so a bare ``None``
        return must not slip past as an unhandled error with no ``request.failed``."""
        return isinstance(policy, Mapping) and bool(policy.get("tofu_enabled"))

    def _recipient_no_pin_keep(
        self, tofu_enabled: bool, context: Tx402ErrorContext
    ) -> bool:
        """A tofu route with no pin yet: keep (pin_pending) only when TOFU is provisioned,
        else fail closed. Never writes; the claim is authoritative in reserve.
        """
        if not tofu_enabled:
            raise ConfigurationError(
                "Recipient TOFU is not provisioned for this scope",
                context=context,
                details={
                    "configPath": "recipientPolicy",
                    "reason": "recipient-tofu-not-provisioned",
                },
            )
        return True

    def _recipient_filter(
        self,
        supported: list[tuple[Mapping[str, Any], _PreparedAsset]],
        host: str,
        context: Tx402ErrorContext,
        spend_store: SpendStore,
    ) -> list[tuple[Mapping[str, Any], _PreparedAsset]]:
        """Synchronous advisory recipient pre-filter. Read-only; reads the pin
        store directly for tofu routes with no static allow entry. The policy read happens
        ONLY when there is no pin, matching the TypeScript path."""
        kept = []
        for requirement, asset in supported:
            network = requirement["network"]
            canonical = canonicalize_recipient(network, requirement["payTo"])
            verdict = self._recipient_static_verdict(host, network, canonical)
            if verdict is None:
                # A STORE outage on either read is a retryable TransportError, fail-closed
                # pre-signature — never a RecipientUnpinnedError or a raw error (§6.3, O17).
                try:
                    pins = spend_store.get_recipient_pins(host, network)  # type: ignore[attr-defined]
                except Exception as error:
                    raise _recipient_store_outage(error, context) from error
                if pins:
                    verdict = self._recipient_pins_match(network, canonical, pins)
                else:
                    try:
                        policy = spend_store.get_recipient_policy(host)  # type: ignore[attr-defined]
                    except Exception as error:
                        raise _recipient_store_outage(error, context) from error
                    verdict = self._recipient_no_pin_keep(
                        self._policy_tofu_enabled(policy), context
                    )
            if verdict:
                kept.append((requirement, asset))
        return kept

    async def _recipient_filter_async(
        self,
        supported: list[tuple[Mapping[str, Any], _PreparedAsset]],
        host: str,
        context: Tx402ErrorContext,
        read_recipient_pins: Callable[..., Awaitable[Sequence[str]]],
        read_recipient_policy: Callable[..., Awaitable[Mapping[str, Any]]],
    ) -> list[tuple[Mapping[str, Any], _PreparedAsset]]:
        """Async advisory recipient pre-filter. The tofu reads are awaited
        through the client's dispatcher; the policy read runs only when there is no pin."""
        kept = []
        for requirement, asset in supported:
            network = requirement["network"]
            canonical = canonicalize_recipient(network, requirement["payTo"])
            verdict = self._recipient_static_verdict(host, network, canonical)
            if verdict is None:
                # A STORE outage on either read is a retryable TransportError, fail-closed
                # pre-signature — never a RecipientUnpinnedError or a raw error (§6.3, O17).
                try:
                    pins = await read_recipient_pins(scope=host, network=network)
                except Exception as error:
                    raise _recipient_store_outage(error, context) from error
                if pins:
                    verdict = self._recipient_pins_match(network, canonical, pins)
                else:
                    try:
                        policy = await read_recipient_policy(scope=host)
                    except Exception as error:
                        raise _recipient_store_outage(error, context) from error
                    verdict = self._recipient_no_pin_keep(
                        self._policy_tofu_enabled(policy), context
                    )
            if verdict:
                kept.append((requirement, asset))
        return kept

    def _finalize(
        self,
        host: str,
        context: Tx402ErrorContext,
        under_cap: list[tuple[Mapping[str, Any], _PreparedAsset]],
        states: dict[str, BudgetState],
        *,
        request_id: str,
        now_epoch_ms: int,
    ) -> PolicyDecision:
        """Pure rolling-hour + freshness filter over the pre-fetched budget states."""
        within_hour: list[PolicyRequirement] = []
        last: tuple[Mapping[str, Any], _PreparedAsset, str, str] | None = None
        for requirement, asset in under_cap:
            state = states[asset.asset_id]
            last = requirement, asset, state.committed_atomic, state.reserved_atomic
            if (
                int(state.committed_atomic)
                + int(state.reserved_atomic)
                + int(requirement["amountAtomic"])
                <= asset.max_per_hour
            ):
                within_hour.append(
                    PolicyRequirement(
                        MappingProxyType(dict(requirement)),
                        asset.asset_id,
                        asset.manifest,
                        str(asset.max_per_request),
                        str(asset.max_per_hour),
                        None if asset.max_total is None else str(asset.max_total),
                    )
                )
        if not within_hour and last is not None:
            requirement, asset, committed, reserved = last
            raise BudgetExceededError(
                "Payment would exceed the rolling hourly limit",
                context=Tx402ErrorContext(
                    request_id=request_id,
                    phase="policy",
                    network=requirement["network"],
                    scheme=requirement["scheme"],
                    amount_atomic=requirement["amountAtomic"],
                    asset_id=asset.asset_id,
                ),
                details={
                    "requestedAtomic": requirement["amountAtomic"],
                    "capAtomic": str(asset.max_per_hour),
                    "committedAtomic": committed,
                    "reservedAtomic": reserved,
                    "capKind": "per-hour",
                },
            )

        fresh: list[PolicyRequirement] = []
        for item in within_hour:
            try:
                timestamp = _timestamp_from_extra(item.requirement["extra"])
            except TypeError as error:
                raise InvalidPaymentRequiredError(
                    "Quote timestamp is invalid",
                    context=context,
                    details={
                        "reason": "quote-timestamp-invalid",
                        "schemaPath": "/accepts/*/extra/timestamp",
                    },
                    cause=error,
                ) from error
            if timestamp is None:
                fresh.append(item)
            elif timestamp - now_epoch_ms > MAX_FUTURE_SKEW_MS:
                raise ClockSkewError(
                    "Quote timestamp is unreasonably future-dated",
                    context=context,
                    details={
                        "observedSkewMs": timestamp - now_epoch_ms,
                        "thresholdMs": MAX_FUTURE_SKEW_MS,
                    },
                )
            elif now_epoch_ms - timestamp <= self._max_quote_age_ms:
                fresh.append(item)
        if not fresh:
            raise InvalidPaymentRequiredError(
                "Payment quote has expired",
                context=context,
                details={
                    "reason": "quote-expired",
                    "schemaPath": "/accepts/*/extra/timestamp",
                },
            )
        return PolicyDecision(host, tuple(fresh))


def _raise_expected_domain(index: int) -> str:
    raise _configuration(f"policy.allowed_domains[{index}]", "expected-string")


def _offered(requirements: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    return {
        "offeredSchemes": list(dict.fromkeys(item["scheme"] for item in requirements)),
        "offeredNetworks": list(dict.fromkeys(item["network"] for item in requirements)),
    }
