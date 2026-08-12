"""Atomic rolling spend reservations, and the store contract they live behind.

SPEC §3, §4.3 and §5.3 make ``SpendStore`` a **public** contract: the only way to hold one
budget across more than one process is to supply an adapter, so the shape of that adapter
is part of the product rather than an implementation detail. :class:`SpendStore` below is
that contract (the **data plane**), :class:`SpendStoreAdmin` is the operator plane with its
own credentials, and :class:`MemorySpendStore` is the process-local reference that
implements both.

Everything an adapter must honour is stated in :class:`SpendStore`'s docstring, once, and
the TypeScript ``SpendStore`` interface in ``packages/tx402/src/core/ledger.ts`` carries the
same text so the two languages cannot describe different contracts.

An adapter can check itself against this module's semantics with
:func:`tx402.spend_store_contract.check_spend_store`, which is shipped rather than kept in
the test tree — an adapter author is not a contributor to this repository and cannot import
its tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, Literal, Protocol, runtime_checkable

from tx402.errors import (
    BudgetExceededError,
    ConfigurationError,
    RecipientUnpinnedError,
    SpendScopeFrozenError,
    Tx402ErrorContext,
)

RESERVATION_TTL_MS = 120_000
ROLLING_WINDOW_MS = 3_600_000
#: ``exposed`` (ADR-026, D-A2) is the durable pre-transmission fence: a reservation marked
#: exposed no longer expires and keeps consuming budget until an operator resolves it.
ReservationState = Literal["reserved", "committed", "released", "expired", "exposed"]


@dataclass(frozen=True, slots=True)
class StoreCapabilities:
    """Declared store capabilities.

    ``atomic_global_freeze`` gates the ``"*"`` freeze: a store that cannot freeze all
    scopes in one atom (Redis Cluster, id-per-scope DO) declares ``False``.
    """

    atomic_global_freeze: bool


@dataclass(frozen=True, slots=True)
class ReservationRef:
    """A durable locator (SPEC §3.1, resolves P0-1).

    A bare reservation UUID cannot address a record in a store sharded by scope+asset (Redis
    hash tag) or by scope (DO). Every lifecycle op therefore takes a ref, not a bare id, and
    the full ``(policy_scope, asset_id, reservation_id)`` triple IS the identity.
    """

    reservation_id: str
    policy_scope: str
    asset_id: str


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    """Caps only; recipient policy has its own setters, not here."""

    max_per_hour_atomic: str | None = None
    max_total_atomic: str | None = None


@dataclass(frozen=True, slots=True)
class SpendReservation:
    reservation_id: str
    policy_scope: str
    request_fingerprint: str
    asset_id: str
    amount_atomic: str
    created_at_epoch_ms: int
    expires_at_epoch_ms: int
    state: ReservationState


@dataclass(frozen=True, slots=True)
class SpendEntry:
    reservation_id: str
    request_fingerprint: str
    asset_id: str
    amount_atomic: str
    committed_at_epoch_ms: int
    settlement_id: str | None = None


@dataclass(frozen=True, slots=True)
class ReserveSpendResult:
    """``reserve`` returns a RESULT, not the bare reservation.

    ``recipient_pin_established`` is response-only and never persisted — an idempotent
    id-reuse replay returns ``False`` and does not re-emit ``recipient.pinned``.
    """

    reservation: SpendReservation
    recipient_pin_established: bool


@dataclass(frozen=True, slots=True)
class BudgetState:
    store_kind: str
    committed_atomic: str
    reserved_atomic: str
    entries: tuple[SpendEntry, ...]
    reservations: tuple[SpendReservation, ...]
    #: The ledger these totals describe — the normalized merchant host.
    #:
    #: ``None`` only on the empty snapshot a client returns before it has paid anything.
    policy_scope: str | None = None
    asset_id: str | None = None
    #: Sum of exposed (maybe-settled) reservations for this scope+asset.
    exposed_atomic: str | None = None
    #: Lifetime committed for this scope+asset — survives the rolling window.
    cumulative_committed_atomic: str | None = None
    #: ``cumulative_committed + exposed_total + reserved_only``, every amount in one term.
    cumulative_consumed_atomic: str | None = None
    #: Administered per-hour cap, when one is set in the store (ADR-025 §4.3).
    per_hour_limit_atomic: str | None = None
    #: Administered cumulative cap, when one is set in the store (ADR-025 §4.3).
    cumulative_limit_atomic: str | None = None
    #: Computed when a per-hour limit is known: ``max(0, limit - rolling consumed)``.
    available_per_hour_atomic: str | None = None
    #: Computed when a cumulative limit is known: ``max(0, limit - cumulative_consumed)``.
    available_cumulative_atomic: str | None = None
    #: True when ``policy_scope`` OR the global ``"*"`` scope is frozen.
    frozen: bool | None = None


@runtime_checkable
class SpendStore(Protocol):
    """The pluggable spend ledger — the DATA plane.

    Implement this to share one budget across processes; :class:`MemorySpendStore` is the
    process-local default. Structural, not nominal: an adapter does not import or subclass
    anything from tx402, it just has these methods, a ``kind``, and ``capabilities``.

    The contract an adapter must honour:

    - **``policy_scope`` is the normalized merchant host.** It is opaque to the store — the
      store must only ever compare it for equality, never parse it — but it is the key that
      makes two processes calling one merchant share one cap. Build it with
      :func:`tx402.policy.normalize_policy_host`.
    - **The full ``(policy_scope, asset_id, reservation_id)`` triple IS the reservation
      identity.** A sharded store cannot detect a *wrong* scope — it routes to that scope's
      shard and finds nothing — so a ref whose triple names no record is a single typed
      ``reservation-not-found`` :class:`~tx402.errors.ConfigurationError`, identical across
      every adapter.
    - **Money is an atomic-unit decimal string throughout.** Never a float.
    - **:meth:`reserve` is atomic.** The cap comparison and the insert are one operation
      under one lock or one transaction. This is SEC-002's guarantee.
    - **:meth:`reserve` rejects an over-cap request with
      :class:`~tx402.errors.BudgetExceededError`.** Any other exception is read as an
      outage: the client converts it to a retryable :class:`~tx402.errors.TransportError`.
    - **:meth:`reserve` is idempotent for a repeated ``reservation_id``** and raises
      ``ValueError`` if the same id arrives with different spend data.
    - **``commit``, ``release`` and ``expose`` are idempotent** for a reservation
      already in that terminal state; a replay returns the record and touches no counter.
    - **A :meth:`commit` failure is money-relevant.** It happens *after* settlement, so the
      client converts it to :class:`~tx402.errors.ResourceDeliveryError` with ``paid=True``
      and does *not* release.
    - **:meth:`get_budget_state` is diagnostics** and may raise; the client swallows the
      failure rather than failing a paid request over a snapshot.

    Every method is keyword-only, so an inserted argument cannot silently break an adapter.
    """

    kind: str
    #: {atomic_global_freeze: bool} — parity with the TS ``capabilities`` field (P1).
    capabilities: StoreCapabilities

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
        recipient_enforcement: str | None = None,  # "off" | "allowlist" | "tofu"
        now_epoch_ms: int,
    ) -> ReserveSpendResult:
        """Atomically admits or refuses ``amount_atomic``; returns a result."""
        ...

    def commit(
        self,
        *,
        ref: ReservationRef,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        """Turns a reservation into a committed entry. Called only after settlement."""
        ...

    def release(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        """Returns reserved budget. Called only when no settlement can have occurred."""
        ...

    def expose(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        """The durable pre-transmit fence: reserved -> exposed, non-expiring."""
        ...

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        """The rolling-window snapshot for one scope and asset."""
        ...

    def list_exposed(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> tuple[SpendReservation, ...]:
        """Exposed (unresolved) reservations for a scope+asset, for operator reconcile."""
        ...

    def is_frozen(self, *, scope: str) -> bool:
        """Read-only freeze check for diagnostics/CLI (``reserve`` checks atomically)."""
        ...


@runtime_checkable
class AsyncSpendStore(Protocol):
    """The async twin of :class:`SpendStore`.

    Identical contract, every data-plane method ``async def``. :class:`AsyncTx402Client`
    awaits it directly; a synchronous :class:`SpendStore` is offloaded via
    ``asyncio.to_thread`` instead.
    """

    kind: str
    capabilities: StoreCapabilities

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
    ) -> ReserveSpendResult: ...

    async def commit(
        self,
        *,
        ref: ReservationRef,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry: ...

    async def release(
        self, *, ref: ReservationRef, now_epoch_ms: int
    ) -> SpendReservation: ...

    async def expose(
        self, *, ref: ReservationRef, now_epoch_ms: int
    ) -> SpendReservation: ...

    async def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState: ...

    async def list_exposed(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> tuple[SpendReservation, ...]: ...

    async def is_frozen(self, *, scope: str) -> bool: ...


@runtime_checkable
class RecipientPinStore(Protocol):
    """Optional TOFU/allowlist capability (data-plane, SPEC §3.1, ADR-028).

    Enforcement is authoritative INSIDE ``reserve``; these read for the
    advisory pre-filter and the CLI. There is no set-if-absent op on the request path.
    """

    def get_recipient_pins(self, scope: str, network: str) -> tuple[str, ...]: ...

    def get_recipient_policy(self, scope: str) -> dict[str, bool]:
        """``{"tofu_enabled": bool, "recipient_assertion_required": bool}`` for a scope."""
        ...


@runtime_checkable
class AsyncRecipientPinStore(Protocol):
    """The async twin of :class:`RecipientPinStore` (SPEC §3.3, resolves the round-6 P1).

    Without it the advisory pin/policy read in ``evaluate`` would block the async loop.
    """

    async def get_recipient_pins(self, scope: str, network: str) -> tuple[str, ...]: ...

    async def get_recipient_policy(self, scope: str) -> dict[str, bool]: ...


@runtime_checkable
class SpendStoreAdmin(Protocol):
    """The admin plane. Operator only, SEPARATE credentials.

    Never handed to the agent path. The reference ``MemorySpendStore`` implements it on
    the same object — in-process it has no credential separation, which is acceptable and
    documented as test-only; production separation requires a durable store with ACLs.
    """

    def freeze(self, scope: str, now_epoch_ms: int) -> None: ...

    def unfreeze(self, scope: str, now_epoch_ms: int) -> None: ...

    def set_recipient_pins(
        self, scope: str, network: str, recipients: tuple[str, ...], now_epoch_ms: int
    ) -> None: ...

    def set_budget_limits(
        self, scope: str, asset_id: str, limits: BudgetLimits, now_epoch_ms: int
    ) -> None: ...

    def get_budget_limits(self, scope: str, asset_id: str) -> BudgetLimits: ...

    def set_recipient_assertion_required(
        self, scope: str, required: bool, now_epoch_ms: int
    ) -> None: ...

    def set_tofu_enabled(self, scope: str, enabled: bool, now_epoch_ms: int) -> None: ...

    def resolve_exposed(
        self,
        ref: ReservationRef,
        outcome: Literal["committed", "released"],
        now_epoch_ms: int,
    ) -> None: ...

    def reset_cumulative(self, scope: str, asset_id: str, now_epoch_ms: int) -> None: ...


#: The data-plane surface a client validates at construction. Admin methods are NOT here — a
#: data credential must not be able to freeze or set limits.
_SPEND_STORE_METHODS = (
    "reserve",
    "commit",
    "release",
    "expose",
    "get_budget_state",
    "list_exposed",
    "is_frozen",
)


def assert_spend_store(candidate: object) -> None:
    """Rejects a spend store missing the data-plane contract, at construction time.

    ``runtime_checkable`` protocols only check that the attributes exist, which is exactly
    the check worth making here: a store's *behaviour* cannot be verified by introspection,
    and :func:`tx402.spend_store_contract.check_spend_store` exists for that. What this
    stops is the failure mode the audit found — a lookalike accepted by duck typing and
    discovered to be missing a method in the middle of a payment.

    Works for both a sync :class:`SpendStore` and an :class:`AsyncSpendStore`: the method
    names are the same and ``capabilities`` must be present with a boolean
    ``atomic_global_freeze`` in either case (SPEC §3.3, round-7 P1).
    """
    missing = [
        name
        for name in _SPEND_STORE_METHODS
        if not callable(getattr(candidate, name, None))
    ]
    if not isinstance(getattr(candidate, "kind", None), str):
        missing.append("kind")
    capabilities = getattr(candidate, "capabilities", None)
    if not isinstance(getattr(capabilities, "atomic_global_freeze", None), bool):
        missing.append("capabilities.atomic_global_freeze")
    if missing:
        raise ConfigurationError(
            "spend_store must implement the SpendStore contract",
            context=Tx402ErrorContext(request_id="configuration", phase="initial"),
            details={
                "configPath": "spend_store",
                "reason": "invalid-spend-store",
                "missing": sorted(missing),
            },
        )


def _reservation_not_found(ref: ReservationRef) -> ConfigurationError:
    """The typed envelope for a ref that names no record."""
    return ConfigurationError(
        "The reservation ref names no record",
        context=Tx402ErrorContext(
            request_id="spend-store", phase="policy", reservation_id=ref.reservation_id
        ),
        details={"configPath": "reservationRef", "reason": "reservation-not-found"},
    )


def _lifecycle_error(reason: str, reservation_id: str) -> ConfigurationError:
    """A typed lifecycle-transition refusal (SPEC §3.4 error table)."""
    return ConfigurationError(
        "The reservation lifecycle transition is not permitted",
        context=Tx402ErrorContext(
            request_id="spend-store", phase="policy", reservation_id=reservation_id
        ),
        details={"configPath": "reservation.lifecycle", "reason": reason},
    )


def _cap_exceeds_administered(config_path: str) -> ConfigurationError:
    """A caller cap that EXCEEDS the store-administered cap (SPEC §3.4 step 4, D-A3).

    Configuration, not a budget decision: a drifted or hostile worker cannot widen the
    operator's ceiling by presenting a looser number. Raised before the budget arithmetic of
    steps 5/6, so the lowered-cap precedence never collides (§4.3, ADR-025 §3).
    """
    return ConfigurationError(
        "Caller cap exceeds the store-administered cap",
        context=Tx402ErrorContext(request_id="spend-store", phase="policy"),
        details={"configPath": config_path, "reason": "cap-exceeds-administered"},
    )


def canonicalize_recipient(network: str, value: str) -> str:
    """Canonicalize a recipient address for pin comparison.

    eip155 -> lowercase hex (the ``same_address`` rule; no EIP-55 checksum re-derivation).
    Every other family (solana) -> verbatim, since base58 is injective and case-sensitive.
    Core-path: no chain libraries. Idempotent, so a store may canonicalize a value the
    client already canonicalized without changing it.
    """
    return value.lower() if network.startswith("eip155:") else value


def canonicalize_asset(asset_id: str) -> str:
    """Canonicalize a CAIP-19 ``asset_id`` for ledger keying.

    eip155 assets -> lowercase (the ``erc20:0x...`` contract address is hex and the
    ``eip155:<chain>`` prefix numeric, so lowercasing the whole id matches the §6.4
    ``same_address`` rule; no EIP-55 checksum is derived). Every other family (solana
    ``token:<mint>``, case-sensitive base58) -> verbatim. Core-path: no chain libraries.
    Idempotent. Mirrors :func:`canonicalize_recipient` and closes the recipient-vs-asset
    asymmetry: an administered cap set under one casing binds a reserve keyed under the
    other. The frozen SPEC §12.2 key *template* is unchanged — only the value that fills the
    ``<asset>`` segment is normalized before keying.
    """
    return asset_id.lower() if asset_id.startswith("eip155:") else asset_id


_ATOMIC_POSITIVE = re.compile(r"[1-9][0-9]*")
_ATOMIC_NON_NEGATIVE = re.compile(r"0|[1-9][0-9]*")


def _atomic(value: str, field: str, *, positive: bool = False) -> int:
    """Parse an atomic-unit integer string, rejecting malformed/negative input.

    Mirrors the TypeScript ``atomic`` guard (``core/ledger.ts``): ``positive`` requires
    ``[1-9][0-9]*`` (a strictly positive amount/cap); otherwise ``0|[1-9][0-9]*`` (a
    non-negative administered cap). A leading zero, sign, whitespace, or non-digit raises
    ``TypeError`` before it can under-count a cap — matching the TS reference store, not the
    permissive bare ``int(...)`` the memory store used to accept (``"-5"`` even LOWERED the
    cap-consumption sum). ``re.fullmatch`` anchors both ends, rejecting a trailing newline.
    """
    pattern = _ATOMIC_POSITIVE if positive else _ATOMIC_NON_NEGATIVE
    if pattern.fullmatch(value) is None:
        raise TypeError(f"{field} must be an atomic integer string")
    return int(value)


def _recipient_unpinned(
    *,
    request_id: str,
    policy_scope: str,
    asset_id: str,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> RecipientUnpinnedError:
    """A ``RecipientUnpinnedError`` with the SPEC §6.5/§8 conditional details (RP-8).

    ``merchantScope`` and ``reason`` are ALWAYS present; ``network``,
    ``presentedRecipient``, and ``expectedRecipients`` are supplied together only for
    ``not-allowlisted``/``pin-mismatch`` (a mismatch against a known set) and are ABSENT for
    ``assertion-required``.
    """
    return RecipientUnpinnedError(
        "The recipient is not pinned for this scope",
        context=Tx402ErrorContext(request_id=request_id, phase="policy", asset_id=asset_id),
        details={"merchantScope": policy_scope, "reason": reason, **(extra or {})},
    )


def _resolve_effective_cap(
    caller: int | None, administered_atomic: str | None, config_path: str
) -> int | None:
    """The effective cap: ``min(caller, administered)``, else whichever exists (step 4).

    A caller cap greater than an administered one is rejected; a stricter (smaller) caller
    cap is honoured via the ``min``. Administered caps are non-negative (``0`` admits none).
    """
    if administered_atomic is None:
        return caller
    administered = _atomic(administered_atomic, "administeredCap")
    if caller is None:
        return administered
    if caller > administered:
        raise _cap_exceeds_administered(config_path)
    return caller  # caller <= administered, so the min is the caller


class MemorySpendStore:
    """Single-process store implementing both the data and admin planes.

    Atomic operations are protected by a re-entrant lock. Accounting:

    - ``_cumulative`` and ``_exposed_total`` are lifetime per-(scope, asset) accumulators.
      The committed lifetime figure cannot be derived by scanning, because committed entries
      are pruned once they fall out of the rolling window; the exposed figure mirrors
      the durable stores, where a scan is not cheap.
    - Rolling-hour figures are derived from the persisted records.
    - This store uses the caller's ``now_epoch_ms``: one clock, no skew.
    """

    kind = "memory"
    # Single process: the global "*" freeze is atomic w.r.t. every reserve.
    capabilities = StoreCapabilities(atomic_global_freeze=True)

    def __init__(self) -> None:
        self._reservations: dict[tuple[str, str, str], SpendReservation] = {}
        self._entries: dict[tuple[str, str, str], SpendEntry] = {}
        self._cumulative: dict[tuple[str, str], int] = {}
        self._exposed_total: dict[tuple[str, str], int] = {}
        self._frozen: set[str] = set()
        self._limits: dict[tuple[str, str], BudgetLimits] = {}
        self._pins: dict[tuple[str, str], tuple[tuple[str, ...], str]] = {}
        self._recipient_policy: dict[str, dict[str, bool]] = {}
        self._lock = RLock()

    def _maintain(self, now_epoch_ms: int) -> None:
        cutoff = now_epoch_ms - ROLLING_WINDOW_MS
        for key, reservation in list(self._reservations.items()):
            current = reservation
            if current.state == "reserved" and current.expires_at_epoch_ms <= now_epoch_ms:
                current = replace(current, state="expired")
                self._reservations[key] = current
            # An exposed record never expires and is never pruned until an operator resolves
            # it: maybe-settled money that keeps consuming the cumulative cap.
            if current.state == "exposed":
                continue
            committed_entry = self._entries.get(key)
            if (
                current.created_at_epoch_ms < cutoff
                and current.state != "reserved"
                and (
                    current.state != "committed"
                    or committed_entry is None
                    or committed_entry.committed_at_epoch_ms < cutoff
                )
            ):
                del self._reservations[key]
        for key, entry in list(self._entries.items()):
            if entry.committed_at_epoch_ms < cutoff:
                del self._entries[key]

    def _matching(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> tuple[tuple[SpendEntry, ...], tuple[SpendReservation, ...], int, int, int]:
        self._maintain(now_epoch_ms)
        cutoff = now_epoch_ms - ROLLING_WINDOW_MS
        reservations = tuple(
            reservation
            for reservation in self._reservations.values()
            if reservation.policy_scope == policy_scope and reservation.asset_id == asset_id
        )
        entries: list[SpendEntry] = []
        for reservation in reservations:
            if reservation.state != "committed":
                continue
            entry = self._entries.get((policy_scope, asset_id, reservation.reservation_id))
            if (
                entry is not None
                and entry.committed_at_epoch_ms >= cutoff
                and entry.committed_at_epoch_ms <= now_epoch_ms
            ):
                entries.append(entry)
        committed = sum(int(entry.amount_atomic) for entry in entries)
        reserved = sum(
            int(reservation.amount_atomic)
            for reservation in reservations
            if reservation.state == "reserved"
            and reservation.created_at_epoch_ms >= cutoff
            and reservation.created_at_epoch_ms <= now_epoch_ms
            and reservation.expires_at_epoch_ms > now_epoch_ms
        )
        # Exposed reservations count toward the per-hour cap only while inside the rolling
        # window; they count toward the cumulative cap forever (via _exposed_total).
        exposed_rolling = sum(
            int(reservation.amount_atomic)
            for reservation in reservations
            if reservation.state == "exposed"
            and reservation.created_at_epoch_ms >= cutoff
            and reservation.created_at_epoch_ms <= now_epoch_ms
        )
        return tuple(entries), reservations, committed, reserved, exposed_rolling

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        with self._lock:
            asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
            entries, reservations, committed, reserved, exposed_rolling = self._matching(
                policy_scope=policy_scope, asset_id=asset_id, now_epoch_ms=now_epoch_ms
            )
            sa_key = (policy_scope, asset_id)
            cumulative_committed = self._cumulative.get(sa_key, 0)
            exposed_total = self._exposed_total.get(sa_key, 0)
            cumulative_consumed = cumulative_committed + exposed_total + reserved
            limits = self._limits.get(sa_key)
            frozen = policy_scope in self._frozen or "*" in self._frozen
            rolling_consumed = committed + reserved + exposed_rolling
            per_hour_limit = limits.max_per_hour_atomic if limits else None
            cumulative_limit = limits.max_total_atomic if limits else None
            return BudgetState(
                self.kind,
                str(committed),
                str(reserved),
                entries,
                reservations,
                policy_scope=policy_scope,
                asset_id=asset_id,
                exposed_atomic=str(exposed_total),
                cumulative_committed_atomic=str(cumulative_committed),
                cumulative_consumed_atomic=str(cumulative_consumed),
                per_hour_limit_atomic=per_hour_limit,
                cumulative_limit_atomic=cumulative_limit,
                available_per_hour_atomic=(
                    str(max(0, int(per_hour_limit) - rolling_consumed))
                    if per_hour_limit is not None
                    else None
                ),
                available_cumulative_atomic=(
                    str(max(0, int(cumulative_limit) - cumulative_consumed))
                    if cumulative_limit is not None
                    else None
                ),
                frozen=frozen,
            )

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
        with self._lock:
            asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16: canonical asset key
            # Validate amount + per-hour cap up front, before any pin claim or insert:
            # a malformed atomic (which a bare int() would accept) is rejected first.
            amount = _atomic(amount_atomic, "amountAtomic", positive=True)
            cap = _atomic(max_per_hour_atomic, "maxPerHourAtomic", positive=True)
            key = (policy_scope, asset_id, reservation_id)
            existing = self._reservations.get(key)
            if existing is not None:
                if (
                    existing.request_fingerprint != request_fingerprint
                    or existing.amount_atomic != amount_atomic
                ):
                    raise ValueError("Reservation ID was reused with different spend data")
                # No pin is claimed on a replay — the flag is response-only.
                return ReserveSpendResult(existing, recipient_pin_established=False)
            # Freeze (SPEC §3.4 step 2, D-B1): deny if this scope OR the global "*" scope is
            # frozen. The check and the insert share the lock, so the freeze is atomic vs.
            # every reserve — atomic_global_freeze is True. A stop-future-authz
            # control, never a rollback: an existing (incl. exposed) reservation keeps
            # counting across a freeze and unfreeze preserves it (KS-7, §5.4).
            if policy_scope in self._frozen or "*" in self._frozen:
                frozen_scope = policy_scope if policy_scope in self._frozen else "*"
                raise SpendScopeFrozenError(
                    "Spending is frozen for this scope",
                    context=Tx402ErrorContext(
                        request_id=request_id,
                        phase="policy",
                        amount_atomic=amount_atomic,
                        asset_id=asset_id,
                    ),
                    details={"scope": policy_scope, "frozenScope": frozen_scope},
                )
            # Recipient assertion (SPEC §3.4 step 3, ADR-028), driven by the STORE's
            # administered source, never the caller's mode — so a compromised caller cannot
            # relax a mismatch or an assertion-required. ``recipient_enforcement`` governs
            # ONLY the no-record disposition and its absence is "off". A store READ failure
            # here would be a retryable TransportError (SS-11), never a RecipientUnpinned
            # error; the in-memory store cannot fail this read.
            # Treat an empty recipient_canonical as NOT presented (guard on None OR ""), so
            # the assertion-required gate fails closed, like the durable Redis/DO stores.
            # Without the "" case the reference store would be the permissive one on a
            # safety gate; an empty recipient also matches no real allowlist.
            presented_recipient: str | None = (
                None
                if not recipient_canonical or recipient_network is None
                else canonicalize_recipient(recipient_network, recipient_canonical)
            )
            recipient_policy = self._recipient_policy.get(policy_scope)
            recipient_pin_established = False
            if (
                recipient_policy is not None
                and recipient_policy.get("recipient_assertion_required")
                and (presented_recipient is None or recipient_network is None)
            ):
                raise _recipient_unpinned(
                    request_id=request_id,
                    policy_scope=policy_scope,
                    asset_id=asset_id,
                    reason="assertion-required",
                )
            if presented_recipient is not None and recipient_network is not None:
                record = self._pins.get((policy_scope, recipient_network))
                if record is not None:
                    recipients, source = record
                    expected_recipients = [
                        canonicalize_recipient(recipient_network, value)
                        for value in recipients
                    ]
                    if presented_recipient not in expected_recipients:
                        raise _recipient_unpinned(
                            request_id=request_id,
                            policy_scope=policy_scope,
                            asset_id=asset_id,
                            reason=(
                                "not-allowlisted"
                                if source == "admin-allowlist"
                                else "pin-mismatch"
                            ),
                            extra={
                                "network": recipient_network,
                                "presentedRecipient": presented_recipient,
                                "expectedRecipients": expected_recipients,
                            },
                        )
                elif (recipient_enforcement or "off") == "tofu":
                    # No record, and the caller enforces TOFU: claim-if-absent while holding
                    # the lock (reading ``tofu_enabled`` in the atom closes the round-6
                    # TOCTOU). Only "tofu" claims; "allowlist" is advisory and "off" admits.
                    if not (recipient_policy and recipient_policy.get("tofu_enabled")):
                        raise ConfigurationError(
                            "Recipient TOFU is not provisioned for this scope",
                            context=Tx402ErrorContext(
                                request_id=request_id, phase="policy", asset_id=asset_id
                            ),
                            details={
                                "configPath": "recipientPolicy",
                                "reason": "recipient-tofu-not-provisioned",
                            },
                        )
                    self._pins[(policy_scope, recipient_network)] = (
                        (presented_recipient,),
                        "tofu",
                    )
                    recipient_pin_established = True
            # Step 4 (D-A3, §4.3): resolve each dimension against any administered cap.
            # ``min`` honours a stricter caller cap; a caller cap that exceeds the
            # administered one is rejected as configuration, before any budget arithmetic
            # (so the lowered-cap precedence never collides).
            sa_key = (policy_scope, asset_id)
            administered = self._limits.get(sa_key)
            effective_max_per_hour = _resolve_effective_cap(
                cap,
                administered.max_per_hour_atomic if administered else None,
                "policy.maxPerHour",
            )
            assert effective_max_per_hour is not None  # caller max_per_hour always present
            effective_max_total = _resolve_effective_cap(
                _atomic(max_total_atomic, "maxTotalAtomic", positive=True)
                if max_total_atomic is not None
                else None,
                administered.max_total_atomic if administered else None,
                "policy.maxTotal",
            )
            _entries, _reservations, committed, reserved, exposed_rolling = self._matching(
                policy_scope=policy_scope, asset_id=asset_id, now_epoch_ms=now_epoch_ms
            )
            # Step 5 — per-hour cap over the rolling window; the three terms are disjoint.
            if committed + reserved + exposed_rolling + amount > effective_max_per_hour:
                raise BudgetExceededError(
                    "Hourly spend limit would be exceeded",
                    context=Tx402ErrorContext(
                        request_id=request_id,
                        phase="policy",
                        amount_atomic=amount_atomic,
                        asset_id=asset_id,
                    ),
                    details={
                        "requestedAtomic": amount_atomic,
                        "capAtomic": str(effective_max_per_hour),
                        "committedAtomic": str(committed),
                        "reservedAtomic": str(reserved + exposed_rolling),
                        "capKind": "per-hour",
                    },
                )
            # Step 6 — cumulative cap, only when one is in effect. ``reserved_only`` is
            # state=="reserved" reservations only; exposed is counted exactly once through
            # ``exposed_total`` (§3.4 step 6, resolves P1-5). This is the same lifetime sum
            # get_budget_state reports as ``cumulative_consumed_atomic``.
            if effective_max_total is not None:
                cumulative_committed = self._cumulative.get(sa_key, 0)
                exposed_total = self._exposed_total.get(sa_key, 0)
                reserved_only = reserved
                consumed = cumulative_committed + exposed_total + reserved_only
                if consumed + amount > effective_max_total:
                    raise BudgetExceededError(
                        "Cumulative spend limit would be exceeded",
                        context=Tx402ErrorContext(
                            request_id=request_id,
                            phase="policy",
                            amount_atomic=amount_atomic,
                            asset_id=asset_id,
                        ),
                        details={
                            "requestedAtomic": amount_atomic,
                            "capAtomic": str(effective_max_total),
                            "committedAtomic": str(cumulative_committed),
                            "reservedAtomic": str(exposed_total + reserved_only),
                            "capKind": "cumulative",
                        },
                    )
            reservation = SpendReservation(
                reservation_id,
                policy_scope,
                request_fingerprint,
                asset_id,
                amount_atomic,
                now_epoch_ms,
                now_epoch_ms + RESERVATION_TTL_MS,
                "reserved",
            )
            self._reservations[key] = reservation
            # ``recipient_pin_established`` is response-only and never persisted:
            # a later id-reuse replay returns the record with it False and re-emits nothing.
            return ReserveSpendResult(
                reservation, recipient_pin_established=recipient_pin_established
            )

    def commit(
        self,
        *,
        ref: ReservationRef,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        with self._lock:
            asset = canonicalize_asset(ref.asset_id)  # SPEC §6.4/U16
            key = (ref.policy_scope, asset, ref.reservation_id)
            existing = self._entries.get(key)
            if existing is not None:
                return existing
            self._maintain(committed_at_epoch_ms)
            reservation = self._reservations.get(key)
            if reservation is None:
                raise _reservation_not_found(ref)
            if reservation.state == "released":
                raise _lifecycle_error("released-cannot-commit", ref.reservation_id)
            # The pre-transmission fence means a legitimate payment is exposed before it
            # settles; an expired reservation can never legitimately commit, and permitting
            # it would breach the cumulative cap (SPEC §3.4, a named 0.2.0 break).
            if reservation.state == "expired":
                raise _lifecycle_error("expired-cannot-commit", ref.reservation_id)
            amount = int(reservation.amount_atomic)
            sa_key = (ref.policy_scope, asset)
            entry = SpendEntry(
                reservation.reservation_id,
                reservation.request_fingerprint,
                reservation.asset_id,
                reservation.amount_atomic,
                committed_at_epoch_ms,
                # An empty settlement_id is "no settlement id" — store None (matching
                # every adapter round-trips an empty id as absent, not "".
                settlement_id or None,
            )
            self._entries[key] = entry
            self._reservations[key] = replace(reservation, state="committed")
            self._cumulative[sa_key] = self._cumulative.get(sa_key, 0) + amount
            if reservation.state == "exposed":
                self._exposed_total[sa_key] = self._exposed_total.get(sa_key, 0) - amount
            return entry

    def release(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        with self._lock:
            self._maintain(now_epoch_ms)
            asset = canonicalize_asset(ref.asset_id)  # SPEC §6.4/U16
            key = (ref.policy_scope, asset, ref.reservation_id)
            reservation = self._reservations.get(key)
            if reservation is None:
                raise _reservation_not_found(ref)
            if reservation.state == "reserved":
                released = replace(reservation, state="released")
                self._reservations[key] = released
                return released
            if reservation.state == "exposed":
                released = replace(reservation, state="released")
                self._reservations[key] = released
                sa_key = (ref.policy_scope, asset)
                self._exposed_total[sa_key] = self._exposed_total.get(sa_key, 0) - int(
                    reservation.amount_atomic
                )
                return released
            # committed / released / expired: replay -> return unchanged (matches shipped).
            return reservation

    def expose(self, *, ref: ReservationRef, now_epoch_ms: int) -> SpendReservation:
        with self._lock:
            self._maintain(now_epoch_ms)
            asset = canonicalize_asset(ref.asset_id)  # SPEC §6.4/U16
            key = (ref.policy_scope, asset, ref.reservation_id)
            reservation = self._reservations.get(key)
            if reservation is None:
                raise _reservation_not_found(ref)
            if reservation.state == "exposed":
                return reservation  # replay, no counter change
            if reservation.state != "reserved":
                raise _lifecycle_error("reservation-already-terminal", ref.reservation_id)
            # Clear expiry by moving to exposed: _maintain never expires or prunes it.
            exposed = replace(reservation, state="exposed")
            self._reservations[key] = exposed
            sa_key = (ref.policy_scope, asset)
            self._exposed_total[sa_key] = self._exposed_total.get(sa_key, 0) + int(
                reservation.amount_atomic
            )
            return exposed

    def list_exposed(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> tuple[SpendReservation, ...]:
        with self._lock:
            self._maintain(now_epoch_ms)
            asset_id = canonicalize_asset(asset_id)  # SPEC §6.4/U16
            return tuple(
                reservation
                for reservation in self._reservations.values()
                if reservation.policy_scope == policy_scope
                and reservation.asset_id == asset_id
                and reservation.state == "exposed"
            )

    def is_frozen(self, *, scope: str) -> bool:
        with self._lock:
            return scope in self._frozen or "*" in self._frozen

    # ── Admin plane. In-process, no credential separation (test-only, §3.5). ──

    def freeze(self, scope: str, now_epoch_ms: int | None = None) -> None:
        with self._lock:
            # atomic_global_freeze is True, so "*" is a permitted scope here.
            self._frozen.add(scope)

    def unfreeze(self, scope: str, now_epoch_ms: int | None = None) -> None:
        with self._lock:
            self._frozen.discard(scope)

    def set_recipient_pins(
        self,
        scope: str,
        network: str,
        recipients: tuple[str, ...],
        now_epoch_ms: int | None = None,
    ) -> None:
        with self._lock:
            self._pins[(scope, network)] = (tuple(recipients), "admin-allowlist")

    def get_recipient_pins(self, scope: str, network: str) -> tuple[str, ...]:
        with self._lock:
            record = self._pins.get((scope, network))
            return record[0] if record is not None else ()

    def get_recipient_policy(self, scope: str) -> dict[str, bool]:
        with self._lock:
            policy = self._recipient_policy.get(scope)
            return {
                "tofu_enabled": bool(policy and policy.get("tofu_enabled")),
                "recipient_assertion_required": bool(
                    policy and policy.get("recipient_assertion_required")
                ),
            }

    def set_budget_limits(
        self,
        scope: str,
        asset_id: str,
        limits: BudgetLimits,
        now_epoch_ms: int | None = None,
    ) -> None:
        with self._lock:
            self._limits[(scope, canonicalize_asset(asset_id))] = limits  # SPEC §6.4/U16

    def get_budget_limits(self, scope: str, asset_id: str) -> BudgetLimits:
        with self._lock:
            return self._limits.get((scope, canonicalize_asset(asset_id)), BudgetLimits())

    def _policy_for(self, scope: str) -> dict[str, bool]:
        policy = self._recipient_policy.get(scope)
        if policy is None:
            policy = {"tofu_enabled": False, "recipient_assertion_required": False}
            self._recipient_policy[scope] = policy
        return policy

    def set_recipient_assertion_required(
        self, scope: str, required: bool, now_epoch_ms: int | None = None
    ) -> None:
        with self._lock:
            self._policy_for(scope)["recipient_assertion_required"] = required

    def set_tofu_enabled(
        self, scope: str, enabled: bool, now_epoch_ms: int | None = None
    ) -> None:
        with self._lock:
            self._policy_for(scope)["tofu_enabled"] = enabled

    def resolve_exposed(
        self,
        ref: ReservationRef,
        outcome: Literal["committed", "released"],
        now_epoch_ms: int,
    ) -> None:
        with self._lock:
            self._maintain(now_epoch_ms)
            key = (ref.policy_scope, canonicalize_asset(ref.asset_id), ref.reservation_id)
            reservation = self._reservations.get(key)
            if reservation is None:
                raise _reservation_not_found(ref)
            if reservation.state == "reserved":
                raise _lifecycle_error("reservation-not-exposed", ref.reservation_id)
            if reservation.state != "exposed":
                raise _lifecycle_error("reservation-already-terminal", ref.reservation_id)
            # resolve_exposed(...) is exactly commit(exposed)/release(exposed).
            if outcome == "committed":
                self.commit(ref=ref, committed_at_epoch_ms=now_epoch_ms)
            else:
                self.release(ref=ref, now_epoch_ms=now_epoch_ms)

    def reset_cumulative(
        self, scope: str, asset_id: str, now_epoch_ms: int | None = None
    ) -> None:
        with self._lock:
            self._cumulative.pop(
                (scope, canonicalize_asset(asset_id)), None
            )  # SPEC §6.4/U16
