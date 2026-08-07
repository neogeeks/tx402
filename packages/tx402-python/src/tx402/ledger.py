"""Atomic rolling spend reservations, and the store contract they live behind.

SPEC §5.3 and §4.3 make ``SpendStore`` a **public** contract: the only way to hold one
budget across more than one process is to supply an adapter, so the shape of that adapter
is part of the product rather than an implementation detail. :class:`SpendStore` below is
that contract, and :class:`MemorySpendStore` is the process-local default (ADR-007).

Everything an adapter must honour is stated in :class:`SpendStore`'s docstring, once, and
the TypeScript ``SpendStore`` interface in ``packages/tx402/src/core/ledger.ts`` carries the
same text so the two languages cannot describe different contracts (ADR-018).

An adapter can check itself against this module's semantics with
:func:`tx402.spend_store_contract.check_spend_store`, which is shipped rather than kept in
the test tree — an adapter author is not a contributor to this repository and cannot import
its tests.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from threading import RLock
from typing import Literal, Protocol, runtime_checkable

from tx402.errors import BudgetExceededError, ConfigurationError, Tx402ErrorContext

RESERVATION_TTL_MS = 120_000
ROLLING_WINDOW_MS = 3_600_000
ReservationState = Literal["reserved", "committed", "released", "expired"]


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
class BudgetState:
    store_kind: str
    committed_atomic: str
    reserved_atomic: str
    entries: tuple[SpendEntry, ...]
    reservations: tuple[SpendReservation, ...]
    #: The ledger these totals describe — the normalized merchant host (ADR-018).
    #:
    #: ``None`` only on the empty snapshot a client returns before it has paid anything.
    policy_scope: str | None = None
    asset_id: str | None = None


@runtime_checkable
class SpendStore(Protocol):
    """The pluggable spend ledger (SPEC §4.3, §5.3).

    Implement this to share one budget across processes; :class:`MemorySpendStore` is the
    process-local default. Structural, not nominal: an adapter does not import or subclass
    anything from tx402, it just has these four methods and a ``kind``.

    The contract an adapter must honour:

    - **``policy_scope`` is the normalized merchant host.** It is opaque to the store — the
      store must only ever compare it for equality, never parse it — but it is the key that
      makes two processes calling one merchant share one cap, so a store must not
      substitute its own. :func:`tx402.policy.normalize_policy_host` produces it.
    - **Money is an atomic-unit decimal string throughout.** Never a float, and never a
      unit-scaled number; the strings are compared and summed as integers.
    - **:meth:`reserve` is atomic.** The cap comparison and the insert are one operation
      under one lock or one transaction, or a concurrent pair of callers can both pass a cap
      only one of them fits under. This is SEC-002's guarantee and it is the single most
      important thing an adapter can get wrong.
    - **:meth:`reserve` rejects an over-cap request with
      :class:`~tx402.errors.BudgetExceededError`.** Any other exception is read as an
      outage: the client converts it to a retryable
      :class:`~tx402.errors.TransportError`, because nothing has been signed yet.
    - **:meth:`reserve` is idempotent for a repeated ``reservation_id``** and raises
      ``ValueError`` if the same id arrives with different spend data.
    - **:meth:`commit` and :meth:`release` are idempotent** for a reservation already in
      that state, and ``commit`` on a released reservation raises.
    - **A :meth:`commit` failure is money-relevant.** It happens *after* settlement, so the
      client converts it to :class:`~tx402.errors.ResourceDeliveryError` with ``paid=True``
      and does *not* release. Fail loudly rather than returning a fabricated entry.
    - **:meth:`get_budget_state` is diagnostics** and may raise; the client swallows the
      failure rather than failing a paid request over a snapshot.

    Every method is keyword-only, in both directions, so an adapter cannot be broken by an
    argument being inserted in the middle of the list.
    """

    kind: str

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
        now_epoch_ms: int,
    ) -> SpendReservation:
        """Atomically admits or refuses ``amount_atomic`` under the rolling cap."""
        ...

    def commit(
        self,
        *,
        reservation_id: str,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        """Turns a reservation into a committed entry. Called only after settlement."""
        ...

    def release(self, *, reservation_id: str, now_epoch_ms: int) -> SpendReservation:
        """Returns reserved budget. Called only when no settlement can have occurred."""
        ...

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        """The rolling-window snapshot for one scope and asset."""
        ...


_SPEND_STORE_METHODS = ("reserve", "commit", "release", "get_budget_state")


def assert_spend_store(candidate: object) -> None:
    """Rejects a spend store that does not implement the contract, at construction.

    ``runtime_checkable`` protocols only check that the attributes exist, which is exactly
    the check worth making here: a store's *behaviour* cannot be verified by introspection,
    and :func:`tx402.spend_store_contract.check_spend_store` exists for that. What this
    stops is the failure mode the audit found — a lookalike accepted by duck typing and
    discovered to be missing a method in the middle of a payment, after a signature had
    already been produced (O54).
    """
    missing = [
        name
        for name in _SPEND_STORE_METHODS
        if not callable(getattr(candidate, name, None))
    ]
    if not isinstance(getattr(candidate, "kind", None), str):
        missing.append("kind")
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


class MemorySpendStore:
    """Single-process store with atomic operations protected by a re-entrant lock."""

    kind = "memory"

    def __init__(self) -> None:
        self._reservations: dict[str, SpendReservation] = {}
        self._entries: dict[str, SpendEntry] = {}
        self._lock = RLock()

    def _maintain(self, now_epoch_ms: int) -> None:
        cutoff = now_epoch_ms - ROLLING_WINDOW_MS
        for reservation_id, reservation in list(self._reservations.items()):
            current = reservation
            if current.state == "reserved" and current.expires_at_epoch_ms <= now_epoch_ms:
                current = replace(current, state="expired")
                self._reservations[reservation_id] = current
            committed_entry = self._entries.get(reservation_id)
            if (
                current.created_at_epoch_ms < cutoff
                and current.state != "reserved"
                and (
                    current.state != "committed"
                    or committed_entry is None
                    or committed_entry.committed_at_epoch_ms < cutoff
                )
            ):
                del self._reservations[reservation_id]
        for reservation_id, entry in list(self._entries.items()):
            if entry.committed_at_epoch_ms < cutoff:
                del self._entries[reservation_id]

    def get_budget_state(
        self, *, policy_scope: str, asset_id: str, now_epoch_ms: int
    ) -> BudgetState:
        with self._lock:
            self._maintain(now_epoch_ms)
            cutoff = now_epoch_ms - ROLLING_WINDOW_MS
            entries = tuple(
                entry
                for entry in self._entries.values()
                if entry.asset_id == asset_id
                and entry.committed_at_epoch_ms >= cutoff
                and entry.committed_at_epoch_ms <= now_epoch_ms
                and self._reservations[entry.reservation_id].policy_scope == policy_scope
            )
            reservations = tuple(
                reservation
                for reservation in self._reservations.values()
                if reservation.policy_scope == policy_scope
                and reservation.asset_id == asset_id
            )
            committed = sum(int(entry.amount_atomic) for entry in entries)
            reserved = sum(
                int(reservation.amount_atomic)
                for reservation in reservations
                if reservation.state == "reserved"
                and reservation.created_at_epoch_ms >= cutoff
                and reservation.created_at_epoch_ms <= now_epoch_ms
                and reservation.expires_at_epoch_ms > now_epoch_ms
            )
            return BudgetState(
                self.kind,
                str(committed),
                str(reserved),
                entries,
                reservations,
                policy_scope=policy_scope,
                asset_id=asset_id,
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
        now_epoch_ms: int,
    ) -> SpendReservation:
        with self._lock:
            existing = self._reservations.get(reservation_id)
            if existing is not None:
                if (
                    existing.policy_scope != policy_scope
                    or existing.request_fingerprint != request_fingerprint
                    or existing.asset_id != asset_id
                    or existing.amount_atomic != amount_atomic
                ):
                    raise ValueError("Reservation ID was reused with different spend data")
                return existing
            current = self.get_budget_state(
                policy_scope=policy_scope, asset_id=asset_id, now_epoch_ms=now_epoch_ms
            )
            if int(current.committed_atomic) + int(current.reserved_atomic) + int(
                amount_atomic
            ) > int(max_per_hour_atomic):
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
                        "capAtomic": max_per_hour_atomic,
                        "committedAtomic": current.committed_atomic,
                        "reservedAtomic": current.reserved_atomic,
                        "capKind": "per-hour",
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
            self._reservations[reservation_id] = reservation
            return reservation

    def commit(
        self,
        *,
        reservation_id: str,
        committed_at_epoch_ms: int,
        settlement_id: str | None = None,
    ) -> SpendEntry:
        with self._lock:
            existing = self._entries.get(reservation_id)
            if existing is not None:
                return existing
            self._maintain(committed_at_epoch_ms)
            reservation = self._reservations[reservation_id]
            if reservation.state == "released":
                raise ValueError("Released reservation cannot commit")
            entry = SpendEntry(
                reservation_id,
                reservation.request_fingerprint,
                reservation.asset_id,
                reservation.amount_atomic,
                committed_at_epoch_ms,
                settlement_id,
            )
            self._entries[reservation_id] = entry
            self._reservations[reservation_id] = replace(reservation, state="committed")
            return entry

    def release(self, *, reservation_id: str, now_epoch_ms: int) -> SpendReservation:
        with self._lock:
            self._maintain(now_epoch_ms)
            reservation = self._reservations[reservation_id]
            if reservation.state != "reserved":
                return reservation
            released = replace(reservation, state="released")
            self._reservations[reservation_id] = released
            return released
