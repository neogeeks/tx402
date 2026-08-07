"""Executes the shared conformance suite against the Python SDK (ADR-005).

The contract these tests implement is written down once, in
``core-spec/conformance/README.md``, and the TypeScript suite at
``packages/tx402/test/conformance.test.ts`` implements the same one.
"""

from __future__ import annotations

import pytest

from tests.conformance import handlers as _handlers  # noqa: F401  (registers Stage B)
from tests.conformance.runner import (
    IMPLEMENTED_THROUGH,
    LoadedVector,
    handler_for,
    load_vectors,
    milestone_is_implemented,
    missing_handlers,
    stage_a,
)

VECTORS = load_vectors()

EXECUTABLE = [
    loaded
    for loaded in VECTORS
    if milestone_is_implemented(loaded.milestone) and handler_for(loaded.kind)
]
PENDING = [loaded for loaded in VECTORS if not milestone_is_implemented(loaded.milestone)]


def _ident(loaded: LoadedVector) -> str:
    return loaded.id


class TestSuiteWiring:
    def test_loads_a_non_empty_integrity_checked_index(self) -> None:
        assert len(VECTORS) > 0

    def test_every_kind_at_or_below_the_implemented_milestone_has_a_handler(self) -> None:
        """The check that stops a milestone from being claimed without being implemented.

        If this fails, either register the handler or lower ``IMPLEMENTED_THROUGH``.
        """
        assert missing_handlers(VECTORS) == []

    def test_every_vector_is_either_executable_or_pending(self) -> None:
        assert len(EXECUTABLE) + len(PENDING) == len(VECTORS)


@pytest.mark.parametrize("loaded", VECTORS, ids=_ident)
class TestStageA:
    """Fixture integrity and frozen names. Runs for every vector, at every milestone."""

    def test_vector_is_internally_consistent(self, loaded: LoadedVector) -> None:
        assert stage_a(loaded) == []


@pytest.mark.parametrize("loaded", EXECUTABLE, ids=_ident)
class TestStageB:
    """The implementation, through ``IMPLEMENTED_THROUGH``."""

    def test_implementation_matches_the_vector(self, loaded: LoadedVector) -> None:
        handler = handler_for(loaded.kind)
        assert handler is not None
        handler(loaded.vector)


def test_pending_vectors_are_all_above_the_implemented_milestone() -> None:
    """Keeps the pending count visible rather than silently skipped.

    Pending vectors have already passed Stage A. This assertion exists so that a
    milestone's remaining work shows up in test output; the set is expected to shrink to
    zero by M8.
    """
    assert all(not milestone_is_implemented(loaded.milestone) for loaded in PENDING)
    assert IMPLEMENTED_THROUGH in {"M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"}
