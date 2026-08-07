"""Python conformance runner (ADR-005).

Implements the two-stage contract in ``core-spec/conformance/README.md``. The TypeScript
runner at ``packages/tx402/test/conformance/runner.ts`` is a direct counterpart — the two
are kept structurally parallel on purpose, so that a reviewer comparing them can see at a
glance that neither language is quietly skipping something.

Test-only. Nothing here — ``jsonschema`` in particular — is imported by the SDK itself.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

REPO_ROOT: Final = Path(__file__).resolve().parents[4]
SCHEMAS_DIR: Final = REPO_ROOT / "core-spec" / "schemas"
CONFORMANCE_DIR: Final = REPO_ROOT / "core-spec" / "conformance"

#: The milestone this language implements through.
#:
#: Every vector at or below it must have a Stage B handler; the runner fails otherwise.
#: Raising this constant is how a milestone is claimed, and it cannot be raised without
#: registering the handlers.
#:
IMPLEMENTED_THROUGH: Final = "M6"

_MILESTONE_ORDER: Final = ("M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8")


def milestone_is_implemented(milestone: str) -> bool:
    return _MILESTONE_ORDER.index(milestone) <= _MILESTONE_ORDER.index(IMPLEMENTED_THROUGH)


# ----------------------------------------------------------------------------------------
# Index and vector loading
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoadedVector:
    """One vector, together with the index entry that vouches for it."""

    entry: dict[str, Any]
    #: The vector with ``$schema`` stripped — that key is an editor affordance, not format.
    vector: dict[str, Any]
    #: SHA-256 of the file's exact bytes, for comparison against the index.
    actual_sha256: str

    @property
    def id(self) -> str:
        return str(self.vector["id"])

    @property
    def kind(self) -> str:
        return str(self.vector["kind"])

    @property
    def milestone(self) -> str:
        return str(self.vector["milestone"])

    @property
    def title(self) -> str:
        return str(self.vector["title"])


def load_vectors() -> list[LoadedVector]:
    """Load the index and every vector it names.

    Deliberately reads through the index rather than globbing: a vector removed from disk
    but left in the index must fail loudly, and one added to disk but never indexed must not
    run.
    """
    index: dict[str, Any] = json.loads((CONFORMANCE_DIR / "index.json").read_text())
    if index["formatVersion"] != 1:
        raise ValueError(
            f"Unsupported conformance index formatVersion {index['formatVersion']}"
        )

    loaded: list[LoadedVector] = []
    for entry in index["vectors"]:
        path = CONFORMANCE_DIR / entry["file"]
        raw = path.read_bytes()
        document: dict[str, Any] = json.loads(raw.decode("utf-8"))
        document.pop("$schema", None)
        loaded.append(
            LoadedVector(
                entry=entry,
                vector=document,
                actual_sha256=f"sha256:{hashlib.sha256(raw).hexdigest()}",
            )
        )
    return loaded


# ----------------------------------------------------------------------------------------
# Schema registry
# ----------------------------------------------------------------------------------------


def _build_registry() -> tuple[Registry[Any], dict[str, dict[str, Any]]]:
    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted(SCHEMAS_DIR.glob("*.schema.json")):
        contents: dict[str, Any] = json.loads(path.read_text())
        schemas[str(contents["$id"])] = contents
        resources.append((str(contents["$id"]), Resource.from_contents(contents)))
    return Registry().with_resources(resources), schemas


_REGISTRY, _SCHEMAS = _build_registry()


def schema(name: str) -> Draft202012Validator:
    """Compiled validator for a schema ``$id`` under ``https://tx402.dev/schemas/v1/``."""
    schema_id = f"https://tx402.dev/schemas/v1/{name}.schema.json"
    if schema_id not in _SCHEMAS:
        raise KeyError(f"No such schema: {name}")
    return Draft202012Validator(
        _SCHEMAS[schema_id],
        registry=_REGISTRY,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def describe_errors(validator: Draft202012Validator, instance: Any) -> str:
    """Render validation errors as something a human can act on."""
    return "; ".join(
        f"{'/'.join(str(part) for part in error.absolute_path) or '/'} {error.message}"
        for error in sorted(validator.iter_errors(instance), key=str)
    )


#: The frozen code list, read from the schema rather than from the SDK, so that a rename in
#: the implementation cannot silently redefine what the fixtures are checked against.
ERROR_CODES: Final[frozenset[str]] = frozenset(
    _SCHEMAS["https://tx402.dev/schemas/v1/common.schema.json"]["$defs"]["errorCode"][
        "enum"
    ]
)


# ----------------------------------------------------------------------------------------
# Stage A — validate the vector itself
# ----------------------------------------------------------------------------------------


def _collect_error_codes(value: Any, found: list[str] | None = None) -> list[str]:
    """Collect every ``errorCode`` a vector expects, wherever it appears.

    Walks rather than reading a fixed path because the expectation shapes differ per kind
    and will keep differing; a walk cannot fall out of date with a new kind.
    """
    if found is None:
        found = []
    if isinstance(value, list):
        for item in value:
            _collect_error_codes(item, found)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key == "errorCode" and isinstance(item, str):
                found.append(item)
            else:
                _collect_error_codes(item, found)
    return found


def stage_a(loaded: LoadedVector) -> list[str]:
    """Validate a vector against the frozen schemas and taxonomy.

    Runs for every vector regardless of milestone. This is what catches a fixture that
    expects a renamed error code or a normalized shape that no longer validates — long
    before the code that would produce either exists.
    """
    problems: list[str] = []

    if loaded.actual_sha256 != loaded.entry["sha256"]:
        problems.append(
            "content hash mismatch — the file changed without the index being rebuilt "
            "(run: node tools/conformance/index.js build)"
        )

    for field in ("id", "kind", "milestone"):
        if loaded.vector[field] != loaded.entry[field]:
            problems.append(
                f"{field} {loaded.vector[field]!r} does not match index "
                f"{loaded.entry[field]!r}"
            )

    vector_schema = schema("conformance-vector")
    if not vector_schema.is_valid(loaded.vector):
        problems.append(
            "does not match the vector schema: "
            f"{describe_errors(vector_schema, loaded.vector)}"
        )

    for code in _collect_error_codes(loaded.vector.get("expected")):
        if code not in ERROR_CODES:
            problems.append(
                f"expects error code {code}, which is not in the frozen taxonomy"
            )

    # A vector claiming a valid decode must describe a shape the normalized schema accepts.
    expected = loaded.vector.get("expected") or {}
    if (
        loaded.kind == "protocol.decode-payment-required"
        and expected.get("outcome") == "valid"
    ):
        normalized_schema = schema("normalized-payment-required")
        normalized = expected.get("normalized")
        if not normalized_schema.is_valid(normalized):
            problems.append(
                "expected.normalized is not a valid NormalizedPaymentRequired: "
                f"{describe_errors(normalized_schema, normalized)}"
            )

    return problems


# ----------------------------------------------------------------------------------------
# Stage B — handler registry
# ----------------------------------------------------------------------------------------

#: Executes the implementation against a vector. Handlers raise on mismatch — returning a
#: boolean would lose the diff, which is the only genuinely useful part of a failure.
StageBHandler = Callable[[dict[str, Any]], None]

_HANDLERS: dict[str, StageBHandler] = {}


def register_handler(kind: str, handler: StageBHandler) -> None:
    _HANDLERS[kind] = handler


def handler_for(kind: str) -> StageBHandler | None:
    return _HANDLERS.get(kind)


def missing_handlers(vectors: list[LoadedVector]) -> list[str]:
    """Kinds at or below :data:`IMPLEMENTED_THROUGH` with no handler. Must be empty."""
    missing = {
        f"{loaded.kind} (required by {loaded.milestone})"
        for loaded in vectors
        if milestone_is_implemented(loaded.milestone) and loaded.kind not in _HANDLERS
    }
    return sorted(missing)
