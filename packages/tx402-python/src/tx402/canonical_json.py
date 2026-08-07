"""tx402 canonical JSON — the deterministic byte form used for signing and hashing.

Frozen at M0 (ADR-012). Two independent implementations must produce identical bytes for
identical input, or a manifest signed by the release tooling will not verify inside this
SDK. The ``canonical-json.*`` conformance vectors pin the output byte for byte.

Rules, in full:

1. Permitted types are object, array, string, integer, boolean, and null. Anything else —
   a float, ``NaN``, ``Infinity``, a ``Decimal``, a ``datetime``, ``bytes`` — is rejected
   rather than coerced. ``bool`` is checked before ``int`` because in Python ``True`` *is*
   an ``int``.
2. Integers must fit the range JavaScript can represent exactly (``|n| <= 2**53 - 1``).
   Python's integers are unbounded, so the narrower language sets the limit; without this
   a document could canonicalize here and silently round in TypeScript.
3. Object keys must be printable ASCII (U+0020 to U+007E) and are sorted ascending.
   Restricting keys to ASCII is what makes the sort unambiguous: JavaScript compares
   strings by UTF-16 code unit and Python by code point, which disagree above the BMP.
4. Strings escape ``"`` and ``\\``, use the short forms for ``\\b \\t \\n \\f \\r``, and
   escape every other character outside U+0020 to U+007E as lowercase ``\\uXXXX``. Output is
   therefore always pure ASCII, which removes any encoding ambiguity before the bytes reach
   a hash or a signature.
5. No insignificant whitespace: ``,`` and ``:`` are bare separators.

Rules 3-5 are precisely what :func:`json.dumps` produces with ``sort_keys=True``,
``ensure_ascii=True``, ``separators=(",", ":")`` and ``allow_nan=False``, so serialization
delegates to the standard library after validation. The TypeScript side writes its escaper
by hand, which keeps the two implementations genuinely independent over one frozen
contract.
"""

from __future__ import annotations

import json
from typing import Any, Final, Literal

__all__ = [
    "CanonicalJsonError",
    "CanonicalJsonErrorReason",
    "canonical_json_bytes",
    "canonicalize_json",
]

CanonicalJsonErrorReason = Literal[
    "non-integer-number",
    "number-out-of-safe-range",
    "non-ascii-key",
    "unsupported-type",
]

#: Largest integer JavaScript represents exactly. The shared ceiling — see rule 2.
_MAX_SAFE_INTEGER: Final = 2**53 - 1


class CanonicalJsonError(ValueError):
    """Raised when a value cannot be canonically serialized."""

    def __init__(self, reason: CanonicalJsonErrorReason, path: str, message: str) -> None:
        super().__init__(message)
        self.reason: CanonicalJsonErrorReason = reason
        #: JSON-Pointer-ish path to the offending value, for diagnostics.
        self.path = path


def _is_printable_ascii(key: str) -> bool:
    return all(0x20 <= ord(character) <= 0x7E for character in key)


def _validate(value: Any, path: str) -> None:
    """Rejects everything the format does not accept, depth-first.

    Validation is separated from serialization so that :func:`json.dumps` is only ever
    handed input it is guaranteed to render deterministically.
    """
    if value is None or isinstance(value, str):
        return

    # bool before int: in Python, isinstance(True, int) is True.
    if isinstance(value, bool):
        return

    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise CanonicalJsonError(
                "number-out-of-safe-range",
                path,
                f"Integer at {path or '/'} exceeds the safe range shared with TypeScript",
            )
        return

    if isinstance(value, float):
        raise CanonicalJsonError(
            "non-integer-number",
            path,
            f"Canonical JSON rejects floats at {path or '/'}; "
            "money is atomic-unit strings (ADR-006)",
        )

    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}/{index}")
        return

    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonError(
                    "unsupported-type",
                    path,
                    f"Object keys must be strings; got {type(key).__name__} at "
                    f"{path or '/'}",
                )
            if not _is_printable_ascii(key):
                raise CanonicalJsonError(
                    "non-ascii-key",
                    f"{path}/{key}",
                    "Object keys must be printable ASCII so that key ordering is "
                    f"language-independent; got {key!r}",
                )
            _validate(item, f"{path}/{key}")
        return

    raise CanonicalJsonError(
        "unsupported-type",
        path,
        f"Canonical JSON does not accept {type(value).__name__} at {path or '/'}",
    )


def canonicalize_json(value: Any) -> str:
    """Serialize a value to its canonical JSON string. The result is always pure ASCII.

    Raises:
        CanonicalJsonError: when the value contains anything the format rejects.
    """
    _validate(value, "")
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical JSON as bytes, ready for hashing or signing.

    The output is ASCII, so the UTF-8 encoding step is a no-op by construction.
    """
    return canonicalize_json(value).encode("ascii")
