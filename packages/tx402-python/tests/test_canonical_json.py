"""Canonical JSON cases the shared vectors cannot express.

The ``canonical-json.*`` vectors are JSON documents, so they can only carry values JSON has.
Several of the format's rules are about values that reach the serializer from *code* — a
``Decimal``, a ``datetime``, ``bytes``, a non-string dict key — and those need a Python test
to exercise.

Mirrors ``packages/tx402/test/canonical-json.test.ts``.
"""

from __future__ import annotations

import datetime
from decimal import Decimal
from typing import Any

import pytest

from tx402.canonical_json import (
    CanonicalJsonError,
    canonical_json_bytes,
    canonicalize_json,
)


def expect_rejection(value: Any, reason: str) -> None:
    """Assert the value is rejected, and rejected for the stated reason."""
    with pytest.raises(CanonicalJsonError) as raised:
        canonicalize_json(value)
    assert raised.value.reason == reason


class TestNonJsonInputs:
    def test_rejects_types_json_has_no_representation_for(self) -> None:
        expect_rejection({"when": datetime.date(2026, 8, 2)}, "unsupported-type")
        expect_rejection({"blob": b"bytes"}, "unsupported-type")
        expect_rejection({"tagged": {1, 2}}, "unsupported-type")
        expect_rejection({"tuple": (1, 2)}, "unsupported-type")

    def test_rejects_decimal_even_though_it_is_exact(self) -> None:
        """A ``Decimal`` is precise in Python and has no JavaScript counterpart.

        Serializing it would produce bytes the TypeScript side could never reproduce, so
        exactness here is not enough.
        """
        expect_rejection({"amount": Decimal("1.5")}, "unsupported-type")

    def test_rejects_non_string_dict_keys(self) -> None:
        """``json.dumps`` would coerce ``1`` to ``"1"``, changing the document silently."""
        expect_rejection({1: "one"}, "unsupported-type")
        expect_rejection({None: "none"}, "unsupported-type")

    def test_rejects_nan_and_infinity(self) -> None:
        expect_rejection({"nan": float("nan")}, "non-integer-number")
        expect_rejection({"inf": float("inf")}, "non-integer-number")
        expect_rejection({"ninf": float("-inf")}, "non-integer-number")

    def test_reports_the_path_to_the_offending_value(self) -> None:
        with pytest.raises(CanonicalJsonError) as raised:
            canonicalize_json(
                {"networks": {"eip155:8453": {"assets": [{"decimals": 6.5}]}}}
            )
        assert raised.value.path == "/networks/eip155:8453/assets/0/decimals"

    def test_rejects_a_non_ascii_key_nested_inside_a_list(self) -> None:
        expect_rejection([{"café": 1}], "non-ascii-key")

    def test_rejects_an_unsafe_integer_nested_deeply(self) -> None:
        expect_rejection({"a": [{"b": 2**53}]}, "number-out-of-safe-range")
        expect_rejection({"a": [{"b": -(2**53)}]}, "number-out-of-safe-range")


class TestAcceptedValues:
    def test_serializes_bare_scalars_not_only_objects(self) -> None:
        assert canonicalize_json(None) == "null"
        assert canonicalize_json(True) == "true"
        assert canonicalize_json(False) == "false"
        assert canonicalize_json(42) == "42"
        assert canonicalize_json("hi") == '"hi"'
        assert canonicalize_json([]) == "[]"

    def test_treats_bool_as_bool_not_as_int(self) -> None:
        """In Python ``isinstance(True, int)`` is True, so order of checks matters."""
        assert canonicalize_json({"flag": True}) == '{"flag":true}'

    def test_preserves_list_order_while_sorting_object_keys(self) -> None:
        assert canonicalize_json({"b": [3, 1, 2], "a": 1}) == '{"a":1,"b":[3,1,2]}'

    def test_accepts_the_safe_integer_boundary_itself(self) -> None:
        assert canonicalize_json(2**53 - 1) == "9007199254740991"
        assert canonicalize_json(-(2**53) + 1) == "-9007199254740991"


class TestCanonicalJsonBytes:
    def test_produces_ascii_bytes_so_utf8_encoding_is_a_no_op(self) -> None:
        raw = canonical_json_bytes({"latin": "café", "astral": "😀"})
        assert all(byte < 0x80 for byte in raw)
        assert raw.decode("ascii") == canonicalize_json({"latin": "café", "astral": "😀"})

    def test_propagates_rejection_rather_than_emitting_partial_bytes(self) -> None:
        with pytest.raises(CanonicalJsonError):
            canonical_json_bytes({"bad": 1.5})
