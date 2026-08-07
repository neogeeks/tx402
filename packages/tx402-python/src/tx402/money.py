"""Integer-only public money parsing (ADR-006, SPEC §4.3)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

MoneyParseFailureReason = Literal[
    "number-not-allowed",
    "expected-string",
    "invalid-format",
    "unexpected-symbol",
    "fractional-precision-exceeded",
    "amount-must-be-positive",
]

_MONEY_PATTERN: Final = re.compile(
    r"^(0|[1-9][0-9]*)(?:\.([0-9]+))? ([A-Z][A-Z0-9]{0,11})$"
)
_SYMBOL_PATTERN: Final = re.compile(r"^[A-Z][A-Z0-9]{0,11}$")


@dataclass(frozen=True, slots=True)
class MoneyAssetMetadata:
    symbol: str
    decimals: int


class MoneyParseError(TypeError):
    def __init__(self, reason: MoneyParseFailureReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def parse_money_atomic(value: object, asset: MoneyAssetMetadata) -> int:
    """Parse ``<decimal> <SYMBOL>`` without ever passing through a float."""
    if isinstance(value, (float, int)) and not isinstance(value, bool):
        raise MoneyParseError(
            "number-not-allowed", "Monetary values must be decimal strings"
        )
    if not isinstance(value, str):
        raise MoneyParseError("expected-string", "Monetary value must be a string")
    if (
        isinstance(asset.decimals, bool)
        or not isinstance(asset.decimals, int)
        or not 0 <= asset.decimals <= 36
        or _SYMBOL_PATTERN.fullmatch(asset.symbol) is None
    ):
        raise MoneyParseError("invalid-format", "Asset money metadata is invalid")

    match = _MONEY_PATTERN.fullmatch(value)
    if match is None:
        raise MoneyParseError(
            "invalid-format", "Money must use canonical `<decimal> <SYMBOL>` syntax"
        )
    whole, fraction, symbol = match.group(1), match.group(2) or "", match.group(3)
    if symbol != asset.symbol:
        raise MoneyParseError(
            "unexpected-symbol", f"Expected {asset.symbol}, received {symbol}"
        )
    if len(fraction) > asset.decimals:
        raise MoneyParseError(
            "fractional-precision-exceeded",
            f"{asset.symbol} supports at most {asset.decimals} fractional digits",
        )
    atomic_text = f"{whole}{fraction.ljust(asset.decimals, '0')}".lstrip("0") or "0"
    if len(atomic_text) > 78:
        raise MoneyParseError("invalid-format", "Money exceeds 78 atomic digits")
    return int(atomic_text)


def parse_positive_money_atomic(value: object, asset: MoneyAssetMetadata) -> int:
    atomic = parse_money_atomic(value, asset)
    if atomic == 0:
        raise MoneyParseError("amount-must-be-positive", "Money amount must be positive")
    return atomic


def format_money_decimal(atomic: int | str, decimals: int) -> str:
    if (
        isinstance(decimals, bool)
        or not isinstance(decimals, int)
        or not 0 <= decimals <= 36
    ):
        raise MoneyParseError("invalid-format", "Asset decimals are invalid")
    value = int(atomic)
    if value < 0:
        raise MoneyParseError(
            "amount-must-be-positive", "Money amount must not be negative"
        )
    digits = str(value).rjust(decimals + 1, "0")
    if decimals == 0:
        return digits
    whole, fraction = digits[:-decimals], digits[-decimals:].rstrip("0")
    return whole if not fraction else f"{whole}.{fraction}"
