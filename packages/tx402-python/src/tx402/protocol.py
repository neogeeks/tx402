"""Strict x402 v2 challenge decoding and tx402 normalization (SPEC §6.2)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Final
from urllib.parse import urlsplit

from x402.http.utils import decode_payment_required_header

from tx402.canonical_json import canonicalize_json
from tx402.errors import (
    InvalidPaymentRequiredError,
    Tx402ErrorContext,
    UnsupportedProtocolError,
)

MAX_PAYMENT_REQUIRED_BYTES: Final = 64 * 1024
MAX_PAYMENT_REQUIRED_DEPTH: Final = 16
MAX_PAYMENT_REQUIREMENTS: Final = 32
_BASE64: Final = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_CAIP2: Final = re.compile(r"^[a-z0-9-]{3,8}:[A-Za-z0-9-]{1,48}$")
_AMOUNT: Final = re.compile(r"^[1-9][0-9]*$")


class _PreflightError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _PreflightError("duplicate-json-key")
        result[key] = value
    return result


def _check_depth(value: Any, depth: int = 1) -> None:
    if isinstance(value, (dict, list)):
        if depth > MAX_PAYMENT_REQUIRED_DEPTH:
            raise _PreflightError("json-depth-exceeded")
        children = value.values() if isinstance(value, dict) else value
        for child in children:
            _check_depth(child, depth + 1)


def _invalid(
    reason: str,
    context: Tx402ErrorContext,
    schema_path: str = "/",
    cause: BaseException | None = None,
) -> InvalidPaymentRequiredError:
    return InvalidPaymentRequiredError(
        f"Invalid PAYMENT-REQUIRED challenge: {reason}",
        context=context,
        details={"reason": reason, "schemaPath": schema_path},
        cause=cause,
    )


def _origin(url: str) -> tuple[str, str, int] | None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, parsed.hostname.lower(), port


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def decode_payment_required(
    header: str | None,
    *,
    request_url: str,
    request_method: str,
    request_id: str,
    clock_epoch_ms: int,
) -> dict[str, Any]:
    """Decode, bound, validate, and normalize one PAYMENT-REQUIRED header."""
    context = Tx402ErrorContext(request_id=request_id, phase="parse")
    if not header:
        raise _invalid("missing-header", context)
    if _BASE64.fullmatch(header) is None or len(header) % 4 != 0:
        raise _invalid("invalid-base64", context)

    try:
        raw = base64.b64decode(header, validate=True)
    except (binascii.Error, ValueError) as error:
        raise _invalid("invalid-base64", context, cause=error) from error
    if len(raw) > MAX_PAYMENT_REQUIRED_BYTES:
        raise _invalid("header-too-large", context)

    try:
        text = raw.decode("utf-8")
        document = json.loads(text, object_pairs_hook=_pairs)
        _check_depth(document)
    except _PreflightError as error:
        raise _invalid(error.reason, context, cause=error) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _invalid("invalid-json", context, cause=error) from error

    if not isinstance(document, dict):
        raise _invalid("upstream-schema-invalid", context)
    version = document.get("x402Version")
    if version != 2:
        raise UnsupportedProtocolError(
            "Unsupported x402 protocol version",
            context=context,
            details={
                "observedVersion": version,
                "supportedVersions": [2],
                "reason": "unsupported-protocol-version",
            },
        )

    accepts = document.get("accepts")
    if not isinstance(accepts, list) or not 1 <= len(accepts) <= MAX_PAYMENT_REQUIREMENTS:
        raise _invalid("requirements-count-out-of-range", context, "/accepts")
    resource = document.get("resource")
    if not isinstance(resource, dict) or not isinstance(resource.get("url"), str):
        raise _invalid("upstream-schema-invalid", context, "/resource")
    declared_url = resource["url"]
    if _origin(declared_url) is None or _origin(declared_url) != _origin(request_url):
        raise _invalid("resource-origin-mismatch", context, "/resource/url")

    for index, requirement in enumerate(accepts):
        if not isinstance(requirement, dict):
            raise _invalid("upstream-schema-invalid", context, f"/accepts/{index}")
        amount = requirement.get("amount")
        if not isinstance(amount, str) or _AMOUNT.fullmatch(amount) is None:
            raise _invalid("amount-not-atomic-integer", context, f"/accepts/{index}/amount")

    try:
        upstream = decode_payment_required_header(header)
        upstream_document = upstream.model_dump(by_alias=True, exclude_none=True)
    except (ValueError, TypeError) as error:
        raise _invalid("upstream-schema-invalid", context, cause=error) from error

    normalized_requirements: list[dict[str, Any]] = []
    for index, requirement in enumerate(upstream_document["accepts"]):
        if (
            not isinstance(requirement.get("scheme"), str)
            or not requirement["scheme"]
            or not isinstance(requirement.get("network"), str)
            or _CAIP2.fullmatch(requirement["network"]) is None
            or not isinstance(requirement.get("asset"), str)
            or not requirement["asset"]
            or not isinstance(requirement.get("payTo"), str)
            or not requirement["payTo"]
            or not isinstance(requirement.get("maxTimeoutSeconds"), int)
            or not 1 <= requirement["maxTimeoutSeconds"] <= 86_400
            or not isinstance(requirement.get("extra"), dict)
        ):
            raise _invalid("upstream-schema-invalid", context, f"/accepts/{index}")
        normalized_requirements.append(
            {
                "index": index,
                "scheme": requirement["scheme"],
                "network": requirement["network"],
                "asset": requirement["asset"],
                "amountAtomic": requirement["amount"],
                "payTo": requirement["payTo"],
                "maxTimeoutSeconds": requirement["maxTimeoutSeconds"],
                "extra": requirement["extra"],
                "rawHash": _digest(canonicalize_json(requirement)),
            }
        )

    received_at = datetime.fromtimestamp(clock_epoch_ms / 1000, tz=timezone.utc)
    normalized: dict[str, Any] = {
        "protocolVersion": 2,
        "resource": {"url": declared_url, "method": request_method.upper()},
        "requirements": normalized_requirements,
        "receivedAt": received_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "headerHash": _digest(header),
    }
    if isinstance(upstream_document.get("error"), str):
        normalized["error"] = upstream_document["error"]
    return normalized
