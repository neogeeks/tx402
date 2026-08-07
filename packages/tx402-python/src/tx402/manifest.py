"""Release manifest verification (SPEC §5.4, ADR-012).

Mirrors ``packages/tx402/src/core/manifest.ts``. The manifest is the only channel through
which chain addresses, token addresses, RPC endpoints, and decimals reach the SDK — SPEC §0
forbids hardcoding any of them into core logic. Because everything downstream trusts it, it
is verified before it is used, and a failure prevents client construction rather than
degrading to a warning.

**Why this validator is hand-written rather than schema-driven.** ``core-spec/schemas/`` has
a complete JSON Schema for this document, and it is the authority used by the conformance
runners, the signing tool, and CI. Depending on ``jsonschema`` at runtime would put a
validation library in the install path of every user for a document with fifteen fields, so
the runtime performs the narrower structural check below and the fixtures keep the two in
agreement.

**Check order is normative.** Both languages evaluate in exactly this order, because two
implementations reporting different reasons for the same bad manifest is itself a
conformance failure:

1. structure and version
2. signature envelope (algorithm, known key, well-formed signature)
3. canonical serializability
4. Ed25519 signature
5. validity window
6. semantic content (networks, aliases)

Nothing semantic is reported before the signature verifies. Describing the contents of a
document that failed authentication invites an attacker to use the error messages as an
oracle.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tx402.canonical_json import CanonicalJsonError, canonicalize_json
from tx402.errors import ConfigurationError, Tx402ErrorContext
from tx402.trusted_keys import MANIFEST_SIGNING_DOMAIN, TRUSTED_MANIFEST_KEYS

__all__ = [
    "ManifestFailureReason",
    "ManifestVerificationResult",
    "NetworkResolution",
    "assert_valid_release_manifest",
    "require_network",
    "resolve_network",
    "verify_release_manifest",
]

#: Why a manifest was rejected. Stable identifiers shared with TypeScript and with the
#: ``manifest.verify.*`` conformance vectors.
ManifestFailureReason = Literal[
    "malformed",
    "unsupported-manifest-version",
    "unsupported-algorithm",
    "unknown-key-id",
    "malformed-signature",
    "non-canonical-document",
    "signature-mismatch",
    "invalid-validity-window",
    "not-yet-issued",
    "expired",
    "alias-collides-with-network",
    "alias-target-unknown",
    "missing-required-network",
]

_SIGNATURE_PATTERN: Final = re.compile(r"^[A-Za-z0-9+/]{86}==$")
_CAIP2_PATTERN: Final = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")


@dataclass(frozen=True, slots=True)
class ManifestVerificationResult:
    """Outcome of verification. ``valid`` discriminates the two shapes."""

    valid: bool
    manifest: dict[str, Any] | None = None
    reason: ManifestFailureReason | None = None
    message: str = ""


def _fail(reason: ManifestFailureReason, message: str) -> ManifestVerificationResult:
    return ManifestVerificationResult(valid=False, reason=reason, message=message)


def _parse_utc_timestamp(value: object) -> float | None:
    """Parse an RFC 3339 UTC timestamp, in milliseconds since the epoch.

    Requires the explicit ``Z``: accepting a local offset would let two hosts disagree about
    whether the same manifest has expired.
    """
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).timestamp() * 1000


def _decode_base64_strict(value: str, expected_bytes: int) -> bytes | None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) == expected_bytes else None


def verify_release_manifest(
    candidate: object,
    *,
    now_epoch_ms: float,
    trusted_keys: Mapping[str, str] | None = None,
    required_networks: Sequence[str] = (),
) -> ManifestVerificationResult:
    """Verify a release manifest offline.

    Never raises for an invalid manifest — it returns the reason, so callers can decide
    between failing construction and reporting.

    Args:
        candidate: the document under test.
        now_epoch_ms: injected clock (SPEC §4.3), so expiry is testable without touching
            the system clock.
        trusted_keys: defaults to the keys compiled into this build.
        required_networks: networks the manifest must declare. Empty by default: SPEC
            §5.4's four-network requirement binds the *bundled* manifest, not a
            caller-supplied one, and a local integration manifest legitimately carries a
            single network.
    """
    keys = TRUSTED_MANIFEST_KEYS if trusted_keys is None else trusted_keys

    # 1. Structure and version ------------------------------------------------------------
    if not isinstance(candidate, dict):
        return _fail("malformed", "Manifest must be a JSON object")

    if candidate.get("manifestVersion") != 1:
        return _fail(
            "unsupported-manifest-version",
            f"Unsupported manifestVersion {candidate.get('manifestVersion')!r}; "
            "this build reads version 1",
        )

    for key in ("release", "issuedAt", "expiresAt"):
        if not isinstance(candidate.get(key), str):
            return _fail("malformed", f"Manifest member {key} must be a string")
    if not isinstance(candidate.get("networks"), dict):
        return _fail("malformed", "Manifest member networks must be an object")
    if not isinstance(candidate.get("networkAliases"), dict):
        return _fail("malformed", "Manifest member networkAliases must be an object")
    if not isinstance(candidate.get("signature"), dict):
        return _fail("malformed", "Manifest member signature must be an object")

    # 2. Signature envelope ---------------------------------------------------------------
    signature: dict[str, Any] = candidate["signature"]

    if signature.get("algorithm") != "ed25519":
        return _fail(
            "unsupported-algorithm",
            f"Unsupported signature algorithm {signature.get('algorithm')!r}; "
            "only ed25519 is accepted",
        )

    key_id = signature.get("keyId")
    if not isinstance(key_id, str) or key_id not in keys:
        return _fail(
            "unknown-key-id", f"Manifest is signed by an untrusted key ID {key_id!r}"
        )

    value = signature.get("value")
    if not isinstance(value, str) or not _SIGNATURE_PATTERN.match(value):
        return _fail(
            "malformed-signature", "Signature value is not a base64 Ed25519 signature"
        )

    signature_bytes = _decode_base64_strict(value, 64)
    if signature_bytes is None:
        return _fail("malformed-signature", "Signature value does not decode to 64 bytes")

    public_key_bytes = _decode_base64_strict(keys[key_id], 32)
    if public_key_bytes is None:
        return _fail("unknown-key-id", f"Trusted key {key_id} is not a 32-byte Ed25519 key")

    # 3. Canonical serializability --------------------------------------------------------
    unsigned = {k: v for k, v in candidate.items() if k != "signature"}
    try:
        canonical = canonicalize_json(unsigned)
    except CanonicalJsonError as error:
        return _fail(
            "non-canonical-document",
            f"Manifest cannot be canonically serialized "
            f"({error.reason} at {error.path or '/'})",
        )

    # 4. Signature ------------------------------------------------------------------------
    signed_bytes = MANIFEST_SIGNING_DOMAIN.encode("ascii") + canonical.encode("ascii")
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes, signed_bytes
        )
    except InvalidSignature:
        return _fail(
            "signature-mismatch", f"Manifest signature does not verify under {key_id}"
        )

    # 5. Validity window ------------------------------------------------------------------
    issued_at = _parse_utc_timestamp(candidate["issuedAt"])
    expires_at = _parse_utc_timestamp(candidate["expiresAt"])
    if issued_at is None or expires_at is None:
        return _fail(
            "malformed",
            "issuedAt and expiresAt must be RFC 3339 UTC timestamps ending in Z",
        )
    if expires_at <= issued_at:
        return _fail("invalid-validity-window", "Manifest expiresAt is not after issuedAt")
    if now_epoch_ms < issued_at:
        return _fail(
            "not-yet-issued", f"Manifest is not valid until {candidate['issuedAt']}"
        )
    if now_epoch_ms >= expires_at:
        return _fail("expired", f"Manifest expired at {candidate['expiresAt']}")

    # 6. Semantic content -----------------------------------------------------------------
    networks: dict[str, Any] = candidate["networks"]
    if not networks:
        return _fail("malformed", "Manifest declares no networks")
    for network_id, network in networks.items():
        if not _CAIP2_PATTERN.match(network_id):
            return _fail(
                "malformed", f"Network key {network_id!r} is not a CAIP-2 identifier"
            )
        if not isinstance(network, dict):
            return _fail("malformed", f"Network {network_id} must be an object")

    for alias, target in candidate["networkAliases"].items():
        if alias in networks:
            return _fail(
                "alias-collides-with-network",
                f"Alias {alias} is also a canonical network identifier; "
                "resolution would be ambiguous",
            )
        if not isinstance(target, str) or target not in networks:
            return _fail(
                "alias-target-unknown",
                f"Alias {alias} points at {target!r}, which the manifest does not declare",
            )

    for required in required_networks:
        if required not in networks:
            return _fail(
                "missing-required-network",
                f"Manifest is missing required network {required}",
            )

    return ManifestVerificationResult(valid=True, manifest=candidate)


def assert_valid_release_manifest(
    candidate: object,
    *,
    context: Tx402ErrorContext,
    now_epoch_ms: float,
    trusted_keys: Mapping[str, str] | None = None,
    required_networks: Sequence[str] = (),
) -> dict[str, Any]:
    """Verify a manifest and raise :class:`ConfigurationError` if it is unusable.

    This is the form the client constructor uses: SPEC §5.4 requires that manifest failure
    prevent construction outright.
    """
    result = verify_release_manifest(
        candidate,
        now_epoch_ms=now_epoch_ms,
        trusted_keys=trusted_keys,
        required_networks=required_networks,
    )
    if result.valid and result.manifest is not None:
        return result.manifest

    raise ConfigurationError(
        f"Release manifest rejected: {result.message}",
        context=context,
        details={"configPath": "manifest", "reason": result.reason},
    )


@dataclass(frozen=True, slots=True)
class NetworkResolution:
    """Outcome of resolving a configured network identifier."""

    resolved: str | None = None
    was_alias: bool = False
    reason: Literal["unknown-network"] | None = None
    message: str = ""


def resolve_network(manifest: Mapping[str, Any], query: str) -> NetworkResolution:
    """Resolve a configured network identifier to its canonical CAIP-2 form.

    Canonical identifiers win over aliases: an identifier that names a real network is never
    re-mapped, even if an alias with the same spelling somehow exists. Verification already
    rejects that collision, so this is defence in depth rather than a live case.

    Every comparison downstream — policy matching, route selection, health indexing,
    diagnostics — uses the canonical form. Keying any of them on an alias would silently
    fail to match a merchant's offer, which is precisely the failure ADR-010 decision 4
    exists to prevent.
    """
    networks: Mapping[str, Any] = manifest["networks"]
    if query in networks:
        return NetworkResolution(resolved=query, was_alias=False)

    aliased = manifest.get("networkAliases", {}).get(query)
    if isinstance(aliased, str) and aliased in networks:
        return NetworkResolution(resolved=aliased, was_alias=True)

    return NetworkResolution(
        reason="unknown-network",
        message=(f"{query!r} is neither a network nor an alias declared by the manifest"),
    )


def require_network(
    manifest: Mapping[str, Any],
    query: str,
    context: Tx402ErrorContext,
    config_path: str = "policy.allowed_networks",
) -> str:
    """Resolve a network identifier and raise :class:`ConfigurationError` if unknown.

    Used wherever an unknown network is a configuration mistake rather than a runtime
    condition — ``policy.allowed_networks``, ``routing.prefer_networks``, the CLI
    ``--network`` flag.
    """
    result = resolve_network(manifest, query)
    if result.resolved is not None:
        return result.resolved

    raise ConfigurationError(
        result.message,
        context=context,
        details={"configPath": config_path, "reason": result.reason},
    )
