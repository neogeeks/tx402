"""Package and project identity.

Mirrors ``packages/tx402/src/meta.ts`` exactly. Every constant here is part of the
cross-language contract enforced by the conformance suite, so the two files must be changed
together. Every outward-facing URL is routed through this module, so no repository or
documentation URL is ever hardcoded at a call site.
"""

from __future__ import annotations

from typing import Final

#: npm and PyPI package name. Unscoped and identical on both registries — see ADR-009.
PACKAGE_NAME: Final = "tx402"

#: x402 protocol version implemented by this SDK.
#:
#: v0.1 implements v2 only. Unknown versions raise ``UnsupportedProtocolError`` and never
#: fall back to heuristic parsing — see ADR-004.
X402_PROTOCOL_VERSION: Final = 2

#: Public project URLs. Intentionally the only place these strings appear in Python.
#:
#: ``security`` is the GitHub Private Vulnerability Reporting inbox, which is the sole
#: disclosure channel — SECURITY.md deliberately publishes no email address, because a
#: repository-scoped advisory is authenticated and an inbox is not.
#:
#: These must stay identical to ``PROJECT_URLS`` in ``packages/tx402/src/meta.ts``;
#: ``TestCrossLanguageParity`` reads that file as text and fails if they drift (ADR-005).
PROJECT_URLS: Final[dict[str, str]] = {
    "homepage": "https://tx402.io",
    "repository": "https://github.com/neogeeks/tx402",
    "issues": "https://github.com/neogeeks/tx402/issues",
    "documentation": "https://docs.tx402.io",
    "security": "https://github.com/neogeeks/tx402/security/advisories/new",
}

#: Diagnostic request-ID header attached to paid retries.
#:
#: Non-authoritative: it carries no payment meaning and may be disabled by strict
#: integrations through client config — see SPEC §6.7.
REQUEST_ID_HEADER: Final = "X-TX402-REQUEST-ID"

#: x402 protocol v2 headers.
#:
#: Verified against ``@x402/core`` 2.20.0. The v1 ``X-PAYMENT`` / ``X-PAYMENT-RESPONSE``
#: headers are deliberately absent — v0.1 does not support protocol v1 (ADR-004).
#:
#: Callers may not supply any of these; doing so raises ``ReservedHeaderError``
#: (SPEC §6.1).
PROTOCOL_HEADERS: Final[dict[str, str]] = {
    "payment_required": "PAYMENT-REQUIRED",
    "payment_signature": "PAYMENT-SIGNATURE",
    "payment_response": "PAYMENT-RESPONSE",
}

#: Every header tx402 owns. Callers may not set any of these on a request.
RESERVED_REQUEST_HEADERS: Final[tuple[str, ...]] = tuple(PROTOCOL_HEADERS.values())
