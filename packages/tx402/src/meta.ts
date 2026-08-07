/**
 * Package and project identity.
 *
 * Every outward-facing URL is routed through this module, so no repository or documentation
 * URL is ever hardcoded at a call site and there is a single place to change if one moves.
 */

/** npm and PyPI package name. Unscoped and identical on both registries — see ADR-009. */
export const PACKAGE_NAME = "tx402";

/**
 * x402 protocol version implemented by this SDK.
 *
 * v0.1 implements v2 only. Unknown versions raise `UnsupportedProtocolError` and never
 * fall back to heuristic parsing — see ADR-004.
 */
export const X402_PROTOCOL_VERSION = 2;

/**
 * Public project URLs.
 *
 * Intentionally the only place these strings appear in TypeScript. `security` is the
 * GitHub Private Vulnerability Reporting inbox, which is the sole disclosure channel —
 * SECURITY.md deliberately publishes no email address, because a repository-scoped
 * advisory is authenticated and an inbox is not.
 *
 * Python mirrors these in `packages/tx402-python/src/tx402/meta.py`, and
 * `TestCrossLanguageParity` reads this file as text to pin the two together (ADR-005).
 * Changing a URL here without changing it there fails that test.
 */
export const PROJECT_URLS = {
  homepage: "https://tx402.io",
  repository: "https://github.com/neogeeks/tx402",
  issues: "https://github.com/neogeeks/tx402/issues",
  documentation: "https://docs.tx402.io",
  security: "https://github.com/neogeeks/tx402/security/advisories/new",
} as const;

/**
 * Diagnostic request-ID header attached to paid retries.
 *
 * Non-authoritative: it carries no payment meaning and may be disabled by strict
 * integrations through client config — see SPEC §6.7.
 */
export const REQUEST_ID_HEADER = "X-TX402-REQUEST-ID";

/**
 * x402 protocol v2 headers.
 *
 * Verified against `@x402/core` 2.20.0. The v1 `X-PAYMENT` / `X-PAYMENT-RESPONSE` headers
 * are deliberately absent — v0.1 does not support protocol v1 (ADR-004).
 *
 * Callers may not supply any of these; doing so raises `ReservedHeaderError` (SPEC §6.1).
 */
export const PROTOCOL_HEADERS = {
  paymentRequired: "PAYMENT-REQUIRED",
  paymentSignature: "PAYMENT-SIGNATURE",
  paymentResponse: "PAYMENT-RESPONSE",
} as const;

/** Every header tx402 owns. Callers may not set any of these on a request. */
export const RESERVED_REQUEST_HEADERS: readonly string[] = [
  PROTOCOL_HEADERS.paymentRequired,
  PROTOCOL_HEADERS.paymentSignature,
  PROTOCOL_HEADERS.paymentResponse,
];
