/** Secret-free request fingerprinting (SEC-009). */

import { createHash } from "node:crypto";

import { canonicalizeJson } from "./canonical-json.js";

export const REQUEST_FINGERPRINT_DOMAIN = "tx402-request-fingerprint-v1\n";

export interface RequestFingerprintInput {
  readonly method: string;
  readonly url: string | URL;
  readonly body: string | Uint8Array | null;
  readonly challengeHash: string;
}

function sha256(bytes: string | Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

/**
 * Normalize the HTTP URL component while removing secret user-info and the non-transmitted
 * fragment. WHATWG URL canonicalizes scheme/host case, default ports, dot segments, and IDNs.
 */
export function normalizeFingerprintUrl(input: string | URL): string {
  const url = new URL(input);
  url.username = "";
  url.password = "";
  url.hash = "";
  return url.href;
}

/** Digest raw request-body bytes. `null` and an empty body intentionally share a digest. */
export function digestRequestBody(body: string | Uint8Array | null): string {
  return sha256(body === null ? new Uint8Array() : body);
}

/**
 * Bind method, normalized secret-free URL, raw body digest, and challenge hash.
 * The domain-separated canonical JSON byte construction is frozen by shared vectors.
 */
export function fingerprintRequest(input: RequestFingerprintInput): string {
  const document = {
    bodyHash: digestRequestBody(input.body),
    challengeHash: input.challengeHash,
    method: input.method.toUpperCase(),
    url: normalizeFingerprintUrl(input.url),
  };
  return sha256(`${REQUEST_FINGERPRINT_DOMAIN}${canonicalizeJson(document)}`);
}
