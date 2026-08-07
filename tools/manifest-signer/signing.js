/**
 * The tx402 release-manifest signing envelope (ADR-012).
 *
 * Shared by the CLI in `index.js`. Kept separate so the envelope construction is readable
 * on its own — it is the part that must never quietly change.
 */

import { createPublicKey, createPrivateKey, sign, verify } from "node:crypto";
import { canonicalJsonBytes } from "./canonical-json.js";

/**
 * Domain separation prefix.
 *
 * Prepended to every signed manifest so that a signature produced over a tx402 manifest can
 * never be replayed as a signature over some other document the same key signs — a future
 * conformance bundle, a package attestation, anything. The version suffix means a change to
 * the envelope invalidates old signatures instead of silently reinterpreting them.
 */
export const SIGNING_DOMAIN = "tx402-release-manifest/v1\n";

/** Ed25519 signatures are 64 bytes; base64 of 64 bytes is 88 characters ending in `==`. */
export const SIGNATURE_BASE64_LENGTH = 88;

/**
 * Builds the exact bytes an Ed25519 signature is computed over.
 *
 * The `signature` member is removed rather than blanked: a placeholder value would have to
 * be agreed on by every implementation, and forgetting to strip it is a much quieter bug
 * than a missing key.
 *
 * @param {Record<string, unknown>} manifest
 * @returns {Buffer}
 */
export function signingInput(manifest) {
  const { signature: _signature, ...unsigned } = manifest;
  return Buffer.concat([
    Buffer.from(SIGNING_DOMAIN, "ascii"),
    canonicalJsonBytes(unsigned),
  ]);
}

/**
 * Wraps a raw 32-byte Ed25519 public key as a KeyObject.
 *
 * Goes through JWK rather than hand-assembling SPKI DER — the DER prefix for Ed25519 is a
 * fixed 12-byte string that is easy to get subtly wrong and produces confusing errors.
 *
 * @param {string} base64RawKey standard-alphabet base64 of the 32-byte key
 */
export function publicKeyFromRaw(base64RawKey) {
  const raw = Buffer.from(base64RawKey, "base64");
  if (raw.byteLength !== 32) {
    throw new Error(`Ed25519 public keys are 32 bytes; got ${raw.byteLength}`);
  }
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

/**
 * @param {Record<string, unknown>} manifest document; its `signature` member is ignored
 * @param {import("node:crypto").KeyObject} privateKey
 * @returns {string} standard-alphabet base64 signature
 */
export function signManifest(manifest, privateKey) {
  // `null` algorithm: Ed25519 hashes internally and rejects a pre-hash.
  return sign(null, signingInput(manifest), privateKey).toString("base64");
}

/**
 * @param {Record<string, unknown>} manifest document including its `signature` member
 * @param {string} base64RawPublicKey
 * @returns {boolean}
 */
export function verifyManifest(manifest, base64RawPublicKey) {
  const signatureMember = /** @type {{ value?: unknown }} */ (manifest.signature);
  if (!signatureMember || typeof signatureMember.value !== "string") return false;

  const signatureBytes = Buffer.from(signatureMember.value, "base64");
  if (signatureBytes.byteLength !== 64) return false;

  return verify(
    null,
    signingInput(manifest),
    publicKeyFromRaw(base64RawPublicKey),
    signatureBytes,
  );
}

/**
 * Extracts the raw 32-byte public key from a PKCS#8 private key.
 *
 * @param {import("node:crypto").KeyObject} privateKey
 * @returns {string} standard-alphabet base64
 */
export function rawPublicKeyOf(privateKey) {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  return Buffer.from(/** @type {string} */ (jwk.x), "base64url").toString("base64");
}

/**
 * @param {string} pem PKCS#8 PEM
 */
export function privateKeyFromPem(pem) {
  const key = createPrivateKey({ key: pem, format: "pem", type: "pkcs8" });
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error(`Expected an Ed25519 private key; got ${key.asymmetricKeyType}`);
  }
  return key;
}
