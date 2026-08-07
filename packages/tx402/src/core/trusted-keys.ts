/**
 * Public keys this build trusts to sign a release manifest (SPEC §5.4).
 *
 * Compiled in, deliberately. A key shipped *alongside* a manifest would authenticate
 * nothing — an attacker who can replace the manifest can replace an adjacent key file just
 * as easily. Trust has to terminate in the package itself, and this module is where it
 * does.
 *
 * There is no remote key fetch in v0.1, and there will not be one without a new threat
 * model: fetching a key at construction time would turn an offline integrity check into a
 * network dependency on tx402 infrastructure, which SPEC §13.1 rules out architecturally.
 *
 * Rotation adds an entry rather than replacing one, so manifests signed by the previous key
 * keep verifying for their remaining lifetime. A key is removed only once every manifest it
 * signed has expired.
 *
 * Mirrored by `packages/tx402-python/src/tx402/trusted_keys.py`.
 */

/** keyId to standard-alphabet base64 of the raw 32-byte Ed25519 public key. */
export const TRUSTED_MANIFEST_KEYS: Readonly<Record<string, string>> = Object.freeze({
  "tx402-release-1": "pFKQxLkGxeV4ZEsRFapcsfe0lulPBOfpnGygqazrgDY=",
  "tx402-release-2": "8wcL7EWGIMVSK75rZ8lnGIwBYiJKQQMsLllpGkaoLt4=",
});

/**
 * Domain separation prefix for manifest signatures (ADR-012).
 *
 * Prepended to the canonical bytes so a signature over a tx402 manifest can never be
 * replayed as a signature over a different document the same key signs. The `/v1` suffix
 * means changing the envelope invalidates old signatures instead of silently
 * reinterpreting them.
 */
export const MANIFEST_SIGNING_DOMAIN = "tx402-release-manifest/v1\n";
