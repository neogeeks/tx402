/**
 * Release manifest types and offline verification (SPEC §5.4, ADR-012).
 *
 * The manifest is the only channel through which chain addresses, token addresses, RPC
 * endpoints, and decimals reach the SDK — SPEC §0 forbids hardcoding any of them into core
 * logic. Because everything downstream trusts it, it is verified before it is used, and a
 * failure prevents client construction rather than degrading to a warning.
 *
 * **Why this validator is hand-written rather than schema-driven.** `core-spec/schemas/`
 * has a complete JSON Schema for this document, and it is the authority used by the
 * conformance runners, the signing tool, and CI. Shipping a schema validator inside the SDK
 * would add roughly 30 KiB gzipped to the core import path for a document with fifteen
 * fields, blowing the ADR-008 blocking gate outright. So the runtime performs the narrower
 * structural check below, and the fixtures keep the two in agreement.
 *
 * **Check order is normative.** Both languages evaluate in exactly this order, because two
 * implementations reporting different reasons for the same bad manifest is itself a
 * conformance failure:
 *
 *   1. structure and version
 *   2. signature envelope (algorithm, known key, well-formed signature)
 *   3. canonical serializability
 *   4. Ed25519 signature
 *   5. validity window
 *   6. semantic content (networks, aliases)
 *
 * Nothing semantic is reported before the signature verifies. Describing the contents of a
 * document that failed authentication invites an attacker to use the error messages as an
 * oracle.
 */

import { verify as verifyEd25519, createPublicKey } from "node:crypto";

import { canonicalizeJson, CanonicalJsonError } from "./canonical-json.js";
import { ConfigurationError, type Tx402ErrorContext } from "./errors.js";
import { MANIFEST_SIGNING_DOMAIN, TRUSTED_MANIFEST_KEYS } from "./trusted-keys.js";

/* ------------------------------------------------------------------------------------- */
/* Types                                                                                   */
/* ------------------------------------------------------------------------------------- */

/** Production and test networks may never be mixed in one selected route (SPEC §5.4). */
export type NetworkEnvironment = "production" | "test";

/** An ERC-20 asset offered on an EVM network. */
export interface EvmManifestAsset {
  readonly symbol: string;
  readonly address: string;
  readonly decimals: number;
  /** EIP-712 domain `version` for this token, required by the exact scheme's typed data. */
  readonly eip712Version?: string;
  readonly schemes: readonly string[];
}

/** An SPL asset offered on a Solana network. Named `mint` per SPEC §5.4's normative example. */
export interface SvmManifestAsset {
  readonly symbol: string;
  readonly mint: string;
  readonly decimals: number;
  readonly tokenProgram?: "spl-token";
  readonly schemes: readonly string[];
}

export type ManifestAsset = EvmManifestAsset | SvmManifestAsset;

export interface EvmManifestNetwork {
  readonly environment: NetworkEnvironment;
  /** Compared against the chain ID an RPC reports, before signing (SPEC §7.1). */
  readonly chainId: number;
  readonly rpcUrls: readonly string[];
  readonly assets: readonly EvmManifestAsset[];
}

export interface SvmManifestNetwork {
  readonly environment: NetworkEnvironment;
  /** Full base58 genesis hash; the CAIP-2 key is its 32-character truncation. */
  readonly genesisHash: string;
  readonly rpcUrls: readonly string[];
  readonly assets: readonly SvmManifestAsset[];
}

export type ManifestNetwork = EvmManifestNetwork | SvmManifestNetwork;

export interface ManifestSignature {
  readonly algorithm: "ed25519";
  readonly keyId: string;
  readonly value: string;
}

/** The signed release manifest (SPEC §5.4). */
export interface ReleaseManifest {
  readonly manifestVersion: 1;
  readonly release: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly networks: Readonly<Record<string, ManifestNetwork>>;
  /** Configuration aliases resolving to canonical CAIP-2 identifiers (ADR-010 decision 4). */
  readonly networkAliases: Readonly<Record<string, string>>;
  readonly signature: ManifestSignature;
}

/**
 * Why a manifest was rejected. Stable identifiers shared with Python and with the
 * `manifest.verify.*` conformance vectors.
 */
export type ManifestFailureReason =
  | "malformed"
  | "unsupported-manifest-version"
  | "unsupported-algorithm"
  | "unknown-key-id"
  | "malformed-signature"
  | "non-canonical-document"
  | "signature-mismatch"
  | "invalid-validity-window"
  | "not-yet-issued"
  | "expired"
  | "alias-collides-with-network"
  | "alias-target-unknown"
  | "missing-required-network";

export type ManifestVerificationResult =
  | { readonly valid: true; readonly manifest: ReleaseManifest }
  | {
      readonly valid: false;
      readonly reason: ManifestFailureReason;
      readonly message: string;
    };

export interface VerifyManifestOptions {
  /** Injected clock (SPEC §4.3), so expiry is testable without touching the system clock. */
  readonly nowEpochMs: number;
  /** Defaults to the keys compiled into this build. */
  readonly trustedKeys?: Readonly<Record<string, string>>;
  /**
   * Networks the manifest must declare. Empty by default: SPEC §5.4's four-network
   * requirement binds the *bundled* manifest, not a caller-supplied one, and a local
   * integration manifest legitimately carries a single network.
   */
  readonly requiredNetworks?: readonly string[];
}

/* ------------------------------------------------------------------------------------- */
/* Verification                                                                            */
/* ------------------------------------------------------------------------------------- */

const SIGNATURE_PATTERN = /^[A-Za-z0-9+/]{86}==$/;
const CAIP2_PATTERN = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;

function fail(reason: ManifestFailureReason, message: string): ManifestVerificationResult {
  return { valid: false, reason, message };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

/**
 * Parses an RFC 3339 UTC timestamp.
 *
 * Requires the explicit `Z`: accepting a local offset would let two hosts disagree about
 * whether the same manifest has expired.
 */
function parseUtcTimestamp(value: unknown): number | null {
  if (typeof value !== "string" || !value.endsWith("Z")) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function decodeBase64Strict(value: string, expectedBytes: number): Uint8Array | null {
  const decoded = Buffer.from(value, "base64");
  // Buffer.from is lenient about junk, so the length check is what actually rejects.
  return decoded.byteLength === expectedBytes ? new Uint8Array(decoded) : null;
}

/**
 * Verifies a release manifest offline. Never throws for an invalid manifest — it returns
 * the reason, so callers can decide between failing construction and reporting.
 */
export function verifyReleaseManifest(
  candidate: unknown,
  options: VerifyManifestOptions,
): ManifestVerificationResult {
  const trustedKeys = options.trustedKeys ?? TRUSTED_MANIFEST_KEYS;

  /* 1. Structure and version --------------------------------------------------------- */

  if (!isPlainObject(candidate)) {
    return fail("malformed", "Manifest must be a JSON object");
  }

  if (candidate.manifestVersion !== 1) {
    return fail(
      "unsupported-manifest-version",
      `Unsupported manifestVersion ${JSON.stringify(candidate.manifestVersion)}; this build reads version 1`,
    );
  }

  // Checked one at a time rather than in a loop: this is what narrows `unknown` to `string`
  // for the timestamp parsing further down, and it keeps the message specific.
  const { release, issuedAt: issuedAtText, expiresAt: expiresAtText } = candidate;
  if (typeof release !== "string") {
    return fail("malformed", "Manifest member release must be a string");
  }
  if (typeof issuedAtText !== "string") {
    return fail("malformed", "Manifest member issuedAt must be a string");
  }
  if (typeof expiresAtText !== "string") {
    return fail("malformed", "Manifest member expiresAt must be a string");
  }
  if (!isPlainObject(candidate.networks)) {
    return fail("malformed", "Manifest member networks must be an object");
  }
  if (!isPlainObject(candidate.networkAliases)) {
    return fail("malformed", "Manifest member networkAliases must be an object");
  }
  if (!isPlainObject(candidate.signature)) {
    return fail("malformed", "Manifest member signature must be an object");
  }

  /* 2. Signature envelope ------------------------------------------------------------ */

  const signature = candidate.signature;

  if (signature.algorithm !== "ed25519") {
    return fail(
      "unsupported-algorithm",
      `Unsupported signature algorithm ${JSON.stringify(signature.algorithm)}; only ed25519 is accepted`,
    );
  }

  if (typeof signature.keyId !== "string" || !(signature.keyId in trustedKeys)) {
    return fail(
      "unknown-key-id",
      `Manifest is signed by an untrusted key ID ${JSON.stringify(signature.keyId)}`,
    );
  }

  if (typeof signature.value !== "string" || !SIGNATURE_PATTERN.test(signature.value)) {
    return fail("malformed-signature", "Signature value is not a base64 Ed25519 signature");
  }

  const signatureBytes = decodeBase64Strict(signature.value, 64);
  if (!signatureBytes) {
    return fail("malformed-signature", "Signature value does not decode to 64 bytes");
  }

  const publicKeyRaw = trustedKeys[signature.keyId];
  const publicKeyBytes = publicKeyRaw ? decodeBase64Strict(publicKeyRaw, 32) : null;
  if (!publicKeyBytes) {
    return fail(
      "unknown-key-id",
      `Trusted key ${signature.keyId} is not a 32-byte Ed25519 key`,
    );
  }

  /* 3. Canonical serializability ----------------------------------------------------- */

  const { signature: _omitted, ...unsigned } = candidate;
  let canonical: string;
  try {
    canonical = canonicalizeJson(unsigned);
  } catch (error) {
    if (error instanceof CanonicalJsonError) {
      return fail(
        "non-canonical-document",
        `Manifest cannot be canonically serialized (${error.reason} at ${error.path || "/"})`,
      );
    }
    throw error;
  }

  /* 4. Signature --------------------------------------------------------------------- */

  const signedBytes = Buffer.concat([
    Buffer.from(MANIFEST_SIGNING_DOMAIN, "ascii"),
    Buffer.from(canonical, "ascii"),
  ]);

  const publicKey = createPublicKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(publicKeyBytes).toString("base64url"),
    },
    format: "jwk",
  });

  // `null` algorithm: Ed25519 hashes internally and rejects a pre-hash.
  if (!verifyEd25519(null, signedBytes, publicKey, signatureBytes)) {
    return fail(
      "signature-mismatch",
      `Manifest signature does not verify under ${signature.keyId}`,
    );
  }

  /* 5. Validity window --------------------------------------------------------------- */

  const issuedAt = parseUtcTimestamp(issuedAtText);
  const expiresAt = parseUtcTimestamp(expiresAtText);
  if (issuedAt === null || expiresAt === null) {
    return fail(
      "malformed",
      "issuedAt and expiresAt must be RFC 3339 UTC timestamps ending in Z",
    );
  }
  if (expiresAt <= issuedAt) {
    return fail("invalid-validity-window", "Manifest expiresAt is not after issuedAt");
  }
  if (options.nowEpochMs < issuedAt) {
    return fail("not-yet-issued", `Manifest is not valid until ${issuedAtText}`);
  }
  if (options.nowEpochMs >= expiresAt) {
    return fail("expired", `Manifest expired at ${expiresAtText}`);
  }

  /* 6. Semantic content -------------------------------------------------------------- */

  const networks = candidate.networks;
  const networkIds = Object.keys(networks);
  if (networkIds.length === 0) {
    return fail("malformed", "Manifest declares no networks");
  }
  for (const networkId of networkIds) {
    if (!CAIP2_PATTERN.test(networkId)) {
      return fail(
        "malformed",
        `Network key ${JSON.stringify(networkId)} is not a CAIP-2 identifier`,
      );
    }
    if (!isPlainObject(networks[networkId])) {
      return fail("malformed", `Network ${networkId} must be an object`);
    }
  }

  for (const [alias, target] of Object.entries(candidate.networkAliases)) {
    if (alias in networks) {
      return fail(
        "alias-collides-with-network",
        `Alias ${alias} is also a canonical network identifier; resolution would be ambiguous`,
      );
    }
    if (typeof target !== "string" || !(target in networks)) {
      return fail(
        "alias-target-unknown",
        `Alias ${alias} points at ${JSON.stringify(target)}, which the manifest does not declare`,
      );
    }
  }

  for (const required of options.requiredNetworks ?? []) {
    if (!(required in networks)) {
      return fail(
        "missing-required-network",
        `Manifest is missing required network ${required}`,
      );
    }
  }

  return { valid: true, manifest: candidate as unknown as ReleaseManifest };
}

/**
 * Verifies a manifest and throws {@link ConfigurationError} if it is unusable.
 *
 * This is the form the client constructor uses: SPEC §5.4 requires that manifest failure
 * prevent construction outright.
 */
export function assertValidReleaseManifest(
  candidate: unknown,
  options: VerifyManifestOptions & { readonly context: Tx402ErrorContext },
): ReleaseManifest {
  const result = verifyReleaseManifest(candidate, options);
  if (result.valid) return result.manifest;

  throw new ConfigurationError(`Release manifest rejected: ${result.message}`, {
    context: options.context,
    details: { configPath: "manifest", reason: result.reason },
  });
}

/* ------------------------------------------------------------------------------------- */
/* Network alias resolution                                                                */
/* ------------------------------------------------------------------------------------- */

export type NetworkResolution =
  | { readonly resolved: string; readonly wasAlias: boolean }
  | { readonly reason: "unknown-network"; readonly message: string };

/**
 * Resolves a configured network identifier to its canonical CAIP-2 form.
 *
 * Canonical identifiers win over aliases: an identifier that names a real network is never
 * re-mapped, even if an alias with the same spelling somehow exists. Verification already
 * rejects that collision, so this is defence in depth rather than a live case.
 *
 * Every comparison downstream — policy matching, route selection, health indexing,
 * diagnostics — uses the canonical form. Keying any of them on an alias would silently fail
 * to match a merchant's offer, which is precisely the failure ADR-010 decision 4 exists to
 * prevent.
 */
export function resolveNetwork(
  manifest: ReleaseManifest,
  query: string,
): NetworkResolution {
  if (query in manifest.networks) {
    return { resolved: query, wasAlias: false };
  }

  const aliased = manifest.networkAliases[query];
  if (aliased !== undefined && aliased in manifest.networks) {
    return { resolved: aliased, wasAlias: true };
  }

  return {
    reason: "unknown-network",
    message: `${JSON.stringify(query)} is neither a network nor an alias declared by the manifest`,
  };
}

/**
 * Resolves a network identifier and throws {@link ConfigurationError} if it is unknown.
 *
 * Used wherever an unknown network is a configuration mistake rather than a runtime
 * condition — `policy.allowedNetworks`, `routing.preferNetworks`, the CLI `--network` flag.
 */
export function requireNetwork(
  manifest: ReleaseManifest,
  query: string,
  context: Tx402ErrorContext,
  configPath = "policy.allowedNetworks",
): string {
  const result = resolveNetwork(manifest, query);
  if ("resolved" in result) return result.resolved;

  throw new ConfigurationError(result.message, {
    context,
    details: { configPath, reason: result.reason },
  });
}
