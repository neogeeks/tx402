/**
 * Manifest guarantees the conformance vectors cannot cover.
 *
 * The vectors check verification *behavior* against shared fixtures. These check facts about
 * this repository: that the embedded copy still matches the signed source, and that the
 * bundled manifest carries what SPEC §5.4 requires it to carry.
 */

import { describe, expect, it } from "vitest";
import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { canonicalizeJson } from "../src/core/canonical-json.js";
import { MANIFEST_SIGNING_DOMAIN } from "../src/core/trusted-keys.js";

import { BUNDLED_MANIFEST } from "../src/core/bundled-manifest.js";
import {
  assertValidReleaseManifest,
  requireNetwork,
  resolveNetwork,
  verifyReleaseManifest,
} from "../src/core/manifest.js";
import { isTx402Error, type Tx402ErrorContext } from "../src/core/errors.js";
import { TRUSTED_MANIFEST_KEYS } from "../src/core/trusted-keys.js";
import { REPO_ROOT } from "./conformance/runner.js";

/** Construction-time context, as the client factory would supply it. */
const CONTEXT: Tx402ErrorContext = { requestId: "construct", phase: "initial" };

/**
 * An Ed25519 keypair minted for this test run.
 *
 * The release signing key is deliberately not in the repository, so the *content* rules —
 * empty networks, a malformed network key, a dangling alias — cannot be reached with the
 * real key: verification checks the signature first and a hand-mutated manifest fails there
 * instead. Signing with an ephemeral key and overriding `trustedKeys` gets past the
 * signature so the checks behind it are exercised, without any secret being committed.
 */
const testKey = generateKeyPairSync("ed25519");
const TEST_KEY_ID = "tx402-release-1";
const TEST_PUBLIC_KEY = Buffer.from(
  testKey.publicKey.export({ format: "jwk" }).x as string,
  "base64url",
).toString("base64");

/** Signs a manifest with the ephemeral key, exactly as tools/manifest-signer would. */
function signWithTestKey(manifest: Record<string, unknown>): Record<string, unknown> {
  const { signature: _omitted, ...unsigned } = manifest;
  const signed = Buffer.concat([
    Buffer.from(MANIFEST_SIGNING_DOMAIN, "ascii"),
    Buffer.from(canonicalizeJson(unsigned), "ascii"),
  ]);
  return {
    ...unsigned,
    signature: {
      algorithm: "ed25519",
      keyId: TEST_KEY_ID,
      value: signEd25519(null, signed, testKey.privateKey).toString("base64"),
    },
  };
}

/** Verifies against the ephemeral key rather than the shipped one. */
function verifyTestSigned(manifest: Record<string, unknown>, nowEpochMs = NOW) {
  return verifyReleaseManifest(manifest, {
    nowEpochMs,
    trustedKeys: { [TEST_KEY_ID]: TEST_PUBLIC_KEY },
  });
}

const SOURCE_MANIFEST_PATH = path.join(
  REPO_ROOT,
  "core-spec/manifests/bundled.manifest.json",
);

/** The four networks SPEC §5.4 requires the *bundled* manifest to declare. */
const REQUIRED_NETWORKS = [
  "eip155:8453",
  "eip155:84532",
  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
  "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
];

/**
 * A moment inside the bundled manifest's validity window.
 *
 * Pinned rather than `Date.now()`: these assertions must not start failing on the day the
 * manifest expires. Expiry itself is covered by `manifest.verify.expired`, and the manifest
 * is re-issued through the runbook, not by a test going red.
 */
const NOW = Date.parse("2026-09-01T00:00:00Z");

describe("bundled manifest", () => {
  it("is byte-identical to the signed source in core-spec (ADR-012)", () => {
    // src/core/bundled-manifest.ts is generated. If this fails, either someone hand-edited
    // the generated file, or the manifest was re-signed without running:
    //   node tools/manifest-signer/index.js embed
    const source: unknown = JSON.parse(readFileSync(SOURCE_MANIFEST_PATH, "utf8"));
    expect(BUNDLED_MANIFEST).toEqual(source);
  });

  it("verifies under the compiled-in trusted key", () => {
    const result = verifyReleaseManifest(BUNDLED_MANIFEST, { nowEpochMs: NOW });
    expect(result).toMatchObject({ valid: true });
  });

  it("declares Base Mainnet, Base Sepolia, Solana Mainnet, and Solana Devnet (SPEC §5.4)", () => {
    const result = verifyReleaseManifest(BUNDLED_MANIFEST, {
      nowEpochMs: NOW,
      requiredNetworks: REQUIRED_NETWORKS,
    });
    expect(result).toMatchObject({ valid: true });
  });

  it("keys Solana networks on genesis hashes, never on the solana:mainnet alias (ADR-010)", () => {
    const networkIds = Object.keys(BUNDLED_MANIFEST.networks);
    expect(networkIds).not.toContain("solana:mainnet");
    expect(networkIds).not.toContain("solana:devnet");
    expect(BUNDLED_MANIFEST.networkAliases["solana:mainnet"]).toBe(
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    );
  });

  it("truncates each Solana genesis hash to exactly its CAIP-2 reference", () => {
    // CAIP-2 caps the reference at 32 characters, so the identifier is a prefix of the full
    // hash. Cluster validation compares the *full* hash from getGenesisHash, which only
    // works if the two agree.
    for (const [networkId, network] of Object.entries(BUNDLED_MANIFEST.networks)) {
      if (!networkId.startsWith("solana:")) continue;
      const reference = networkId.slice("solana:".length);
      expect((network as { genesisHash: string }).genesisHash.slice(0, 32)).toBe(reference);
      expect(reference).toHaveLength(32);
    }
  });

  it("gives every EVM network a chainId matching its CAIP-2 reference (SPEC §7.1)", () => {
    for (const [networkId, network] of Object.entries(BUNDLED_MANIFEST.networks)) {
      if (!networkId.startsWith("eip155:")) continue;
      const reference = Number(networkId.slice("eip155:".length));
      expect((network as { chainId: number }).chainId).toBe(reference);
    }
  });

  it("never mixes production and test assets within a network", () => {
    const environments = Object.values(BUNDLED_MANIFEST.networks).map(
      (network) => network.environment,
    );
    expect(new Set(environments)).toEqual(new Set(["production", "test"]));
  });

  it("names a trusted key that this build actually carries", () => {
    expect(Object.keys(TRUSTED_MANIFEST_KEYS)).toContain(BUNDLED_MANIFEST.signature.keyId);
  });
});

describe("manifest verification edge cases", () => {
  it("rejects a non-object", () => {
    expect(verifyReleaseManifest("not a manifest", { nowEpochMs: NOW })).toMatchObject({
      valid: false,
      reason: "malformed",
    });
    expect(verifyReleaseManifest(null, { nowEpochMs: NOW })).toMatchObject({
      valid: false,
      reason: "malformed",
    });
    expect(verifyReleaseManifest([], { nowEpochMs: NOW })).toMatchObject({
      valid: false,
      reason: "malformed",
    });
  });

  it("rejects a manifest whose validity window is inverted", () => {
    const inverted = {
      ...BUNDLED_MANIFEST,
      issuedAt: "2027-08-02T00:00:00Z",
      expiresAt: "2026-08-02T00:00:00Z",
    };
    // The signature no longer covers these values, so this also confirms the check order:
    // signature is verified before the window is examined, and a tampered document must
    // report the tampering rather than the semantic problem it introduced.
    expect(verifyReleaseManifest(inverted, { nowEpochMs: NOW })).toMatchObject({
      valid: false,
      reason: "signature-mismatch",
    });
  });

  it("reports missing-required-network only when the caller asked for one", () => {
    const withRequirement = verifyReleaseManifest(BUNDLED_MANIFEST, {
      nowEpochMs: NOW,
      requiredNetworks: ["eip155:1"],
    });
    expect(withRequirement).toMatchObject({
      valid: false,
      reason: "missing-required-network",
    });

    // A caller-supplied manifest legitimately carries a single network, so the default is
    // to require nothing (SPEC §5.4's four-network rule binds the bundled manifest only).
    expect(verifyReleaseManifest(BUNDLED_MANIFEST, { nowEpochMs: NOW })).toMatchObject({
      valid: true,
    });
  });

  it("rejects a signature value that is base64 of the wrong length", () => {
    const wrongLength = {
      ...BUNDLED_MANIFEST,
      signature: { ...BUNDLED_MANIFEST.signature, value: "c2hvcnQ=" },
    };
    expect(verifyReleaseManifest(wrongLength, { nowEpochMs: NOW })).toMatchObject({
      valid: false,
      reason: "malformed-signature",
    });
  });

  it("rejects a trusted key that is not 32 bytes", () => {
    // Defends the key table itself: a truncated or mistyped entry must fail closed rather
    // than reach the Ed25519 primitive with a malformed key.
    expect(
      verifyReleaseManifest(BUNDLED_MANIFEST, {
        nowEpochMs: NOW,
        trustedKeys: { "tx402-release-1": "c2hvcnQ=" },
      }),
    ).toMatchObject({ valid: false, reason: "unknown-key-id" });
  });

  it("rejects a network key that is not a CAIP-2 identifier", () => {
    expect(
      verifyReleaseManifest(
        { ...BUNDLED_MANIFEST, networks: { "not a caip2 id": {} } },
        { nowEpochMs: NOW },
      ),
    ).toMatchObject({ valid: false, reason: "signature-mismatch" });
  });
});

describe("manifest structure — rejected before the signature is examined", () => {
  // These run ahead of signature verification, so a plain object mutation reaches them.
  const cases: [string, Record<string, unknown>][] = [
    ["release is not a string", { release: 1 }],
    ["issuedAt is not a string", { issuedAt: 20260802 }],
    ["expiresAt is missing", { expiresAt: undefined }],
    ["networks is not an object", { networks: [] }],
    ["networkAliases is not an object", { networkAliases: "none" }],
    ["signature is not an object", { signature: "nope" }],
  ];

  for (const [label, override] of cases) {
    it(`rejects a manifest where ${label}`, () => {
      expect(
        verifyReleaseManifest({ ...BUNDLED_MANIFEST, ...override }, { nowEpochMs: NOW }),
      ).toMatchObject({ valid: false, reason: "malformed" });
    });
  }
});

describe("manifest content — checked only after the signature verifies", () => {
  it("accepts a correctly signed minimal manifest", () => {
    // Confirms the ephemeral-key harness itself works, so a failure below is a real
    // content rejection rather than a broken fixture.
    expect(verifyTestSigned(signWithTestKey({ ...BUNDLED_MANIFEST }))).toMatchObject({
      valid: true,
    });
  });

  it("rejects a manifest declaring no networks", () => {
    const empty = signWithTestKey({
      ...BUNDLED_MANIFEST,
      networks: {},
      networkAliases: {},
    });
    expect(verifyTestSigned(empty)).toMatchObject({ valid: false, reason: "malformed" });
  });

  it("rejects a network key that is not a CAIP-2 identifier", () => {
    const bad = signWithTestKey({
      ...BUNDLED_MANIFEST,
      networks: { "not a caip2 id": { environment: "test" } },
      networkAliases: {},
    });
    expect(verifyTestSigned(bad)).toMatchObject({ valid: false, reason: "malformed" });
  });

  it("rejects a network entry that is not an object", () => {
    const bad = signWithTestKey({
      ...BUNDLED_MANIFEST,
      networks: { "eip155:8453": "not an object" },
      networkAliases: {},
    });
    expect(verifyTestSigned(bad)).toMatchObject({ valid: false, reason: "malformed" });
  });

  it("rejects a timestamp without an explicit UTC Z", () => {
    // A local offset would let two hosts disagree about whether the manifest has expired.
    const localOffset = signWithTestKey({
      ...BUNDLED_MANIFEST,
      issuedAt: "2026-08-02T00:00:00+02:00",
    });
    expect(verifyTestSigned(localOffset)).toMatchObject({
      valid: false,
      reason: "malformed",
    });
  });

  it("rejects a timestamp that ends in Z but is not a date", () => {
    const nonsense = signWithTestKey({ ...BUNDLED_MANIFEST, expiresAt: "not-a-dateZ" });
    expect(verifyTestSigned(nonsense)).toMatchObject({ valid: false, reason: "malformed" });
  });

  it("rejects an inverted validity window", () => {
    const inverted = signWithTestKey({
      ...BUNDLED_MANIFEST,
      issuedAt: "2027-08-02T00:00:00Z",
      expiresAt: "2026-08-02T00:00:00Z",
    });
    expect(verifyTestSigned(inverted)).toMatchObject({
      valid: false,
      reason: "invalid-validity-window",
    });
  });

  it("rejects an alias whose target is not a string", () => {
    const bad = signWithTestKey({
      ...BUNDLED_MANIFEST,
      networkAliases: { "solana:mainnet": 42 },
    });
    expect(verifyTestSigned(bad)).toMatchObject({
      valid: false,
      reason: "alias-target-unknown",
    });
  });
});

describe("assertValidReleaseManifest", () => {
  it("returns the manifest when it verifies", () => {
    expect(
      assertValidReleaseManifest(BUNDLED_MANIFEST, { nowEpochMs: NOW, context: CONTEXT }),
    ).toBe(BUNDLED_MANIFEST);
  });

  it("throws ConfigurationError carrying the machine-readable reason (SPEC §5.4)", () => {
    // SPEC §5.4 requires manifest failure to prevent client construction, so the throwing
    // form is what the factory calls. The reason has to survive into `details` — a caller
    // debugging a failed construction needs to know it was expiry, not a bad key.
    try {
      assertValidReleaseManifest(BUNDLED_MANIFEST, {
        nowEpochMs: Date.parse("2028-01-01T00:00:00Z"),
        context: CONTEXT,
      });
    } catch (error) {
      expect(isTx402Error(error)).toBe(true);
      expect(error).toMatchObject({
        code: "TX402_CONFIG_INVALID",
        details: { configPath: "manifest", reason: "expired" },
      });
      return;
    }
    throw new Error("Expected construction to fail");
  });
});

describe("requireNetwork", () => {
  it("resolves an alias to its canonical identifier", () => {
    expect(requireNetwork(BUNDLED_MANIFEST, "solana:mainnet", CONTEXT)).toBe(
      "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    );
  });

  it("returns a canonical identifier unchanged", () => {
    expect(requireNetwork(BUNDLED_MANIFEST, "eip155:8453", CONTEXT)).toBe("eip155:8453");
  });

  it("throws ConfigurationError naming the config path that carried the bad value", () => {
    try {
      requireNetwork(BUNDLED_MANIFEST, "eip155:1", CONTEXT, "routing.preferNetworks");
    } catch (error) {
      expect(error).toMatchObject({
        code: "TX402_CONFIG_INVALID",
        details: { configPath: "routing.preferNetworks", reason: "unknown-network" },
      });
      return;
    }
    throw new Error("Expected an unknown network to be rejected");
  });
});

describe("resolveNetwork", () => {
  it("ignores an alias whose target the manifest does not declare", () => {
    // Verification already rejects this, so it is defence in depth: a manifest that somehow
    // reached this point with a dangling alias must not resolve through it.
    const dangling = {
      ...BUNDLED_MANIFEST,
      networkAliases: { "solana:testnet": "solana:nowhere" },
    };
    expect(resolveNetwork(dangling, "solana:testnet")).toMatchObject({
      reason: "unknown-network",
    });
  });
});
