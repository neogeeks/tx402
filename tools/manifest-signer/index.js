#!/usr/bin/env node
/**
 * tx402 release-manifest tool (SPEC §5.4, ADR-012).
 *
 *   tx402-manifest keygen --key-id tx402-release-1 --out <dir>
 *   tx402-manifest sign   --manifest <file> [--key <pem>] [--key-id <id>]
 *   tx402-manifest verify --manifest <file> [--keys <dir>]
 *
 * The private key is read from `--key` or, preferably, from the `TX402_MANIFEST_SIGNING_KEY`
 * environment variable holding a PKCS#8 PEM. It is never accepted as a command-line
 * argument value: argv is visible to every process on the machine and is routinely captured
 * by shell history and CI logs.
 *
 * `verify` is the interesting command day to day — it is what CI runs to satisfy SEC-007
 * before publishing.
 */

import { generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  privateKeyFromPem,
  rawPublicKeyOf,
  signManifest,
  verifyManifest,
} from "./signing.js";
import { renderPython, renderTypeScript } from "./embed.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../..");
const DEFAULT_KEY_DIR = path.join(repoRoot, "core-spec/manifests/keys");
const DEFAULT_MANIFEST = path.join(repoRoot, "core-spec/manifests/bundled.manifest.json");

/**
 * @param {string[]} argv
 * @returns {Record<string, string | boolean>}
 */
function parseFlags(argv) {
  /** @type {Record<string, string | boolean>} */
  const flags = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) continue;
    const name = token.slice(2);
    const next = argv[index + 1];
    if (next === undefined || next.startsWith("--")) {
      flags[name] = true;
    } else {
      flags[name] = next;
      index += 1;
    }
  }
  return flags;
}

/** @param {string} file */
function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/**
 * Writes JSON with a trailing newline and two-space indent so that manifests stay readable
 * in review and diff cleanly. The on-disk formatting is irrelevant to the signature, which
 * is computed over the canonical form.
 *
 * @param {string} file
 * @param {unknown} value
 */
function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

/** @returns {Record<string, string>} keyId -> base64 raw public key */
function loadPublicKeys(directory) {
  if (!existsSync(directory)) return {};
  /** @type {Record<string, string>} */
  const keys = {};
  for (const entry of readdirSync(directory)) {
    if (!entry.endsWith(".pub.json")) continue;
    const record = readJson(path.join(directory, entry));
    if (record.algorithm !== "ed25519") {
      throw new Error(`${entry}: unsupported algorithm ${record.algorithm}`);
    }
    keys[record.keyId] = record.publicKey;
  }
  return keys;
}

function loadPrivateKey(flags) {
  const fromEnv = process.env.TX402_MANIFEST_SIGNING_KEY;
  if (fromEnv) return privateKeyFromPem(fromEnv);

  const keyPath = typeof flags.key === "string" ? flags.key : undefined;
  if (!keyPath) {
    throw new Error(
      "No signing key. Set TX402_MANIFEST_SIGNING_KEY to a PKCS#8 PEM, or pass --key <file>.",
    );
  }
  return privateKeyFromPem(readFileSync(keyPath, "utf8"));
}

function keygen(flags) {
  const keyId = typeof flags["key-id"] === "string" ? flags["key-id"] : "tx402-release-1";
  const outDir = typeof flags.out === "string" ? flags.out : DEFAULT_KEY_DIR;

  if (!/^tx402-release-[0-9]+$/.test(keyId)) {
    throw new Error(`--key-id must match tx402-release-<n>; got ${keyId}`);
  }

  mkdirSync(outDir, { recursive: true });

  const privatePath = path.join(outDir, `${keyId}.private.pem`);
  if (existsSync(privatePath)) {
    throw new Error(
      `${privatePath} already exists. Refusing to overwrite a signing key — ` +
        "every manifest it signed would stop verifying. Bump --key-id instead.",
    );
  }

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  writeFileSync(privatePath, privateKey.export({ format: "pem", type: "pkcs8" }), {
    mode: 0o600,
  });

  const raw = Buffer.from(
    /** @type {string} */ (publicKey.export({ format: "jwk" }).x),
    "base64url",
  ).toString("base64");

  writeJson(path.join(outDir, `${keyId}.pub.json`), {
    keyId,
    algorithm: "ed25519",
    publicKey: raw,
  });

  console.log(`Generated ${keyId}`);
  console.log(`  private  ${privatePath}   (gitignored — back this up)`);
  console.log(`  public   ${path.join(outDir, `${keyId}.pub.json`)}`);
  console.log(`  raw pub  ${raw}`);
  console.log(
    "\nMirror the public key into packages/tx402/src/core/trusted-keys.ts and\n" +
      "packages/tx402-python/src/tx402/trusted_keys.py — the SDKs trust compiled-in keys only.",
  );
  return 0;
}

function signCommand(flags) {
  const manifestPath =
    typeof flags.manifest === "string" ? flags.manifest : DEFAULT_MANIFEST;
  const manifest = readJson(manifestPath);
  const privateKey = loadPrivateKey(flags);

  const keyId =
    typeof flags["key-id"] === "string" ? flags["key-id"] : manifest.signature?.keyId;
  if (!keyId) {
    throw new Error(
      "No key ID. Pass --key-id or put one in the manifest's signature member.",
    );
  }

  const declaredPublicKey = loadPublicKeys(DEFAULT_KEY_DIR)[keyId];
  const actualPublicKey = rawPublicKeyOf(privateKey);
  if (declaredPublicKey && declaredPublicKey !== actualPublicKey) {
    throw new Error(
      `The supplied private key does not match the published public key for ${keyId}. ` +
        "Signing anyway would produce a manifest no shipped SDK can verify.",
    );
  }

  // Signature is computed over the document with `signature` removed, so the placeholder
  // written here cannot influence the result.
  manifest.signature = { algorithm: "ed25519", keyId, value: "" };
  manifest.signature.value = signManifest(manifest, privateKey);

  writeJson(manifestPath, manifest);
  console.log(`Signed ${manifestPath} with ${keyId}`);
  return 0;
}

function verifyCommand(flags) {
  const manifestPath =
    typeof flags.manifest === "string" ? flags.manifest : DEFAULT_MANIFEST;
  const keyDir = typeof flags.keys === "string" ? flags.keys : DEFAULT_KEY_DIR;

  const manifest = readJson(manifestPath);
  const keys = loadPublicKeys(keyDir);
  const keyId = manifest.signature?.keyId;

  if (!keyId || !keys[keyId]) {
    console.error(`FAIL  unknown key ID: ${keyId ?? "<absent>"}`);
    return 1;
  }

  if (!verifyManifest(manifest, keys[keyId])) {
    console.error(`FAIL  signature does not verify under ${keyId}`);
    return 1;
  }

  const expiresAt = Date.parse(manifest.expiresAt);
  const remainingDays = Math.floor((expiresAt - Date.now()) / 86_400_000);
  if (Number.isFinite(expiresAt) && remainingDays < 0) {
    console.error(
      `FAIL  manifest expired ${-remainingDays} days ago (${manifest.expiresAt})`,
    );
    return 1;
  }

  console.log(`OK    ${manifestPath}`);
  console.log(`      release ${manifest.release}, signed by ${keyId}`);
  console.log(`      networks: ${Object.keys(manifest.networks ?? {}).join(", ")}`);
  console.log(`      expires ${manifest.expiresAt} (${remainingDays} days)`);
  if (remainingDays < 90) {
    console.log("      NOTE: under 90 days remaining — schedule a re-issue.");
  }
  return 0;
}

const TS_EMBED_TARGET = path.join(repoRoot, "packages/tx402/src/core/bundled-manifest.ts");
const PY_EMBED_TARGET = path.join(
  repoRoot,
  "packages/tx402-python/src/tx402/bundled_manifest.py",
);

function embedCommand(flags) {
  const manifestPath =
    typeof flags.manifest === "string" ? flags.manifest : DEFAULT_MANIFEST;
  const manifest = readJson(manifestPath);

  const keys = loadPublicKeys(DEFAULT_KEY_DIR);
  const keyId = manifest.signature?.keyId;
  if (!keyId || !keys[keyId] || !verifyManifest(manifest, keys[keyId])) {
    throw new Error(
      `${manifestPath} does not verify. Refusing to embed an unsigned or tampered manifest — ` +
        "every SDK that shipped it would fail to construct a client.",
    );
  }

  writeFileSync(TS_EMBED_TARGET, renderTypeScript(manifest));
  writeFileSync(PY_EMBED_TARGET, renderPython(manifest));

  console.log(`Embedded ${manifestPath} (signed by ${keyId}) into:`);
  console.log(`  ${path.relative(repoRoot, TS_EMBED_TARGET)}`);
  console.log(`  ${path.relative(repoRoot, PY_EMBED_TARGET)}`);
  return 0;
}

const USAGE = `tx402-manifest — release manifest tooling (SPEC §5.4, ADR-012)

Usage:
  tx402-manifest keygen [--key-id tx402-release-N] [--out <dir>]
  tx402-manifest sign   [--manifest <file>] [--key <pem>] [--key-id <id>]
  tx402-manifest verify [--manifest <file>] [--keys <dir>]
  tx402-manifest embed  [--manifest <file>]

The signing key is read from TX402_MANIFEST_SIGNING_KEY (a PKCS#8 PEM) when set;
otherwise from --key <file>. It is never passed as a flag value.`;

function main(argv) {
  const [command, ...rest] = argv.slice(2);
  const flags = parseFlags(rest);

  switch (command) {
    case "keygen":
      return keygen(flags);
    case "sign":
      return signCommand(flags);
    case "verify":
      return verifyCommand(flags);
    case "embed":
      return embedCommand(flags);
    case "--help":
    case "-h":
    case undefined:
      console.log(USAGE);
      return 0;
    default:
      console.error(`Unknown command: ${command}\n\n${USAGE}`);
      return 2;
  }
}

try {
  process.exitCode = main(process.argv);
} catch (error) {
  console.error(
    `tx402-manifest: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
}
