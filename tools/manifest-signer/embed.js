/**
 * Emits the signed manifest as source in both languages.
 *
 * The SDKs cannot read `core-spec/manifests/bundled.manifest.json` at runtime: the file is
 * not inside either published package, and reaching for the filesystem would break the
 * serverless and edge deployments ADR-007 explicitly protects. So the manifest is embedded
 * as source instead.
 *
 * Generating it — rather than maintaining a second copy by hand — means the embedded bytes
 * cannot drift from the bytes that were signed. `manifest.embedded-matches-source` in both
 * test suites re-checks that on every run, so a hand edit to a generated file is caught
 * even if this tool is never re-run.
 */

const HEADER_LINES = [
  "GENERATED FILE — do not edit.",
  "",
  "Emitted by `node tools/manifest-signer/index.js embed` from",
  "core-spec/manifests/bundled.manifest.json, which is the signed source of truth.",
  "Edit that file, re-sign it, then re-run embed.",
];

/**
 * Renders a JSON value as a TypeScript literal.
 *
 * @param {unknown} value
 * @param {number} depth
 * @returns {string}
 */
function toTs(value, depth) {
  const pad = "  ".repeat(depth);
  const padInner = "  ".repeat(depth + 1);

  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  if (typeof value === "string") return JSON.stringify(value);

  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const items = value.map((item) => `${padInner}${toTs(item, depth + 1)}`);
    return `[\n${items.join(",\n")},\n${pad}]`;
  }

  const entries = Object.entries(value);
  if (entries.length === 0) return "{}";
  const rendered = entries.map(
    ([key, item]) => `${padInner}${JSON.stringify(key)}: ${toTs(item, depth + 1)}`,
  );
  return `{\n${rendered.join(",\n")},\n${pad}}`;
}

/**
 * Renders a JSON value as a Python literal.
 *
 * @param {unknown} value
 * @param {number} depth
 * @returns {string}
 */
function toPy(value, depth) {
  const pad = "    ".repeat(depth);
  const padInner = "    ".repeat(depth + 1);

  if (value === null) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return JSON.stringify(value);

  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const items = value.map((item) => `${padInner}${toPy(item, depth + 1)}`);
    return `[\n${items.join(",\n")},\n${pad}]`;
  }

  const entries = Object.entries(value);
  if (entries.length === 0) return "{}";
  const rendered = entries.map(
    ([key, item]) => `${padInner}${JSON.stringify(key)}: ${toPy(item, depth + 1)}`,
  );
  return `{\n${rendered.join(",\n")},\n${pad}}`;
}

/**
 * @param {Record<string, unknown>} manifest
 * @returns {string}
 */
export function renderTypeScript(manifest) {
  const banner = HEADER_LINES.map((line) => (line ? ` * ${line}` : " *")).join("\n");
  return `/**
${banner}
 */

import type { ReleaseManifest } from "./manifest.js";

/** The signed release manifest shipped with this build (SPEC §5.4). */
export const BUNDLED_MANIFEST: ReleaseManifest = ${toTs(manifest, 0)} as const;
`;
}

/**
 * @param {Record<string, unknown>} manifest
 * @returns {string}
 */
export function renderPython(manifest) {
  const banner = HEADER_LINES.join("\n");
  return `"""${banner}
"""

from __future__ import annotations

from typing import Any, Final

#: The signed release manifest shipped with this build (SPEC §5.4).
BUNDLED_MANIFEST: Final[dict[str, Any]] = ${toPy(manifest, 0)}
`;
}
