/**
 * Every file a reader outside this repository actually reads.
 *
 * This list exists because scoping a documentation guard to the page a finding was reported
 * on is how the same defect keeps reappearing one directory over. The internal-identifier
 * sweep was written to walk `docs/` only; the very commit that removed thirteen citations
 * from `docs/` added two more to `examples/`, and the guard could not see them because
 * `examples/` was bound as a constant and never swept.
 *
 * So the unit of enforcement is "reader-facing text", not "the documentation site". Anything
 * published to a reader belongs here: the site, the shipped examples, the repository README,
 * and each package's own README — the last two being what npm and PyPI render on the
 * package page, which is the first thing most readers see and the surface least likely to be
 * remembered.
 */

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const DOCS = join(REPO, "docs", "src", "content", "docs");
export const EXAMPLES = join(REPO, "examples");

/** Extensions that carry prose a reader reads. Source comments count — examples teach. */
const READABLE = new Set([".mdx", ".md", ".ts", ".py"]);

/** Directories that are build output or dependencies rather than authored text. */
const SKIP = new Set(["node_modules", "dist", ".venv", "venv", "__pycache__", ".astro"]);

function walk(dir: string, into: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP.has(entry.name)) walk(join(dir, entry.name), into);
    } else if (READABLE.has(entry.name.slice(entry.name.lastIndexOf(".")))) {
      into.push(join(dir, entry.name));
    }
  }
}

/** Every authored page on the documentation site, generated ones included. */
export function sitePages(): string[] {
  const files: string[] = [];
  walk(DOCS, files);
  return files.filter((file) => file.endsWith(".mdx"));
}

/**
 * Every reader-facing file in the repository.
 *
 * Deliberately a superset of {@link sitePages}: a guard that runs over this list cannot be
 * satisfied by moving the offending text out of `docs/`.
 */
export function readerSurfaces(): string[] {
  const files: string[] = [];
  walk(DOCS, files);
  walk(EXAMPLES, files);
  files.push(join(REPO, "README.md"));
  files.push(join(REPO, "packages", "tx402", "README.md"));
  files.push(join(REPO, "packages", "tx402-python", "README.md"));
  return files;
}

/** Reads one surface, for an assertion that wants to name the file it failed on. */
export function read(file: string): string {
  return readFileSync(file, "utf8");
}

/** The path as a reader would cite it, so a failure message points somewhere useful. */
export function relative(file: string): string {
  return file.slice(REPO.length + 1);
}
